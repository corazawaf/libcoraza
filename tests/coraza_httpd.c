/*
 * coraza_httpd - minimal HTTP server with Coraza WAF
 * Uses libmicrohttpd + libcoraza for standalone FTW testing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <microhttpd.h>
#include <coraza/coraza.h>

static coraza_waf_t waf = 0;
static volatile int running = 1;

static void handle_signal(int sig) {
    (void)sig;
    running = 0;
}

struct connection_info {
    char *data;
    size_t data_len;
};

static enum MHD_Result header_iterator(void *cls,
    enum MHD_ValueKind kind, const char *key, const char *value)
{
    (void)kind;
    coraza_transaction_t tx = (coraza_transaction_t)(uintptr_t)cls;
    if (key && value) {
        coraza_add_request_header(tx, (char*)key, strlen(key), (char*)value, strlen(value));
    }
    return MHD_YES;
}

static enum MHD_Result handle_request(void *cls,
    struct MHD_Connection *connection,
    const char *url, const char *method, const char *version,
    const char *upload_data, size_t *upload_data_size,
    void **con_cls)
{
    (void)cls;

    /* First call: set up connection info */
    if (*con_cls == NULL) {
        struct connection_info *ci = calloc(1, sizeof(struct connection_info));
        *con_cls = ci;
        return MHD_YES;
    }

    struct connection_info *ci = *con_cls;

    /* Accumulate POST data */
    if (*upload_data_size > 0) {
        char *tmp = realloc(ci->data, ci->data_len + *upload_data_size + 1);
        if (!tmp) return MHD_NO;
        ci->data = tmp;
        memcpy(ci->data + ci->data_len, upload_data, *upload_data_size);
        ci->data_len += *upload_data_size;
        ci->data[ci->data_len] = '\0';
        *upload_data_size = 0;
        return MHD_YES;
    }

    /* All data received, process with Coraza */
    coraza_transaction_t tx = coraza_new_transaction(waf);
    if (tx == 0) return MHD_NO;

    /* Phase 0: connection */
    coraza_process_connection(tx, "127.0.0.1", 12345, "127.0.0.1", 80);

    /* Strip HTTP/ prefix for version */
    const char *proto = "1.1";
    if (version && strncmp(version, "HTTP/", 5) == 0)
        proto = version + 5;
    coraza_process_uri(tx, (char*)url, (char*)method, (char*)proto);
    coraza_intervention_t *it = coraza_intervention(tx);
    int denied = (it && it->status >= 400);
    int deny_status = it ? it->status : 0;
    if (it) coraza_free_intervention(it);

    /* Phase 1: request headers */
    if (!denied) {
        MHD_get_connection_values(connection, MHD_HEADER_KIND,
            header_iterator, (void*)(uintptr_t)tx);

        coraza_process_request_headers(tx);
        it = coraza_intervention(tx);
        if (it && it->status >= 400) { denied = 1; deny_status = it->status; }
        if (it) coraza_free_intervention(it);
    }

    /* Phase 2: request body */
    if (!denied && ci->data) {
        coraza_append_request_body(tx, (unsigned char*)ci->data, ci->data_len);
    }
    if (!denied) {
        coraza_process_request_body(tx);
        it = coraza_intervention(tx);
        if (it && it->status >= 400) { denied = 1; deny_status = it->status; }
        if (it) coraza_free_intervention(it);
    }

    /* Phase 3: response headers */
    if (!denied) {
        coraza_add_response_header(tx, "Content-Type", 12, "text/plain", 10);
        coraza_process_response_headers(tx, 200, "HTTP/1.1");
        it = coraza_intervention(tx);
        if (it && it->status >= 400) { denied = 1; deny_status = it->status; }
        if (it) coraza_free_intervention(it);
    }

    /* Phase 4: response body */
    const char *resp_body;
    size_t resp_len;
    if (denied) {
        resp_body = "Access Denied\n";
        resp_len = 14;
    } else if (strcmp(url, "/reflect") == 0 && ci->data) {
        resp_body = ci->data;
        resp_len = ci->data_len;
    } else {
        resp_body = "OK\n";
        resp_len = 3;
    }

    if (!denied) {
        coraza_append_response_body(tx, (unsigned char*)resp_body, resp_len);
        coraza_process_response_body(tx);
        it = coraza_intervention(tx);
        if (it && it->status >= 400) { denied = 1; deny_status = it->status; }
        if (it) coraza_free_intervention(it);
    }

    /* Phase 5: logging */
    coraza_process_logging(tx);
    it = coraza_intervention(tx);
    if (it) coraza_free_intervention(it);

    /* Send response */
    int status = denied ? deny_status : 200;
    if (denied) {
        resp_body = "Access Denied\n";
        resp_len = 14;
    }

    struct MHD_Response *response = MHD_create_response_from_buffer(
        resp_len, (void*)resp_body, MHD_RESPMEM_MUST_COPY);
    if (!response) {
        coraza_free_transaction(tx);
        return MHD_NO;
    }
    enum MHD_Result ret = MHD_queue_response(connection, status, response);
    MHD_destroy_response(response);

    coraza_free_transaction(tx);

    return ret;
}

static void request_completed(void *cls, struct MHD_Connection *connection,
    void **con_cls, enum MHD_RequestTerminationCode toe)
{
    (void)cls; (void)connection; (void)toe;
    struct connection_info *ci = *con_cls;
    if (ci) {
        free(ci->data);
        free(ci);
    }
}

int main(int argc, char **argv) {
    const char *config_file = "coraza_includes.conf";
    int port = 8080;

    if (argc > 1) config_file = argv[1];
    if (argc > 2) port = atoi(argv[2]);

    /* Create WAF */
    coraza_waf_config_t config = coraza_new_waf_config();
    if (coraza_rules_add_file(config, (char*)config_file) < 0) {
        fprintf(stderr, "Failed to load rules from %s\n", config_file);
        coraza_free_waf_config(config);
        return 1;
    }

    char *err = NULL;
    waf = coraza_new_waf(config, &err);
    coraza_free_waf_config(config);
    if (waf == 0) {
        fprintf(stderr, "Failed to create WAF: %s\n", err ? err : "unknown");
        return 1;
    }
    printf("WAF loaded, %d rules\n", coraza_rules_count(waf));

    /* Start HTTP server */
    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_INTERNAL_POLLING_THREAD,
        port, NULL, NULL,
        &handle_request, NULL,
        MHD_OPTION_NOTIFY_COMPLETED, &request_completed, NULL,
        MHD_OPTION_CLIENT_DISCIPLINE_LVL, (int)-1,
        MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)5,
        MHD_OPTION_END);

    if (!daemon) {
        fprintf(stderr, "Failed to start HTTP server\n");
        coraza_free_waf(waf);
        return 1;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    printf("Coraza HTTP server listening on port %d\n", port);

    while (running) sleep(1);

    MHD_stop_daemon(daemon);
    coraza_free_waf(waf);
    return 0;
}
