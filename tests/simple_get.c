#include <stdio.h>

#include "coraza/coraza.h"

void logcb(void *context, coraza_debug_log_level_t level, const char *msg, const char *fields)
{
    printf("[%s][level %d] %s %s\n", (const char *)context, level, msg, fields);
}


int main()
{
    coraza_waf_config_t config = coraza_new_waf_config();
    if (config == 0) {
        printf("Failed to create config\n");
        return 1;
    }
    printf("Compiling rules...\n");
    coraza_rules_add(config, "SecRule REMOTE_ADDR \"127.0.0.1\" \"id:1,phase:1,deny,log,msg:'test 123',status:403\"");

    printf("Attaching log callback\n");
    coraza_add_debug_log_callback(config, logcb, "simple_get");

    coraza_waf_t waf = 0;
    coraza_transaction_t tx = 0;
    coraza_intervention_t *intervention = NULL;
    char *err = NULL;
    char ** uri = NULL;

    printf("Starting...\n");
    waf = coraza_new_waf(config, &err);
    if (err) {
        printf("%s\n", err);
        return 1;
    }
    if (waf == 0) {
        printf("Failed to create waf\n");
        return 1;
    }

    printf("%d rules compiled\n", coraza_rules_count(waf));
    printf("Creating transaction...\n");
    tx = coraza_new_transaction_with_id(waf, "simple_get");
    if(tx == 0) {
        printf("Failed to create transaction\n");
        return 1;
    }

    printf("Processing connection...\n");
    coraza_process_connection(tx, "127.0.0.1", 55555, "", 80);
    printf("Processing request line\n");
    coraza_process_uri(tx, "/someurl", "GET", "HTTP/1.1");
    printf("Processing phase 1\n");
    coraza_process_request_headers(tx);
    printf("Processing phase 2\n");
    coraza_process_request_body(tx);
    printf("Processing phase 3\n");
    coraza_process_response_headers(tx, 200, "HTTP/1.1");
    printf("Processing phase 4\n");
    coraza_process_response_body(tx);
    printf("Processing phase 5\n");
    coraza_process_logging(tx);
    printf("Processing intervention\n");

    intervention = coraza_intervention(tx);
    if (intervention == NULL)
    {
        printf("Failed to disrupt transaction\n");
        return 1;
    }
    printf("Transaction disrupted with status %d\n", intervention->status);

    if(coraza_free_transaction(tx) != 0) {
        printf("Failed to free transaction 1\n");
        return 1;
    }
    coraza_free_waf(waf);
    coraza_free_waf_config(config);
    coraza_free_intervention(intervention);
    return 0;
}
