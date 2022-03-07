#include "coraza_core.h"
#include "stdio.h"

int main()
{
    coraza_waf_t *waf = NULL;
    coraza_transaction_t *tx = NULL;
    coraza_intervention_t *intervention = NULL;
    printf("Starting...\n");
    waf = coraza_new_waf();
    if (waf == NULL) {
        printf("Failed to create waf\n");
        return 1;
    }
    char *err = NULL;
    printf("Compiling rules...\n");
    coraza_rules_add(waf, "SecRule REMOTE_ADDR \"127.0.0.1\" \"id:1,phase:1,deny,status:403\"", &err);
    if(err) {
        printf("%s\n", err);
        return 1;
    }
    printf("%d rules compiled\n", coraza_rules_count(waf));
    printf("Creating transaction...\n");
    tx = coraza_new_transaction(waf, NULL);
    if(tx == NULL) {
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

    char ** uri = NULL;
    uri = coraza_transaction_variable(tx, "request_uri", "");
    if(uri == NULL) {
        printf("Failed to get request_uri\n");
        return 1;
    }
    printf("Request URI: %s\n", *uri);
    free(uri);

    if(coraza_transaction_free(tx) != 0) {
        printf("Failed to free transaction 1\n");
        return 1;
    }
    /*
    if(tx != NULL) {
        printf("Failed to free transaction 2\n");
        return 1;
    }*/
    free(intervention);
    coraza_free_waf(waf);
    /*
    if(waf != NULL) {
        printf("Failed to free WAF\n");
        return 1;
    }*/
    return 0;
}