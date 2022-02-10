#include "coraza_core.h"
#include "stdio.h"

int main() {
    coraza_waf_t waf = coraza_new_waf();
    char *err = NULL;
    coraza_rules_from_string(waf, "SecRule REMOTE_ADDR \"127.0.0.1\" \"id:1,phase:1,deny,status:403\"", &err);
    if(err) {
        printf("%s\n", err);
        return 1;
    }
    coraza_transaction_t tx = coraza_new_transaction(waf, NULL);
    coraza_process_connection(tx, "127.0.0.1", 55555, "", 80);
    coraza_process_request_headers(tx);
    coraza_intervention_t *intervention = NULL;
    if(coraza_intervention(tx, intervention) == 0) {
        printf("%s\n", intervention->action);
        return 1;
    }

    return 0;
}