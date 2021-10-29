#include <ctype.h>
#include "coraza.h"
#include "apr_buckets.h"
#include "apr_general.h"
#include "apr.h"
#include "apr_hash.h"
#include "apr_lib.h"
#include "apr_strings.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "util_filter.h"

#include "httpd.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "coraza_filters.h"

#ifndef _SRC_APACHE_HTTP_CORAZA__
#define _SRC_APACHE_HTTP_CORAZA__

#define NOTE_MSR "coraza-tx-context"
#define CORAZA_APACHE_CONNECTOR "Coraza-Apache v0.1.0-beta"
/* #define REQUEST_EARLY */
#define LATE_CONNECTION_PROCESS

#define N_INTERVENTION_STATUS 200

typedef struct
{
    request_rec *r;
    coraza_transaction_t *t;
} coraza_t;

typedef struct
{
    void *waf;
    int coraza_state;
    char *name_for_debug;
} coraza_conf_t;

extern module AP_MODULE_DECLARE_DATA coraza_module;
extern const command_rec module_directives[];

int process_intervention(coraza_transaction_t *t, request_rec *r);

int coraza_apache_init(apr_pool_t *pool);
int coraza_apache_cleanup();
static apr_status_t coraza_module_cleanup(void *data);

/*

static int hook_connection_early(conn_rec *conn);

static int msc_hook_pre_config(apr_pool_t *mp, apr_pool_t *mp_log,
    apr_pool_t *mp_temp);
static int msc_hook_post_config(apr_pool_t *mp, apr_pool_t *mp_log,
    apr_pool_t *mp_temp, server_rec *s);

static int hook_request_late(request_rec *r);
static int hook_request_early(request_rec *r);
static int hook_log_transaction(request_rec *r);

static void hook_insert_filter(request_rec *r);
*/
/*
*/

static int process_request_headers(request_rec *r, coraza_t *msr);

#endif /*  _SRC_APACHE_HTTP_MODSECURITY__ */