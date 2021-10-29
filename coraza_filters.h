#include "http_core.h"
#include "http_request.h"
#include "httpd.h"
#include "ap_release.h"

#include <apr_general.h>
#include <apr_optional.h>

#ifndef _SRC_CORAZA_FILTERS__
#define _SRC_CORAZA_FILTERS__

#include "mod_coraza.h"

apr_status_t output_filter(ap_filter_t *f, apr_bucket_brigade *bb_in);

apr_status_t input_filter(ap_filter_t *f, apr_bucket_brigade *bb_out,
                          ap_input_mode_t mode, apr_read_type_e block, apr_off_t nbytes);

#endif /* _SRC_CORAZA_FILTERS__ */