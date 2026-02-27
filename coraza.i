/* SWIG interface file for libcoraza */
%module coraza

%{
/* Include the actual generated header in the wrapper code */
#include "coraza/coraza.h"
%}

/* Include SWIG standard integer type support */
%include <stdint.i>

/*
 * The debug log and error callback types require language-specific
 * function pointer implementations. They are excluded from the default
 * SWIG wrapper to avoid portability issues. Language-specific bindings
 * may re-enable these using %callback or director classes.
 */
%ignore coraza_add_debug_log_callback;
%ignore coraza_add_error_callback;

/*
 * Handle the char** output parameter for error messages.
 * coraza_new_waf() and coraza_rules_merge() report errors via a char**
 * output parameter. The typemaps below hide this parameter from the
 * target language and raise an exception when an error is returned.
 */
%typemap(in, numinputs=0) char **er (char *_swig_er = NULL) {
    $1 = &_swig_er;
}

%typemap(argout) char **er {
    if (*$1) {
        char *_swig_err_msg = *$1;
        *$1 = NULL;
#ifdef SWIGJAVA
        SWIG_JavaThrowException(jenv, SWIG_JavaRuntimeException, _swig_err_msg);
        return $null;
#else
        SWIG_exception_fail(SWIG_RuntimeError, _swig_err_msg);
#endif
    }
}

/*
 * coraza_matched_rule_get_error_log() returns a heap-allocated string
 * that the caller is responsible for freeing. %newobject instructs SWIG
 * to take ownership so the target language runtime frees it automatically.
 */
%newobject coraza_matched_rule_get_error_log;

/*
 * Byte-buffer typemap: collapses (const unsigned char *data, int length)
 * into a single native bytes/array argument in the target language.
 */
#ifdef SWIGPYTHON
%typemap(in) (const unsigned char *data, int length) {
    if (!PyBytes_Check($input) && !PyByteArray_Check($input)) {
        PyErr_SetString(PyExc_TypeError, "Expected bytes or bytearray");
        SWIG_fail;
    }
    if (PyBytes_Check($input)) {
        $1 = (unsigned char *)PyBytes_AS_STRING($input);
        $2 = (int)PyBytes_GET_SIZE($input);
    } else {
        $1 = (unsigned char *)PyByteArray_AS_STRING($input);
        $2 = (int)PyByteArray_GET_SIZE($input);
    }
}
#endif

#ifdef SWIGJAVA
/*
 * Java: load the JNI shared library automatically when the module is
 * first referenced.  The library is expected to be named libcoraza_jni.so
 * (Linux / macOS) or coraza_jni.dll (Windows).
 */
%pragma(java) jniclasscode=%{
  static {
    System.loadLibrary("coraza_jni");
  }
%}

/* Map (const unsigned char *data, int length) → byte[] in Java. */
%typemap(jni)    (const unsigned char *data, int length) "jbyteArray"
%typemap(jtype)  (const unsigned char *data, int length) "byte[]"
%typemap(jstype) (const unsigned char *data, int length) "byte[]"
%typemap(javain) (const unsigned char *data, int length) "$javainput"
%typemap(in)     (const unsigned char *data, int length) {
    $1 = (unsigned char *)JCALL2(GetByteArrayElements, jenv, $input, NULL);
    $2 = (int)JCALL1(GetArrayLength, jenv, $input);
}
%typemap(argout) (const unsigned char *data, int length) {
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *)$1, JNI_ABORT);
}
#endif

/*
 * Type definitions
 *
 * These mirror the types in coraza/coraza.h but are defined here to avoid
 * exposing the CGO-generated Go runtime boilerplate to SWIG.
 */

typedef uintptr_t coraza_waf_config_t;
typedef uintptr_t coraza_waf_t;
typedef uintptr_t coraza_transaction_t;
typedef uintptr_t coraza_matched_rule_t;

typedef struct coraza_intervention_t {
    char *action;
    int status;
    int pause;
    int disruptive;
} coraza_intervention_t;

typedef enum coraza_debug_log_level_t {
    CORAZA_DEBUG_LOG_LEVEL_UNKNOWN,
    CORAZA_DEBUG_LOG_LEVEL_TRACE,
    CORAZA_DEBUG_LOG_LEVEL_DEBUG,
    CORAZA_DEBUG_LOG_LEVEL_INFO,
    CORAZA_DEBUG_LOG_LEVEL_WARN,
    CORAZA_DEBUG_LOG_LEVEL_ERROR,
} coraza_debug_log_level_t;

typedef enum coraza_severity_t {
    CORAZA_SEVERITY_UNKNOWN,
    CORAZA_SEVERITY_DEBUG,
    CORAZA_SEVERITY_INFO,
    CORAZA_SEVERITY_NOTICE,
    CORAZA_SEVERITY_WARNING,
    CORAZA_SEVERITY_ERROR,
    CORAZA_SEVERITY_CRITICAL,
    CORAZA_SEVERITY_ALERT,
    CORAZA_SEVERITY_EMERGENCY,
} coraza_severity_t;

/*
 * Function declarations
 */

extern coraza_waf_config_t coraza_new_waf_config();
extern int coraza_rules_add_file(coraza_waf_config_t c, const char *file);
extern int coraza_rules_add(coraza_waf_config_t c, const char *directives);
extern int coraza_free_waf_config(coraza_waf_config_t config);
extern coraza_waf_t coraza_new_waf(coraza_waf_config_t config, char **er);
extern coraza_transaction_t coraza_new_transaction(coraza_waf_t w);
extern coraza_transaction_t coraza_new_transaction_with_id(coraza_waf_t w,
                                                           const char *id);
extern coraza_intervention_t *coraza_intervention(coraza_transaction_t t);
extern int coraza_process_connection(coraza_transaction_t t,
                                     const char *sourceAddress,
                                     int clientPort,
                                     const char *serverHost,
                                     int serverPort);
extern int coraza_process_request_body(coraza_transaction_t t);
extern int coraza_update_status_code(coraza_transaction_t t, int code);
extern int coraza_process_uri(coraza_transaction_t t, const char *uri,
                              const char *method, const char *proto);
extern int coraza_add_request_header(coraza_transaction_t t, const char *name,
                                     int name_len, const char *value,
                                     int value_len);
extern int coraza_process_request_headers(coraza_transaction_t t);
extern int coraza_process_logging(coraza_transaction_t t);
extern int coraza_append_request_body(coraza_transaction_t t,
                                      const unsigned char *data, int length);
extern int coraza_add_get_args(coraza_transaction_t t, const char *name,
                               const char *value);
extern int coraza_add_response_header(coraza_transaction_t t,
                                      const char *name, int name_len,
                                      const char *value, int value_len);
extern int coraza_append_response_body(coraza_transaction_t t,
                                       const unsigned char *data, int length);
extern int coraza_process_response_body(coraza_transaction_t t);
extern int coraza_process_response_headers(coraza_transaction_t t, int status,
                                           const char *proto);
extern int coraza_rules_count(coraza_waf_t w);
extern int coraza_free_transaction(coraza_transaction_t t);
extern int coraza_free_intervention(coraza_intervention_t *it);
extern int coraza_rules_merge(coraza_waf_t w1, coraza_waf_t w2, char **er);
extern int coraza_request_body_from_file(coraza_transaction_t t,
                                         const char *file);
extern int coraza_free_waf(coraza_waf_t t);
extern coraza_severity_t coraza_matched_rule_get_severity(
    coraza_matched_rule_t r);
extern char *coraza_matched_rule_get_error_log(coraza_matched_rule_t r);
