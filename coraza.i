/* SWIG interface file for libcoraza */
/*
 * SOURCE OF TRUTH: libcoraza/coraza.go
 * Every //export function in coraza.go must be reflected here as either an
 * extern declaration or a %ignore directive (for callback-based functions).
 * Run `make check-swig-sync` to verify the two files are in sync.
 */
%module coraza

%{
/* Include the actual generated header in the wrapper code */
#include <stdlib.h>
#include "coraza/coraza.h"
%}

/* Include SWIG standard integer type support */
%include <stdint.i>

/*
 * The raw coraza_add_*_callback functions take C function pointers and
 * cannot be wrapped by SWIG directly. They are excluded here; each language
 * gets its own coraza_set_error_callback / coraza_set_debug_log_callback
 * wrapper (defined below) that uses the userContext parameter as a
 * trampoline to call back into the target language runtime.
 */
%ignore coraza_add_debug_log_callback;
%ignore coraza_add_error_callback;
%ignore coraza_free_string;

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
        free(_swig_err_msg);
        return $null;
#else
        SWIG_Error(SWIG_RuntimeError, _swig_err_msg);
        free(_swig_err_msg);
        SWIG_fail;
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
    Py_ssize_t _swig_buf_sz;
    if (PyBytes_Check($input)) {
        $1 = (unsigned char *)PyBytes_AS_STRING($input);
        _swig_buf_sz = PyBytes_GET_SIZE($input);
    } else {
        $1 = (unsigned char *)PyByteArray_AS_STRING($input);
        _swig_buf_sz = PyByteArray_GET_SIZE($input);
    }
    /* Guard against Py_ssize_t → int truncation (buffer > 2 GB). */
    if (_swig_buf_sz > INT_MAX) {
        PyErr_SetString(PyExc_ValueError, "buffer exceeds maximum length (2 GB)");
        SWIG_fail;
    }
    $2 = (int)_swig_buf_sz;
}

/*
 * Python callback trampolines.
 *
 * Use coraza_set_error_callback / coraza_set_debug_log_callback to register
 * plain Python callables.  The callable is stored as the userContext passed
 * to the underlying C API, and a static C trampoline calls back into Python
 * via the CPython C API.
 *
 * Signatures expected by the target language:
 *   on_error(rule_handle: int) -> None
 *       rule_handle can be passed to coraza_matched_rule_get_error_log() etc.
 *   on_debug_log(level: int, message: str, fields: str) -> None
 *
 * Lifetime note: the callable is Py_INCREF'd on registration and lives for
 * the lifetime of the WAF.  Keep an external reference and del it after
 * freeing the WAF if earlier collection is needed.
 */
%{
static void _swig_py_error_trampoline(void *ctx, coraza_matched_rule_t rule) {
    PyGILState_STATE gs = PyGILState_Ensure();
    PyObject *cb = (PyObject *)ctx;
    /* Use "K" (unsigned long long) to avoid truncation on 64-bit Windows
     * where unsigned long is 32 bits but uintptr_t is 64 bits. */
    PyObject *r = PyObject_CallFunction(cb, "K", (unsigned long long)rule);
    Py_XDECREF(r);
    if (PyErr_Occurred()) PyErr_Print();
    PyGILState_Release(gs);
}

static void _swig_py_debug_trampoline(void *ctx, coraza_debug_log_level_t level,
                                       const char *msg, const char *fields) {
    PyGILState_STATE gs = PyGILState_Ensure();
    PyObject *cb = (PyObject *)ctx;
    PyObject *r = PyObject_CallFunction(cb, "iss", (int)level,
                                        msg ? msg : "", fields ? fields : "");
    Py_XDECREF(r);
    if (PyErr_Occurred()) PyErr_Print();
    PyGILState_Release(gs);
}
%}

%exception coraza_set_error_callback {
    $action
    if (PyErr_Occurred()) SWIG_fail;
}
%exception coraza_set_debug_log_callback {
    $action
    if (PyErr_Occurred()) SWIG_fail;
}
%inline %{
int coraza_set_error_callback(coraza_waf_config_t cfg, PyObject *cb) {
    if (!PyCallable_Check(cb)) {
        PyErr_SetString(PyExc_TypeError, "coraza_set_error_callback: expected a callable");
        return 1;
    }
    Py_INCREF(cb);
    return coraza_add_error_callback(cfg, _swig_py_error_trampoline, (void *)cb);
}
int coraza_set_debug_log_callback(coraza_waf_config_t cfg, PyObject *cb) {
    if (!PyCallable_Check(cb)) {
        PyErr_SetString(PyExc_TypeError, "coraza_set_debug_log_callback: expected a callable");
        return 1;
    }
    Py_INCREF(cb);
    return coraza_add_debug_log_callback(cfg, _swig_py_debug_trampoline, (void *)cb);
}
%}
%exception;
#endif

#ifdef SWIGJAVA
/*
 * Suppress SWIG's auto-generated wrappers for coraza_set_error_callback and
 * coraza_set_debug_log_callback.  These are handled entirely via JNI (see the
 * JNIEXPORT functions below and the %pragma(java) modulecode declarations at
 * the end of this block).  Without these %ignore directives some SWIG versions
 * pick up the PyObject* signatures from the Python %inline block and generate
 * unusable SWIGTYPE_p_Object wrappers.
 */
%ignore coraza_set_error_callback;
%ignore coraza_set_debug_log_callback;

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

/*
 * Java callback trampolines.
 *
 * Implement CorazaErrorCallback / CorazaDebugLogCallback (provided in the
 * examples/java/ directory) and pass instances to:
 *   coraza.coraza_set_error_callback(cfg, callback)
 *   coraza.coraza_set_debug_log_callback(cfg, callback)
 *
 * The Java object is stored as a JNI global reference in a heap-allocated
 * context struct.  A static C trampoline calls back into Java via JNI,
 * attaching the current thread as a daemon if needed (e.g. Go goroutines).
 *
 * Lifetime note: the global reference lives for the lifetime of the WAF.
 */
%{
typedef struct {
    JavaVM   *jvm;
    jobject   obj; /* JNI global reference to the Java callback object */
    jmethodID mid;
} _swig_java_cb_ctx_t;

static void _swig_java_error_trampoline(void *ctx, coraza_matched_rule_t rule) {
    _swig_java_cb_ctx_t *jctx = (_swig_java_cb_ctx_t *)ctx;
    JNIEnv *env = NULL;
    jboolean attached = JNI_FALSE;
    if ((*jctx->jvm)->GetEnv(jctx->jvm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
        (*jctx->jvm)->AttachCurrentThreadAsDaemon(jctx->jvm, (void **)&env, NULL);
        attached = JNI_TRUE;
    }
    (*env)->CallVoidMethod(env, jctx->obj, jctx->mid, (jlong)(uintptr_t)rule);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionDescribe(env);
    if (attached) (*jctx->jvm)->DetachCurrentThread(jctx->jvm);
}

static void _swig_java_debug_trampoline(void *ctx, coraza_debug_log_level_t level,
                                         const char *msg, const char *fields) {
    _swig_java_cb_ctx_t *jctx = (_swig_java_cb_ctx_t *)ctx;
    JNIEnv *env = NULL;
    jboolean attached = JNI_FALSE;
    if ((*jctx->jvm)->GetEnv(jctx->jvm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
        (*jctx->jvm)->AttachCurrentThreadAsDaemon(jctx->jvm, (void **)&env, NULL);
        attached = JNI_TRUE;
    }
    jstring jmsg    = (*env)->NewStringUTF(env, msg    ? msg    : "");
    jstring jfields = (*env)->NewStringUTF(env, fields ? fields : "");
    /* NewStringUTF returns NULL on OOM; skip the call rather than crash. */
    if (jmsg && jfields) {
        (*env)->CallVoidMethod(env, jctx->obj, jctx->mid, (jint)level, jmsg, jfields);
    }
    if (jmsg)    (*env)->DeleteLocalRef(env, jmsg);
    if (jfields) (*env)->DeleteLocalRef(env, jfields);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionDescribe(env);
    if (attached) (*jctx->jvm)->DetachCurrentThread(jctx->jvm);
}

JNIEXPORT jint JNICALL Java_coraza_coraza_1set_1error_1callback(
        JNIEnv *env, jclass cls, jlong cfg, jobject cb) {
    if (!cb) return 1;
    _swig_java_cb_ctx_t *ctx =
        (_swig_java_cb_ctx_t *)malloc(sizeof(_swig_java_cb_ctx_t));
    if (!ctx) return 1;  /* OOM */
    (*env)->GetJavaVM(env, &ctx->jvm);
    ctx->obj = (*env)->NewGlobalRef(env, cb);
    ctx->mid = (*env)->GetMethodID(env, (*env)->GetObjectClass(env, cb),
                                    "onError", "(J)V");
    /* GetMethodID returns NULL (+ pending exception) if the method is absent.
     * Clean up and surface the exception rather than storing a NULL mid. */
    if (!ctx->mid) {
        (*env)->DeleteGlobalRef(env, ctx->obj);
        free(ctx);
        return 1;
    }
    jint ret = (jint)coraza_add_error_callback((coraza_waf_config_t)(uintptr_t)cfg,
                                               _swig_java_error_trampoline, ctx);
    if (ret != 0) {
        (*env)->DeleteGlobalRef(env, ctx->obj);
        free(ctx);
    }
    return ret;
}

JNIEXPORT jint JNICALL Java_coraza_coraza_1set_1debug_1log_1callback(
        JNIEnv *env, jclass cls, jlong cfg, jobject cb) {
    if (!cb) return 1;
    _swig_java_cb_ctx_t *ctx =
        (_swig_java_cb_ctx_t *)malloc(sizeof(_swig_java_cb_ctx_t));
    if (!ctx) return 1;  /* OOM */
    (*env)->GetJavaVM(env, &ctx->jvm);
    ctx->obj = (*env)->NewGlobalRef(env, cb);
    ctx->mid = (*env)->GetMethodID(env, (*env)->GetObjectClass(env, cb),
                                    "onDebugLog",
                                    "(ILjava/lang/String;Ljava/lang/String;)V");
    if (!ctx->mid) {
        (*env)->DeleteGlobalRef(env, ctx->obj);
        free(ctx);
        return 1;
    }
    jint ret = (jint)coraza_add_debug_log_callback((coraza_waf_config_t)(uintptr_t)cfg,
                                                    _swig_java_debug_trampoline, ctx);
    if (ret != 0) {
        (*env)->DeleteGlobalRef(env, ctx->obj);
        free(ctx);
    }
    return ret;
}
%}

/*
 * Inject native method declarations directly into the coraza Java class.
 * %native cannot express Java's Object type — using modulecode gives full
 * control over the Java signature. JNI implementations are in the %{...%}
 * block above: Java_coraza_coraza_1set_1error_1callback etc.
 */
%pragma(java) modulecode=%{
  public static native int coraza_set_error_callback(long cfg, Object callback);
  public static native int coraza_set_debug_log_callback(long cfg, Object callback);
%}
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
    char *data;
    int rule_id;
} coraza_intervention_t;

typedef enum coraza_result_t {
    CORAZA_ERROR = -1,
    CORAZA_OK = 0,
    CORAZA_INTERRUPTION = 1,
} coraza_result_t;

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
extern int coraza_is_request_body_accessible(coraza_transaction_t t);
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
extern int coraza_is_response_body_processable(coraza_transaction_t t);
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
extern int coraza_matched_rule_get_id(coraza_matched_rule_t r);
extern char *coraza_matched_rule_get_error_log(coraza_matched_rule_t r);
extern int coraza_add_request_headers(coraza_transaction_t t,
                                      const char *packed, int packed_len,
                                      int count);
extern int coraza_add_response_headers(coraza_transaction_t t,
                                       const char *packed, int packed_len,
                                       int count);
extern void coraza_free_string(char *s);
