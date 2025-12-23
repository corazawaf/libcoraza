package main

/*
#ifndef _LIBCORAZA_H_
#define _LIBCORAZA_H_
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

typedef struct coraza_intervention_t
{
	char *action;
    int status;
    int pause;
    int disruptive;
} coraza_intervention_t;

typedef uintptr_t coraza_waf_config_t;
typedef uintptr_t coraza_waf_t;
typedef uintptr_t coraza_transaction_t;
typedef uintptr_t coraza_matched_rule_t;

typedef enum coraza_debug_log_level_t {
	CORAZA_DEBUG_LOG_LEVEL_TRACE,
	CORAZA_DEBUG_LOG_LEVEL_DEBUG,
	CORAZA_DEBUG_LOG_LEVEL_INFO,
	CORAZA_DEBUG_LOG_LEVEL_WARN,
	CORAZA_DEBUG_LOG_LEVEL_ERROR,
} coraza_debug_log_level_t;

typedef void (*coraza_debug_log_cb) (void *, coraza_debug_log_level_t, const char *msg, const char *fields);

typedef enum coraza_severity_t {
	CORAZA_SEVERITY_DEBUG,
	CORAZA_SEVERITY_INFO,
	CORAZA_SEVERITY_NOTICE,
	CORAZA_SEVERITY_WARNING,
	CORAZA_SEVERITY_ERROR,
	CORAZA_SEVERITY_CRITICAL,
	CORAZA_SEVERITY_ALERT,
	CORAZA_SEVERITY_EMERGENCY,
} coraza_severity_t;

typedef void (*coraza_error_cb) (void *, coraza_matched_rule_t);

#endif

static void call_debug_log_cb(coraza_debug_log_cb cb, void *ctx, coraza_debug_log_level_t level, const char *msg, const char *fields) {
	cb(ctx, level, msg, fields);
}

static void call_error_cb(coraza_error_cb cb, void *ctx, coraza_matched_rule_t rule) {
	cb(ctx, rule);
}

*/
import "C"
import (
	"io"
	"os"
	"runtime/cgo"
	"unsafe"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/types"
	"golang.org/x/exp/constraints"
)

type WafConfigHandle struct {
	config coraza.WAFConfig
}

//export coraza_new_waf_config
func coraza_new_waf_config() C.coraza_waf_config_t {
	return C.coraza_waf_config_t(cgo.NewHandle(&WafConfigHandle{
		config: coraza.NewWAFConfig(),
	}))
}

//export coraza_rules_add_file
func coraza_rules_add_file(c C.coraza_waf_config_t, file *C.char) C.int {
	configHandle := fromRaw[*WafConfigHandle](c)
	configHandle.config = configHandle.config.WithDirectivesFromFile(C.GoString(file))
	return 0
}

//export coraza_rules_add
func coraza_rules_add(c C.coraza_waf_config_t, directives *C.char) C.int {
	configHandle := fromRaw[*WafConfigHandle](c)
	configHandle.config = configHandle.config.WithDirectives(C.GoString(directives))
	return 0
}

/**
 * Adds a debug log callback to a WAF config
 * @param[in] pointer to valid WAF config
 * @param[in] pointer to log callback
 * @param[in] pointer to custom user context passed every time the log callback is called. This must live as long as
 * while the parent config and its dependent objects are active.
 * @returns 0 on success, 1 on failure
 */
//export coraza_add_debug_log_callback
func coraza_add_debug_log_callback(c C.coraza_waf_config_t, cb C.coraza_debug_log_cb, userContext *C.void) C.int {
	configHandle := fromRaw[*WafConfigHandle](c)
	configHandle.config = configHandle.config.WithDebugLogger(newDebugLogger(func(lvl debuglog.Level, message, fields string) {
		rawLevel := C.CORAZA_DEBUG_LOG_LEVEL_DEBUG
		switch lvl {
		case debuglog.LevelTrace:
			rawLevel = C.CORAZA_DEBUG_LOG_LEVEL_TRACE
		case debuglog.LevelDebug:
			rawLevel = C.CORAZA_DEBUG_LOG_LEVEL_DEBUG
		case debuglog.LevelInfo:
			rawLevel = C.CORAZA_DEBUG_LOG_LEVEL_INFO
		case debuglog.LevelWarn:
			rawLevel = C.CORAZA_DEBUG_LOG_LEVEL_WARN
		case debuglog.LevelError:
			rawLevel = C.CORAZA_DEBUG_LOG_LEVEL_ERROR
		}
		cMsg := C.CString(message)
		cFields := C.CString(fields)
		defer C.free(unsafe.Pointer(cMsg))
		defer C.free(unsafe.Pointer(cFields))
		C.call_debug_log_cb(cb, unsafe.Pointer(userContext), C.coraza_debug_log_level_t(rawLevel), cMsg, cFields)
	}))
	return 0
}

/**
 * Adds a error callback to a WAF config
 * @param[in] pointer to valid WAF config
 * @param[in] pointer to error callback
 * @param[in] pointer to custom user context passed every time the error callback is called. This must live as long as
 * while the parent config and its dependent objects are active.
 * @returns 0 on success, 1 on failure
 */
//export coraza_add_error_callback
func coraza_add_error_callback(c C.coraza_waf_config_t, cb C.coraza_error_cb, userContext *C.void) C.int {
	configHandle := fromRaw[*WafConfigHandle](c)
	configHandle.config = configHandle.config.WithErrorCallback(func(rule types.MatchedRule) {
		ruleHandle := cgo.NewHandle(rule)
		defer ruleHandle.Delete()
		C.call_error_cb(cb, unsafe.Pointer(userContext), C.coraza_matched_rule_t(ruleHandle))
	})
	return 0
}

//export coraza_free_waf_config
func coraza_free_waf_config(config C.coraza_waf_config_t) C.int {
	deleteRaw(config)
	return 0
}

/**
 * Creates a new  WAF instance
 * @returns pointer to WAF instance
 */
//export coraza_new_waf
func coraza_new_waf(config C.coraza_waf_config_t, er **C.char) C.coraza_waf_t {
	configHandle := fromRaw[*WafConfigHandle](config)
	waf, err := coraza.NewWAF(configHandle.config)
	if err != nil {
		*er = C.CString(err.Error())
		return 0
	}
	return C.coraza_waf_t(cgo.NewHandle(waf))
}

/**
 * Creates a new transaction for a WAF instance
 * @param[in] pointer to valid WAF instance
 * @returns pointer to transaction
 */
//export coraza_new_transaction
func coraza_new_transaction(w C.coraza_waf_t) C.coraza_transaction_t {
	waf := fromRaw[coraza.WAF](w)
	tx := waf.NewTransaction()
	return C.coraza_transaction_t(cgo.NewHandle(tx))
}

//export coraza_new_transaction_with_id
func coraza_new_transaction_with_id(w C.coraza_waf_t, id *C.char) C.coraza_transaction_t {
	waf := fromRaw[coraza.WAF](w)
	tx := waf.NewTransactionWithID(C.GoString(id))
	return C.coraza_transaction_t(cgo.NewHandle(tx))
}

//export coraza_intervention
func coraza_intervention(t C.coraza_transaction_t) *C.coraza_intervention_t {
	tx := fromRaw[types.Transaction](t)
	if tx.Interruption() == nil {
		return nil
	}
	mem := (*C.coraza_intervention_t)(C.malloc(C.size_t(unsafe.Sizeof(C.coraza_intervention_t{}))))
	mem.action = C.CString(tx.Interruption().Action)
	mem.status = C.int(tx.Interruption().Status)
	return mem
}

//export coraza_process_connection
func coraza_process_connection(t C.coraza_transaction_t, sourceAddress *C.char, clientPort C.int, serverHost *C.char, serverPort C.int) C.int {
	tx := fromRaw[types.Transaction](t)
	srcAddr := C.GoString(sourceAddress)
	cp := int(clientPort)
	ch := C.GoString(serverHost)
	sp := int(serverPort)
	tx.ProcessConnection(srcAddr, cp, ch, sp)
	return 0
}

//export coraza_process_request_body
func coraza_process_request_body(t C.coraza_transaction_t) C.int {
	tx := fromRaw[types.Transaction](t)
	if _, err := tx.ProcessRequestBody(); err != nil {
		return 1
	}
	return 0
}

//export coraza_update_status_code
func coraza_update_status_code(t C.coraza_transaction_t, code C.int) C.int {
	//tx := valueFromRawHandle[types.Transaction](t)
	//c := strconv.Itoa(int(code))
	//tx.Variables().ResponseStatus.Set(c)
	return 0
}

// msr->t, r->unparsed_uri, r->method, r->protocol + offset
//
//export coraza_process_uri
func coraza_process_uri(t C.coraza_transaction_t, uri *C.char, method *C.char, proto *C.char) C.int {
	tx := fromRaw[types.Transaction](t)

	tx.ProcessURI(C.GoString(uri), C.GoString(method), C.GoString(proto))
	return 0
}

//export coraza_add_request_header
func coraza_add_request_header(t C.coraza_transaction_t, name *C.char, name_len C.int, value *C.char, value_len C.int) C.int {
	tx := fromRaw[types.Transaction](t)
	tx.AddRequestHeader(C.GoStringN(name, name_len), C.GoStringN(value, value_len))
	return 0
}

//export coraza_process_request_headers
func coraza_process_request_headers(t C.coraza_transaction_t) C.int {
	tx := fromRaw[types.Transaction](t)
	tx.ProcessRequestHeaders()
	return 0
}

//export coraza_process_logging
func coraza_process_logging(t C.coraza_transaction_t) C.int {
	tx := fromRaw[types.Transaction](t)
	tx.ProcessLogging()
	return 0
}

//export coraza_append_request_body
func coraza_append_request_body(t C.coraza_transaction_t, data *C.uchar, length C.int) C.int {
	tx := fromRaw[types.Transaction](t)
	if _, _, err := tx.WriteRequestBody(C.GoBytes(unsafe.Pointer(data), length)); err != nil {
		return 1
	}
	return 0
}

//export coraza_add_get_args
func coraza_add_get_args(t C.coraza_transaction_t, name *C.char, value *C.char) C.int {
	tx := fromRaw[types.Transaction](t)
	tx.AddGetRequestArgument(C.GoString(name), C.GoString(value))
	return 0
}

//export coraza_add_response_header
func coraza_add_response_header(t C.coraza_transaction_t, name *C.char, name_len C.int, value *C.char, value_len C.int) C.int {
	tx := fromRaw[types.Transaction](t)
	tx.AddResponseHeader(C.GoStringN(name, name_len), C.GoStringN(value, value_len))
	return 0
}

//export coraza_append_response_body
func coraza_append_response_body(t C.coraza_transaction_t, data *C.uchar, length C.int) C.int {
	tx := fromRaw[types.Transaction](t)
	if _, _, err := tx.WriteResponseBody(C.GoBytes(unsafe.Pointer(data), length)); err != nil {
		return 1
	}
	return 0
}

//export coraza_process_response_body
func coraza_process_response_body(t C.coraza_transaction_t) C.int {
	tx := fromRaw[types.Transaction](t)
	if _, err := tx.ProcessResponseBody(); err != nil {
		return 1
	}
	return 0
}

//export coraza_process_response_headers
func coraza_process_response_headers(t C.coraza_transaction_t, status C.int, proto *C.char) C.int {
	tx := fromRaw[types.Transaction](t)
	tx.ProcessResponseHeaders(int(status), C.GoString(proto))
	return 0
}

//export coraza_rules_count
func coraza_rules_count(w C.coraza_waf_t) C.int {
	return 0
}

//export coraza_free_transaction
func coraza_free_transaction(t C.coraza_transaction_t) C.int {
	tx := fromRaw[types.Transaction](t)
	if tx.Close() != nil {
		return 1
	}
	deleteRaw(t)
	return 0
}

//export coraza_free_intervention
func coraza_free_intervention(it *C.coraza_intervention_t) C.int {
	if it == nil {
		return 1
	}
	defer C.free(unsafe.Pointer(it))
	C.free(unsafe.Pointer(it.action))
	return 0
}

//export coraza_rules_merge
func coraza_rules_merge(w1 C.coraza_waf_t, w2 C.coraza_waf_t, er **C.char) C.int {
	return 0
}

//export coraza_request_body_from_file
func coraza_request_body_from_file(t C.coraza_transaction_t, file *C.char) C.int {
	tx := fromRaw[types.Transaction](t)
	f, err := os.Open(C.GoString(file))
	if err != nil {
		return 1
	}
	defer f.Close()
	// we read the file in chunks and send it to the engine
	for {
		buf := make([]byte, 1024)
		n, err := f.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return 1
		}
		if _, _, err := tx.WriteRequestBody(buf[:n]); err != nil {
			return 1
		}
	}
	return 0
}

//export coraza_free_waf
func coraza_free_waf(t C.coraza_waf_t) C.int {
	deleteRaw(t)
	return 0
}

/**
 * Returns the severity of a matched rule.
 * @param[in] pointer to matched rule
 * @returns severity of the matched rule
 */
//export coraza_matched_rule_get_severity
func coraza_matched_rule_get_severity(r C.coraza_matched_rule_t) C.coraza_severity_t {
	matchedRule := fromRaw[types.MatchedRule](r)
	switch matchedRule.Rule().Severity() {
	case types.RuleSeverityEmergency:
		return C.CORAZA_SEVERITY_EMERGENCY
	case types.RuleSeverityAlert:
		return C.CORAZA_SEVERITY_ALERT
	case types.RuleSeverityCritical:
		return C.CORAZA_SEVERITY_CRITICAL
	case types.RuleSeverityError:
		return C.CORAZA_SEVERITY_ERROR
	case types.RuleSeverityWarning:
		return C.CORAZA_SEVERITY_WARNING
	case types.RuleSeverityNotice:
		return C.CORAZA_SEVERITY_NOTICE
	case types.RuleSeverityInfo:
		return C.CORAZA_SEVERITY_INFO
	case types.RuleSeverityDebug:
		return C.CORAZA_SEVERITY_DEBUG
	}
	// Unknown severity, return the highest severity so user can be aware of the issue
	return C.CORAZA_SEVERITY_EMERGENCY
}

/*
 * Returns the error log of a matched rule. The caller is responsible for freeing the returned string.
 * @param[in] pointer to matched rule
 * @returns error log of the matched rule
 */
//export coraza_matched_rule_get_error_log
func coraza_matched_rule_get_error_log(r C.coraza_matched_rule_t) *C.char {
	rule := fromRaw[types.MatchedRule](r)
	cMsg := C.CString(rule.ErrorLog())
	return cMsg
}

/*
Internal helpers
*/

// It should just be C.CString(s) but we need this to build tests
func stringToC(s string) *C.char {
	return C.CString(s)
}

// It should just be C.GoString(c) but we need this to build tests
func stringFromC(c *C.char) string {
	return C.GoString(c)
}

func txFromCgoHandle(h cgo.Handle) C.coraza_transaction_t {
	return C.coraza_transaction_t(h)
}

func wafFromCgoHandle(h cgo.Handle) C.coraza_waf_t {
	return C.coraza_waf_t(h)
}

func fromRaw[T any, U constraints.Unsigned](raw U) T {
	return cgo.Handle(raw).Value().(T)
}

func deleteRaw[U constraints.Unsigned](raw U) {
	cgo.Handle(raw).Delete()
}

func main() {}
