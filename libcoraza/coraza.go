package main

/*
#ifndef _LIBCORAZA_H_
#define _LIBCORAZA_H_
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef struct coraza_intervention_t
{
	char *action;
    int status;
    int pause;
    int disruptive;
} coraza_intervention_t;

typedef uint64_t coraza_waf_config_t;
typedef uint64_t coraza_waf_t;
typedef uint64_t coraza_transaction_t;

typedef void (*coraza_log_cb) (const void *);
void send_log_to_cb(coraza_log_cb cb, const char *msg);
#endif
*/
import "C"
import (
	"io"
	"os"
	"reflect"
	"unsafe"

	"github.com/corazawaf/coraza/v3"

	"github.com/corazawaf/coraza/v3/types"
)

var configMap = make(map[uint64]*WafConfigHandle)
var wafMap = make(map[uint64]*WafHandle)
var txMap = make(map[uint64]types.Transaction)

type WafConfigHandle struct {
	config coraza.WAFConfig
}

type WafHandle struct {
	waf coraza.WAF
}

//export coraza_new_waf_config
func coraza_new_waf_config() C.coraza_waf_config_t {
	config := coraza.NewWAFConfig()
	handle := &WafConfigHandle{
		config: config,
	}
	ptr := wafConfigHandleToPtr(handle)
	configMap[ptr] = handle
	return C.coraza_waf_config_t(ptr)
}

//export coraza_add_rules_to_waf_config
func coraza_add_rules_to_waf_config(c C.coraza_waf_config_t, rules *C.char) C.int {
	handle := ptrToWafConfigHandle(c)
	handle.config = handle.config.WithDirectives(C.GoString(rules))
	return 0
}

//export coraza_add_rules_from_file_to_waf_config
func coraza_add_rules_from_file_to_waf_config(c C.coraza_waf_config_t, file *C.char) C.int {
	handle := ptrToWafConfigHandle(c)
	handle.config = handle.config.WithDirectivesFromFile(C.GoString(file))
	return 0
}

//export coraza_free_waf_config
func coraza_free_waf_config(c C.coraza_waf_config_t) {
	delete(configMap, uint64(c))
}

/**
 * Creates a new  WAF instance
 * @returns pointer to WAF instance
 */
//export coraza_new_waf
func coraza_new_waf() C.coraza_waf_t {
	config := coraza.NewWAFConfig()
	waf, err := coraza.NewWAF(config)
	if err != nil {
		return 0
	}
	handle := &WafHandle{
		waf: waf,
	}
	ptr := wafToPtr(handle)
	wafMap[ptr] = handle
	return C.coraza_waf_t(ptr)
}

//export coraza_new_waf_with_config
func coraza_new_waf_with_config(c C.coraza_waf_config_t) C.coraza_waf_t {
	wafConfigHandle := ptrToWafConfigHandle(c)
	waf, err := coraza.NewWAF(wafConfigHandle.config)
	if err != nil {
		return 0
	}
	handle := &WafHandle{
		waf: waf,
	}
	ptr := wafToPtr(handle)
	wafMap[ptr] = handle
	return C.coraza_waf_t(ptr)
}

/**
 * Creates a new transaction for a WAF instance
 * @param[in] pointer to valid WAF instance
 * @param[in] pointer to log callback, can be null
 * @returns pointer to transaction
 */
//export coraza_new_transaction
func coraza_new_transaction(waf C.coraza_waf_t, logCb unsafe.Pointer) C.coraza_transaction_t {
	handle := ptrToWafHandle(waf)
	tx := handle.waf.NewTransaction()
	ptr := transactionToPtr(tx)
	txMap[ptr] = tx
	return C.coraza_transaction_t(ptr)
}

//export coraza_new_transaction_with_id
func coraza_new_transaction_with_id(waf C.coraza_waf_t, id *C.char, logCb unsafe.Pointer) C.coraza_transaction_t {
	handle := ptrToWafHandle(waf)
	tx := handle.waf.NewTransactionWithID(C.GoString(id))
	ptr := transactionToPtr(tx)
	txMap[ptr] = tx
	return C.coraza_transaction_t(ptr)
}

//export coraza_intervention
func coraza_intervention(tx C.coraza_transaction_t) *C.coraza_intervention_t {
	t := ptrToTransaction(tx)
	if t.Interruption() == nil {
		return nil
	}
	mem := (*C.coraza_intervention_t)(C.malloc(C.size_t(unsafe.Sizeof(C.coraza_intervention_t{}))))
	mem.action = C.CString(t.Interruption().Action)
	mem.status = C.int(t.Interruption().Status)
	return mem
}

//export coraza_process_connection
func coraza_process_connection(t C.coraza_transaction_t, sourceAddress *C.char, clientPort C.int, serverHost *C.char, serverPort C.int) C.int {
	tx := ptrToTransaction(t)
	srcAddr := C.GoString(sourceAddress)
	cp := int(clientPort)
	ch := C.GoString(serverHost)
	sp := int(serverPort)
	tx.ProcessConnection(srcAddr, cp, ch, sp)
	return 0
}

//export coraza_process_request_body
func coraza_process_request_body(t C.coraza_transaction_t) C.int {
	tx := ptrToTransaction(t)
	if _, err := tx.ProcessRequestBody(); err != nil {
		return 1
	}
	return 0
}

//export coraza_update_status_code
func coraza_update_status_code(t C.coraza_transaction_t, code C.int) C.int {
	// tx := ptrToTransaction(t)
	// c := strconv.Itoa(int(code))
	// tx.Variables.ResponseStatus.Set(c)
	return 0
}

// msr->t, r->unparsed_uri, r->method, r->protocol + offset
//
//export coraza_process_uri
func coraza_process_uri(t C.coraza_transaction_t, uri *C.char, method *C.char, proto *C.char) C.int {
	tx := ptrToTransaction(t)

	tx.ProcessURI(C.GoString(uri), C.GoString(method), C.GoString(proto))
	return 0
}

//export coraza_add_request_header
func coraza_add_request_header(t C.coraza_transaction_t, name *C.char, name_len C.int, value *C.char, value_len C.int) C.int {
	tx := ptrToTransaction(t)
	tx.AddRequestHeader(C.GoStringN(name, name_len), C.GoStringN(value, value_len))
	return 0
}

//export coraza_process_request_headers
func coraza_process_request_headers(t C.coraza_transaction_t) C.int {
	tx := ptrToTransaction(t)
	tx.ProcessRequestHeaders()
	return 0
}

//export coraza_process_logging
func coraza_process_logging(t C.coraza_transaction_t) C.int {
	tx := ptrToTransaction(t)
	tx.ProcessLogging()
	return 0
}

//export coraza_append_request_body
func coraza_append_request_body(t C.coraza_transaction_t, data *C.uchar, length C.int) C.int {
	tx := ptrToTransaction(t)
	if _, _, err := tx.WriteRequestBody(C.GoBytes(unsafe.Pointer(data), length)); err != nil {
		return 1
	}
	return 0
}

//export coraza_add_get_args
func coraza_add_get_args(t C.coraza_transaction_t, name *C.char, value *C.char) C.int {
	tx := ptrToTransaction(t)
	tx.AddGetRequestArgument(C.GoString(name), C.GoString(value))
	return 0
}

//export coraza_add_response_header
func coraza_add_response_header(t C.coraza_transaction_t, name *C.char, name_len C.int, value *C.char, value_len C.int) C.int {
	tx := ptrToTransaction(t)
	tx.AddResponseHeader(C.GoStringN(name, name_len), C.GoStringN(value, value_len))
	return 0
}

//export coraza_append_response_body
func coraza_append_response_body(t C.coraza_transaction_t, data *C.uchar, length C.int) C.int {
	tx := ptrToTransaction(t)
	if _, _, err := tx.WriteResponseBody(C.GoBytes(unsafe.Pointer(data), length)); err != nil {
		return 1
	}
	return 0
}

//export coraza_process_response_body
func coraza_process_response_body(t C.coraza_transaction_t) C.int {
	tx := ptrToTransaction(t)
	if _, err := tx.ProcessResponseBody(); err != nil {
		return 1
	}
	return 0
}

//export coraza_process_response_headers
func coraza_process_response_headers(t C.coraza_transaction_t, status C.int, proto *C.char) C.int {
	tx := ptrToTransaction(t)
	tx.ProcessResponseHeaders(int(status), C.GoString(proto))
	return 0
}

//export coraza_rules_add_file
func coraza_rules_add_file(w C.coraza_waf_t, file *C.char, er **C.char) C.int {
	handle := ptrToWafHandle(w)
	config := coraza.NewWAFConfig().WithDirectivesFromFile(C.GoString(file))
	var err error
	handle.waf, err = coraza.NewWAF(config)
	if err != nil {
		*er = C.CString(err.Error())
		// we share the pointer, so we shouldn't free it, right?
		return 0
	}
	wafMap[uint64(w)] = handle
	return 1
}

//export coraza_rules_add
func coraza_rules_add(w C.coraza_waf_t, directives *C.char, er **C.char) C.int {
	handle := ptrToWafHandle(w)
	config := coraza.NewWAFConfig().WithDirectives(C.GoString(directives))
	var err error
	handle.waf, err = coraza.NewWAF(config)
	if err != nil {
		*er = C.CString(err.Error())
		// we share the pointer, so we shouldn't free it, right?
		return 0
	}
	wafMap[uint64(w)] = handle
	return 1
}

//export coraza_rules_count
func coraza_rules_count(w C.coraza_waf_t) C.int {
	return 0
}

//export coraza_free_transaction
func coraza_free_transaction(t C.coraza_transaction_t) C.int {
	tx := ptrToTransaction(t)
	if tx.Close() != nil {
		return 1
	}
	delete(txMap, uint64(t))
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
	tx := ptrToTransaction(t)
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
	// waf := ptrToWaf(t)
	delete(wafMap, uint64(t))
	return 0
}

//export coraza_set_log_cb
func coraza_set_log_cb(waf C.coraza_waf_t, cb C.coraza_log_cb) {
}

/*
Internal helpers
*/

func ptrToWafConfigHandle(config C.coraza_waf_config_t) *WafConfigHandle {
	return configMap[uint64(config)]
}

func ptrToWafHandle(waf C.coraza_waf_t) *WafHandle {
	return wafMap[uint64(waf)]
}

func ptrToTransaction(t C.coraza_transaction_t) types.Transaction {
	return txMap[uint64(t)]
}

func transactionToPtr(tx types.Transaction) uint64 {
	return uint64(reflect.ValueOf(&tx).Pointer())
}

func wafToPtr(waf *WafHandle) uint64 {
	return uint64(reflect.ValueOf(&waf).Pointer())
}

func wafConfigHandleToPtr(config *WafConfigHandle) uint64 {
	return uint64(reflect.ValueOf(&config).Pointer())
}

// It should just be C.CString(s) but we need this to build tests
func stringToC(s string) *C.char {
	return C.CString(s)
}

func main() {}
