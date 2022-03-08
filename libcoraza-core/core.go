package main

/*
#ifndef _CORAZA_CORE_H_
#define _CORAZA_CORE_H_
#include <stdio.h>
#include <stdlib.h>

typedef struct coraza_intervention_t
{
	char *action;
	char *log;
    char *url;
    int status;
    int pause;
    int disruptive;
} coraza_intervention_t;

typedef void* coraza_waf_t;
typedef void* coraza_transaction_t;

//typedef void (*coraza_log_cb)(void *, const void *);
#endif
*/
import "C"
import (
	"fmt"
	"io"
	"os"
	"strconv"
	"unsafe"

	"github.com/jptosso/coraza-waf/v2"
	"github.com/jptosso/coraza-waf/v2/seclang"
	"github.com/jptosso/coraza-waf/v2/types/variables"
)

/**
 * Creates a new  WAF instance
 * @returns pointer to WAF instance
 */
//export coraza_new_waf
func coraza_new_waf() C.coraza_waf_t {
	waf := coraza.NewWaf()
	return wafToPtr(waf)
}

/**
 * Creates a new transaction for a WAF instance
 * @param[in] pointer to valid WAF instance
 * @param[in] pointer to log callback, can be null
 * @returns pointer to transaction
 */
//export coraza_new_transaction
func coraza_new_transaction(waf C.coraza_waf_t, logCb unsafe.Pointer) C.coraza_transaction_t {
	w := ptrToWaf(waf)
	tx := w.NewTransaction()
	return transactionToPtr(tx)
}

//export coraza_new_transaction_with_id
func coraza_new_transaction_with_id(waf C.coraza_waf_t, id *C.char, logCb unsafe.Pointer) C.coraza_transaction_t {
	idd := C.GoString(id)
	txPtr := coraza_new_transaction(waf, logCb)
	tx := ptrToTransaction(txPtr)
	tx.ID = idd
	tx.GetCollection(variables.UniqueID).Set("", []string{idd})
	return txPtr
}

//export coraza_intervention
func coraza_intervention(tx C.coraza_transaction_t) *C.coraza_intervention_t {
	t := ptrToTransaction(tx)
	if t.Interruption == nil {
		return nil
	}
	// TODO this must be triple checked
	mem := (*C.coraza_intervention_t)(C.malloc(C.size_t(unsafe.Sizeof(C.coraza_intervention_t{}))))
	mem.action = C.CString(t.Interruption.Action)
	mem.status = C.int(t.Interruption.Status)
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
	tx := ptrToTransaction(t)
	c := strconv.Itoa(int(code))
	tx.GetCollection(variables.ResponseStatus).Set("", []string{c})
	return 0
}

//msr->t, r->unparsed_uri, r->method, r->protocol + offset
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
	if _, err := tx.RequestBodyBuffer.Write(C.GoBytes(unsafe.Pointer(data), length)); err != nil {
		return 1
	}
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
	if _, err := tx.ResponseBodyBuffer.Write(C.GoBytes(unsafe.Pointer(data), length)); err != nil {
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
	waf := ptrToWaf(w)
	parser, _ := seclang.NewParser(waf)
	if err := parser.FromFile(C.GoString(file)); err != nil {
		*er = C.CString(err.Error())
		// we share the pointer, so we shouldn't free it, right?
		return 0
	}
	return 1
}

//export coraza_rules_add
func coraza_rules_add(w C.coraza_waf_t, directives *C.char, er **C.char) C.int {
	waf := ptrToWaf(w)
	if err := corazaRulesFromString(waf, C.GoString(directives)); err != nil {
		*er = C.CString(err.Error())
		// we share the pointer, so we shouldn't free it, right?
		return 0
	}
	return 1
}

//export coraza_rules_count
func coraza_rules_count(w C.coraza_waf_t) C.int {
	waf := ptrToWaf(w)
	return C.int(waf.Rules.Count())
}

/**
 * Returns an array of strings containing the transaction data
 * @param[in] name of the variable (must be valid)
 * @param[in] key of the variable (can be empty)
 * @returns An array of C strings or nil in case of any error
 */
//export coraza_transaction_variable
func coraza_transaction_variable(t C.coraza_transaction_t, name *C.char, key *C.char) **C.char {
	tx := ptrToTransaction(t)
	v, err := variables.Parse(C.GoString(name))
	if err != nil {
		return nil
	}
	val := tx.GetCollection(v)
	if val == nil {
		return nil
	}
	res := val.Get(C.GoString(key))
	// return a C array of strings
	if len(res) == 0 {
		return nil
	}
	return sliceToC(res)
}

//export coraza_transaction_free
func coraza_transaction_free(t C.coraza_transaction_t) C.int {
	tx := ptrToTransaction(t)
	defer C.free(unsafe.Pointer(t))
	if tx.Clean() != nil {
		return 1
	}
	return 0
}

//export coraza_rules_merge
func coraza_rules_merge(w1 C.coraza_waf_t, w2 C.coraza_waf_t, er **C.char) C.int {
	waf1 := ptrToWaf(w1)
	waf2 := ptrToWaf(w2)
	for _, r := range waf2.Rules.GetRules() {
		waf1.Rules.Add(r)
	}
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
	if _, err := io.Copy(tx.RequestBodyBuffer, f); err != nil {
		return 1
	}
	return 0
}

//export coraza_free_waf
func coraza_free_waf(t C.coraza_waf_t) C.int {
	waf := ptrToWaf(t)
	if waf == nil {
		return 1
	}
	defer C.free(unsafe.Pointer(t))
	waf.Logger = nil
	waf.AuditLogRelevantStatus = nil
	// TODO there are more private members to free
	return 0
}

/*
Internal helpers
*/

func ptrToWaf(waf C.coraza_waf_t) *coraza.Waf {
	return (*coraza.Waf)((*[1]*coraza.Waf)(waf)[0])
}

func ptrToTransaction(t C.coraza_transaction_t) *coraza.Transaction {
	return (*coraza.Transaction)((*[1]*coraza.Transaction)(t)[0])
}

func transactionToPtr(tx *coraza.Transaction) C.coraza_transaction_t {
	txMemAlloc := C.malloc(C.size_t(unsafe.Sizeof(uintptr(0))))
	a := (*[1]*coraza.Transaction)(txMemAlloc)
	a[0] = (*coraza.Transaction)(unsafe.Pointer(tx))
	return (C.coraza_transaction_t)(txMemAlloc)
}

func wafToPtr(waf *coraza.Waf) C.coraza_waf_t {
	wafMemAlloc := C.malloc(C.size_t(unsafe.Sizeof(uintptr(0))))
	a := (*[1]*coraza.Waf)(wafMemAlloc)
	a[0] = (*coraza.Waf)(unsafe.Pointer(waf))
	return (C.coraza_waf_t)(wafMemAlloc)
}

func corazaRulesFromString(w *coraza.Waf, directives string) error {
	if w == nil {
		return fmt.Errorf("waf is nil")
	}
	parser, err := seclang.NewParser(w)
	if err != nil {
		return err
	}
	return parser.FromString(directives)
}

// It should just be C.CString(s) but we need this to build tests
func stringToC(s string) *C.char {
	return C.CString(s)
}

func sliceToC(s []string) **C.char {
	cArray := C.malloc(C.size_t(len(s)) * C.size_t(unsafe.Sizeof(uintptr(0))))

	// convert the C array to a Go Array so we can index it
	a := (*[1<<30 - 1]*C.char)(cArray)

	for idx, substring := range s {
		a[idx] = C.CString(substring)
	}

	return (**C.char)(cArray)
}

func main() {}

