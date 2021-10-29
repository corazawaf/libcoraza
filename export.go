package main

/*
#ifndef _CORAZA_H_
#define _CORAZA_H_
typedef struct coraza_intervention_t
{
    int status;
    int pause;
    char *url;
    char *log;
    int disruptive;
} coraza_intervention_t;

typedef void* coraza_waf_t;
typedef void* coraza_transaction_t;
typedef void* coraza_seclang_t;

//typedef void (*coraza_log_cb)(void *, const void *);
#endif
*/
import "C"
import (
	"strconv"
	"unsafe"

	"github.com/jptosso/coraza-waf"
	"github.com/jptosso/coraza-waf/seclang"
)

//export coraza_new_waf
func coraza_new_waf() unsafe.Pointer {
	waf := coraza.NewWaf()
	corazaMemAlloc := C.malloc(C.size_t(unsafe.Sizeof(uintptr(0))))
	a := (*[1]*coraza.Waf)(corazaMemAlloc)
	a[0] = &(*(*coraza.Waf)(unsafe.Pointer(waf)))
	return corazaMemAlloc
}

//export coraza_new_transaction
func coraza_new_transaction(waf C.coraza_waf_t, logCb unsafe.Pointer) unsafe.Pointer {
	if waf == nil {
		panic("waf is nil")
	}
	w := *(*coraza.Waf)((*[1]*coraza.Waf)(waf)[0])

	tx := w.NewTransaction()
	txMemAlloc := C.malloc(C.size_t(unsafe.Sizeof(uintptr(0))))
	a := (*[1]*coraza.Transaction)(txMemAlloc)
	a[0] = &(*(*coraza.Transaction)(unsafe.Pointer(tx)))
	return txMemAlloc
}

//export coraza_new_transaction_with_id
func coraza_new_transaction_with_id(waf C.coraza_waf_t, logCb unsafe.Pointer, id *C.char) unsafe.Pointer {
	idd := C.GoString(id)
	tx := coraza_new_transaction(waf, logCb)
	t := *(*coraza.Transaction)((*[1]*coraza.Transaction)(tx)[0])
	t.Id = idd
	t.GetCollection(coraza.VARIABLE_UNIQUE_ID).Set("", []string{idd})
	return tx
}

//export coraza_new_seclang_parser
func coraza_new_seclang_parser(waf C.coraza_waf_t) unsafe.Pointer {
	if waf == nil {
		panic("waf is nil")
	}
	w := *(*coraza.Waf)((*[1]*coraza.Waf)(waf)[0])
	parser, _ := seclang.NewParser(&w)
	pMemAlloc := C.malloc(C.size_t(unsafe.Sizeof(uintptr(0))))
	a := (*[1]*coraza.Transaction)(pMemAlloc)
	a[0] = &(*(*coraza.Transaction)(unsafe.Pointer(parser)))
	return pMemAlloc
}

//export coraza_intervention
func coraza_intervention(tx C.coraza_transaction_t, it *C.coraza_intervention_t) int {
	t := *(*coraza.Transaction)((*[1]*coraza.Transaction)(tx)[0])
	if t.Interruption != nil {
		return 1
	}
	i := t.Interruption
	it.status = C.int(i.Status)
	return 0
}

//export coraza_process_connection
func coraza_process_connection(t C.coraza_transaction_t, sourceAddress *C.char, clientPort C.int, serverHost *C.char, serverPort C.int) int {
	tx := *(*coraza.Transaction)((*[1]*coraza.Transaction)(t)[0])
	srcAddr := C.GoString(sourceAddress)
	cp := int(clientPort)
	ch := C.GoString(serverHost)
	sp := int(serverPort)
	tx.ProcessConnection(srcAddr, cp, ch, sp)
	return 0
}

//export coraza_process_request_body
func coraza_process_request_body(t C.coraza_transaction_t) int {
	tx := *(*coraza.Transaction)((*[1]*coraza.Transaction)(t)[0])
	tx.ProcessRequestBody()
	return 0
}

//export coraza_update_status_code
func coraza_update_status_code(t C.coraza_transaction_t, code C.int) int {
	tx := *(*coraza.Transaction)((*[1]*coraza.Transaction)(t)[0])
	c := strconv.Itoa(int(code))
	tx.GetCollection(coraza.VARIABLE_RESPONSE_STATUS).Set("", []string{c})
	return 0
}

//msr->t, r->unparsed_uri, r->method, r->protocol + offset
//export coraza_process_uri
func coraza_process_uri(t C.coraza_transaction_t, uri *C.char, method *C.char, proto *C.char) int {
	tx := *(*coraza.Transaction)((*[1]*coraza.Transaction)(t)[0])

	tx.ProcessUri(C.GoString(uri), C.GoString(method), C.GoString(proto))
	return 0
}

//export coraza_add_request_header
func coraza_add_request_header(t C.coraza_transaction_t, name *C.char, value *C.char) int {
	tx := *(*coraza.Transaction)((*[1]*coraza.Transaction)(t)[0])
	tx.AddRequestHeader(C.GoString(name), C.GoString(value))
	return 0
}

//export coraza_process_request_headers
func coraza_process_request_headers(t C.coraza_transaction_t) int {
	tx := *(*coraza.Transaction)((*[1]*coraza.Transaction)(t)[0])
	tx.ProcessRequestHeaders()
	return 0
}

//export coraza_process_logging
func coraza_process_logging(t C.coraza_transaction_t) int {
	tx := *(*coraza.Transaction)((*[1]*coraza.Transaction)(t)[0])
	tx.ProcessLogging()
	return 0
}

//export coraza_append_request_body
func coraza_append_request_body(t C.coraza_transaction_t, data *C.char, length C.int) int {
	tx := *(*coraza.Transaction)((*[1]*coraza.Transaction)(t)[0])
	tx.RequestBodyBuffer.Write(C.GoBytes(unsafe.Pointer(data), length))
	return 0
}

//export coraza_add_response_header
func coraza_add_response_header(t C.coraza_transaction_t, name *C.char, value *C.char) int {
	tx := *(*coraza.Transaction)((*[1]*coraza.Transaction)(t)[0])
	tx.AddResponseHeader(C.GoString(name), C.GoString(value))
	return 0
}

//export coraza_append_response_body
func coraza_append_response_body(t C.coraza_transaction_t, data *C.char, length C.int) int {
	tx := *(*coraza.Transaction)((*[1]*coraza.Transaction)(t)[0])
	tx.ResponseBodyBuffer.Write(C.GoBytes(unsafe.Pointer(data), length))
	return 0
}

//export coraza_process_response_body
func coraza_process_response_body(t C.coraza_transaction_t) int {
	tx := *(*coraza.Transaction)((*[1]*coraza.Transaction)(t)[0])
	tx.ProcessResponseBody()
	return 0
}

//export coraza_process_response_headers
func coraza_process_response_headers(t C.coraza_transaction_t, status C.int, proto *C.char) int {
	tx := *(*coraza.Transaction)((*[1]*coraza.Transaction)(t)[0])
	tx.ProcessResponseHeaders(int(status), C.GoString(proto))
	return 0
}

//export coraza_rules_add_file
func coraza_rules_add_file(w C.coraza_waf_t, file *C.char, er **C.char) int {
	waf := *(*coraza.Waf)((*[1]*coraza.Waf)(w)[0])
	parser, _ := seclang.NewParser(&waf)
	if err := parser.FromFile(C.GoString(file)); err != nil {
		*er = C.CString(err.Error())
		return 0
	}
	return 1
}

func main() {}
