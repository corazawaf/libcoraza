package main

import (
	"testing"
	"unsafe"

	"github.com/jptosso/coraza-waf/v2"
	"github.com/jptosso/coraza-waf/v2/types/variables"
)

var waf *coraza.Waf
var wafPtr unsafe.Pointer

func TestWafInitialization(t *testing.T) {
	waf2 := coraza_new_waf()
	wafPtr = unsafe.Pointer(waf2)
	if wafPtr == nil {
		t.Fatal("Waf initialization failed")
	}

	w := ptrToWaf(waf2)
	if w.RequestBodyInMemoryLimit == 0 {
		t.Fatal("Waf initialization failed (set memory)")
	}
	w.WebAppID = "some-sample"
	waf = w
}

func TestWafIsConsistent(t *testing.T) {
	if waf == nil {
		TestWafInitialization(t)
	}
	w := *(*coraza.Waf)((*[1]*coraza.Waf)(wafPtr)[0])

	if w.WebAppID != waf.WebAppID {
		t.Fatal("Waf initialization is inconsistent, got web app id: ", w.WebAppID)
	}
}

func TestAddRulesToWaf(t *testing.T) {
	waf := coraza_new_waf()
	w := ptrToWaf(waf)
	if err := corazaRulesFromString(w, `SecRule UNIQUE_ID "" "id:1"`); err != nil {
		t.Fatal("Error adding rule: ", err)
	}
	// we reload the pointer just for testing
	w = ptrToWaf(waf)
	if w.Rules.Count() != 1 {
		t.Error("Rule count is not 1")
	}
}

func TestTransactionInitialization(t *testing.T) {
	waf := coraza_new_waf()
	tt := coraza_new_transaction(waf, nil)
	if tt == nil {
		t.Fatal("Transaction initialization failed")
	}
	tx := ptrToTransaction(tt)
	tx.ProcessConnection("127.0.0.1", 55555, "127.0.0.1", 80)
	tx = ptrToTransaction(tt)
	if tx.ID == "" {
		t.Fatal("Transaction initialization failed")
	}
	if tx.GetCollection(variables.RemoteAddr).GetFirstString("") != "127.0.0.1" {
		t.Fatal("Transaction initialization failed")
	}
}

func BenchmarkTransactionCreation(b *testing.B) {
	waf := coraza_new_waf()
	for i := 0; i < b.N; i++ {
		coraza_new_transaction(waf, nil)
	}
}

func BenchmarkTransactionProcessing(b *testing.B) {
	waf := coraza_new_waf()
	coraza_rules_from_string(waf, stringToC(`SecRule UNIQUE_ID "" "id:1"`), nil)
	for i := 0; i < b.N; i++ {
		txPtr := coraza_new_transaction(waf, nil)
		tx := ptrToTransaction(txPtr)
		tx.ProcessConnection("127.0.0.1", 55555, "127.0.0.1", 80)
		tx.ProcessURI("https://www.example.com/some?params=123", "GET", "HTTP/1.1")
		tx.AddRequestHeader("Host", "www.example.com")
		tx.ProcessRequestHeaders()
		tx.ProcessRequestBody()
		tx.AddResponseHeader("Content-Type", "text/html")
		tx.ProcessResponseHeaders(200, "OK")
		tx.ProcessResponseBody()
		tx.ProcessLogging()
		tx.Clean()
	}
}
