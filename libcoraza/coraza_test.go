package main

import (
	"testing"

	"github.com/corazawaf/coraza/v3"
)

var waf *coraza.WAF
var wafPtr uint64

func TestWafInitialization(t *testing.T) {
	waf2 := coraza_new_waf()
	wafPtr = uint64(waf2)
}

func TestWafIsConsistent(t *testing.T) {
	if waf == nil {
		TestWafInitialization(t)
	}
}

func TestAddRulesToWaf(t *testing.T) {
}

func TestTransactionInitialization(t *testing.T) {
	waf := coraza_new_waf()
	tt := coraza_new_transaction(waf, nil)
	if tt == 0 {
		t.Fatal("Transaction initialization failed")
	}
	t2 := coraza_new_transaction(waf, nil)
	if t2 == tt {
		t.Fatal("Transactions are duplicated")
	}
	tx := ptrToTransaction(tt)
	tx.ProcessConnection("127.0.0.1", 8080, "127.0.0.1", 80)
}

func TestTxCleaning(t *testing.T) {
	waf := coraza_new_waf()
	txPtr := coraza_new_transaction(waf, nil)
	coraza_free_transaction(txPtr)
	if _, ok := txMap[uint64(txPtr)]; ok {
		t.Fatal("Transaction was not removed from the map")
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
	coraza_rules_add(waf, stringToC(`SecRule UNIQUE_ID "" "id:1"`), nil)
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
		tx.Close()
	}
}
