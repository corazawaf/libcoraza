package main

import (
	"strings"
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

func TestAddFileToWaf(t *testing.T) {
	er := stringToC("a")
	waf := coraza_new_waf()
	coraza_rules_add_file(waf, stringToC(`default.conf`), &er)
	tt := coraza_new_transaction(waf, nil)
	if tt == 0 {
		t.Fatal("Transaction initialization failed")
	}
	tx := ptrToTransaction(tt)
	tx.ProcessConnection("127.0.0.1", 8080, "127.0.0.1", 80)
	tx.ProcessURI("https://www.example.com/some?params=123", "GET", "HTTP/1.1")
	tx.AddRequestHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36 Edg/111.0.1661.44")
	tx.ProcessRequestHeaders()
	tx.ProcessRequestBody()
	tx.AddResponseHeader("Content-Type", "text/html")
	tx.ProcessResponseHeaders(200, "OK")
	tx.ProcessResponseBody()
	tx.ProcessLogging()
	intervention := tx.Interruption()
	tx.Close()
	if intervention.Action != "drop" {
		t.Fatal("action was not correct")
	}
}

func TestAddRulesToWaf(t *testing.T) {
	er := stringToC("a")
	waf := coraza_new_waf()
	coraza_rules_add(waf, stringToC(`SecRule REQUEST_HEADERS:User-Agent "Mozilla" "phase:1, id:3,drop,status:403,log,msg:'Blocked User-Agent'"`), &er)
	tt := coraza_new_transaction(waf, nil)
	if tt == 0 {
		t.Fatal("Transaction initialization failed")
	}
	tx := ptrToTransaction(tt)
	tx.ProcessConnection("127.0.0.1", 8080, "127.0.0.1", 80)
	tx.ProcessURI("https://www.example.com/some?params=123", "GET", "HTTP/1.1")
	tx.AddRequestHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36 Edg/111.0.1661.44")
	tx.ProcessRequestHeaders()
	tx.ProcessRequestBody()
	tx.AddResponseHeader("Content-Type", "text/html")
	tx.ProcessResponseHeaders(200, "OK")
	tx.ProcessResponseBody()
	tx.ProcessLogging()
	intervention := tx.Interruption()
	tx.Close()
	if intervention.Action != "drop" {
		t.Fatal("action was not correct")
	}
}

func TestTransactionInitialization(t *testing.T) {
	waf := coraza_new_waf()
	tt := coraza_new_transaction(waf, nil)
	if tt == 0 {
		t.Fatal("Transaction initialization failed")
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

func TestMyCtostring(t *testing.T) {
	testStr := "testtest"
	testStrC := stringToC(testStr)
	testStrGo := MyCtostring(testStrC)
	if cmp := strings.Compare(testStr, testStrGo); cmp != 0 {
		t.Fatal("There was a failure in converting C string to Go string using MyCtostring.")
	}
}

func TestMyCtostringN(t *testing.T) {
	testStr := "testtest"
	testStrC := stringToC(testStr)
	testStrLen := intToCint(len(testStr))
	testStrGo := MyCtostringN(testStrC, testStrLen)
	if cmp := strings.Compare(testStr, testStrGo); cmp != 0 {
		t.Fatal("There was a failure in converting C string to Go string using MyCtostringN.")
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
