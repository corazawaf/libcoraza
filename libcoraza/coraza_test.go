package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"runtime/cgo"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

var waf *coraza.WAF
var wafPtr uintptr

func TestWafInitialization(t *testing.T) {
	config := coraza_new_waf_config()
	waf := coraza_new_waf(config, nil)
	if waf == 0 {
		t.Fatal("Waf initialization failed")
	}
	wafPtr = uintptr(waf)
}

func TestWafIsConsistent(t *testing.T) {
	if waf == nil {
		TestWafInitialization(t)
	}
}

func TestAddRulesToWaf(t *testing.T) {
}

func TestRulesCount(t *testing.T) {
	config := coraza_new_waf_config()
	w := coraza_new_waf(config, nil)
	coraza_free_waf_config(config)
	if coraza_rules_count(w) != 0 {
		t.Fatal("Expected 0 rules for empty WAF")
	}
	coraza_free_waf(w)

	config = coraza_new_waf_config()
	coraza_rules_add(config, stringToC(`SecRule REMOTE_ADDR "127.0.0.1" "id:1,phase:1,deny,status:403"`))
	w = coraza_new_waf(config, nil)
	coraza_free_waf_config(config)
	if coraza_rules_count(w) != 1 {
		t.Fatal("Expected 1 rule addition")
	}
	coraza_free_waf(w)

	config = coraza_new_waf_config()
	coraza_rules_add(config, stringToC(`SecRule REMOTE_ADDR "127.0.0.1" "id:1,phase:1,deny,status:403"`))
	coraza_rules_add(config, stringToC(`SecRule REQUEST_URI "/test" "id:2,phase:1,deny,status:403"`))
	w = coraza_new_waf(config, nil)
	coraza_free_waf_config(config)
	if coraza_rules_count(w) != 2 {
		t.Fatal("Expected 2 rule additions")
	}
	coraza_free_waf(w)
}

func TestUpdateStatusCode(t *testing.T) {
	config := coraza_new_waf_config()
	w := coraza_new_waf(config, nil)
	coraza_free_waf_config(config)
	tt := coraza_new_transaction(w)
	rv := coraza_update_status_code(tt, 404)
	if rv != 0 {
		t.Fatal("coraza_update_status_code failed")
	}
	tx := cgo.Handle(tt).Value().(types.Transaction)
	txi := tx.(plugintypes.TransactionState)
	status := txi.Variables().ResponseStatus().Get()
	if status != "404" {
		t.Fatalf("Expected status 404, got %s", status)
	}
	coraza_free_transaction(tt)
	coraza_free_waf(w)
}

func TestCoraza_add_get_args(t *testing.T) {
	config := coraza_new_waf_config()
	waf := coraza_new_waf(config, nil)
	tt := coraza_new_transaction(waf)
	coraza_add_get_args(tt, stringToC("aa"), stringToC("bb"))
	tx := cgo.Handle(tt).Value().(types.Transaction)
	txi := tx.(plugintypes.TransactionState)
	argsGet := txi.Variables().ArgsGet()
	value := argsGet.Get("aa")
	if len(value) != 1 && value[0] != "bb" {
		t.Fatal("coraza_add_get_args can't add args")
	}
	coraza_add_get_args(tt, stringToC("dd"), stringToC("ee"))
	value = argsGet.Get("dd")
	if len(value) != 1 && value[0] != "ee" {
		t.Fatal("coraza_add_get_args can't add args with another key")
	}
	coraza_add_get_args(tt, stringToC("aa"), stringToC("cc"))
	value = argsGet.Get("aa")
	if len(value) != 2 && value[0] != "bb" && value[1] != "cc" {
		t.Fatal("coraza_add_get_args can't add args with same key more than once")
	}
}

func TestTransactionInitialization(t *testing.T) {
	config := coraza_new_waf_config()
	waf := coraza_new_waf(config, nil)
	tt := coraza_new_transaction(waf)
	if tt == 0 {
		t.Fatal("Transaction initialization failed")
	}
	t2 := coraza_new_transaction(waf)
	if t2 == tt {
		t.Fatal("Transactions are duplicated")
	}
	tx := cgo.Handle(tt).Value().(types.Transaction)
	tx.ProcessConnection("127.0.0.1", 8080, "127.0.0.1", 80)
}

func TestMultipleConfigsAllocatedDeallocated(t *testing.T) {
	const numConfigs = 1000
	configs := make([]cgo.Handle, numConfigs)
	for i := 0; i < numConfigs; i++ {
		configs[i] = cgo.Handle(coraza_new_waf_config())
	}
	// free every other config while performing an operation on the other config
	for i := 1; i < numConfigs; i += 2 {
		coraza_new_waf(wafFromCgoHandle(configs[i-1]), nil)
		coraza_free_waf_config(wafFromCgoHandle(configs[i]))
	}
	for i := 0; i < numConfigs; i += 2 {
		coraza_free_waf_config(wafFromCgoHandle(configs[i]))
	}
}

func TestMultipleTransactionsAllocatedDeallocated(t *testing.T) {
	const numTransactions = 1000
	config := coraza_new_waf_config()
	waf := coraza_new_waf(config, nil)
	txes := make([]cgo.Handle, numTransactions)
	for i := 0; i < numTransactions; i++ {
		txes[i] = cgo.Handle(coraza_new_transaction(waf))
	}
	// free every other transaction while performing an operation on the other transaction
	// if there are any collisions between handles, this will result in a seg fault
	for i := 1; i < numTransactions; i += 2 {
		tx := cgo.Handle(txes[i-1]).Value().(types.Transaction)
		tx.ProcessConnection("127.0.0.1", 8080, "127.0.0.1", 80)
		coraza_free_transaction(txFromCgoHandle(txes[i]))
	}
	for i := 0; i < numTransactions; i += 2 {
		coraza_free_transaction(txFromCgoHandle(txes[i]))
	}
}

func TestMultipleWafsAllocatedDeallocated(t *testing.T) {
	const numWafs = 1000
	wafs := make([]cgo.Handle, numWafs)
	for i := 0; i < numWafs; i++ {
		config := coraza_new_waf_config()
		wafs[i] = cgo.Handle(coraza_new_waf(config, nil))
	}
	// free every other waf while performing an operation on the other waf
	// if there are any collisions between handles, this will result in a seg fault
	for i := 1; i < numWafs; i += 2 {
		coraza_new_transaction(wafFromCgoHandle(cgo.Handle(wafs[i-1])))
		coraza_free_waf(wafFromCgoHandle(cgo.Handle(wafs[i])))
	}
	for i := 0; i < numWafs; i += 2 {
		coraza_free_waf(wafFromCgoHandle(cgo.Handle(wafs[i])))
	}
}

func TestParallelConfigs(t *testing.T) {
	const numParallelConfigs = 30
	const numTotalConfigs = 1000

	errgrp, _ := errgroup.WithContext(context.Background())
	sm := semaphore.NewWeighted(numParallelConfigs)
	for i := 0; i < numTotalConfigs; i++ {
		errgrp.Go(func() error {
			// acquire the semaphore
			if err := sm.Acquire(context.Background(), 1); err != nil {
				return err
			}
			defer sm.Release(1)

			// initialize the config
			runtime.GC()
			config := coraza_new_waf_config()
			runtime.GC()

			// check if the config handle is valid
			_, ok := cgo.Handle(config).Value().(*WafConfigHandle)
			if !ok {
				return errors.New("Config handle conversion failed")
			}

			// create a waf
			waf := coraza_new_waf(config, nil)
			if waf == 0 {
				return errors.New("Waf initialization failed")
			}

			// deinitialize the config
			runtime.GC()
			rv := coraza_free_waf_config(config)
			if rv != 0 {
				return errors.New("Config deinitialization failed")
			}
			runtime.GC()
			return nil
		})
	}
	if err := errgrp.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestParallelWafs(t *testing.T) {
	const numParallelWafs = 30
	const numTotalWafs = 1000

	errgrp, _ := errgroup.WithContext(context.Background())
	sm := semaphore.NewWeighted(numParallelWafs)
	for i := 0; i < numTotalWafs; i++ {
		errgrp.Go(func() error {
			// acquire the semaphore
			if err := sm.Acquire(context.Background(), 1); err != nil {
				return err
			}
			defer sm.Release(1)

			// initialize the waf
			runtime.GC()
			config := coraza_new_waf_config()
			rv := coraza_rules_add(config, stringToC(`SecRule REMOTE_ADDR "127.0.0.1" "id:1,phase:1,deny,log,msg:'test 123',status:403"`))
			if rv != 0 {
				return errors.New("Rules addition failed")
			}
			waf := coraza_new_waf(config, nil)
			if waf == 0 {
				return errors.New("Waf initialization failed")
			}
			runtime.GC()

			// check if the waf handle is valid
			_, ok := cgo.Handle(waf).Value().(*WafHandle)
			if !ok {
				return errors.New("Waf handle conversion failed")
			}

			// create a transaction
			tt := coraza_new_transaction(waf)
			if tt == 0 {
				return errors.New("Transaction initialization failed")
			}

			// process the transaction
			coraza_process_connection(tt, stringToC("127.0.0.1"), 8080, stringToC("127.0.0.1"), 80)
			coraza_process_request_headers(tt) // change phase to trigger the rule
			intervention := coraza_intervention(tt)
			if intervention == nil {
				return errors.New("Intervention is nil")
			}
			if intervention.status != 403 {
				return errors.New("Intervention status is not 403")
			}

			// deinitialize the transaction
			rv = coraza_free_transaction(tt)
			if rv != 0 {
				return errors.New("Transaction deinitialization failed")
			}

			// deinitialize the waf
			runtime.GC()
			rv = coraza_free_waf(waf)
			if rv != 0 {
				return errors.New("Waf deinitialization failed")
			}
			runtime.GC()
			return nil
		})
	}
	if err := errgrp.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestParallelTransactions(t *testing.T) {
	const numParallelTransactions = 30
	const numTotalTransactions = 1000

	config := coraza_new_waf_config()
	rv := coraza_rules_add(config, stringToC(`SecRule REMOTE_ADDR "127.0.0.1" "id:1,phase:1,deny,log,msg:'test 123',status:403"`))
	if rv != 0 {
		t.Fatal("Rules addition failed")
	}
	waf := coraza_new_waf(config, nil)
	if waf == 0 {
		t.Fatal("Waf initialization failed")
	}
	errgrp, _ := errgroup.WithContext(context.Background())
	sm := semaphore.NewWeighted(numParallelTransactions)
	for i := 0; i < numTotalTransactions; i++ {
		errgrp.Go(func() error {
			// acquire the semaphore
			if err := sm.Acquire(context.Background(), 1); err != nil {
				return err
			}
			defer sm.Release(1)

			// initialize the transaction
			runtime.GC()
			tt := coraza_new_transaction(waf)
			if tt == 0 {
				return errors.New("Transaction initialization failed")
			}
			runtime.GC()

			// check if the transaction handle is valid
			_, ok := cgo.Handle(tt).Value().(types.Transaction)
			if !ok {
				return errors.New("Transaction handle conversion failed")
			}

			coraza_process_connection(tt, stringToC("127.0.0.1"), 8080, stringToC("127.0.0.1"), 80)
			coraza_process_request_headers(tt) // change phase to trigger the rule
			intervention := coraza_intervention(tt)
			if intervention == nil {
				return errors.New("Intervention is nil")
			}
			if intervention.status != 403 {
				return errors.New("Intervention status is not 403")
			}
			if stringFromC(intervention.action) != "deny" {
				return errors.New("Intervention action is not deny")
			}

			// deinitialize the transaction
			runtime.GC()
			rv := coraza_free_transaction(tt)
			if rv != 0 {
				return errors.New("Transaction deinitialization failed")
			}
			runtime.GC()
			return nil
		})
	}
	if err := errgrp.Wait(); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkTransactionCreation(b *testing.B) {
	config := coraza_new_waf_config()
	waf := coraza_new_waf(config, nil)
	for i := 0; i < b.N; i++ {
		coraza_new_transaction(waf)
	}
}

func BenchmarkTransactionProcessing(b *testing.B) {
	config := coraza_new_waf_config()
	coraza_rules_add(config, stringToC(`SecRule UNIQUE_ID "" "id:1"`))
	waf := coraza_new_waf(config, nil)
	for i := 0; i < b.N; i++ {
		txPtr := coraza_new_transaction(waf)
		tx := cgo.Handle(txPtr).Value().(types.Transaction)
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

func TestInterventionNil(t *testing.T) {
	config := coraza_new_waf_config()
	waf := coraza_new_waf(config, nil)
	coraza_free_waf_config(config)
	tt := coraza_new_transaction(waf)
	if tt == 0 {
		t.Fatal("Transaction initialization failed")
	}
	intervention := coraza_intervention(tt)
	if intervention != nil {
		t.Fatal("Expected nil intervention for transaction with no matching rules")
	}
	coraza_free_transaction(tt)
	coraza_free_waf(waf)
}

func TestNewTransactionWithID(t *testing.T) {
	config := coraza_new_waf_config()
	waf := coraza_new_waf(config, nil)
	coraza_free_waf_config(config)
	tt := coraza_new_transaction_with_id(waf, stringToC("test-tx-id"))
	if tt == 0 {
		t.Fatal("Transaction with ID initialization failed")
	}
	coraza_free_transaction(tt)
	coraza_free_waf(waf)
}

func TestProcessUri(t *testing.T) {
	config := coraza_new_waf_config()
	waf := coraza_new_waf(config, nil)
	coraza_free_waf_config(config)
	tt := coraza_new_transaction(waf)
	rv := coraza_process_uri(tt, stringToC("/test?foo=bar"), stringToC("GET"), stringToC("HTTP/1.1"))
	if rv != 0 {
		t.Fatal("coraza_process_uri failed")
	}
	coraza_free_transaction(tt)
	coraza_free_waf(waf)
}

func TestAddRequestHeader(t *testing.T) {
	config := coraza_new_waf_config()
	waf := coraza_new_waf(config, nil)
	coraza_free_waf_config(config)
	tt := coraza_new_transaction(waf)
	rv := coraza_add_request_header(tt, stringToC("Host"), 4, stringToC("localhost"), 9)
	if rv != 0 {
		t.Fatal("coraza_add_request_header failed")
	}
	tx := cgo.Handle(tt).Value().(types.Transaction)
	txi := tx.(plugintypes.TransactionState)
	values := txi.Variables().RequestHeaders().Get("host")
	if len(values) != 1 || values[0] != "localhost" {
		t.Fatalf("Expected header value 'localhost', got %v", values)
	}
	coraza_free_transaction(tt)
	coraza_free_waf(waf)
}

func TestProcessRequestBody(t *testing.T) {
	config := coraza_new_waf_config()
	waf := coraza_new_waf(config, nil)
	coraza_free_waf_config(config)
	tt := coraza_new_transaction(waf)
	rv := coraza_process_request_body(tt)
	if rv != 0 {
		t.Fatal("coraza_process_request_body failed")
	}
	coraza_free_transaction(tt)
	coraza_free_waf(waf)
}

func TestAddResponseHeader(t *testing.T) {
	config := coraza_new_waf_config()
	waf := coraza_new_waf(config, nil)
	coraza_free_waf_config(config)
	tt := coraza_new_transaction(waf)
	rv := coraza_add_response_header(tt, stringToC("Content-Type"), 12, stringToC("text/html"), 9)
	if rv != 0 {
		t.Fatal("coraza_add_response_header failed")
	}
	tx := cgo.Handle(tt).Value().(types.Transaction)
	txi := tx.(plugintypes.TransactionState)
	values := txi.Variables().ResponseHeaders().Get("content-type")
	if len(values) != 1 || values[0] != "text/html" {
		t.Fatalf("Expected response header 'text/html', got %v", values)
	}
	coraza_free_transaction(tt)
	coraza_free_waf(waf)
}

func TestProcessResponseHeaders(t *testing.T) {
	config := coraza_new_waf_config()
	waf := coraza_new_waf(config, nil)
	coraza_free_waf_config(config)
	tt := coraza_new_transaction(waf)
	rv := coraza_process_response_headers(tt, 200, stringToC("HTTP/1.1"))
	if rv != 0 {
		t.Fatal("coraza_process_response_headers failed")
	}
	coraza_free_transaction(tt)
	coraza_free_waf(waf)
}

func TestProcessResponseBody(t *testing.T) {
	config := coraza_new_waf_config()
	waf := coraza_new_waf(config, nil)
	coraza_free_waf_config(config)
	tt := coraza_new_transaction(waf)
	rv := coraza_process_response_body(tt)
	if rv != 0 {
		t.Fatal("coraza_process_response_body failed")
	}
	coraza_free_transaction(tt)
	coraza_free_waf(waf)
}

func TestProcessLogging(t *testing.T) {
	config := coraza_new_waf_config()
	waf := coraza_new_waf(config, nil)
	coraza_free_waf_config(config)
	tt := coraza_new_transaction(waf)
	rv := coraza_process_logging(tt)
	if rv != 0 {
		t.Fatal("coraza_process_logging failed")
	}
	coraza_free_transaction(tt)
	coraza_free_waf(waf)
}

func TestFreeIntervention(t *testing.T) {
	// Test freeing a nil intervention - should return 1
	rv := coraza_free_intervention(nil)
	if rv != 1 {
		t.Fatalf("coraza_free_intervention(nil) expected 1, got %d", rv)
	}

	// Test freeing a valid intervention obtained from a disrupted transaction
	config := coraza_new_waf_config()
	coraza_rules_add(config, stringToC(`SecRule REMOTE_ADDR "127.0.0.1" "id:1,phase:1,deny,status:403"`))
	waf := coraza_new_waf(config, nil)
	coraza_free_waf_config(config)
	tt := coraza_new_transaction(waf)
	coraza_process_connection(tt, stringToC("127.0.0.1"), 80, stringToC(""), 80)
	coraza_process_request_headers(tt)
	intervention := coraza_intervention(tt)
	if intervention == nil {
		t.Fatal("Expected non-nil intervention")
	}
	rv = coraza_free_intervention(intervention)
	if rv != 0 {
		t.Fatalf("coraza_free_intervention expected 0, got %d", rv)
	}
	coraza_free_transaction(tt)
	coraza_free_waf(waf)
}

func TestRulesMerge(t *testing.T) {
	config1 := coraza_new_waf_config()
	waf1 := coraza_new_waf(config1, nil)
	coraza_free_waf_config(config1)

	config2 := coraza_new_waf_config()
	waf2 := coraza_new_waf(config2, nil)
	coraza_free_waf_config(config2)

	rv := coraza_rules_merge(waf1, waf2, nil)
	if rv != 0 {
		t.Fatalf("coraza_rules_merge expected 0, got %d", rv)
	}

	coraza_free_waf(waf1)
	coraza_free_waf(waf2)
}

func TestNewDebugLogger(t *testing.T) {
	l := newDebugLogger(func(lvl debuglog.Level, message, fields string) {})
	if l == nil {
		t.Fatal("newDebugLogger returned nil")
	}

	// Test WithLevel
	l2 := l.WithLevel(debuglog.LevelInfo)
	if l2 == nil {
		t.Fatal("WithLevel returned nil")
	}

	// Test WithOutput
	var buf bytes.Buffer
	l3 := l.WithOutput(&buf)
	if l3 == nil {
		t.Fatal("WithOutput returned nil")
	}
}

func TestRulesAddFile(t *testing.T) {
	f, err := os.CreateTemp("", "coraza-rules-*.conf")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(`SecRule REMOTE_ADDR "127.0.0.1" "id:1,phase:1,deny,status:403"`); err != nil {
		t.Fatal(err)
	}
	f.Close()

	config := coraza_new_waf_config()
	rv := coraza_rules_add_file(config, stringToC(f.Name()))
	if rv != 0 {
		t.Fatalf("coraza_rules_add_file expected 0, got %d", rv)
	}
	waf := coraza_new_waf(config, nil)
	if waf == 0 {
		t.Fatal("WAF creation failed after adding rules from file")
	}
	if coraza_rules_count(waf) != 1 {
		t.Fatalf("Expected 1 rule from file, got %d", coraza_rules_count(waf))
	}
	coraza_free_waf(waf)
	coraza_free_waf_config(config)
}

func TestNewWafWithError(t *testing.T) {
	config := coraza_new_waf_config()
	coraza_rules_add_file(config, stringToC("/nonexistent/path/to/rules.conf"))
	waf, errOccurred := newWafCheckError(config)
	if !errOccurred {
		t.Fatal("Expected WAF creation to fail with non-existent rules file")
	}
	if waf != 0 {
		t.Fatal("Expected zero WAF handle on error")
	}
	coraza_free_waf_config(config)
}

func TestAppendRequestBody(t *testing.T) {
	config := coraza_new_waf_config()
	waf := coraza_new_waf(config, nil)
	coraza_free_waf_config(config)
	tt := coraza_new_transaction(waf)

	// Empty slice should be a no-op
	rv := appendRequestBody(tt, []byte{})
	if rv != 0 {
		t.Fatalf("appendRequestBody with empty slice expected 0, got %d", rv)
	}

	// Non-empty slice
	rv = appendRequestBody(tt, []byte("test request body content"))
	if rv != 0 {
		t.Fatalf("appendRequestBody expected 0, got %d", rv)
	}
	coraza_free_transaction(tt)
	coraza_free_waf(waf)
}

func TestAppendResponseBody(t *testing.T) {
	config := coraza_new_waf_config()
	waf := coraza_new_waf(config, nil)
	coraza_free_waf_config(config)
	tt := coraza_new_transaction(waf)

	rv := appendResponseBody(tt, []byte("test response body content"))
	if rv != 0 {
		t.Fatalf("appendResponseBody expected 0, got %d", rv)
	}
	coraza_free_transaction(tt)
	coraza_free_waf(waf)
}

func TestRequestBodyFromFile(t *testing.T) {
	f, err := os.CreateTemp("", "coraza-body-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString("test request body from file"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	config := coraza_new_waf_config()
	waf := coraza_new_waf(config, nil)
	coraza_free_waf_config(config)
	tt := coraza_new_transaction(waf)

	rv := coraza_request_body_from_file(tt, stringToC(f.Name()))
	if rv != 0 {
		t.Fatalf("coraza_request_body_from_file expected 0, got %d", rv)
	}
	coraza_free_transaction(tt)
	coraza_free_waf(waf)
}

func TestRequestBodyFromFileError(t *testing.T) {
	config := coraza_new_waf_config()
	waf := coraza_new_waf(config, nil)
	coraza_free_waf_config(config)
	tt := coraza_new_transaction(waf)

	rv := coraza_request_body_from_file(tt, stringToC("/nonexistent/body/file.txt"))
	if rv != 1 {
		t.Fatalf("coraza_request_body_from_file expected 1 (error), got %d", rv)
	}
	coraza_free_transaction(tt)
	coraza_free_waf(waf)
}

// FuzzProcessTransaction exercises the full transaction processing pipeline with
// fuzzed inputs covering remote address, URI, HTTP method, protocol, and headers.
func FuzzProcessTransaction(f *testing.F) {
	f.Add("127.0.0.1", "/index.html", "GET", "HTTP/1.1", "Host", "localhost")
	f.Add("192.168.1.1", "/admin", "POST", "HTTP/2.0", "Content-Type", "application/json")
	f.Add("10.0.0.1", "/search?q=test", "GET", "HTTP/1.1", "User-Agent", "Mozilla/5.0")
	f.Add("", "/", "", "", "", "")
	f.Add("::1", "/path?a=b&c=d", "PUT", "HTTP/1.0", "X-Custom", "value")

	config := coraza_new_waf_config()
	coraza_rules_add(config, stringToC(`SecRule REQUEST_URI "@contains admin" "id:100,phase:1,deny,status:403"`))
	waf := coraza_new_waf(config, nil)
	coraza_free_waf_config(config)

	f.Fuzz(func(t *testing.T, remoteAddr, uri, method, proto, headerName, headerValue string) {
		tt := coraza_new_transaction(waf)
		if tt == 0 {
			return
		}

		coraza_process_connection(tt, stringToC(remoteAddr), 80, stringToC(""), 80)
		coraza_process_uri(tt, stringToC(uri), stringToC(method), stringToC(proto))
		addRequestHeaderStr(tt, headerName, headerValue)
		coraza_process_request_headers(tt)
		appendRequestBody(tt, []byte(uri))
		coraza_process_request_body(tt)
		coraza_process_response_headers(tt, 200, stringToC("HTTP/1.1"))
		appendResponseBody(tt, []byte(headerValue))
		coraza_process_response_body(tt)
		coraza_process_logging(tt)
		coraza_intervention(tt)
		coraza_free_transaction(tt)
	})
}

func TestNewWafSuccess(t *testing.T) {
	config := coraza_new_waf_config()
	waf, errOccurred := newWafCheckError(config)
	if errOccurred {
		t.Fatal("Expected WAF creation to succeed with empty config")
	}
	if waf == 0 {
		t.Fatal("Expected valid WAF handle")
	}
	coraza_free_waf(waf)
	coraza_free_waf_config(config)
}

func TestMatchedRuleFunctions(t *testing.T) {
	config := coraza_new_waf_config()
	// Use an explicit severity so we can verify the mapping
	coraza_rules_add(config, stringToC(`SecRule REMOTE_ADDR "127.0.0.1" "id:1,phase:1,deny,log,msg:'test',severity:CRITICAL,status:403"`))
	getHandle, releaseHandle := captureMatchedRule(config)
	defer releaseHandle()

	waf := coraza_new_waf(config, nil)
	coraza_free_waf_config(config)

	tt := coraza_new_transaction(waf)
	coraza_process_connection(tt, stringToC("127.0.0.1"), 80, stringToC(""), 80)
	coraza_process_request_headers(tt) // triggers the deny rule

	handle := getHandle()
	if handle == 0 {
		t.Fatal("Expected matched rule handle after rule match")
	}

	// Test coraza_matched_rule_get_severity - CRITICAL maps to enum value 6
	severity := coraza_matched_rule_get_severity(handle)
	if severityToInt(severity) != 6 { // CORAZA_SEVERITY_CRITICAL
		t.Fatalf("Expected CRITICAL severity (6), got %d", severityToInt(severity))
	}

	// Test coraza_matched_rule_get_error_log - should return a non-empty log string
	errorLog := coraza_matched_rule_get_error_log(handle)
	logStr := stringFromC(errorLog)
	freeString(errorLog)
	if logStr == "" {
		t.Fatal("Expected non-empty error log from matched rule")
	}

	coraza_free_transaction(tt)
	coraza_free_waf(waf)
}

// TestMatchedRuleSeverities exercises coraza_matched_rule_get_severity across
// multiple severity levels to increase branch coverage.
func TestMatchedRuleSeverities(t *testing.T) {
	// Maps severity name to expected CORAZA_SEVERITY_* enum value.
	// Enum order: UNKNOWN=0, DEBUG=1, INFO=2, NOTICE=3, WARNING=4, ERROR=5, CRITICAL=6, ALERT=7, EMERGENCY=8
	cases := []struct {
		name     string
		expected int
	}{
		{"EMERGENCY", 8},
		{"ALERT", 7},
		{"CRITICAL", 6},
		{"ERROR", 5},
		{"WARNING", 4},
		{"NOTICE", 3},
		{"INFO", 2},
		{"DEBUG", 1},
	}
	for i, tc := range cases {
		tc := tc
		i := i
		t.Run(tc.name, func(t *testing.T) {
			config := coraza_new_waf_config()
			rule := fmt.Sprintf(
				`SecRule REMOTE_ADDR "127.0.0.1" "id:%d,phase:1,deny,log,severity:%s,status:403"`,
				100+i, tc.name,
			)
			coraza_rules_add(config, stringToC(rule))
			getHandle, releaseHandle := captureMatchedRule(config)
			defer releaseHandle()

			waf := coraza_new_waf(config, nil)
			coraza_free_waf_config(config)

			tt := coraza_new_transaction(waf)
			coraza_process_connection(tt, stringToC("127.0.0.1"), 80, stringToC(""), 80)
			coraza_process_request_headers(tt)

			handle := getHandle()
			if handle == 0 {
				t.Fatalf("Expected matched rule handle for severity %s", tc.name)
			}
			severity := coraza_matched_rule_get_severity(handle)
			if severityToInt(severity) != tc.expected {
				t.Errorf("Severity %s: expected %d, got %d", tc.name, tc.expected, severityToInt(severity))
			}

			coraza_free_transaction(tt)
			coraza_free_waf(waf)
		})
	}
}

// TestCaptureMatchedRuleNoMatch exercises the no-match path of captureMatchedRule
// where the rule does not trigger (no matching request).
func TestCaptureMatchedRuleNoMatch(t *testing.T) {
	config := coraza_new_waf_config()
	coraza_rules_add(config, stringToC(`SecRule REMOTE_ADDR "192.168.99.99" "id:200,phase:1,deny,log,status:403"`))
	getHandle, releaseHandle := captureMatchedRule(config)
	defer releaseHandle()

	waf := coraza_new_waf(config, nil)
	coraza_free_waf_config(config)

	tt := coraza_new_transaction(waf)
	coraza_process_connection(tt, stringToC("127.0.0.1"), 80, stringToC(""), 80) // doesn't match 192.168.99.99
	coraza_process_request_headers(tt)

	handle := getHandle()
	if handle != 0 {
		t.Fatal("Expected zero handle when no rule matched")
	}
	coraza_free_transaction(tt)
	coraza_free_waf(waf)
}
