package main

import (
	"context"
	"errors"
	"runtime"
	"runtime/cgo"
	"testing"

	"github.com/corazawaf/coraza/v3"
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
	tests := []struct {
		name         string
		rules        string
		canCreateWaf bool
	}{
		{
			name:         "rule",
			rules:        `SecRule REMOTE_ADDR "127.0.0.1" "id:1,phase:1,deny,log,msg:'test 123',status:403"`,
			canCreateWaf: true,
		},
		{
			name:         "include local file",
			rules:        `Include testdata/test.conf`,
			canCreateWaf: true,
		},
		{
			name:         "include invalid rule",
			rules:        `foobar123`,
			canCreateWaf: false,
		},
		{
			name:         "include non-existent file",
			rules:        `Include testdata/nonexistent.conf`,
			canCreateWaf: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := coraza_new_waf_config()
			rv := coraza_rules_add(config, stringToC(test.rules))
			if rv != 0 {
				t.Fatalf("Rules addition failed: %d", rv)
			}

			er := stringToC("")
			waf := coraza_new_waf(config, &er)
			if test.canCreateWaf && (waf == 0 || stringFromC(er) != "") {
				t.Fatalf("Waf creation failed: %d", waf)
			} else if !test.canCreateWaf && (waf != 0 || stringFromC(er) == "") {
				t.Fatalf("Waf creation should have failed: %d", waf)
			}
			if stringFromC(er) != "" {
				t.Logf("Waf creation error: %s", stringFromC(er))
			}
		})
	}
}

func TestAddRulesFromFileToWaf(t *testing.T) {
	tests := []struct {
		name         string
		file         string
		canCreateWaf bool
	}{
		{
			name:         "test.conf",
			file:         "testdata/test.conf",
			canCreateWaf: true,
		},
		{
			name:         "nonexistent.conf",
			file:         "testdata/nonexistent.conf",
			canCreateWaf: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := coraza_new_waf_config()
			rv := coraza_rules_add_file(config, stringToC(test.file))
			if rv != 0 {
				t.Fatalf("Rules addition failed: %d", rv)
			}

			er := stringToC("")
			waf := coraza_new_waf(config, &er)
			if test.canCreateWaf && (waf == 0 || stringFromC(er) != "") {
				t.Fatalf("Waf creation failed: %d", waf)
			} else if !test.canCreateWaf && (waf != 0 || stringFromC(er) == "") {
				t.Fatalf("Waf creation should have failed: %d", waf)
			}
		})
	}
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
			_, ok := cgo.Handle(waf).Value().(coraza.WAF)
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
