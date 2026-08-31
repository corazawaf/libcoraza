-- simple_get.lua - Lua SWIG example for libcoraza.
--
-- Exercises all exported functions testable from Lua, including callbacks.
--
-- Build and run from the repository root:
--
--   make
--   make -C examples/lua
--   make -C examples/lua run

local coraza = require("coraza")

local DENY_RULE = 'SecRule REMOTE_ADDR "@ipMatch 127.0.0.1" ' ..
    '"id:1,phase:1,deny,log,msg:\'block\',status:403"'
local PASS_RULE = 'SecRule REMOTE_ADDR "@ipMatch 10.0.0.1" ' ..
    '"id:2,phase:1,pass,log,msg:\'allow\'"'

local function check(cond, msg)
    if not cond then
        error(msg, 2)
    end
end

-- ---------------------------------------------------------------------------
-- test_lifecycle
-- Covers: coraza_new_waf_config, coraza_rules_add, coraza_rules_add_file,
--         coraza_new_waf, coraza_rules_count, coraza_free_waf_config,
--         coraza_new_transaction_with_id, coraza_process_connection,
--         coraza_add_request_header, coraza_add_get_args,
--         coraza_process_uri, coraza_process_request_headers,
--         coraza_append_request_body, coraza_process_request_body,
--         coraza_process_response_headers, coraza_add_response_header,
--         coraza_append_response_body, coraza_process_response_body,
--         coraza_update_status_code, coraza_process_logging,
--         coraza_intervention, coraza_free_intervention,
--         coraza_free_transaction, coraza_new_transaction, coraza_free_waf
-- ---------------------------------------------------------------------------
local function test_lifecycle()
    -- coraza_new_waf_config
    local cfg = coraza.coraza_new_waf_config()
    check(cfg ~= 0, "coraza_new_waf_config returned 0")

    -- coraza_rules_add
    local ret = coraza.coraza_rules_add(cfg, DENY_RULE)
    check(ret == 0, "coraza_rules_add failed: " .. ret)

    -- coraza_rules_add_file — write a second rule to a temp file
    local tmpfile = os.tmpname() .. ".conf"
    local f = assert(io.open(tmpfile, "w"))
    f:write(PASS_RULE .. "\n")
    f:close()

    ret = coraza.coraza_rules_add_file(cfg, tmpfile)
    check(ret == 0, "coraza_rules_add_file failed: " .. ret)

    -- coraza_new_waf — must be created while the rules file still exists
    local waf = coraza.coraza_new_waf(cfg)
    check(waf ~= 0, "coraza_new_waf returned 0")
    os.remove(tmpfile)

    -- coraza_rules_count
    local count = coraza.coraza_rules_count(waf)
    check(count >= 2, "expected >= 2 rules, got " .. count)

    -- coraza_free_waf_config
    ret = coraza.coraza_free_waf_config(cfg)
    check(ret == 0, "coraza_free_waf_config failed: " .. ret)

    -- coraza_new_transaction_with_id
    local tx = coraza.coraza_new_transaction_with_id(waf, "lua-simple-get")
    check(tx ~= 0, "coraza_new_transaction_with_id returned 0")

    -- coraza_process_connection
    ret = coraza.coraza_process_connection(tx, "127.0.0.1", 55555, "localhost", 80)
    check(ret == 0, "coraza_process_connection failed: " .. ret)

    -- coraza_add_request_header
    -- Use byte length of the header name and value strings.
    local hname, hvalue = "Host", "localhost"
    ret = coraza.coraza_add_request_header(tx, hname, #hname, hvalue, #hvalue)
    check(ret == 0, "coraza_add_request_header failed: " .. ret)

    -- coraza_add_get_args
    ret = coraza.coraza_add_get_args(tx, "foo", "bar")
    check(ret == 0, "coraza_add_get_args failed: " .. ret)

    -- coraza_process_uri
    ret = coraza.coraza_process_uri(tx, "/someurl?foo=bar", "GET", "HTTP/1.1")
    check(ret == 0, "coraza_process_uri failed: " .. ret)

    -- coraza_process_request_headers
    ret = coraza.coraza_process_request_headers(tx)
    check(ret == 0, "coraza_process_request_headers failed: " .. ret)

    -- coraza_append_request_body (string typemap: single argument)
    ret = coraza.coraza_append_request_body(tx, "hello=world")
    check(ret == 0, "coraza_append_request_body failed: " .. ret)

    -- coraza_process_request_body
    ret = coraza.coraza_process_request_body(tx)
    check(ret == 0, "coraza_process_request_body failed: " .. ret)

    -- coraza_process_response_headers
    ret = coraza.coraza_process_response_headers(tx, 200, "HTTP/1.1")
    check(ret == 0, "coraza_process_response_headers failed: " .. ret)

    -- coraza_add_response_header
    local cname, cvalue = "Content-Type", "text/plain"
    ret = coraza.coraza_add_response_header(tx, cname, #cname, cvalue, #cvalue)
    check(ret == 0, "coraza_add_response_header failed: " .. ret)

    -- coraza_append_response_body (string typemap: single argument)
    ret = coraza.coraza_append_response_body(tx, "OK")
    check(ret == 0, "coraza_append_response_body failed: " .. ret)

    -- coraza_process_response_body
    ret = coraza.coraza_process_response_body(tx)
    check(ret == 0, "coraza_process_response_body failed: " .. ret)

    -- coraza_update_status_code
    coraza.coraza_update_status_code(tx, 200)

    -- coraza_process_logging
    ret = coraza.coraza_process_logging(tx)
    check(ret == 0, "coraza_process_logging failed: " .. ret)

    -- coraza_intervention — the deny rule on 127.0.0.1 must have fired
    local it = coraza.coraza_intervention(tx)
    check(it ~= nil, "expected an intervention but got nil")
    check(it.status == 403, "expected status 403, got " .. it.status)
    print("  Intervention: action=" .. tostring(it.action) ..
          " status=" .. it.status .. " data=" .. tostring(it.data))

    -- coraza_free_intervention
    ret = coraza.coraza_free_intervention(it)
    check(ret == 0, "coraza_free_intervention failed: " .. ret)

    -- coraza_free_transaction
    ret = coraza.coraza_free_transaction(tx)
    check(ret == 0, "coraza_free_transaction failed: " .. ret)

    -- coraza_new_transaction (non-ID variant)
    local tx2 = coraza.coraza_new_transaction(waf)
    check(tx2 ~= 0, "coraza_new_transaction returned 0")
    coraza.coraza_free_transaction(tx2)

    -- coraza_free_waf
    ret = coraza.coraza_free_waf(waf)
    check(ret == 0, "coraza_free_waf failed: " .. ret)

    print("  test_lifecycle: PASS")
end

-- ---------------------------------------------------------------------------
-- test_request_body_from_file
-- Covers: coraza_request_body_from_file
-- ---------------------------------------------------------------------------
local function test_request_body_from_file()
    local cfg = coraza.coraza_new_waf_config()
    coraza.coraza_rules_add(cfg, PASS_RULE)
    local waf = coraza.coraza_new_waf(cfg)
    coraza.coraza_free_waf_config(cfg)

    local tx = coraza.coraza_new_transaction(waf)
    coraza.coraza_process_connection(tx, "10.0.0.1", 12345, "localhost", 80)
    coraza.coraza_process_uri(tx, "/upload", "POST", "HTTP/1.1")
    coraza.coraza_process_request_headers(tx)

    local bodyfile = os.tmpname() .. ".txt"
    local f = assert(io.open(bodyfile, "w"))
    f:write("body content from file")
    f:close()

    local ret = coraza.coraza_request_body_from_file(tx, bodyfile)
    os.remove(bodyfile)
    check(ret == 0, "coraza_request_body_from_file failed: " .. ret)

    check(coraza.coraza_process_request_body(tx) == 0,
          "coraza_process_request_body failed")
    check(coraza.coraza_process_response_headers(tx, 200, "HTTP/1.1") == 0,
          "coraza_process_response_headers failed")
    check(coraza.coraza_process_response_body(tx) == 0,
          "coraza_process_response_body failed")
    check(coraza.coraza_process_logging(tx) == 0,
          "coraza_process_logging failed")
    check(coraza.coraza_free_transaction(tx) == 0,
          "coraza_free_transaction failed")
    check(coraza.coraza_free_waf(waf) == 0, "coraza_free_waf failed")

    print("  test_request_body_from_file: PASS")
end

-- ---------------------------------------------------------------------------
-- test_rules_merge
-- Covers: coraza_rules_merge
-- NOTE: coraza_rules_merge is currently a stub (always returns 0, does not
-- actually merge rules). This test only verifies the call does not crash.
-- ---------------------------------------------------------------------------
local function test_rules_merge()
    local cfg1 = coraza.coraza_new_waf_config()
    coraza.coraza_rules_add(cfg1, PASS_RULE)
    local waf1 = coraza.coraza_new_waf(cfg1)
    check(coraza.coraza_free_waf_config(cfg1) == 0,
          "coraza_free_waf_config failed")

    local cfg2 = coraza.coraza_new_waf_config()
    local waf2 = coraza.coraza_new_waf(cfg2)
    check(coraza.coraza_free_waf_config(cfg2) == 0,
          "coraza_free_waf_config failed")

    local ret = coraza.coraza_rules_merge(waf1, waf2)
    check(ret == 0, "coraza_rules_merge failed: " .. ret)

    check(coraza.coraza_free_waf(waf1) == 0, "coraza_free_waf(waf1) failed")
    check(coraza.coraza_free_waf(waf2) == 0, "coraza_free_waf(waf2) failed")

    print("  test_rules_merge: PASS")
end

-- ---------------------------------------------------------------------------
-- test_callbacks
-- Covers: coraza_set_error_callback, coraza_set_debug_log_callback,
--         coraza_matched_rule_get_error_log, coraza_matched_rule_get_severity
-- ---------------------------------------------------------------------------
local function test_callbacks()
    local matched_logs = {}
    local debug_msgs   = {}

    local function on_error(rule_handle)
        local log = coraza.coraza_matched_rule_get_error_log(rule_handle)
        local sev = coraza.coraza_matched_rule_get_severity(rule_handle)
        table.insert(matched_logs, {sev, log})
    end

    local function on_debug_log(level, message, fields)
        table.insert(debug_msgs, {level, message})
    end

    local cfg = coraza.coraza_new_waf_config()
    coraza.coraza_rules_add(cfg, DENY_RULE)
    check(coraza.coraza_set_error_callback(cfg, on_error) == 0,
          "coraza_set_error_callback failed")
    check(coraza.coraza_set_debug_log_callback(cfg, on_debug_log) == 0,
          "coraza_set_debug_log_callback failed")

    local waf = coraza.coraza_new_waf(cfg)
    check(coraza.coraza_free_waf_config(cfg) == 0, "coraza_free_waf_config failed")

    local tx = coraza.coraza_new_transaction(waf)
    coraza.coraza_process_connection(tx, "127.0.0.1", 12345, "localhost", 80)
    coraza.coraza_process_uri(tx, "/test", "GET", "HTTP/1.1")
    coraza.coraza_process_request_headers(tx)
    coraza.coraza_process_logging(tx)
    check(coraza.coraza_free_transaction(tx) == 0, "coraza_free_transaction failed")
    check(coraza.coraza_free_waf(waf) == 0, "coraza_free_waf failed")

    check(#matched_logs > 0,
          "expected at least one matched rule via error callback")
    print("  Matched rules via callback: " .. #matched_logs)
    -- Debug messages depend on Coraza's internal log level (default: ERROR).
    -- We verify the callback was accepted without asserting message count.
    print("  Debug messages received: " .. #debug_msgs)
    print("  test_callbacks: PASS")
end

-- ---------------------------------------------------------------------------
-- test_intervention_redirect
-- Covers: coraza_intervention .data field (redirect URL), coraza_free_intervention
-- Validates the char *data struct field end-to-end through the SWIG layer.
-- ---------------------------------------------------------------------------
local function test_intervention_redirect()
    local redirect_rule = 'SecRule ARGS:trigger "@streq yes" ' ..
        '"id:10,phase:1,status:302,redirect:http://example.com"'

    local cfg = coraza.coraza_new_waf_config()
    coraza.coraza_rules_add(cfg, redirect_rule)
    local waf = coraza.coraza_new_waf(cfg)
    check(coraza.coraza_free_waf_config(cfg) == 0, "coraza_free_waf_config failed")

    local tx = coraza.coraza_new_transaction(waf)
    coraza.coraza_process_connection(tx, "10.0.0.1", 12345, "localhost", 80)
    coraza.coraza_add_get_args(tx, "trigger", "yes")
    coraza.coraza_process_uri(tx, "/?trigger=yes", "GET", "HTTP/1.1")
    coraza.coraza_process_request_headers(tx)

    local it = coraza.coraza_intervention(tx)
    check(it ~= nil, "expected a redirect intervention but got nil")
    check(it.status == 302, "expected status 302, got " .. it.status)
    check(it.action == "redirect",
          "expected action 'redirect', got " .. tostring(it.action))
    check(it.data == "http://example.com",
          "expected data 'http://example.com', got " .. tostring(it.data))

    check(coraza.coraza_free_intervention(it) == 0,
          "coraza_free_intervention failed")
    check(coraza.coraza_free_transaction(tx) == 0, "coraza_free_transaction failed")
    check(coraza.coraza_free_waf(waf) == 0, "coraza_free_waf failed")

    print("  test_intervention_redirect: PASS")
end

-- ---------------------------------------------------------------------------
-- test_waf_creation_error
-- Covers: coraza_new_waf char**er typemap — bad config raises a Lua error.
-- ---------------------------------------------------------------------------
local function test_waf_creation_error()
    local cfg = coraza.coraza_new_waf_config()
    -- Reference a non-existent rules file to force WAF creation to fail.
    coraza.coraza_rules_add_file(cfg, "/nonexistent/path/rules.conf")
    local ok, err = pcall(function()
        return coraza.coraza_new_waf(cfg)
    end)
    check(not ok,
          "expected error from coraza_new_waf but none was raised")
    check(coraza.coraza_free_waf_config(cfg) == 0, "coraza_free_waf_config failed")

    print("  test_waf_creation_error: PASS")
end

-- ---------------------------------------------------------------------------
-- test_invalid_inputs
-- Covers: Lua typemap validation (non-string body, non-function callback).
-- ---------------------------------------------------------------------------
local function test_invalid_inputs()
    -- coraza_append_request_body must reject non-string input (e.g. a table).
    local cfg = coraza.coraza_new_waf_config()
    local waf = coraza.coraza_new_waf(cfg)
    coraza.coraza_free_waf_config(cfg)
    local tx = coraza.coraza_new_transaction(waf)
    local ok, _ = pcall(function()
        coraza.coraza_append_request_body(tx, {})
    end)
    check(not ok, "expected error for table input but none was raised")
    coraza.coraza_free_transaction(tx)
    coraza.coraza_free_waf(waf)

    -- coraza_set_error_callback must reject non-function arguments.
    cfg = coraza.coraza_new_waf_config()
    ok, _ = pcall(function()
        coraza.coraza_set_error_callback(cfg, "not a function")
    end)
    check(not ok, "expected error for non-function callback but none was raised")
    check(coraza.coraza_free_waf_config(cfg) == 0, "coraza_free_waf_config failed")

    -- coraza_set_debug_log_callback must reject non-function arguments.
    cfg = coraza.coraza_new_waf_config()
    ok, _ = pcall(function()
        coraza.coraza_set_debug_log_callback(cfg, 42)
    end)
    check(not ok, "expected error for non-function callback but none was raised")
    check(coraza.coraza_free_waf_config(cfg) == 0, "coraza_free_waf_config failed")

    print("  test_invalid_inputs: PASS")
end

print("Running libcoraza Lua SWIG tests...")
test_lifecycle()
test_request_body_from_file()
test_rules_merge()
test_callbacks()
test_intervention_redirect()
test_waf_creation_error()
test_invalid_inputs()
print("All tests passed.")
