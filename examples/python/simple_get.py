#!/usr/bin/env python3
"""simple_get.py - Python SWIG example for libcoraza.

Exercises all exported functions that can be tested without a native
callback (coraza_add_debug_log_callback / coraza_add_error_callback
require language-specific function-pointer support and are excluded from
the default SWIG wrapper).

Build and run from the repository root::

    make
    make -C examples/python
    make -C examples/python run
"""

import os
import sys
import tempfile

# Ensure the SWIG-generated coraza.py / _coraza.so are found.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import coraza as _c  # noqa: E402

_DENY_RULE = (
    'SecRule REMOTE_ADDR "@ipMatch 127.0.0.1" '
    '"id:1,phase:1,deny,log,msg:\'block\',status:403"'
)
_PASS_RULE = (
    'SecRule REMOTE_ADDR "@ipMatch 10.0.0.1" '
    '"id:2,phase:1,pass,log,msg:\'allow\'"'
)


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


# ---------------------------------------------------------------------------
# test_lifecycle
# Covers: coraza_new_waf_config, coraza_rules_add, coraza_rules_add_file,
#         coraza_new_waf, coraza_rules_count, coraza_free_waf_config,
#         coraza_new_transaction_with_id, coraza_process_connection,
#         coraza_add_request_header, coraza_add_get_args,
#         coraza_process_uri, coraza_process_request_headers,
#         coraza_append_request_body, coraza_process_request_body,
#         coraza_process_response_headers, coraza_add_response_header,
#         coraza_append_response_body, coraza_process_response_body,
#         coraza_update_status_code, coraza_process_logging,
#         coraza_intervention, coraza_free_intervention,
#         coraza_free_transaction, coraza_new_transaction, coraza_free_waf
# ---------------------------------------------------------------------------
def test_lifecycle():
    # coraza_new_waf_config
    cfg = _c.coraza_new_waf_config()
    _check(cfg != 0, "coraza_new_waf_config returned 0")

    # coraza_rules_add
    ret = _c.coraza_rules_add(cfg, _DENY_RULE)
    _check(ret == 0, f"coraza_rules_add failed: {ret}")

    # coraza_rules_add_file — write a second rule to a temp file
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".conf", delete=False
    ) as tf:
        tf.write(_PASS_RULE + "\n")
        rules_file = tf.name
    try:
        ret = _c.coraza_rules_add_file(cfg, rules_file)
        _check(ret == 0, f"coraza_rules_add_file failed: {ret}")

        # coraza_new_waf — must be created while the rules file still exists
        waf = _c.coraza_new_waf(cfg)
        _check(waf != 0, "coraza_new_waf returned 0")
    finally:
        os.unlink(rules_file)

    # coraza_rules_count
    count = _c.coraza_rules_count(waf)
    _check(count >= 2, f"expected >= 2 rules, got {count}")

    # coraza_free_waf_config
    ret = _c.coraza_free_waf_config(cfg)
    _check(ret == 0, f"coraza_free_waf_config failed: {ret}")

    # coraza_new_transaction_with_id
    tx = _c.coraza_new_transaction_with_id(waf, "python-simple-get")
    _check(tx != 0, "coraza_new_transaction_with_id returned 0")

    # coraza_process_connection
    ret = _c.coraza_process_connection(tx, "127.0.0.1", 55555, "localhost", 80)
    _check(ret == 0, f"coraza_process_connection failed: {ret}")

    # coraza_add_request_header
    # Use len(x.encode()) for byte length — required for correctness with non-ASCII values.
    hname, hvalue = "Host", "localhost"
    ret = _c.coraza_add_request_header(
        tx, hname, len(hname.encode()), hvalue, len(hvalue.encode())
    )
    _check(ret == 0, f"coraza_add_request_header failed: {ret}")

    # coraza_add_get_args
    ret = _c.coraza_add_get_args(tx, "foo", "bar")
    _check(ret == 0, f"coraza_add_get_args failed: {ret}")

    # coraza_process_uri
    ret = _c.coraza_process_uri(tx, "/someurl?foo=bar", "GET", "HTTP/1.1")
    _check(ret == 0, f"coraza_process_uri failed: {ret}")

    # coraza_process_request_headers
    ret = _c.coraza_process_request_headers(tx)
    _check(ret == 0, f"coraza_process_request_headers failed: {ret}")

    # coraza_append_request_body (bytes typemap: single argument)
    body = b"hello=world"
    ret = _c.coraza_append_request_body(tx, body)
    _check(ret == 0, f"coraza_append_request_body failed: {ret}")

    # coraza_process_request_body
    ret = _c.coraza_process_request_body(tx)
    _check(ret == 0, f"coraza_process_request_body failed: {ret}")

    # coraza_process_response_headers
    ret = _c.coraza_process_response_headers(tx, 200, "HTTP/1.1")
    _check(ret == 0, f"coraza_process_response_headers failed: {ret}")

    # coraza_add_response_header
    cname, cvalue = "Content-Type", "text/plain"
    ret = _c.coraza_add_response_header(
        tx, cname, len(cname.encode()), cvalue, len(cvalue.encode())
    )
    _check(ret == 0, f"coraza_add_response_header failed: {ret}")

    # coraza_append_response_body (bytes typemap: single argument)
    resp_body = b"OK"
    ret = _c.coraza_append_response_body(tx, resp_body)
    _check(ret == 0, f"coraza_append_response_body failed: {ret}")

    # coraza_process_response_body
    ret = _c.coraza_process_response_body(tx)
    _check(ret == 0, f"coraza_process_response_body failed: {ret}")

    # coraza_update_status_code
    _c.coraza_update_status_code(tx, 200)

    # coraza_process_logging
    ret = _c.coraza_process_logging(tx)
    _check(ret == 0, f"coraza_process_logging failed: {ret}")

    # coraza_intervention — the deny rule on 127.0.0.1 must have fired
    it = _c.coraza_intervention(tx)
    _check(it is not None, "expected an intervention but got None")
    _check(it.status == 403, f"expected status 403, got {it.status}")
    print(f"  Intervention: action={it.action!r} status={it.status} data={it.data!r}")

    # coraza_free_intervention
    ret = _c.coraza_free_intervention(it)
    _check(ret == 0, f"coraza_free_intervention failed: {ret}")

    # coraza_free_transaction
    ret = _c.coraza_free_transaction(tx)
    _check(ret == 0, f"coraza_free_transaction failed: {ret}")

    # coraza_new_transaction (non-ID variant)
    tx2 = _c.coraza_new_transaction(waf)
    _check(tx2 != 0, "coraza_new_transaction returned 0")
    _c.coraza_free_transaction(tx2)

    # coraza_free_waf
    ret = _c.coraza_free_waf(waf)
    _check(ret == 0, f"coraza_free_waf failed: {ret}")

    print("  test_lifecycle: PASS")


# ---------------------------------------------------------------------------
# test_request_body_from_file
# Covers: coraza_request_body_from_file
# ---------------------------------------------------------------------------
def test_request_body_from_file():
    cfg = _c.coraza_new_waf_config()
    _c.coraza_rules_add(cfg, _PASS_RULE)
    waf = _c.coraza_new_waf(cfg)
    _c.coraza_free_waf_config(cfg)

    tx = _c.coraza_new_transaction(waf)
    _c.coraza_process_connection(tx, "10.0.0.1", 12345, "localhost", 80)
    _c.coraza_process_uri(tx, "/upload", "POST", "HTTP/1.1")
    _c.coraza_process_request_headers(tx)

    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"body content from file")
        body_file = tf.name
    try:
        ret = _c.coraza_request_body_from_file(tx, body_file)
        _check(ret == 0, f"coraza_request_body_from_file failed: {ret}")
    finally:
        os.unlink(body_file)

    _check(_c.coraza_process_request_body(tx) == 0, "coraza_process_request_body failed")
    _check(_c.coraza_process_response_headers(tx, 200, "HTTP/1.1") == 0, "coraza_process_response_headers failed")
    _check(_c.coraza_process_response_body(tx) == 0, "coraza_process_response_body failed")
    _check(_c.coraza_process_logging(tx) == 0, "coraza_process_logging failed")
    _check(_c.coraza_free_transaction(tx) == 0, "coraza_free_transaction failed")
    _check(_c.coraza_free_waf(waf) == 0, "coraza_free_waf failed")

    print("  test_request_body_from_file: PASS")


# ---------------------------------------------------------------------------
# test_rules_merge
# Covers: coraza_rules_merge
# NOTE: coraza_rules_merge is currently a stub (always returns 0, does not
# actually merge rules). This test only verifies the call does not crash.
# ---------------------------------------------------------------------------
def test_rules_merge():
    cfg1 = _c.coraza_new_waf_config()
    _c.coraza_rules_add(cfg1, _PASS_RULE)
    waf1 = _c.coraza_new_waf(cfg1)
    _check(_c.coraza_free_waf_config(cfg1) == 0, "coraza_free_waf_config failed")

    cfg2 = _c.coraza_new_waf_config()
    waf2 = _c.coraza_new_waf(cfg2)
    _check(_c.coraza_free_waf_config(cfg2) == 0, "coraza_free_waf_config failed")

    ret = _c.coraza_rules_merge(waf1, waf2)
    _check(ret == 0, f"coraza_rules_merge failed: {ret}")

    _check(_c.coraza_free_waf(waf1) == 0, "coraza_free_waf(waf1) failed")
    _check(_c.coraza_free_waf(waf2) == 0, "coraza_free_waf(waf2) failed")

    print("  test_rules_merge: PASS")


# ---------------------------------------------------------------------------
# test_callbacks
# Covers: coraza_set_error_callback, coraza_set_debug_log_callback,
#         coraza_matched_rule_get_error_log, coraza_matched_rule_get_severity
# ---------------------------------------------------------------------------
def test_callbacks():
    matched_logs = []
    debug_msgs = []

    def on_error(rule_handle):
        log = _c.coraza_matched_rule_get_error_log(rule_handle)
        sev = _c.coraza_matched_rule_get_severity(rule_handle)
        matched_logs.append((sev, log))

    def on_debug_log(level, message, fields):
        debug_msgs.append((level, message))

    cfg = _c.coraza_new_waf_config()
    _c.coraza_rules_add(cfg, _DENY_RULE)
    _check(_c.coraza_set_error_callback(cfg, on_error) == 0,
           "coraza_set_error_callback failed")
    _check(_c.coraza_set_debug_log_callback(cfg, on_debug_log) == 0,
           "coraza_set_debug_log_callback failed")

    waf = _c.coraza_new_waf(cfg)
    _check(_c.coraza_free_waf_config(cfg) == 0, "coraza_free_waf_config failed")

    tx = _c.coraza_new_transaction(waf)
    _c.coraza_process_connection(tx, "127.0.0.1", 12345, "localhost", 80)
    _c.coraza_process_uri(tx, "/test", "GET", "HTTP/1.1")
    _c.coraza_process_request_headers(tx)
    _c.coraza_process_logging(tx)
    _check(_c.coraza_free_transaction(tx) == 0, "coraza_free_transaction failed")
    _check(_c.coraza_free_waf(waf) == 0, "coraza_free_waf failed")

    _check(len(matched_logs) > 0,
           "expected at least one matched rule via error callback")
    print(f"  Matched rules via callback: {matched_logs}")
    _check(len(debug_msgs) > 0,
           "expected at least one debug log message via debug callback")
    print(f"  Debug messages received: {len(debug_msgs)}")
    print("  test_callbacks: PASS")


if __name__ == "__main__":
    print("Running libcoraza Python SWIG tests...")
    test_lifecycle()
    test_request_body_from_file()
    test_rules_merge()
    test_callbacks()
    print("All tests passed.")
