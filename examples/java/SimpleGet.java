import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * SimpleGet.java — Java SWIG example for libcoraza.
 *
 * <p>Exercises all exported functions that can be tested without a native
 * callback ({@code coraza_add_debug_log_callback} /
 * {@code coraza_add_error_callback} require language-specific
 * function-pointer support and are excluded from the default SWIG wrapper).
 *
 * <p>Build and run from the repository root:
 * <pre>
 *   make
 *   make -C examples/java
 *   LD_LIBRARY_PATH=examples/java \
 *     java -cp examples/java/gen/ -Djava.library.path=examples/java SimpleGet
 * </pre>
 */
public class SimpleGet {

    private static final String DENY_RULE =
        "SecRule REMOTE_ADDR \"@ipMatch 127.0.0.1\" " +
        "\"id:1,phase:1,deny,log,msg:'block',status:403\"";

    private static final String PASS_RULE =
        "SecRule REMOTE_ADDR \"@ipMatch 10.0.0.1\" " +
        "\"id:2,phase:1,pass,log,msg:'allow'\"";

    private static void check(boolean cond, String msg) {
        if (!cond) {
            throw new AssertionError(msg);
        }
    }

    // -----------------------------------------------------------------------
    // testLifecycle
    // Covers: coraza_new_waf_config, coraza_rules_add, coraza_rules_add_file,
    //         coraza_new_waf, coraza_rules_count, coraza_free_waf_config,
    //         coraza_new_transaction_with_id, coraza_process_connection,
    //         coraza_add_request_header, coraza_add_get_args,
    //         coraza_process_uri, coraza_process_request_headers,
    //         coraza_append_request_body, coraza_process_request_body,
    //         coraza_process_response_headers, coraza_add_response_header,
    //         coraza_append_response_body, coraza_process_response_body,
    //         coraza_update_status_code, coraza_process_logging,
    //         coraza_intervention, coraza_free_intervention,
    //         coraza_free_transaction, coraza_new_transaction, coraza_free_waf
    // -----------------------------------------------------------------------
    static void testLifecycle() throws IOException {
        // coraza_new_waf_config
        long cfg = coraza.coraza_new_waf_config();
        check(cfg != 0, "coraza_new_waf_config returned 0");

        // coraza_rules_add
        int ret = coraza.coraza_rules_add(cfg, DENY_RULE);
        check(ret == 0, "coraza_rules_add failed: " + ret);

        // coraza_rules_add_file — write a second rule to a temp file
        File rulesFile = File.createTempFile("coraza-rules-", ".conf");
        try {
            try (FileWriter fw = new FileWriter(rulesFile)) {
                fw.write(PASS_RULE + "\n");
            }
            ret = coraza.coraza_rules_add_file(cfg, rulesFile.getAbsolutePath());
            check(ret == 0, "coraza_rules_add_file failed: " + ret);

            // coraza_new_waf — must be created while the rules file still exists
            long waf = coraza.coraza_new_waf(cfg);
            check(waf != 0, "coraza_new_waf returned 0");

            // coraza_rules_count
            int count = coraza.coraza_rules_count(waf);
            check(count >= 2, "expected >= 2 rules, got " + count);

            // coraza_free_waf_config
            ret = coraza.coraza_free_waf_config(cfg);
            check(ret == 0, "coraza_free_waf_config failed: " + ret);

            // coraza_new_transaction_with_id
            long tx = coraza.coraza_new_transaction_with_id(waf, "java-simple-get");
            check(tx != 0, "coraza_new_transaction_with_id returned 0");

            // coraza_process_connection
            ret = coraza.coraza_process_connection(tx, "127.0.0.1", 55555, "localhost", 80);
            check(ret == 0, "coraza_process_connection failed: " + ret);

            // coraza_add_request_header
            String hname = "Host", hvalue = "localhost";
            ret = coraza.coraza_add_request_header(
                    tx, hname, hname.length(), hvalue, hvalue.length());
            check(ret == 0, "coraza_add_request_header failed: " + ret);

            // coraza_add_get_args
            ret = coraza.coraza_add_get_args(tx, "foo", "bar");
            check(ret == 0, "coraza_add_get_args failed: " + ret);

            // coraza_process_uri
            ret = coraza.coraza_process_uri(tx, "/someurl?foo=bar", "GET", "HTTP/1.1");
            check(ret == 0, "coraza_process_uri failed: " + ret);

            // coraza_process_request_headers
            ret = coraza.coraza_process_request_headers(tx);
            check(ret == 0, "coraza_process_request_headers failed: " + ret);

            // coraza_append_request_body (byte[] typemap: single array arg)
            ret = coraza.coraza_append_request_body(tx, "hello=world".getBytes());
            check(ret == 0, "coraza_append_request_body failed: " + ret);

            // coraza_process_request_body
            ret = coraza.coraza_process_request_body(tx);
            check(ret == 0, "coraza_process_request_body failed: " + ret);

            // coraza_process_response_headers
            ret = coraza.coraza_process_response_headers(tx, 200, "HTTP/1.1");
            check(ret == 0, "coraza_process_response_headers failed: " + ret);

            // coraza_add_response_header
            String cname = "Content-Type", cvalue = "text/plain";
            ret = coraza.coraza_add_response_header(
                    tx, cname, cname.length(), cvalue, cvalue.length());
            check(ret == 0, "coraza_add_response_header failed: " + ret);

            // coraza_append_response_body (byte[] typemap: single array arg)
            ret = coraza.coraza_append_response_body(tx, "OK".getBytes());
            check(ret == 0, "coraza_append_response_body failed: " + ret);

            // coraza_process_response_body
            ret = coraza.coraza_process_response_body(tx);
            check(ret == 0, "coraza_process_response_body failed: " + ret);

            // coraza_update_status_code
            coraza.coraza_update_status_code(tx, 200);

            // coraza_process_logging
            ret = coraza.coraza_process_logging(tx);
            check(ret == 0, "coraza_process_logging failed: " + ret);

            // coraza_intervention — deny rule on 127.0.0.1 must have fired
            coraza_intervention_t it = coraza.coraza_intervention(tx);
            check(it != null, "expected an intervention but got null");
            check(it.getStatus() == 403, "expected status 403, got " + it.getStatus());
            System.out.println("  Intervention: action=" + it.getAction()
                    + " status=" + it.getStatus() + " data=" + it.getData());

            // coraza_free_intervention
            ret = coraza.coraza_free_intervention(it);
            check(ret == 0, "coraza_free_intervention failed: " + ret);

            // coraza_free_transaction
            ret = coraza.coraza_free_transaction(tx);
            check(ret == 0, "coraza_free_transaction failed: " + ret);

            // coraza_new_transaction (non-ID variant)
            long tx2 = coraza.coraza_new_transaction(waf);
            check(tx2 != 0, "coraza_new_transaction returned 0");
            coraza.coraza_free_transaction(tx2);

            // coraza_free_waf
            ret = coraza.coraza_free_waf(waf);
            check(ret == 0, "coraza_free_waf failed: " + ret);
        } finally {
            rulesFile.delete();
        }

        System.out.println("  testLifecycle: PASS");
    }

    // -----------------------------------------------------------------------
    // testRequestBodyFromFile
    // Covers: coraza_request_body_from_file
    // -----------------------------------------------------------------------
    static void testRequestBodyFromFile() throws IOException {
        long cfg = coraza.coraza_new_waf_config();
        coraza.coraza_rules_add(cfg, PASS_RULE);
        long waf = coraza.coraza_new_waf(cfg);
        coraza.coraza_free_waf_config(cfg);

        long tx = coraza.coraza_new_transaction(waf);
        coraza.coraza_process_connection(tx, "10.0.0.1", 12345, "localhost", 80);
        coraza.coraza_process_uri(tx, "/upload", "POST", "HTTP/1.1");
        coraza.coraza_process_request_headers(tx);

        File bodyFile = File.createTempFile("coraza-body-", ".txt");
        try {
            try (FileWriter fw = new FileWriter(bodyFile)) {
                fw.write("body content from file");
            }
            int ret = coraza.coraza_request_body_from_file(
                    tx, bodyFile.getAbsolutePath());
            check(ret == 0, "coraza_request_body_from_file failed: " + ret);
        } finally {
            bodyFile.delete();
        }

        check(coraza.coraza_process_request_body(tx) == 0, "coraza_process_request_body failed");
        check(coraza.coraza_process_response_headers(tx, 200, "HTTP/1.1") == 0, "coraza_process_response_headers failed");
        check(coraza.coraza_process_response_body(tx) == 0, "coraza_process_response_body failed");
        check(coraza.coraza_process_logging(tx) == 0, "coraza_process_logging failed");
        check(coraza.coraza_free_transaction(tx) == 0, "coraza_free_transaction failed");
        check(coraza.coraza_free_waf(waf) == 0, "coraza_free_waf failed");

        System.out.println("  testRequestBodyFromFile: PASS");
    }

    // -----------------------------------------------------------------------
    // testRulesMerge
    // Covers: coraza_rules_merge
    // NOTE: coraza_rules_merge is currently a stub (always returns 0, does not
    // actually merge rules). This test only verifies the call does not crash.
    // -----------------------------------------------------------------------
    static void testRulesMerge() {
        long cfg1 = coraza.coraza_new_waf_config();
        coraza.coraza_rules_add(cfg1, PASS_RULE);
        long waf1 = coraza.coraza_new_waf(cfg1);
        check(coraza.coraza_free_waf_config(cfg1) == 0, "coraza_free_waf_config failed");

        long cfg2 = coraza.coraza_new_waf_config();
        long waf2 = coraza.coraza_new_waf(cfg2);
        check(coraza.coraza_free_waf_config(cfg2) == 0, "coraza_free_waf_config failed");

        int ret = coraza.coraza_rules_merge(waf1, waf2);
        check(ret == 0, "coraza_rules_merge failed: " + ret);

        check(coraza.coraza_free_waf(waf1) == 0, "coraza_free_waf(waf1) failed");
        check(coraza.coraza_free_waf(waf2) == 0, "coraza_free_waf(waf2) failed");

        System.out.println("  testRulesMerge: PASS");
    }

    // -----------------------------------------------------------------------
    // testCallbacks
    // Covers: coraza_set_error_callback, coraza_set_debug_log_callback,
    //         coraza_matched_rule_get_error_log, coraza_matched_rule_get_severity
    // -----------------------------------------------------------------------
    static void testCallbacks() {
        List<String> matchedLogs = new ArrayList<>();
        List<String> debugMsgs  = new ArrayList<>();

        CorazaErrorCallback onError = ruleHandle -> {
            String log = coraza.coraza_matched_rule_get_error_log(ruleHandle);
            int sev    = coraza.coraza_matched_rule_get_severity(ruleHandle).swigValue();
            matchedLogs.add("sev=" + sev + " " + log);
        };

        CorazaDebugLogCallback onDebug = (level, message, fields) ->
            debugMsgs.add("[" + level + "] " + message);

        long cfg = coraza.coraza_new_waf_config();
        coraza.coraza_rules_add(cfg, DENY_RULE);
        check(coraza.coraza_set_error_callback(cfg, onError) == 0,
              "coraza_set_error_callback failed");
        check(coraza.coraza_set_debug_log_callback(cfg, onDebug) == 0,
              "coraza_set_debug_log_callback failed");

        long waf = coraza.coraza_new_waf(cfg);
        check(coraza.coraza_free_waf_config(cfg) == 0, "coraza_free_waf_config failed");

        long tx = coraza.coraza_new_transaction(waf);
        coraza.coraza_process_connection(tx, "127.0.0.1", 12345, "localhost", 80);
        coraza.coraza_process_uri(tx, "/test", "GET", "HTTP/1.1");
        coraza.coraza_process_request_headers(tx);
        coraza.coraza_process_logging(tx);
        check(coraza.coraza_free_transaction(tx) == 0, "coraza_free_transaction failed");
        check(coraza.coraza_free_waf(waf) == 0, "coraza_free_waf failed");

        check(!matchedLogs.isEmpty(),
              "expected at least one matched rule via error callback");
        System.out.println("  Matched rules via callback: " + matchedLogs);
        // Debug messages depend on Coraza's internal log level (default: ERROR).
        // We verify the callback was accepted without asserting message count.
        System.out.println("  Debug messages received: " + debugMsgs.size());
        System.out.println("  testCallbacks: PASS");
    }

    // -----------------------------------------------------------------------
    // testInterventionRedirect
    // Covers: coraza_intervention .data field (redirect URL).
    // Validates the char *data struct field that was previously missing from
    // coraza.i — ensures the fix is exercised end-to-end through the SWIG layer.
    // -----------------------------------------------------------------------
    static void testInterventionRedirect() {
        String redirectRule =
            "SecRule ARGS:trigger \"@streq yes\" " +
            "\"id:10,phase:1,status:302,redirect:http://example.com\"";

        long cfg = coraza.coraza_new_waf_config();
        coraza.coraza_rules_add(cfg, redirectRule);
        long waf = coraza.coraza_new_waf(cfg);
        check(coraza.coraza_free_waf_config(cfg) == 0, "coraza_free_waf_config failed");

        long tx = coraza.coraza_new_transaction(waf);
        coraza.coraza_process_connection(tx, "10.0.0.1", 12345, "localhost", 80);
        coraza.coraza_add_get_args(tx, "trigger", "yes");
        coraza.coraza_process_uri(tx, "/?trigger=yes", "GET", "HTTP/1.1");
        coraza.coraza_process_request_headers(tx);

        coraza_intervention_t it = coraza.coraza_intervention(tx);
        check(it != null, "expected a redirect intervention but got null");
        check(it.getStatus() == 302, "expected status 302, got " + it.getStatus());
        check("redirect".equals(it.getAction()),
              "expected action 'redirect', got " + it.getAction());
        check("http://example.com".equals(it.getData()),
              "expected data 'http://example.com', got " + it.getData());

        check(coraza.coraza_free_intervention(it) == 0, "coraza_free_intervention failed");
        check(coraza.coraza_free_transaction(tx) == 0, "coraza_free_transaction failed");
        check(coraza.coraza_free_waf(waf) == 0, "coraza_free_waf failed");

        System.out.println("  testInterventionRedirect: PASS");
    }

    // -----------------------------------------------------------------------
    // testWafCreationError
    // Covers: coraza_new_waf char**er typemap — bad config raises RuntimeException.
    // -----------------------------------------------------------------------
    static void testWafCreationError() {
        long cfg = coraza.coraza_new_waf_config();
        // Reference a non-existent rules file to force WAF creation to fail.
        coraza.coraza_rules_add_file(cfg, "/nonexistent/path/rules.conf");
        try {
            coraza.coraza_new_waf(cfg);
            throw new AssertionError("expected RuntimeException from coraza_new_waf but none was raised");
        } catch (RuntimeException e) {
            // expected
        }
        check(coraza.coraza_free_waf_config(cfg) == 0, "coraza_free_waf_config failed");

        System.out.println("  testWafCreationError: PASS");
    }

    public static void main(String[] args) throws IOException {
        System.out.println("Running libcoraza Java SWIG tests...");
        testLifecycle();
        testRequestBodyFromFile();
        testRulesMerge();
        testCallbacks();
        testInterventionRedirect();
        testWafCreationError();
        System.out.println("All tests passed.");
    }
}
