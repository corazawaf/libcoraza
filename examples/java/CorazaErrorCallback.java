/**
 * Callback interface for libcoraza rule-match events.
 *
 * <p>Implement this interface and register an instance with
 * {@code coraza.coraza_set_error_callback(cfg, callback)} before calling
 * {@code coraza.coraza_new_waf(cfg)}.  The callback fires once for every WAF
 * rule that matches during transaction processing, including non-disruptive
 * rules (pass, log) — not only blocking ones.
 *
 * <p>Example:
 * <pre>
 *   coraza.coraza_set_error_callback(cfg, ruleHandle -> {
 *       System.out.println(coraza.coraza_matched_rule_get_error_log(ruleHandle));
 *   });
 * </pre>
 */
public interface CorazaErrorCallback {
    /**
     * Called when a WAF rule matches.
     *
     * @param matchedRuleHandle opaque handle valid only for the duration of
     *        this call; pass to {@code coraza.coraza_matched_rule_get_severity()}
     *        or {@code coraza.coraza_matched_rule_get_error_log()} to inspect.
     */
    void onError(long matchedRuleHandle);
}
