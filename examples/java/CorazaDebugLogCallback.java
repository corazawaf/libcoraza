/**
 * Callback interface for libcoraza internal debug log events.
 *
 * <p>Implement this interface and register an instance with
 * {@code coraza.coraza_set_debug_log_callback(cfg, callback)} before calling
 * {@code coraza.coraza_new_waf(cfg)}.
 *
 * <p>Example:
 * <pre>
 *   coraza.coraza_set_debug_log_callback(cfg, (level, message, fields) -> {
 *       System.out.println("[" + level + "] " + message);
 *   });
 * </pre>
 */
public interface CorazaDebugLogCallback {
    /**
     * Called for each internal debug log message emitted by the WAF engine.
     *
     * @param level   log level as a {@code coraza_debug_log_level_t} ordinal
     *                (0=UNKNOWN, 1=TRACE, 2=DEBUG, 3=INFO, 4=WARN, 5=ERROR)
     * @param message human-readable log message
     * @param fields  structured key=value fields (may be an empty string)
     */
    void onDebugLog(int level, String message, String fields);
}
