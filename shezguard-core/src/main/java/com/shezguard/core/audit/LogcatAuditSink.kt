package com.shezguard.core.audit

import android.os.SystemClock
import android.util.Log
import com.shezguard.core.Outcome

/**
 * An [AuditSink] that writes one redacted line per decision to logcat, for **debug builds**.
 *
 * Register it only in debug builds, e.g.
 * ```kotlin
 * intentPolicy {
 *     if (BuildConfig.DEBUG) auditSink(LogcatAuditSink())
 *     ...
 * }
 * ```
 * Logcat is readable by anyone with `adb` access and ends up in bug reports. The lines hold only
 * the redacted [AuditEvent] content (no URI, values, extras, package names or digests), but a
 * release build should still not advertise its validation decisions.
 *
 * Tag `ShezGuard`; `Log.WARN` for Block, `Log.INFO` otherwise. Line format:
 * ```
 * outcome=BLOCK ep=product score=0/70 caller=- violations=[URI_PATH_TRAVERSAL@uri.path, PARAM_UNKNOWN@param:<undeclared>x7]
 * ```
 * Identical redacted violations are grouped as `xN`. `score=<total>/<threshold>`, with `-` for no
 * threshold; `caller=-` when the caller was not looked at.
 *
 * **Flood cap.** An attacker can trigger many blocked intents. At most [maxLinesPerMinute] lines
 * are written per 60-second window; later events in the window are dropped and counted, and the
 * first event after the window ends writes one `suppressed=N` line first.
 *
 * Thread-safe: concurrent calls are serialised.
 *
 * @param minOutcome the lowest outcome that is logged (`ALLOW` < `SANITIZE` < `BLOCK`). Default
 * `BLOCK`.
 * @param maxLinesPerMinute the cap per 60-second window. Default 30. Must be positive.
 */
public class LogcatAuditSink internal constructor(
    private val minOutcome: Outcome,
    private val maxLinesPerMinute: Int,
    private val clock: () -> Long,
) : AuditSink {

    /** See the class documentation. */
    @JvmOverloads
    public constructor(minOutcome: Outcome = Outcome.BLOCK, maxLinesPerMinute: Int = DEFAULT_MAX_LINES_PER_MINUTE) :
        this(minOutcome, maxLinesPerMinute, { SystemClock.elapsedRealtime() })

    init {
        require(maxLinesPerMinute > 0) { "maxLinesPerMinute must be positive" }
    }

    private var windowStart: Long? = null
    private var lines = 0
    private var suppressed = 0

    @Synchronized
    override fun onDecision(event: AuditEvent) {
        if (event.outcome.ordinal < minOutcome.ordinal) return
        val now = clock()
        val start = windowStart
        if (start == null || now - start >= WINDOW_MS) {
            if (suppressed > 0) Log.w(TAG, "suppressed=$suppressed (more than $maxLinesPerMinute lines per minute)")
            windowStart = now
            lines = 0
            suppressed = 0
        }
        if (lines >= maxLinesPerMinute) {
            suppressed++
            return
        }
        lines++
        Log.println(if (event.outcome == Outcome.BLOCK) Log.WARN else Log.INFO, TAG, format(event))
    }

    /** Defaults. */
    public companion object {
        /** The logcat tag. */
        public const val TAG: String = "ShezGuard"

        /** Default cap per 60-second window. */
        public const val DEFAULT_MAX_LINES_PER_MINUTE: Int = 30

        private const val WINDOW_MS = 60_000L

        internal fun format(e: AuditEvent): String {
            val grouped = LinkedHashMap<String, Int>()
            e.violations.forEach { grouped.merge(it.toString(), 1, Int::plus) }
            val violations = grouped.entries.joinToString(", ", "[", "]") { (k, n) -> if (n > 1) "${k}x$n" else k }
            return "outcome=${e.outcome} ep=${e.entryPoint} score=${e.scoreTotal}/${e.threshold ?: "-"} " +
                "caller=${e.callerIdentitySource ?: "-"} violations=$violations"
        }
    }
}
