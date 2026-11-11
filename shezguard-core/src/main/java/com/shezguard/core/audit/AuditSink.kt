package com.shezguard.core.audit

import com.shezguard.core.IdentitySource
import com.shezguard.core.Outcome
import com.shezguard.core.RiskScore
import com.shezguard.core.Severity
import com.shezguard.core.Tier
import com.shezguard.core.Violation
import com.shezguard.core.ViolationCode
import com.shezguard.core.policy.ENTRY_POINT_NAME
import java.util.Collections

/**
 * Receives one [AuditEvent] per `ShezGuard.evaluate(...)` call (SPEC section 7.1).
 *
 * Register a sink once, on the policy: `intentPolicy { auditSink(mySink) ... }`. The default is
 * [NONE], which does nothing.
 *
 * **Contract for implementations.**
 * - **Called synchronously** on the thread that called `evaluate`, usually the main thread,
 *   exactly once, **after** the decision is complete. Keep it fast and non-blocking; hand any I/O
 *   (files, network) to your own executor. A slow sink delays the app but cannot change the
 *   decision.
 * - **Called concurrently** if the app evaluates intents on several threads: the same sink
 *   instance can run on several threads at once and **must be thread-safe**.
 * - **Exceptions are swallowed, deliberately.** A `RuntimeException` thrown by the sink is caught
 *   and discarded without logging, so a faulty sink can neither change the decision nor crash
 *   the app, and its message (which might contain anything) is never written anywhere by
 *   ShezGuard. `Error`s are not caught.
 * - The sink only sees the immutable [AuditEvent], never the `Decision` or the `Intent`.
 */
public fun interface AuditSink {
    /** Called once per evaluation with a redacted, immutable [event]. */
    public fun onDecision(event: AuditEvent)

    /** Built-in sinks. */
    public companion object {
        /** Does nothing. The default for every policy. */
        public val NONE: AuditSink = AuditSink { }
    }
}

/**
 * A redacted, immutable record of one decision (SPEC section 7.1).
 *
 * It carries only identifiers chosen by the app or by ShezGuard: the entry point name, codes,
 * redacted field labels, numbers and enums. It **never** carries the intent, the data URI or any
 * of its components or parameter values, the host, extras keys or values, nested intents, caller
 * package names, certificate digests or exception messages. Field labels are the redacted
 * `Field.toString()` forms, so an undeclared parameter or extra appears as `param:<undeclared>` /
 * `extra:<undeclared>`.
 *
 * @property entryPoint the entry point name passed to `evaluate`, or `<invalid>` if it is not a
 * valid entry point name (1 to 64 characters from `A-Z a-z 0-9 _ . -`).
 * @property outcome the decision's outcome.
 * @property violations every violation, in evaluation order, redacted.
 * @property scoreTotal the soft-signal score, `0..100`.
 * @property threshold the block threshold applied, or `null` when no entry point policy applied
 * (`ENTRY_POINT_UNKNOWN`, `EVALUATION_FAILED`).
 * @property contributions the score contributions.
 * @property callerIdentitySource which caller identity source was used, if any.
 */
public class AuditEvent private constructor(
    public val entryPoint: String,
    public val outcome: Outcome,
    public val violations: List<AuditViolation>,
    public val scoreTotal: Int,
    public val threshold: Int?,
    public val contributions: List<AuditContribution>,
    public val callerIdentitySource: IdentitySource?,
) {
    override fun equals(other: Any?): Boolean = other is AuditEvent &&
        other.entryPoint == entryPoint && other.outcome == outcome && other.violations == violations &&
        other.scoreTotal == scoreTotal && other.threshold == threshold && other.contributions == contributions &&
        other.callerIdentitySource == callerIdentitySource

    override fun hashCode(): Int =
        listOf(entryPoint, outcome, violations, scoreTotal, threshold, contributions, callerIdentitySource).hashCode()

    override fun toString(): String =
        "AuditEvent(entryPoint=$entryPoint, outcome=$outcome, score=$scoreTotal, threshold=$threshold, " +
            "callerIdentitySource=$callerIdentitySource, violations=$violations, contributions=$contributions)"

    internal companion object {
        const val INVALID_ENTRY_POINT: String = "<invalid>"

        /** Builds the event from a decision's parts; only redacted forms are copied. */
        fun from(
            entryPoint: String,
            outcome: Outcome,
            violations: List<Violation>,
            score: RiskScore,
            callerIdentitySource: IdentitySource?,
        ): AuditEvent = AuditEvent(
            entryPoint = if (ENTRY_POINT_NAME.matches(entryPoint)) entryPoint else INVALID_ENTRY_POINT,
            outcome = outcome,
            violations = frozen(violations.map { AuditViolation(it.code, it.field.toString(), it.tier, it.severity) }),
            scoreTotal = score.total,
            threshold = score.threshold,
            contributions = frozen(score.contributions.map { AuditContribution(it.violation.code, it.weight, it.occurrences) }),
            callerIdentitySource = callerIdentitySource,
        )

        private fun <T> frozen(list: List<T>): List<T> = Collections.unmodifiableList(ArrayList(list))
    }
}

/**
 * One violation in an [AuditEvent].
 *
 * @property code the stable code.
 * @property field the redacted field label, e.g. `uri.path`, `param:id`, `param:<undeclared>`.
 * @property tier the code's tier.
 * @property severity the violation's severity.
 */
public class AuditViolation internal constructor(
    public val code: ViolationCode,
    public val field: String,
    public val tier: Tier,
    public val severity: Severity,
) {
    override fun equals(other: Any?): Boolean =
        other is AuditViolation && other.code == code && other.field == field && other.tier == tier && other.severity == severity

    override fun hashCode(): Int = listOf(code, field, tier, severity).hashCode()

    override fun toString(): String = "${code.id}@$field"
}

/**
 * One score contribution in an [AuditEvent].
 *
 * @property code the SOFT code that contributed.
 * @property weight the weight it added.
 * @property occurrences how many violations with this code were found.
 */
public class AuditContribution internal constructor(
    public val code: ViolationCode,
    public val weight: Int,
    public val occurrences: Int,
) {
    override fun equals(other: Any?): Boolean =
        other is AuditContribution && other.code == code && other.weight == weight && other.occurrences == occurrences

    override fun hashCode(): Int = listOf(code, weight, occurrences).hashCode()

    override fun toString(): String = "${code.id}=$weight x$occurrences"
}
