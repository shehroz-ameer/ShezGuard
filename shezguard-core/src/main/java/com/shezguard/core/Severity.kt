package com.shezguard.core

/**
 * How serious a [Violation] is.
 *
 * Severity is reported for every violation so a decision is explainable, but it only
 * feeds the risk score for [Tier.SOFT] violations (SPEC section 5.1). A [Tier.HARD]
 * violation blocks whatever its severity.
 *
 * **Default weights (SPEC 5.2, step 7).** The default score weight of a [Tier.SOFT] code is the
 * [defaultWeight] of its default severity; a policy can override it per code
 * (`policy.ScoreWeights`). The values are design choices, not empirically derived. They are
 * chosen so that, at the default block threshold of 70 and with each soft code counted once:
 * no single soft signal blocks; one HIGH signal plus every LOW signal that can occur with it
 * stays below 70 (50 + 3 x 5 = 65); and two HIGH signals block (100).
 *
 * @property defaultWeight the score a [Tier.SOFT] code of this severity adds by default,
 * once per evaluation. The total score is capped at 100.
 */
public enum class Severity(public val defaultWeight: Int) {
    /** Unusual but usually harmless, e.g. a non-canonical but equivalent URI. Default weight 5. */
    LOW(5),

    /** Suspicious on its own, harmless only in some contexts. Default weight 25 (no SOFT code uses it in v1). */
    MEDIUM(25),

    /** Strongly suggests an attack attempt or a dangerous misuse. Default weight 50. */
    HIGH(50),

    /** A known attack pattern or a failure that makes the intent unsafe to inspect. Default weight 100 (no SOFT code uses it in v1). */
    CRITICAL(100),
}

/**
 * How a [Violation] affects the decision (SPEC section 5.1).
 */
public enum class Tier {
    /**
     * Always blocks, regardless of weight or threshold. Structural and content
     * violations are hard, so weights can never bypass deny by default.
     */
    HARD,

    /**
     * Can be fixed by removing the offending part (SPEC section 4.1), which produces a
     * Sanitize decision unless something else blocks.
     */
    REMOVABLE,

    /** An advisory signal. It adds weight to the [RiskScore] and never blocks on its own. */
    SOFT,
}

/** The kind of decision ShezGuard reached, without the payload carried by [Decision]. */
public enum class Outcome {
    /** No HARD or REMOVABLE violation, and the soft score is below the block threshold. Soft signals may be listed. */
    ALLOW,

    /**
     * No HARD violation, the soft score is below the block threshold, and at least one
     * [Tier.REMOVABLE] violation was found. The intent is usable only with those parts removed.
     */
    SANITIZE,

    /** The intent must not be used. */
    BLOCK,
}
