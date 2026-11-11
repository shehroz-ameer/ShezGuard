package com.shezguard.core

/**
 * One soft signal's contribution to a [RiskScore]: one distinct [ViolationCode], counted once
 * however often it occurred (SPEC 5.2).
 *
 * Holds no raw intent data: [violation] carries a code, a [Field] whose `toString` redacts
 * undeclared names, and a severity.
 *
 * @property violation the first [Tier.SOFT] violation with this code, in evaluation order.
 * @property weight the weight it added. Never negative.
 * @property occurrences how many violations with this code the evaluation found. At least 1.
 * Shown for explanation only; the weight is added once.
 */
public data class ScoreContribution(
    public val violation: Violation,
    public val weight: Int,
    public val occurrences: Int = 1,
) {
    init {
        require(weight >= 0) { "weight must not be negative" }
        require(occurrences >= 1) { "occurrences must be at least 1" }
        require(violation.tier == Tier.SOFT) {
            "only SOFT violations contribute to the score (SPEC 5.1); got ${violation.code.id}"
        }
    }
}

/**
 * The explainable risk score for one evaluation (SPEC section 5.2).
 *
 * A transparent, additive tally of a few advisory signals, compared with a fixed threshold.
 * It is not learned, adaptive or statistical, and it does not detect attacks: every
 * attack-specific check is a HARD rule that blocks regardless of the score.
 *
 * Only [Tier.SOFT] violations contribute, each distinct code once. Codes with weight 0 are
 * not listed here, but remain in the decision's violations. [total] is the sum of the
 * contribution weights capped at [MAX], so every point can be traced to a listed contribution.
 * The intent is blocked by the score when `total >= threshold`.
 *
 * @property total the capped score, in `0..100`.
 * @property contributions every soft code that added weight, in order of first occurrence.
 * @property threshold the block threshold that was applied, in `1..100`, or `null` when no
 * entry point policy applied (an unknown entry point, or an evaluation that failed).
 */
public class RiskScore private constructor(
    public val total: Int,
    public val contributions: List<ScoreContribution>,
    public val threshold: Int?,
) {
    override fun equals(other: Any?): Boolean =
        other is RiskScore && other.total == total && other.contributions == contributions && other.threshold == threshold

    override fun hashCode(): Int = (31 * total + contributions.hashCode()) * 31 + (threshold ?: 0)

    override fun toString(): String = "RiskScore(total=$total, threshold=$threshold, contributions=$contributions)"

    /** Factory functions. */
    public companion object {
        /** The maximum score. */
        public const val MAX: Int = 100

        /** A score with no contributions and no threshold. */
        public val ZERO: RiskScore = RiskScore(0, emptyList(), null)

        /**
         * Builds a score from [contributions], summing their weights and capping at [MAX].
         *
         * @param threshold the block threshold applied, in `1..100`, or `null` if none applied.
         */
        public fun of(contributions: List<ScoreContribution>, threshold: Int? = null): RiskScore {
            require(threshold == null || threshold in 1..MAX) { "threshold must be in 1..$MAX" }
            val sum = contributions.sumOf { it.weight.toLong() }
            return RiskScore(sum.coerceAtMost(MAX.toLong()).toInt(), contributions.toList(), threshold)
        }
    }
}
