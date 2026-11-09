package com.shezguard.core

/**
 * One soft signal's contribution to a [RiskScore].
 *
 * @property violation the [Tier.SOFT] violation that contributed.
 * @property weight the weight it added. Never negative.
 */
public data class ScoreContribution(
    public val violation: Violation,
    public val weight: Int,
) {
    init {
        require(weight >= 0) { "weight must not be negative" }
        require(violation.tier == Tier.SOFT) {
            "only SOFT violations contribute to the score (SPEC 5.1); got ${violation.code.id}"
        }
    }
}

/**
 * The explainable risk score for one evaluation (SPEC section 5.2).
 *
 * Only [Tier.SOFT] violations contribute; hard and removable violations decide the
 * outcome directly. The total is the sum of contribution weights capped at 100, so
 * the result is deterministic and every point can be traced to a listed contribution.
 *
 * @property total the capped score, in `0..100`.
 * @property contributions every soft signal that added weight, in evaluation order.
 */
public class RiskScore private constructor(
    public val total: Int,
    public val contributions: List<ScoreContribution>,
) {
    override fun equals(other: Any?): Boolean =
        other is RiskScore && other.total == total && other.contributions == contributions

    override fun hashCode(): Int = 31 * total + contributions.hashCode()

    override fun toString(): String = "RiskScore(total=$total, contributions=$contributions)"

    /** Factory functions. */
    public companion object {
        /** The maximum score. */
        public const val MAX: Int = 100

        /** A score with no contributions. */
        public val ZERO: RiskScore = RiskScore(0, emptyList())

        /** Builds a score from [contributions], summing their weights and capping at [MAX]. */
        public fun of(contributions: List<ScoreContribution>): RiskScore {
            val sum = contributions.sumOf { it.weight.toLong() }
            return RiskScore(sum.coerceAtMost(MAX.toLong()).toInt(), contributions.toList())
        }
    }
}
