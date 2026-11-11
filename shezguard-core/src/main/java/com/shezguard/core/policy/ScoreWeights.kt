package com.shezguard.core.policy

import com.shezguard.core.Severity
import com.shezguard.core.Tier
import com.shezguard.core.ViolationCode

/**
 * Per-entry-point score weights for [Tier.SOFT] codes (SPEC 5.2).
 *
 * The weight of a code is its override here, or else the default weight of the code's
 * default severity ([Severity.defaultWeight]). With the defaults in v1:
 *
 * | Code | Default weight |
 * |---|---|
 * | `URI_NON_CANONICAL` | 5 |
 * | `PARAM_UNKNOWN_IGNORED` | 5 |
 * | `CALLER_UNIDENTIFIED` | 5 |
 * | `DOMAIN_VERIFICATION_UNAVAILABLE` | 5 |
 * | `CALLER_NOT_ALLOWED` | 50 |
 * | `DOMAIN_NOT_VERIFIED` | 50 |
 *
 * These are design choices, not empirically derived values. Each code is added at most once
 * per evaluation, however many violations it has.
 *
 * Only SOFT codes may be overridden: HARD violations always block and REMOVABLE ones always
 * sanitize, whatever the weight, so a weight for them would be misleading.
 *
 * @param overrides weights in `0..100` for SOFT codes. 0 keeps the signal listed in the
 * decision's violations but makes it count for nothing; 100 makes it block on its own at any
 * threshold.
 */
public class ScoreWeights(overrides: Map<ViolationCode, Int> = emptyMap()) {

    /** The overridden weights, by code. Codes not listed use their default. */
    public val overrides: Map<ViolationCode, Int> = overrides.toMap()

    init {
        this.overrides.forEach { (code, w) ->
            require(code.tier == Tier.SOFT) { "${code.id} is ${code.tier}, not SOFT; only SOFT codes are scored" }
            require(w in MIN_WEIGHT..MAX_WEIGHT) { "weight for ${code.id} must be in $MIN_WEIGHT..$MAX_WEIGHT" }
        }
    }

    /**
     * The weight of the SOFT [code]: its override, or its default severity's weight.
     *
     * @throws IllegalArgumentException if [code] is not SOFT.
     */
    public fun weightOf(code: ViolationCode): Int {
        require(code.tier == Tier.SOFT) { "${code.id} is ${code.tier}, not SOFT; only SOFT codes are scored" }
        return overrides[code] ?: code.defaultSeverity.defaultWeight
    }

    override fun equals(other: Any?): Boolean = other is ScoreWeights && other.overrides == overrides

    override fun hashCode(): Int = overrides.hashCode()

    override fun toString(): String = "ScoreWeights(overrides=${overrides.mapKeys { it.key.id }})"

    /** Range and defaults. */
    public companion object {
        /** The lowest allowed weight. */
        public const val MIN_WEIGHT: Int = 0

        /** The highest allowed weight. */
        public const val MAX_WEIGHT: Int = 100

        /** No overrides: every SOFT code uses its default weight. */
        public val DEFAULT: ScoreWeights = ScoreWeights()
    }
}
