package com.shezguard.core.eval

import com.shezguard.core.Outcome
import com.shezguard.core.RiskScore
import com.shezguard.core.Tier
import com.shezguard.core.Violation
import com.shezguard.core.policy.EntryPointPolicy
import com.shezguard.core.policy.Threshold

/**
 * The SPEC 5.1 outcome rule, applied in this order:
 * 1. any [Tier.HARD] violation: Block;
 * 2. soft-signal score `>=` the block threshold: Block;
 * 3. any [Tier.REMOVABLE] violation: Sanitize;
 * 4. otherwise Allow, with soft signals listed.
 *
 * The rule is complete already; step 7 only supplies a real [Scorer].
 */
internal object OutcomeRule {
    fun decide(violations: List<Violation>, score: RiskScore, threshold: Threshold): Outcome = when {
        violations.any { it.tier == Tier.HARD } -> Outcome.BLOCK
        score.total >= threshold.block -> Outcome.BLOCK
        violations.any { it.tier == Tier.REMOVABLE } -> Outcome.SANITIZE
        else -> Outcome.ALLOW
    }
}

/**
 * Turns the soft violations of one evaluation into a [RiskScore] (SPEC 5.2).
 *
 * Step 5b uses [NONE], which always returns [RiskScore.ZERO]; because the block threshold
 * is at least 1, the score cannot block yet. Step 7 replaces it with the weighted scorer
 * without changing [OutcomeRule].
 */
internal fun interface Scorer {
    /** @param soft the [Tier.SOFT] violations, in evaluation order. */
    fun score(soft: List<Violation>, policy: EntryPointPolicy): RiskScore

    companion object {
        val NONE: Scorer = Scorer { _, _ -> RiskScore.ZERO }
    }
}
