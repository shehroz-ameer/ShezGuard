package com.shezguard.core.eval

import com.shezguard.core.Outcome
import com.shezguard.core.RiskScore
import com.shezguard.core.ScoreContribution
import com.shezguard.core.Tier
import com.shezguard.core.Violation
import com.shezguard.core.ViolationCode
import com.shezguard.core.policy.EntryPointPolicy
import com.shezguard.core.policy.Threshold

/**
 * The SPEC 5.1 outcome rule, applied in this order:
 * 1. any [Tier.HARD] violation: Block;
 * 2. soft-signal score `>=` the block threshold: Block;
 * 3. any [Tier.REMOVABLE] violation: Sanitize;
 * 4. otherwise Allow, with soft signals listed.
 *
 * Unchanged since step 5b; step 7 only replaced the placeholder [Scorer] with [Scorer.WEIGHTED].
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
 * The scorer only ever produces a score; [OutcomeRule] decides. Because the rule checks HARD
 * violations first and the score can only add a Block, no scorer and no weights can turn a
 * HARD violation into Sanitize or Allow, or a REMOVABLE one into Allow.
 */
internal fun interface Scorer {
    /** @param soft the [Tier.SOFT] violations, in evaluation order. */
    fun score(soft: List<Violation>, policy: EntryPointPolicy): RiskScore

    companion object {
        /**
         * The weighted scorer (step 7): one [ScoreContribution] per distinct SOFT code, in order
         * of first occurrence, with weight `policy.scoreWeights.weightOf(code)` added once and the
         * number of occurrences recorded. Codes with weight 0 are left out. The total is the
         * capped sum (`RiskScore.of`), and the applied block threshold is recorded.
         */
        val WEIGHTED: Scorer = Scorer { soft, policy ->
            val byCode = LinkedHashMap<ViolationCode, MutableList<Violation>>()
            for (v in soft) {
                if (v.tier == Tier.SOFT) byCode.getOrPut(v.code) { ArrayList() }.add(v)
            }
            val contributions = byCode.mapNotNull { (code, vs) ->
                val w = policy.scoreWeights.weightOf(code)
                if (w == 0) null else ScoreContribution(vs.first(), w, vs.size)
            }
            RiskScore.of(contributions, policy.threshold.block)
        }
    }
}
