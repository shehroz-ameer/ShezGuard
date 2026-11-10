package com.shezguard.core.eval

import com.shezguard.core.Field
import com.shezguard.core.Outcome
import com.shezguard.core.RiskScore
import com.shezguard.core.ScoreContribution
import com.shezguard.core.Violation
import com.shezguard.core.ViolationCode
import com.shezguard.core.policy.Threshold
import org.junit.Assert.assertEquals
import org.junit.Test

/** SPEC 5.1 outcome rule, applied in order. Pure JVM. */
class OutcomeRuleTest {

    private fun v(code: ViolationCode) = Violation(code, "ep", Field.EntryPoint)
    private val hard = v(ViolationCode.URI_PATH_TRAVERSAL)
    private val removable = v(ViolationCode.PARAM_UNKNOWN_DROPPED)
    private val soft = v(ViolationCode.URI_NON_CANONICAL)
    private val t = Threshold(block = 70)

    private fun score(total: Int) = RiskScore.of(listOf(ScoreContribution(soft, total)))

    @Test
    fun noViolationsAllow() = assertEquals(Outcome.ALLOW, OutcomeRule.decide(emptyList(), RiskScore.ZERO, t))

    @Test
    fun softOnlyAllow() = assertEquals(Outcome.ALLOW, OutcomeRule.decide(listOf(soft), RiskScore.ZERO, t))

    @Test
    fun removableGivesSanitize() =
        assertEquals(Outcome.SANITIZE, OutcomeRule.decide(listOf(soft, removable), RiskScore.ZERO, t))

    @Test
    fun anyHardBlocksWhateverElseIsPresent() =
        assertEquals(Outcome.BLOCK, OutcomeRule.decide(listOf(soft, removable, hard), RiskScore.ZERO, t))

    /** Step 7 plugs a real scorer in; the rule already handles the threshold. */
    @Test
    fun scoreAtThresholdBlocksEvenWithRemovable() {
        assertEquals(Outcome.BLOCK, OutcomeRule.decide(listOf(soft, removable), score(70), t))
        assertEquals(Outcome.SANITIZE, OutcomeRule.decide(listOf(soft, removable), score(69), t))
        assertEquals(Outcome.ALLOW, OutcomeRule.decide(listOf(soft), score(69), t))
    }

    @Test
    fun step5bScorerAlwaysReturnsZero() {
        assertEquals(RiskScore.ZERO, Scorer.NONE.score(listOf(soft, soft, soft), EvalFixtures.policy["product"]!!))
    }
}
