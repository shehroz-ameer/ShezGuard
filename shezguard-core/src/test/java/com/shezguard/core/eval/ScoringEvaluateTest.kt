package com.shezguard.core.eval

import com.shezguard.core.Decision
import com.shezguard.core.Outcome
import com.shezguard.core.ShezGuard
import com.shezguard.core.Tier
import com.shezguard.core.ViolationCode.ENTRY_POINT_UNKNOWN
import com.shezguard.core.ViolationCode.PARAM_UNKNOWN_IGNORED
import com.shezguard.core.ViolationCode.URI_NON_CANONICAL
import com.shezguard.core.ViolationCode.URI_PATH_TRAVERSAL
import com.shezguard.core.eval.EvalFixtures.codes
import com.shezguard.core.eval.EvalFixtures.renderedOutput
import com.shezguard.core.eval.EvalFixtures.summary
import com.shezguard.core.eval.EvalFixtures.viewIntent
import com.shezguard.core.policy.CharClass
import com.shezguard.core.policy.EntryPointBuilder
import com.shezguard.core.policy.Unknown
import com.shezguard.core.policy.intentPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/** Step 7 end to end: the score in real decisions. Robolectric, SDK 34. */
@RunWith(RobolectricTestRunner::class)
class ScoringEvaluateTest {

    private fun EntryPointBuilder.browse() {
        allowSchemes("https")
        allowHosts("example.com")
        anyPath()
        param("q") { string(CharClass.TEXT) }
        unknownParams(Unknown.Ignore)
    }

    private val policy = intentPolicy {
        entryPoint("at70") { browse(); scoreWeight(URI_NON_CANONICAL, 40); scoreWeight(PARAM_UNKNOWN_IGNORED, 30) }
        entryPoint("at69") { browse(); scoreWeight(URI_NON_CANONICAL, 39); scoreWeight(PARAM_UNKNOWN_IGNORED, 30) }
        entryPoint("defaults") { browse() }
        entryPoint("allMax") { browse(); scoreWeight(URI_NON_CANONICAL, 100); scoreWeight(PARAM_UNKNOWN_IGNORED, 100); threshold(100) }
        entryPoint("allZero") { browse(); scoreWeight(URI_NON_CANONICAL, 0); scoreWeight(PARAM_UNKNOWN_IGNORED, 0) }
    }

    /** One non-canonical path (`//`) and two undeclared parameters. */
    private val link = "https://example.com/a//b?q=shoes&utm_source=x&gclid=y"

    @Test
    fun blocksOnScoreAloneAtThresholdAndExplainsIt() {
        val d = ShezGuard.evaluate(viewIntent(link), policy, "at70")
        assertTrue(d.toString(), d is Decision.Block)
        assertTrue("only soft signals", d.violations.all { it.tier == Tier.SOFT })
        assertEquals(70, d.score.total)
        assertEquals(70, d.score.threshold)
        assertEquals(listOf(URI_NON_CANONICAL, PARAM_UNKNOWN_IGNORED), d.score.contributions.map { it.violation.code })
        assertEquals(listOf(40, 30), d.score.contributions.map { it.weight })
        assertEquals(listOf(1, 2), d.score.contributions.map { it.occurrences })
        assertTrue(d.toString(), d.toString().contains("score=70/70"))
    }

    @Test
    fun allowsOneBelowThreshold() {
        val d = ShezGuard.evaluate(viewIntent(link), policy, "at69")
        assertTrue(d.toString(), d is Decision.Allow)
        assertEquals(69, d.score.total)
        assertEquals("shoes", (d as Decision.Allow).data!!.param("q"))
    }

    @Test
    fun defaultWeightsCannotChangeAnOutcomeBeforeStep8() {
        val many = "https://example.com/a//b//c?q=x&" + (1..20).joinToString("&") { "t$it=v" }
        val d = ShezGuard.evaluate(viewIntent(many), policy, "defaults")
        assertEquals(Outcome.ALLOW, d.outcome)
        assertEquals(10, d.score.total)
        assertEquals(20, d.score.contributions.single { it.violation.code == PARAM_UNKNOWN_IGNORED }.occurrences)
    }

    @Test
    fun zeroWeightsKeepSignalsListedButScoreNothing() {
        val d = ShezGuard.evaluate(viewIntent(link), policy, "allZero")
        assertTrue(d is Decision.Allow)
        assertEquals(setOf(URI_NON_CANONICAL, PARAM_UNKNOWN_IGNORED), codes(d))
        assertEquals(0, d.score.total)
        assertTrue(d.score.contributions.isEmpty())
    }

    @Test
    fun hardViolationBlocksWhateverTheWeights() {
        for (ep in listOf("allZero", "defaults", "at69")) {
            val d = ShezGuard.evaluate(viewIntent("https://example.com/a/../b?q=x&u=1"), policy, ep)
            assertTrue(d is Decision.Block)
            assertTrue(URI_PATH_TRAVERSAL in codes(d))
        }
        // Score 100 at threshold 100 with a hard violation: still Block, for the hard reason too.
        val d = ShezGuard.evaluate(viewIntent("https://example.com/a//b/%2e%2e/c?u=1"), policy, "allMax")
        assertTrue(d is Decision.Block)
        assertTrue(codes(d).any { it.tier == Tier.HARD })
    }

    @Test
    fun noEntryPointPolicyMeansNoThreshold() {
        val d = ShezGuard.evaluate(viewIntent(link), policy, "missing")
        assertEquals(setOf(ENTRY_POINT_UNKNOWN), codes(d))
        assertNull(d.score.threshold)
        assertEquals(0, d.score.total)
    }

    @Test
    fun scoreExplanationNeverContainsRawValues() {
        val m = "zqx"
        val d = ShezGuard.evaluate(viewIntent("https://example.com/${m}p//${m}q?q=${m}v&${m}n=${m}v&${m}m=1"), policy, "at70")
        assertTrue(d is Decision.Block)
        val out = renderedOutput(d) + d.score.contributions.joinToString { it.toString() + it.violation.field }
        assertFalse(out, out.contains(m))
    }

    @Test
    fun sameInputAlwaysGivesTheSameScore() {
        for (ep in listOf("at70", "at69", "defaults", "allZero", "allMax")) {
            val first = summary(ShezGuard.evaluate(viewIntent(link), policy, ep))
            repeat(5) { assertEquals(first, summary(ShezGuard.evaluate(viewIntent(link), policy, ep))) }
        }
    }
}
