package com.shezguard.core.policy

import com.shezguard.core.ViolationCode
import com.shezguard.core.ViolationCode.CALLER_NOT_ALLOWED
import com.shezguard.core.ViolationCode.EXTRA_NOT_ALLOWED
import com.shezguard.core.ViolationCode.PARAM_UNKNOWN_IGNORED
import com.shezguard.core.ViolationCode.URI_NON_CANONICAL
import com.shezguard.core.ViolationCode.URI_PATH_TRAVERSAL
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Step 7 proposal (b): score weight overrides in the model and the DSL. Pure JVM. */
class ScoreWeightsTest {

    // ---- Model -----------------------------------------------------------------------

    @Test
    fun defaultHasNoOverridesAndIsTheEntryPointDefault() {
        assertTrue(ScoreWeights.DEFAULT.overrides.isEmpty())
        assertSame(ScoreWeights.DEFAULT, EntryPointPolicy("p").scoreWeights)
    }

    @Test
    fun modelRejectsNonSoftCodes() {
        assertThrows(IllegalArgumentException::class.java) { ScoreWeights(mapOf(URI_PATH_TRAVERSAL to 10)) }
        assertThrows(IllegalArgumentException::class.java) { ScoreWeights(mapOf(EXTRA_NOT_ALLOWED to 10)) }
        assertThrows(IllegalArgumentException::class.java) { ScoreWeights.DEFAULT.weightOf(URI_PATH_TRAVERSAL) }
    }

    @Test
    fun modelRejectsWeightsOutsideZeroToHundred() {
        assertThrows(IllegalArgumentException::class.java) { ScoreWeights(mapOf(URI_NON_CANONICAL to -1)) }
        assertThrows(IllegalArgumentException::class.java) { ScoreWeights(mapOf(URI_NON_CANONICAL to 101)) }
        assertEquals(0, ScoreWeights(mapOf(URI_NON_CANONICAL to 0)).weightOf(URI_NON_CANONICAL))
        assertEquals(100, ScoreWeights(mapOf(URI_NON_CANONICAL to 100)).weightOf(URI_NON_CANONICAL))
    }

    // ---- DSL -------------------------------------------------------------------------

    private fun problems(block: EntryPointBuilder.() -> Unit): List<String> = try {
        intentPolicy { entryPoint("p", block) }
        throw AssertionError("expected PolicyDefinitionException")
    } catch (e: PolicyDefinitionException) {
        e.problems
    }

    @Test
    fun dslSetsOverridesPerEntryPoint() {
        val policy = intentPolicy {
            entryPoint("a") {
                scoreWeight(URI_NON_CANONICAL, 0)
                scoreWeight(CALLER_NOT_ALLOWED, 80)
            }
            entryPoint("b") { }
        }
        assertEquals(mapOf(URI_NON_CANONICAL to 0, CALLER_NOT_ALLOWED to 80), policy["a"]!!.scoreWeights.overrides)
        assertEquals(5, policy["a"]!!.scoreWeights.weightOf(PARAM_UNKNOWN_IGNORED))
        assertSame(ScoreWeights.DEFAULT, policy["b"]!!.scoreWeights)
    }

    @Test
    fun dslRejectsWeightOnHardCode() {
        val p = problems { scoreWeight(URI_PATH_TRAVERSAL, 20) }
        assertEquals(
            listOf(
                "entryPoint(\"p\"): scoreWeight(URI_PATH_TRAVERSAL, 20): URI_PATH_TRAVERSAL is HARD, not SOFT. " +
                    "Only SOFT signals are scored; HARD always blocks and REMOVABLE always sanitizes, whatever the weight. " +
                    "Remove this call.",
            ),
            p,
        )
    }

    @Test
    fun dslRejectsWeightOnRemovableCode() {
        val p = problems { scoreWeight(EXTRA_NOT_ALLOWED, 20) }
        assertTrue(p.toString(), p.single().contains("scoreWeight(EXTRA_NOT_ALLOWED, 20): EXTRA_NOT_ALLOWED is REMOVABLE, not SOFT."))
    }

    @Test
    fun dslRejectsWeightOutOfRange() {
        val p = problems {
            scoreWeight(URI_NON_CANONICAL, 101)
            scoreWeight(PARAM_UNKNOWN_IGNORED, -1)
        }
        assertEquals(
            listOf(
                "entryPoint(\"p\"): scoreWeight(URI_NON_CANONICAL, 101): weight must be in 0..100.",
                "entryPoint(\"p\"): scoreWeight(PARAM_UNKNOWN_IGNORED, -1): weight must be in 0..100.",
            ),
            p,
        )
    }

    @Test
    fun dslRejectsDuplicateWeight() {
        val p = problems {
            scoreWeight(URI_NON_CANONICAL, 10)
            scoreWeight(URI_NON_CANONICAL, 10)
        }
        assertEquals(
            listOf(
                "entryPoint(\"p\"): scoreWeight(URI_NON_CANONICAL, ...) is set more than once. " +
                    "Set it once; a second call is an error, not an override.",
            ),
            p,
        )
    }

    @Test
    fun dslCollectsEveryWeightProblemTogether() {
        val p = problems {
            scoreWeight(URI_PATH_TRAVERSAL, 5)
            scoreWeight(URI_NON_CANONICAL, 500)
            scoreWeight(CALLER_NOT_ALLOWED, 1)
            scoreWeight(CALLER_NOT_ALLOWED, 2)
            threshold(0)
        }
        assertEquals(4, p.size)
    }

    @Test
    fun everySoftCodeCanBeOverriddenAndNoOtherCanBe() {
        for (code in ViolationCode.entries) {
            val ok = runCatching { intentPolicy { entryPoint("p") { scoreWeight(code, 1) } } }.isSuccess
            assertEquals(code.id, code.tier == com.shezguard.core.Tier.SOFT, ok)
        }
    }
}
