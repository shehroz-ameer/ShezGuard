package com.shezguard.core.policy

import androidx.core.content.IntentSanitizer
import com.shezguard.core.android.NestedIntentSanitizer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/** DSL rules that need a real `androidx.core.content.IntentSanitizer` (Android classes). */
@RunWith(RobolectricTestRunner::class)
class PolicyDslNestedIntentTest {

    private fun sanitizer() = NestedIntentSanitizer(IntentSanitizer.Builder().allowAnyComponent().build())

    @Test
    fun buildsAllowSanitizedNestedIntentRule() {
        val rule = Nested.AllowSanitized(setOf("next_intent"), sanitizer())
        val ep = intentPolicy { entryPoint("p") { nestedIntents(rule) } }["p"]!!
        assertEquals(rule, ep.nestedIntents)
    }

    @Test // rule 12
    fun rejectsExtraKeyThatIsAlsoANestedIntentKey() {
        val e = try {
            intentPolicy {
                entryPoint("p") {
                    extras { allow("next_intent", ExtraType.STRING) }
                    nestedIntents(Nested.AllowSanitized(setOf("next_intent"), sanitizer()))
                }
            }
            null
        } catch (e: PolicyDefinitionException) {
            e
        } ?: throw AssertionError("expected PolicyDefinitionException")
        val fragments = listOf("\"next_intent\"", "extras { allow(", "Nested.AllowSanitized", "remove it from extras")
        assertTrue(e.problems.toString(), e.problems.any { p -> fragments.all { it in p } })
    }
}
