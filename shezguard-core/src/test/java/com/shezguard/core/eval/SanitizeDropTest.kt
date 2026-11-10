package com.shezguard.core.eval

import android.content.ComponentName
import android.content.Intent
import android.net.Uri
import com.shezguard.core.Decision
import com.shezguard.core.Field
import com.shezguard.core.Outcome
import com.shezguard.core.ShezGuard
import com.shezguard.core.Violation
import com.shezguard.core.ViolationCode.PARAM_INVALID_FORMAT
import com.shezguard.core.ViolationCode.PARAM_UNKNOWN_DROPPED
import com.shezguard.core.eval.EvalFixtures.codes
import com.shezguard.core.eval.EvalFixtures.policy
import com.shezguard.core.eval.EvalFixtures.viewIntent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Sanitize under `Unknown.Drop` (SPEC 4.1, proposal (d)): only unknown parameters are
 * removed, everything else in the URI and the intent stays exactly as it was.
 */
@RunWith(RobolectricTestRunner::class)
class SanitizeDropTest {

    private fun sanitize(intent: Intent): Decision.Sanitize {
        val d = ShezGuard.evaluate(intent, policy, "search")
        assertTrue("expected Sanitize, got $d", d is Decision.Sanitize)
        return d as Decision.Sanitize
    }

    @Test
    fun dropsUnknownTrackingParamsAndKeepsTheRestByteForByte() {
        val raw = "https://Example.com/search?utm_source=x&q=red%20shoes+sale&fbclid=AbC-z#Top%20Part"
        val d = sanitize(viewIntent(raw))
        assertEquals("https://Example.com/search?q=red%20shoes+sale#Top%20Part", d.sanitizedIntent.dataString)
        assertEquals(
            listOf(
                Violation(PARAM_UNKNOWN_DROPPED, "search", Field.Param("utm_source", declared = false)),
                Violation(PARAM_UNKNOWN_DROPPED, "search", Field.Param("fbclid", declared = false)),
            ),
            d.violations,
        )
        assertEquals("red shoes sale", d.data!!.param("q"))
        assertEquals("Top Part", d.data!!.fragment)
        assertEquals(setOf("q"), d.data!!.paramNames)
    }

    @Test
    fun removesQuestionMarkWhenEveryParamIsDropped() {
        val d = sanitize(viewIntent("https://example.com/search?utm=1&gclid=2#f"))
        assertEquals("https://example.com/search#f", d.sanitizedIntent.dataString)
        val noFragment = sanitize(viewIntent("https://example.com/search?utm=1"))
        assertEquals("https://example.com/search", noFragment.sanitizedIntent.dataString)
    }

    @Test
    fun dropsEveryOccurrenceOfARepeatedUnknownParam() {
        val d = sanitize(viewIntent("https://example.com/search?utm=1&q=a&utm=2"))
        assertEquals("https://example.com/search?q=a", d.sanitizedIntent.dataString)
    }

    @Test
    fun keepsComponentActionFlagsCategoriesTypePackageAndExtras() {
        val original = Intent("com.example.SEARCH").apply {
            setDataAndType(Uri.parse("https://example.com/search?q=a&utm=1"), "text/plain")
            component = ComponentName("com.example", "com.example.SearchActivity")
            addCategory(Intent.CATEGORY_BROWSABLE)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            setPackage("com.example")
            putExtra("k", "v")
        }
        val copy = sanitize(original).sanitizedIntent
        assertNotSame(original, copy)
        assertEquals("https://example.com/search?q=a", copy.dataString)
        assertEquals(original.action, copy.action)
        assertEquals(original.component, copy.component)
        assertEquals(original.flags, copy.flags)
        assertEquals(original.categories, copy.categories)
        assertEquals("text/plain", copy.type)
        assertEquals(original.`package`, copy.`package`)
        assertEquals("v", copy.getStringExtra("k")) // read here by the test only, never by ShezGuard
    }

    @Test
    fun sanitizeNeverModifiesTheCallersIntent() {
        val raw = "https://example.com/search?utm=1&q=a"
        val original = viewIntent(raw).apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) }
        val dataBefore = original.data
        sanitize(original)
        assertEquals(raw, original.dataString)
        assertTrue(dataBefore === original.data)
        assertEquals(Intent.FLAG_ACTIVITY_NEW_TASK, original.flags)
    }

    @Test
    fun dropDoesNotRescueAHardViolation() {
        val d = ShezGuard.evaluate(viewIntent("https://example.com/search?utm=1&q=%3Cscript%3E%00"), policy, "search")
        assertEquals(Outcome.BLOCK, d.outcome)
        val d2 = ShezGuard.evaluate(viewIntent("https://example.com/other?utm=1"), policy, "search")
        assertEquals(Outcome.BLOCK, d2.outcome)
        assertTrue(PARAM_UNKNOWN_DROPPED in codes(d2))
    }

    @Test
    fun dropDoesNotRescueAnInvalidDeclaredValue() {
        val p = com.shezguard.core.policy.intentPolicy {
            entryPoint("p") {
                allowSchemes("https"); allowHosts("example.com"); anyPath()
                param("id") { digitsOnly() }
                unknownParams(com.shezguard.core.policy.Unknown.Drop)
            }
        }
        val d = ShezGuard.evaluate(viewIntent("https://example.com/?id=x&utm=1"), p, "p")
        assertEquals(Outcome.BLOCK, d.outcome)
        assertTrue(PARAM_INVALID_FORMAT in codes(d))
    }

    @Test
    fun cleanIntentUnderDropIsAllowedNotSanitized() {
        val d = ShezGuard.evaluate(viewIntent("https://example.com/search?q=a"), policy, "search")
        assertTrue(d is Decision.Allow)
    }

    @Test
    fun keepsBuilderEncodedFormOfRetainedParams() {
        val uri = Uri.Builder().scheme("https").authority("example.com").appendPath("search")
            .appendQueryParameter("q", "a+b & c").appendQueryParameter("utm", "x").build()
        val d = sanitize(Intent(Intent.ACTION_VIEW, uri))
        assertEquals("https://example.com/search?q=a%2Bb%20%26%20c", d.sanitizedIntent.dataString)
        assertEquals("a+b & c", d.data!!.param("q"))
        assertNull(d.data!!.param("utm"))
    }
}
