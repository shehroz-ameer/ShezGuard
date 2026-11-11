package com.shezguard.core.eval

import android.content.Intent
import android.os.Bundle
import com.shezguard.core.Decision
import com.shezguard.core.Field
import com.shezguard.core.ShezGuard
import com.shezguard.core.ViolationCode.EXTRAS_TOO_DEEP
import com.shezguard.core.ViolationCode.EXTRAS_TOO_MANY
import com.shezguard.core.ViolationCode.EXTRA_NOT_ALLOWED
import com.shezguard.core.ViolationCode.EXTRA_TOO_LARGE
import com.shezguard.core.ViolationCode.EXTRA_WRONG_TYPE
import com.shezguard.core.ViolationCode.NESTED_INTENT_DENIED
import com.shezguard.core.ViolationCode.PARAM_UNKNOWN_DROPPED
import com.shezguard.core.eval.EvalFixtures.codes
import com.shezguard.core.eval.EvalFixtures.renderedOutput
import com.shezguard.core.eval.ExtrasFixtures.nestedBundles
import com.shezguard.core.eval.ExtrasFixtures.policy
import com.shezguard.core.eval.ExtrasFixtures.received
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Extras rules end to end with real `Intent`/`Bundle` objects, both in-process and after a
 * Parcel round trip (as received over IPC). SDK 29 unparcels eagerly, SDK 34 lazily
 * (`docs/PAPER_NOTES.md` N7). Robolectric-only, device check pending (step 14).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [24, 29, 34])
class ExtrasEvaluateTest {

    private fun share(vararg extras: Pair<String, Any?>): Intent = Intent().apply {
        val b = Bundle()
        for ((k, v) in extras) {
            when (v) {
                null -> b.putString(k, null)
                is String -> b.putString(k, v)
                is Int -> b.putInt(k, v)
                is Boolean -> b.putBoolean(k, v)
                is Long -> b.putLong(k, v)
                is LongArray -> b.putLongArray(k, v)
                is Array<*> -> @Suppress("UNCHECKED_CAST") b.putStringArray(k, v as Array<String?>)
                is Bundle -> b.putBundle(k, v)
                is android.os.Parcelable -> b.putParcelable(k, v)
                else -> error("unsupported test value")
            }
        }
        putExtras(b)
    }

    /** Runs [check] on the in-process intent and on its Parcel round trip. */
    private fun both(intent: Intent, ep: String = "share", check: (Decision) -> Unit) {
        check(ShezGuard.evaluate(intent, policy, ep))
        check(ShezGuard.evaluate(received(intent), policy, ep))
    }

    // ---- Allowed extras ------------------------------------------------------------

    @Test
    fun allowsDeclaredExtrasOfTheRightType() {
        val intent = share("title" to "hi", "count" to 3, "on" to true, "tags" to arrayOf("a", "b"), "ids" to longArrayOf(1, 2))
        val d = ShezGuard.evaluate(intent, policy, "share")
        assertTrue(d.toString(), d is Decision.Allow)
        assertSame(intent, (d as Decision.Allow).intent)
        both(intent) { assertTrue(it.toString(), it is Decision.Allow) }
    }

    @Test
    fun nullValueUnderAllowedKeyCountsAsAbsent() {
        both(share("title" to null)) { assertTrue(it.toString(), it is Decision.Allow) }
    }

    // ---- Unexpected types (type confusion) -------------------------------------------

    @Test
    fun blocksTypeConfusionUnderAllowedKey() {
        both(share("count" to "3", "title" to 3, "on" to "true")) {
            assertEquals(setOf(EXTRA_WRONG_TYPE), codes(it))
            assertEquals(3, it.violations.size)
        }
    }

    @Test
    fun blocksCharSequenceArrayPosingAsStringArray() {
        val intent = Intent().putExtra("tags", arrayOf<CharSequence>("a"))
        both(intent) { assertEquals(setOf(EXTRA_WRONG_TYPE), codes(it)) }
    }

    @Test
    fun blocksCustomParcelableUnderAllowedKey() {
        both(share("title" to PlainParcelable())) { assertEquals(setOf(EXTRA_WRONG_TYPE), codes(it)) }
    }

    // ---- Oversized extras ------------------------------------------------------------

    @Test
    fun blocksOversizedStringExtra() {
        both(share("title" to "a".repeat(256))) { assertTrue(it is Decision.Allow) }
        both(share("title" to "a".repeat(257))) { assertEquals(setOf(EXTRA_TOO_LARGE), codes(it)) }
    }

    @Test
    fun blocksOversizedArrayAndArrayElement() {
        both(share("ids" to LongArray(65), "tags" to arrayOf("ok", "x".repeat(257)))) {
            assertEquals(listOf(EXTRA_TOO_LARGE, EXTRA_TOO_LARGE), it.violations.map { v -> v.code })
        }
    }

    @Test
    fun blocksTooManyExtras() {
        val intent = Intent().apply { repeat(17) { putExtra("k$it", "v") } }
        both(intent) { assertEquals(listOf(EXTRAS_TOO_MANY to Field.Extras), it.violations.map { v -> v.code to v.field }) }
        val sixteen = Intent().apply { repeat(16) { putExtra("k$it", "v") } }
        both(sixteen) { assertFalse(EXTRAS_TOO_MANY in codes(it)) }
    }

    // ---- Unknown keys ----------------------------------------------------------------

    @Test
    fun sanitizesUnknownExtraKeyByRemovingIt() {
        val intent = share("title" to "hi", "tags" to arrayOf("a"), "evil" to "x")
        both(intent) { d ->
            assertTrue(d.toString(), d is Decision.Sanitize)
            assertEquals(listOf(EXTRA_NOT_ALLOWED to Field.Extra("evil", false)), d.violations.map { it.code to it.field })
            val out = (d as Decision.Sanitize).sanitizedIntent.extras!!
            assertEquals(setOf("title", "tags"), out.keySet())
            assertEquals("hi", out.getString("title"))
            assertArrayEquals(arrayOf("a"), out.getStringArray("tags"))
        }
        // The caller's intent still has the key.
        assertEquals("x", intent.getStringExtra("evil"))
    }

    @Test
    fun sanitizedArraysAreCopiesNotTheCallersObjects() {
        val tags = arrayOf("a")
        val intent = share("tags" to tags, "evil" to "x")
        val d = ShezGuard.evaluate(intent, policy, "share") as Decision.Sanitize
        val out = d.sanitizedIntent.getStringArrayExtra("tags")!!
        assertFalse(out === tags)
        out[0] = "changed"
        assertEquals("a", intent.getStringArrayExtra("tags")!![0])
    }

    @Test
    fun sanitizesWhenEveryExtraIsRemoved() {
        both(share("evil" to "x")) { d ->
            assertTrue(d is Decision.Sanitize)
            assertNull((d as Decision.Sanitize).sanitizedIntent.extras)
        }
    }

    @Test
    fun nullKeyIsReportedAsUndeclaredAndRemoved() {
        val intent = Intent().putExtras(Bundle().apply { putString(null, "x"); putString("title", "hi") })
        both(intent) { d ->
            assertEquals(listOf(EXTRA_NOT_ALLOWED to Field.Extra("", false)), d.violations.map { it.code to it.field })
            assertEquals(setOf("title"), (d as Decision.Sanitize).sanitizedIntent.extras!!.keySet())
        }
    }

    @Test
    fun customParcelableUnderUnknownKeyIsRemoved() {
        both(share("title" to "hi", "lib" to PlainParcelable())) { d ->
            assertEquals(listOf(EXTRA_NOT_ALLOWED), d.violations.map { it.code })
            assertEquals(setOf("title"), (d as Decision.Sanitize).sanitizedIntent.extras!!.keySet())
        }
    }

    // ---- Depth limit -----------------------------------------------------------------

    @Test
    fun allowsNestedBundlesUpToTheDepthLimit() {
        // Four nested Bundles below the extras: inspected in full, so only the unknown key is reported.
        both(share("evil" to nestedBundles(4) { putString("s", "x") })) {
            assertEquals(listOf(EXTRA_NOT_ALLOWED), it.violations.map { v -> v.code })
        }
    }

    @Test
    fun blocksExtrasNestedBeyondDepthLimit() {
        both(share("evil" to nestedBundles(5) { putString("s", "x") })) {
            assertEquals(listOf(EXTRAS_TOO_DEEP, EXTRA_NOT_ALLOWED), it.violations.map { v -> v.code })
        }
    }

    @Test
    fun blocksNestedIntentHiddenAtTheDepthLimit() {
        both(share("evil" to nestedBundles(4) { putParcelable("i", Intent("x")) })) {
            assertEquals(listOf(EXTRA_NOT_ALLOWED, NESTED_INTENT_DENIED), it.violations.map { v -> v.code })
        }
    }

    // ---- URI and extras together -----------------------------------------------------

    @Test
    fun uriDropAndExtraRemovalShareOneSanitizedCopy() {
        val intent = EvalFixtures.viewIntent("https://example.com/search?q=shoes&utm=1")
            .putExtra("title", "hi").putExtra("evil", "x")
        both(intent, "searchExtras") { d ->
            assertEquals(setOf(PARAM_UNKNOWN_DROPPED, EXTRA_NOT_ALLOWED), codes(d))
            val s = d as Decision.Sanitize
            assertEquals("https://example.com/search?q=shoes", s.sanitizedIntent.dataString)
            assertEquals(setOf("title"), s.sanitizedIntent.extras!!.keySet())
            assertEquals("shoes", s.data!!.param("q"))
        }
    }

    @Test
    fun extrasStageRunsEvenWhenTheUriAlreadyBlocks() {
        // Author decision 1 (step 6): all violations are collected.
        val intent = EvalFixtures.viewIntent("https://evil.com/search?q=x").putExtra("evil", Intent("x"))
        both(intent, "searchExtras") {
            assertTrue(codes(it).containsAll(setOf(EXTRA_NOT_ALLOWED, NESTED_INTENT_DENIED)))
            assertTrue(it is Decision.Block)
        }
    }

    // ---- The input intent is never modified ------------------------------------------

    /** Test-only deep snapshot of extras; reading them here is the test's doing, not ShezGuard's. */
    @Suppress("DEPRECATION")
    private fun snapshot(b: Bundle?): Map<String?, Any?>? = b?.keySet()?.associateWith { k ->
        when (val v = b.get(k)) {
            is Bundle -> snapshot(v)
            is Intent -> listOf(v.action, v.component, v.flags, v.categories?.toSet(), snapshot(v.extras))
            is Array<*> -> v.toList()
            is LongArray -> v.toList()
            else -> v
        }
    }

    @Test
    fun inputIntentAndItsExtrasAreNeverModified() {
        val nested = Intent(Intent.ACTION_VIEW).setComponent(ExtrasFixtures.target)
            .putExtra("note", "n").putExtra("secret", "s").addCategory("c")
        val cases = listOf(
            "share" to share("title" to "hi", "ids" to longArrayOf(1), "evil" to "x"),             // Sanitize
            "share" to share("title" to 1, "evil" to Bundle().apply { putParcelable("i", Intent("x")) }), // Block
            "share" to share("title" to "hi"),                                                     // Allow
            "forward" to Intent().putExtra("title", "t").putExtra("next", nested).putExtra("evil", "x"), // Sanitize
            "forward" to Intent().putExtra("next", Intent("x")),                                    // Block
        )
        for ((ep, intent) in cases) {
            for (input in listOf(intent, received(intent))) {
                val before = snapshot(Bundle(input.extras!!))
                val extrasRef = input.extras?.keySet()
                ShezGuard.evaluate(input, policy, ep)
                assertEquals("$ep: extras changed", before, snapshot(input.extras))
                assertEquals(extrasRef, input.extras?.keySet())
            }
        }
        assertEquals(setOf("note", "secret"), nested.extras!!.keySet())
        assertEquals(setOf("c"), nested.categories)
    }

    // ---- Redaction -------------------------------------------------------------------

    @Test
    fun noDecisionOutputContainsExtraKeysOrValues() {
        val m = "zqx"
        val intent = share("title" to "${m}v", "${m}k" to "${m}v", "count" to "${m}v")
        both(intent) { assertFalse(renderedOutput(it), renderedOutput(it).contains(m)) }
    }
}
