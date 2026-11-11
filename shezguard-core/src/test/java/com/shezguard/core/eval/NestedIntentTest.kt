package com.shezguard.core.eval

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Intent
import android.os.Bundle
import android.os.Parcelable
import android.util.SparseArray
import com.shezguard.core.Decision
import com.shezguard.core.Field
import com.shezguard.core.ShezGuard
import com.shezguard.core.ViolationCode.EXTRA_NOT_ALLOWED
import com.shezguard.core.ViolationCode.EXTRA_WRONG_TYPE
import com.shezguard.core.ViolationCode.NESTED_INTENT_DENIED
import com.shezguard.core.ViolationCode.NESTED_INTENT_SANITIZED
import com.shezguard.core.eval.EvalFixtures.codes
import com.shezguard.core.eval.EvalFixtures.renderedOutput
import com.shezguard.core.eval.ExtrasFixtures.policy
import com.shezguard.core.eval.ExtrasFixtures.received
import com.shezguard.core.eval.ExtrasFixtures.target
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/**
 * Threat 1, intent redirection: nested intents in extras, under `Nested.Deny` and under
 * `Nested.AllowSanitized` (wrapping `androidx.core.content.IntentSanitizer`).
 * Robolectric-only, device check pending (step 14).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [24, 29, 34])
@Suppress("DEPRECATION")
class NestedIntentTest {

    private val explicit get() = Intent().setComponent(ComponentName("com.victim", "com.victim.AdminActivity"))
    private val implicit get() = Intent("com.victim.action.ADMIN")

    private fun pending(): PendingIntent =
        PendingIntent.getActivity(RuntimeEnvironment.getApplication(), 0, Intent("x"), PendingIntent.FLAG_IMMUTABLE)

    /** In-process and after a Parcel round trip. PendingIntent is only checked in-process (see test). */
    private fun both(intent: Intent, ep: String, roundTrip: Boolean = true, check: (Decision) -> Unit) {
        check(ShezGuard.evaluate(intent, policy, ep))
        if (roundTrip) check(ShezGuard.evaluate(received(intent), policy, ep))
    }

    private fun assertDenied(intent: Intent, ep: String = "share", roundTrip: Boolean = true) = both(intent, ep, roundTrip) {
        assertTrue(it.toString(), it is Decision.Block)
        assertEquals(listOf(EXTRA_NOT_ALLOWED, NESTED_INTENT_DENIED), it.violations.map { v -> v.code })
        assertTrue(it.violations.all { v -> v.field == Field.Extra("evil", false) })
    }

    // ---- Nested.Deny: every shape ----------------------------------------------------

    @Test
    fun blocksExplicitNestedIntentRedirection() = assertDenied(Intent().putExtra("evil", explicit))

    @Test
    fun blocksImplicitNestedIntentRedirection() = assertDenied(Intent().putExtra("evil", implicit))

    @Test
    fun blocksNestedIntentInParcelableArray() =
        assertDenied(Intent().putExtra("evil", arrayOf<Parcelable>(Bundle(), explicit)))

    @Test
    fun blocksNestedIntentInArrayList() =
        assertDenied(Intent().putParcelableArrayListExtra("evil", arrayListOf<Parcelable>(Bundle(), implicit)))

    @Test
    fun blocksNestedIntentInNestedBundle() =
        assertDenied(Intent().putExtra("evil", Bundle().apply { putBundle("b", Bundle().apply { putParcelable("i", explicit) }) }))

    @Test
    fun blocksNestedIntentAsMapValue() =
        assertDenied(Intent().putExtra("evil", hashMapOf<String, Any>("a" to "b", "i" to explicit)))

    @Test
    fun blocksNestedIntentInSparseArray() =
        assertDenied(Intent().putExtras(Bundle().apply { putSparseParcelableArray("evil", SparseArray<Parcelable>().apply { put(3, implicit) }) }))

    @Test
    fun blocksNestedIntentInsideAnotherNestedIntent() =
        assertDenied(Intent().putExtra("evil", Intent("outer").putExtra("inner", explicit)))

    /** PendingIntent parcelling depends on Robolectric's binder emulation, so only the in-process form is asserted. */
    @Test
    fun blocksPendingIntentExtra() = assertDenied(Intent().putExtra("evil", pending()), roundTrip = false)

    @Test
    fun blocksIntentSenderExtra() = assertDenied(Intent().putExtra("evil", pending().intentSender), roundTrip = false)

    @Test
    fun blocksNestedIntentUnderAllowedKey() {
        both(Intent().putExtra("title", explicit), "share") {
            assertEquals(listOf(EXTRA_WRONG_TYPE, NESTED_INTENT_DENIED), it.violations.map { v -> v.code })
        }
    }

    // ---- Nested.AllowSanitized: IntentSanitizer rejections become violations ---------

    private fun nextTo(nested: Intent): Intent = Intent().putExtra("title", "t").putExtra("next", nested)

    @Test
    fun sanitizesNestedIntentThroughIntentSanitizer() {
        val nested = Intent(Intent.ACTION_VIEW).setComponent(target)
            .putExtra("note", "keep").putExtra("secret", "drop")
            .addCategory("evil.category").addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        both(nextTo(nested), "forward") { d ->
            assertTrue(d.toString(), d is Decision.Sanitize)
            assertEquals(listOf(NESTED_INTENT_SANITIZED to Field.Extra("next", true)), d.violations.map { it.code to it.field })
            val out = (d as Decision.Sanitize).sanitizedIntent
            val fwd = out.getParcelableExtra<Intent>("next")!!
            assertEquals(target, fwd.component)
            assertEquals("keep", fwd.getStringExtra("note"))
            assertFalse(fwd.hasExtra("secret"))
            assertNull(fwd.categories)
            assertEquals(0, fwd.flags and Intent.FLAG_GRANT_READ_URI_PERMISSION)
            assertEquals("t", out.getStringExtra("title"))
        }
        // The caller's nested intent is untouched.
        assertEquals("drop", nested.getStringExtra("secret"))
    }

    /** Author condition 5: the forwarded nested extra is IntentSanitizer's output, even when nothing was removed. */
    @Test
    fun forwardedNestedIntentIsTheSanitizerOutputNotTheOriginal() {
        val nested = Intent(Intent.ACTION_VIEW).setComponent(target).putExtra("note", "hi")
        val intent = nextTo(nested)
        for (input in listOf(intent, received(intent))) {
            val before = ExtrasFixtures.notePredicateCalls
            val d = ShezGuard.evaluate(input, policy, "forward")
            assertEquals("the sanitizer ran exactly once", before + 1, ExtrasFixtures.notePredicateCalls)
            assertTrue(d.toString(), d is Decision.Sanitize)
            assertEquals(listOf(NESTED_INTENT_SANITIZED), d.violations.map { it.code })
            val fwd = (d as Decision.Sanitize).sanitizedIntent.getParcelableExtra<Intent>("next")!!
            assertNotSame(nested, fwd)
            assertNotSame(input.getParcelableExtra<Intent>("next"), fwd)
            assertEquals(target, fwd.component)
            assertEquals("hi", fwd.getStringExtra("note"))
        }
    }

    @Test
    fun blocksNestedIntentWhoseComponentIntentSanitizerRewrites() {
        // IntentSanitizer replaces a rejected component with android/java.lang.Void: a rewrite, not a removal.
        both(nextTo(explicit), "forward") {
            assertTrue(it is Decision.Block)
            assertEquals(listOf(NESTED_INTENT_DENIED to Field.Extra("next", true)), it.violations.map { v -> v.code to v.field })
        }
    }

    @Test
    fun blocksImplicitNestedIntentWithoutAllowAnyComponent() {
        both(nextTo(Intent(Intent.ACTION_VIEW)), "forward") { assertEquals(listOf(NESTED_INTENT_DENIED), it.violations.map { v -> v.code }) }
    }

    @Test
    fun sanitizesImplicitNestedIntentWithAllowAnyComponent() {
        both(Intent().putExtra("next", Intent(Intent.ACTION_VIEW).putExtra("x", "y")), "forwardAny") { d ->
            assertTrue(d.toString(), d is Decision.Sanitize)
            val fwd = (d as Decision.Sanitize).sanitizedIntent.getParcelableExtra<Intent>("next")!!
            assertNull(fwd.component)
            assertFalse(fwd.hasExtra("x"))
        }
    }

    @Test
    fun blocksNestedIntentUnderUnlistedKey() {
        both(Intent().putExtra("other", Intent(Intent.ACTION_VIEW).setComponent(target)), "forward") {
            assertEquals(listOf(EXTRA_NOT_ALLOWED, NESTED_INTENT_DENIED), it.violations.map { v -> v.code })
        }
    }

    @Test
    fun blocksPendingIntentUnderSanitizedKey() {
        val d = ShezGuard.evaluate(Intent().putExtra("next", pending()), policy, "forward")
        assertEquals(listOf(NESTED_INTENT_DENIED), d.violations.map { it.code })
    }

    @Test
    fun blocksNestedIntentArrayUnderSanitizedKey() {
        both(Intent().putExtra("next", arrayOf<Parcelable>(Intent(Intent.ACTION_VIEW).setComponent(target))), "forward") {
            assertEquals(listOf(NESTED_INTENT_DENIED), it.violations.map { v -> v.code })
        }
    }

    @Test
    fun blocksNonIntentValueUnderSanitizedKey() {
        both(Intent().putExtra("next", "intent:#Intent;end"), "forward") {
            assertEquals(listOf(EXTRA_WRONG_TYPE), it.violations.map { v -> v.code })
        }
    }

    @Test
    fun nullUnderSanitizedKeyCountsAsAbsent() {
        both(Intent().putExtras(Bundle().apply { putParcelable("next", null) }), "forward") {
            assertTrue(it.toString(), it is Decision.Allow)
        }
    }

    @Test
    fun blocksDoublyNestedIntentLeftBySanitizer() {
        // The sanitizer allows an Intent extra ("inner"); IntentSanitizer does not sanitize it, so ShezGuard denies.
        val nested = Intent(Intent.ACTION_VIEW).setComponent(target).putExtra("inner", explicit)
        both(nextTo(nested), "forward") { assertEquals(listOf(NESTED_INTENT_DENIED), it.violations.map { v -> v.code }) }
    }

    @Test
    fun intentSanitizerExceptionBecomesViolation() {
        val nested = Intent(Intent.ACTION_VIEW).setComponent(target).putExtra("explode", "x")
        both(nextTo(nested), "forward") {
            assertTrue(it is Decision.Block)
            assertEquals(listOf(NESTED_INTENT_DENIED), it.violations.map { v -> v.code })
        }
    }

    @Test
    fun intentSanitizerMessagesNeverReachDecisionOutput() {
        val m = "zqx"
        val nested = Intent(Intent.ACTION_VIEW).setComponent(target).putExtra("secret", "${m}value")
            .setData(android.net.Uri.parse("https://$m.example/"))
        both(nextTo(nested), "forward") { d ->
            assertNotNull(d)
            assertFalse(renderedOutput(d), renderedOutput(d).contains(m))
        }
    }

    @Test
    fun denyIsTheDefault() {
        // "share" sets no nested rule: a nested intent under a listed-looking key is still denied.
        both(Intent().putExtra("next", Intent(Intent.ACTION_VIEW).setComponent(target)), "share") {
            assertEquals(listOf(EXTRA_NOT_ALLOWED, NESTED_INTENT_DENIED), it.violations.map { v -> v.code })
        }
        assertTrue(codes(ShezGuard.evaluate(Intent().putExtra("next", explicit), policy, "share")).contains(NESTED_INTENT_DENIED))
    }
}
