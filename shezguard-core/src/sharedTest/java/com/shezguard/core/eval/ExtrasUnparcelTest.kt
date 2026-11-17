package com.shezguard.core.eval

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Parcel
import com.shezguard.core.Decision
import com.shezguard.core.Field
import com.shezguard.core.ShezGuard
import com.shezguard.core.ViolationCode.EVALUATION_FAILED
import com.shezguard.core.ViolationCode.EXTRAS_UNPARCEL_FAILED
import com.shezguard.core.ViolationCode.EXTRA_NOT_ALLOWED
import com.shezguard.core.ViolationCode.HOST_NOT_ALLOWED
import com.shezguard.core.eval.EvalFixtures.codes
import com.shezguard.core.eval.ExtrasFixtures.extrasParcelled
import com.shezguard.core.eval.ExtrasFixtures.policy
import com.shezguard.core.eval.ExtrasFixtures.received
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.robolectric.annotation.Config

/**
 * Threat 5, malformed Bundles: reading extras that throw must give `EXTRAS_UNPARCEL_FAILED`,
 * never a crash, and must leave the caller's Bundle untouched (`docs/PAPER_NOTES.md` N6, N7).
 * Below API 33 the failure happens at `keySet()` (whole Bundle); from API 33 at `get(key)`
 * (one key). Shared with the instrumented tests (step 14). Tests using [ThrowingParcelable] also assert
 * that its `CREATOR` really ran, so a "class not found" failure cannot pass them (it did on devices before
 * `received()` set the app's class loader); the count is printed as `[N7s]` for the device comparison.
 */
@RunWith(AndroidJUnit4::class)
@Config(sdk = [24, 29, 34])
class ExtrasUnparcelTest {

    private val lazyValues get() = Build.VERSION.SDK_INT >= 33

    @Before
    fun reset() {
        ThrowingParcelable.created = 0
    }

    /** The hostile code was reached, not just some read failure. */
    private fun assertHostileCreatorRan(test: String) {
        println("[N7s] sdk=${Build.VERSION.SDK_INT} $test hostile CREATOR ran ${ThrowingParcelable.created}x")
        assertTrue("the hostile CREATOR did not run", ThrowingParcelable.created >= 1)
    }

    private fun hostile(parcelable: android.os.Parcelable) =
        received(Intent().putExtra("title", "hi").putExtra("evil", parcelable))

    private fun assertUnparcelFailed(d: Decision) {
        assertTrue(d.toString(), d is Decision.Block)
        assertFalse(EVALUATION_FAILED in codes(d))
        if (lazyValues) {
            // Per key: the failing key is reported, the other key was read normally.
            assertEquals(
                listOf(EXTRAS_UNPARCEL_FAILED to Field.Extra("evil", false), EXTRA_NOT_ALLOWED to Field.Extra("evil", false)),
                d.violations.map { it.code to it.field },
            )
        } else {
            assertEquals(listOf(EXTRAS_UNPARCEL_FAILED to Field.Extras), d.violations.map { it.code to it.field })
        }
    }

    @Test
    fun blocksBundleWhoseParcelableThrowsOnRead() {
        assertUnparcelFailed(ShezGuard.evaluate(hostile(ThrowingParcelable()), policy, "share"))
        assertHostileCreatorRan("blocksBundleWhoseParcelableThrowsOnRead")
    }

    @Test
    fun blocksBundleWithParcelableMissingItsCreator() = assertUnparcelFailed(ShezGuard.evaluate(hostile(NoCreatorParcelable()), policy, "share"))

    @Test
    fun blocksThrowingBundleNestedInsideAnotherBundle() {
        val intent = received(Intent().putExtra("evil", Bundle().apply { putParcelable("p", ThrowingParcelable()) }))
        val d = ShezGuard.evaluate(intent, policy, "share")
        assertTrue(d is Decision.Block)
        // A nested Bundle stays parcelled until read (Parcel.readBundle), on every level.
        assertEquals(listOf(EXTRAS_UNPARCEL_FAILED, EXTRA_NOT_ALLOWED), d.violations.map { it.code })
        assertHostileCreatorRan("blocksThrowingBundleNestedInsideAnotherBundle")
    }

    @Test
    fun callerBundleStaysParcelledAfterUnparcelFailure() {
        val intent = hostile(ThrowingParcelable())
        assertTrue("precondition: extras arrive parcelled", extrasParcelled(intent))
        ShezGuard.evaluate(intent, policy, "share")
        assertTrue("ShezGuard unparcelled the caller's Bundle", extrasParcelled(intent))
    }

    @Test
    fun repeatedEvaluationGivesTheSameDecision() {
        // ShezGuard reads a fresh copy each time, so the platform's partial map (N6) never leaks into a second decision.
        val intent = hostile(ThrowingParcelable())
        val first = ShezGuard.evaluate(intent, policy, "share")
        val second = ShezGuard.evaluate(intent, policy, "share")
        assertEquals(EvalFixtures.summary(first), EvalFixtures.summary(second))
    }

    @Test
    fun uriViolationsAreKeptWhenExtrasFailToUnparcel() {
        val intent = received(EvalFixtures.viewIntent("https://evil.com/search?q=x").putExtra("evil", ThrowingParcelable()))
        val d = ShezGuard.evaluate(intent, policy, "searchExtras")
        assertTrue(codes(d).containsAll(setOf(HOST_NOT_ALLOWED, EXTRAS_UNPARCEL_FAILED)))
        assertFalse(EVALUATION_FAILED in codes(d))
    }

    /**
     * Characterises the platform (N6), not ShezGuard: after a failed unparcel the Bundle keeps the
     * entries read so far and later reads succeed silently. Shown below API 33 only, where the
     * failure happens inside `keySet()`; from API 33 the hostile value is lazy and `keySet()` succeeds.
     */
    @Test
    fun characterisesPartialMapAfterFailedUnparcel() {
        assumeTrue("from API 33 the hostile value is lazy and keySet() succeeds (N7)", !lazyValues)
        val p = Parcel.obtain()
        val b = try {
            // ArrayMap orders by key hash: "a" (97) is written before "zzzz".
            p.writeBundle(Bundle().apply { putString("a", "1"); putParcelable("zzzz", ThrowingParcelable()) })
            p.setDataPosition(0)
            p.readBundle(javaClass.classLoader)!!
        } finally {
            p.recycle()
        }
        val first = runCatching { b.keySet() }
        assertTrue("first read must throw", first.isFailure)
        val second = b.keySet()
        println("[N6] sdk=${Build.VERSION.SDK_INT} first keySet() threw ${first.exceptionOrNull()?.javaClass?.simpleName}; second keySet()=${second.toList()}")
        assertEquals(setOf("a"), second)
    }
}
