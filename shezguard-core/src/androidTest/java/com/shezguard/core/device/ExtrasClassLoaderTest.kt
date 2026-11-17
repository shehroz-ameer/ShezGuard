package com.shezguard.core.device

import android.content.Intent
import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.shezguard.core.Decision
import com.shezguard.core.ShezGuard
import com.shezguard.core.ViolationCode.EVALUATION_FAILED
import com.shezguard.core.ViolationCode.EXTRAS_UNPARCEL_FAILED
import com.shezguard.core.eval.EvalFixtures.codes
import com.shezguard.core.eval.ExtrasFixtures.policy
import com.shezguard.core.eval.ExtrasFixtures.received
import com.shezguard.core.eval.ExtrasFixtures.receivedWithoutLoader
import com.shezguard.core.eval.GadgetPayload
import com.shezguard.core.eval.ThrowingParcelable
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Device-only (step 14). Without an extras class loader, a device resolves app classes with the loader
 * of `Parcel` (N8), so a hostile `CREATOR` never runs: the read fails with "class not found" instead.
 * Under Robolectric the two are the same. Until the step 14 follow-up, the shared extras tests used such
 * intents and so passed on devices without reaching the hostile code; `ExtrasFixtures.received` now sets
 * the app's loader, as `ActivityThread` does. This class keeps both cases side by side. Lines `[N7d]`.
 */
@RunWith(AndroidJUnit4::class)
class ExtrasClassLoaderTest {

    private val sdk = Build.VERSION.SDK_INT

    @Before
    fun reset() {
        ThrowingParcelable.created = 0
        GadgetPayload.readObjectCalls = 0
    }

    private fun hostile(withAppLoader: Boolean): Intent {
        val sent = Intent().putExtra("title", "hi").putExtra("evil", ThrowingParcelable())
        return if (withAppLoader) received(sent) else receivedWithoutLoader(sent)
    }

    private fun summary(d: Decision) = "${d.outcome} ${d.violations.map { "${it.code.id}@${it.field}" }}"

    @Test
    fun recordsWhetherHostileCreatorRunsWithoutLoader() {
        val d = ShezGuard.evaluate(hostile(false), policy, "share")
        println("[N7d] sdk=$sdk loader=none hostile CREATOR ran ${ThrowingParcelable.created}x; ${summary(d)}")
        assertTrue(d is Decision.Block)
        assertTrue(EXTRAS_UNPARCEL_FAILED in codes(d))
    }

    @Test
    fun blocksHostileCreatorWithAppLoader() {
        val d = ShezGuard.evaluate(hostile(true), policy, "share")
        println("[N7d] sdk=$sdk loader=app hostile CREATOR ran ${ThrowingParcelable.created}x; ${summary(d)}")
        assertTrue("the hostile CREATOR ran", ThrowingParcelable.created >= 1)
        assertTrue(d.toString(), d is Decision.Block)
        assertTrue(EXTRAS_UNPARCEL_FAILED in codes(d))
        assertFalse(EVALUATION_FAILED in codes(d))
    }

    @Test
    fun recordsWhetherGadgetReadObjectRunsWithoutLoader() {
        val d = ShezGuard.evaluate(receivedWithoutLoader(Intent().putExtra("title", "hi").putExtra("profile", GadgetPayload("a"))), policy, "share")
        println("[N7d] sdk=$sdk loader=none gadget readObject ran ${GadgetPayload.readObjectCalls}x; ${summary(d)}")
    }

    @Test
    fun gadgetReadObjectRunsWithAppLoader() {
        val intent = received(Intent().putExtra("title", "hi").putExtra("profile", GadgetPayload("a")))
        val d = ShezGuard.evaluate(intent, policy, "share")
        println("[N7d] sdk=$sdk loader=app gadget readObject ran ${GadgetPayload.readObjectCalls}x; ${summary(d)}")
        // Same as SerializableExtrasTest.gadgetReadObjectRunsDuringExtrasInspection (L1, L27: not prevented).
        assertEquals(1, GadgetPayload.readObjectCalls)
        assertTrue(d.toString(), d is Decision.Sanitize)
    }
}
