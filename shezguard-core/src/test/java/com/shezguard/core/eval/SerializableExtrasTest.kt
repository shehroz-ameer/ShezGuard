package com.shezguard.core.eval

import android.content.Intent
import android.os.Build
import com.shezguard.core.Decision
import com.shezguard.core.Field
import com.shezguard.core.ShezGuard
import com.shezguard.core.ViolationCode.EVALUATION_FAILED
import com.shezguard.core.ViolationCode.EXTRAS_UNPARCEL_FAILED
import com.shezguard.core.ViolationCode.EXTRA_NOT_ALLOWED
import com.shezguard.core.eval.EvalFixtures.codes
import com.shezguard.core.eval.ExtrasFixtures.policy
import com.shezguard.core.eval.ExtrasFixtures.received
import com.shezguard.core.eval.SerialFixtures.withUnknownClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Threat 5 with `Serializable` extras, the two attacks of the demo app's `t5_malformed_bundle.sh`
 * (step 12, docs/ATTACK_MATRIX.md). Robolectric-only; the device results are in the matrix.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [24, 29, 34])
class SerializableExtrasTest {

    private val lazyValues get() = Build.VERSION.SDK_INT >= 33

    @Before
    fun reset() {
        GadgetPayload.readObjectCalls = 0
    }

    /**
     * t5: a `Serializable` whose class does not exist in the receiving app. The intent is parcelled and
     * the class name is replaced in the raw bytes by a name of the same length that no class has, as
     * when another app sends one of its own classes. ShezGuard must block it and must not throw.
     */
    @Test
    fun blocksSerializableOfUnknownClassWithoutCrashing() {
        val intent = withUnknownClass(Intent().putExtra("title", "hi").putExtra("profile", KnownPayloadA("x")))
        val d = ShezGuard.evaluate(intent, policy, "share")
        assertTrue(d.toString(), d is Decision.Block)
        assertFalse(EVALUATION_FAILED in codes(d))
        if (lazyValues) {
            assertEquals(
                listOf(EXTRAS_UNPARCEL_FAILED to Field.Extra("profile", false), EXTRA_NOT_ALLOWED to Field.Extra("profile", false)),
                d.violations.map { it.code to it.field },
            )
        } else {
            assertEquals(listOf(EXTRAS_UNPARCEL_FAILED to Field.Extras), d.violations.map { it.code to it.field })
        }
    }

    /** Control for the test above: the unpatched class is known, so the extra reads normally and is only not allowed. */
    @Test
    fun knownSerializableIsReadAndOnlyNotAllowed() {
        val d = ShezGuard.evaluate(received(Intent().putExtra("title", "hi").putExtra("profile", KnownPayloadA("x"))), policy, "share")
        assertTrue(d.toString(), d is Decision.Sanitize)
        assertEquals(listOf(EXTRA_NOT_ALLOWED), d.violations.map { it.code })
    }

    /**
     * 5b, NOT prevented (docs/LIMITATIONS.md L1, L27): a class the app has, whose `readObject` has a side
     * effect. ShezGuard reads every extra to look for nested intents, so the side effect runs inside
     * `evaluate`, before any decision, even though the key is not allowed and the decision removes it.
     * This test documents the limitation; it does not prove a block.
     */
    @Test
    fun gadgetReadObjectRunsDuringExtrasInspection() {
        val intent = received(Intent().putExtra("title", "hi").putExtra("profile", GadgetPayload("attacker")))
        assertEquals("precondition: nothing deserialised yet", 0, GadgetPayload.readObjectCalls)
        val d = ShezGuard.evaluate(intent, policy, "share")
        assertEquals("readObject ran inside evaluate", 1, GadgetPayload.readObjectCalls)
        assertTrue(d.toString(), d is Decision.Sanitize)
        assertEquals(listOf(EXTRA_NOT_ALLOWED), d.violations.map { it.code })
        assertFalse("the sanitized intent no longer carries the gadget", (d as Decision.Sanitize).sanitizedIntent.extras!!.containsKey("profile"))
    }
}

