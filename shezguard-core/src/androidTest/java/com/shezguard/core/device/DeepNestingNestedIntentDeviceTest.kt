package com.shezguard.core.device

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.shezguard.core.Decision
import com.shezguard.core.Outcome
import com.shezguard.core.ShezGuard
import com.shezguard.core.ViolationCode.EXTRAS_UNPARCEL_FAILED
import com.shezguard.core.ViolationCode.NESTED_INTENT_DENIED
import com.shezguard.core.device.DeepNesting.DEPTH
import com.shezguard.core.device.DeepNesting.describe
import com.shezguard.core.device.DeepNesting.onMain
import com.shezguard.core.device.DeepNesting.sdk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Step 16, H1, a nested intent under `AllowSanitized` whose `IntentSanitizer` read overflows (main thread). */
@RunWith(AndroidJUnit4::class)
class DeepNestingNestedIntentDeviceTest {
    private fun assertBlocked(d: Decision?) {
        assertEquals(Outcome.BLOCK, d!!.outcome)
        val codes = d.violations.map { it.code }
        assertTrue(codes.toString(), NESTED_INTENT_DENIED in codes || EXTRAS_UNPARCEL_FAILED in codes)
    }

    @Test
    fun deniesNestedIntentWhoseSanitizerReadOverflowsThenStillAllowsAndBlocksAgain() {
        val policy = DeepNesting.policy()
        val first = onMain("nested overflow #1") { ShezGuard.evaluate(DeepNesting.deepNested(), policy, "fwd") }
        println("[H1] sdk=$sdk nested intent depth $DEPTH (first evaluation in process): ${describe(first)}")
        assertBlocked(first)

        val benign = onMain("evaluate benign") { ShezGuard.evaluate(DeepNesting.benignView(), policy, "any") }
        println("[H1] sdk=$sdk evaluate benign after nested overflow: ${describe(benign)}")
        assertEquals(Outcome.ALLOW, benign!!.outcome)

        val again = onMain("nested overflow #2") { ShezGuard.evaluate(DeepNesting.deepNested(), policy, "fwd") }
        println("[H1] sdk=$sdk nested intent depth $DEPTH again: ${describe(again)}")
        assertBlocked(again)
    }
}
