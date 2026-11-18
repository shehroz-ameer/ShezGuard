package com.shezguard.core.device

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.shezguard.core.Outcome
import com.shezguard.core.ShezGuard
import com.shezguard.core.ViolationCode.EXTRAS_UNPARCEL_FAILED
import com.shezguard.core.device.DeepNesting.DEPTH
import com.shezguard.core.device.DeepNesting.describe
import com.shezguard.core.device.DeepNesting.onMain
import com.shezguard.core.device.DeepNesting.sdk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Step 16, H1, `ShezGuard.evaluate` on the main thread. Attack category: malformed Bundle that crashes the app (threat 5). */
@RunWith(AndroidJUnit4::class)
class DeepNestingEvaluateDeviceTest {
    @Test
    fun blocksDeeplyNestedListExtraThenStillAllowsAndBlocksAgain() {
        val policy = DeepNesting.policy()
        val deep = DeepNesting.deepView()
        val first = onMain("evaluate overflow #1") { ShezGuard.evaluate(deep, policy, "any") }
        println("[H1] sdk=$sdk evaluate depth $DEPTH (first evaluation in process): ${describe(first)}")
        assertEquals(Outcome.BLOCK, first!!.outcome)
        assertTrue(first.violations.toString(), EXTRAS_UNPARCEL_FAILED in first.violations.map { it.code })

        val benign = onMain("evaluate benign") { ShezGuard.evaluate(DeepNesting.benignView(), policy, "any") }
        println("[H1] sdk=$sdk evaluate benign after overflow: ${describe(benign)}")
        assertEquals(Outcome.ALLOW, benign!!.outcome)

        val again = onMain("evaluate overflow #2") { ShezGuard.evaluate(DeepNesting.deepView(), policy, "any") }
        println("[H1] sdk=$sdk evaluate depth $DEPTH again: ${describe(again)}")
        assertEquals(Outcome.BLOCK, again!!.outcome)
        assertTrue(again.violations.toString(), EXTRAS_UNPARCEL_FAILED in again.violations.map { it.code })
    }
}
