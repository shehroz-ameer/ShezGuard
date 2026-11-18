package com.shezguard.core.device

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.shezguard.core.ActivityGuard
import com.shezguard.core.device.DeepNesting.DEPTH
import com.shezguard.core.device.DeepNesting.onMain
import com.shezguard.core.device.DeepNesting.sdk
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith

/** Step 16, H1, `ActivityGuard.onNewIntent` on the main thread. */
@RunWith(AndroidJUnit4::class)
class DeepNestingOnNewIntentDeviceTest {
    @Test
    fun blocksDeeplyNestedListExtraInOnNewIntentThenStillAllowsAndBlocksAgain() {
        val guard = ActivityGuard(DeepNesting.policy())
        val activity = onMain("construct activity") { DeepGuardedActivity() }!!
        val deep = DeepNesting.deepView()
        val first = onMain("onNewIntent overflow #1") { guard.onNewIntent(activity, deep) }
        println("[H1] sdk=$sdk onNewIntent depth $DEPTH (first evaluation in process): ${if (first == null) "Block (null)" else "NOT BLOCKED"}")
        assertNull(first)

        val benign = onMain("onNewIntent benign") { guard.onNewIntent(activity, DeepNesting.benignView()) }
        println("[H1] sdk=$sdk onNewIntent benign after overflow: ${benign?.decision?.outcome ?: "Block (null)"}")
        assertNotNull(benign)

        val again = onMain("onNewIntent overflow #2") { guard.onNewIntent(activity, DeepNesting.deepView()) }
        println("[H1] sdk=$sdk onNewIntent depth $DEPTH again: ${if (again == null) "Block (null)" else "NOT BLOCKED"}")
        assertNull(again)
    }
}
