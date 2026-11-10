package com.shezguard.core.eval

import android.content.Intent
import android.os.Bundle
import android.os.Parcel
import com.shezguard.core.Decision
import com.shezguard.core.ShezGuard
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Proposal (d)1: copying the intent for Sanitize must not unparcel its extras. Checked on
 * SDK 29 (last level with the old `Uri` parcel format) and SDK 34 (the project's pinned level)
 * through the hidden `BaseBundle.isParcelled()`, via reflection. AOSP source for API 24 to 34
 * is summarised in `docs/PAPER_NOTES.md` N5. Robolectric is not a device.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [29, 34])
class IntentCopyParcelTest {

    private fun received(): Intent {
        val sent = EvalFixtures.viewIntent("https://example.com/search?q=a&utm=1").apply { putExtra("k", "v") }
        val p = Parcel.obtain()
        try {
            sent.writeToParcel(p, 0)
            p.setDataPosition(0)
            return Intent.CREATOR.createFromParcel(p)
        } finally {
            p.recycle()
        }
    }

    private fun extrasParcelled(i: Intent): Boolean {
        val f = Intent::class.java.getDeclaredField("mExtras").apply { isAccessible = true }
        val bundle = f.get(i) as Bundle? ?: return false
        val m = Class.forName("android.os.BaseBundle").getDeclaredMethod("isParcelled").apply { isAccessible = true }
        return m.invoke(bundle) as Boolean
    }

    @Test
    fun sanitizeCopyDoesNotUnparcelExtras() {
        val original = received()
        assertTrue("precondition: extras arrive parcelled", extrasParcelled(original))
        val d = ShezGuard.evaluate(original, EvalFixtures.policy, "search")
        assertTrue(d.toString(), d is Decision.Sanitize)
        assertTrue("original extras were unparcelled", extrasParcelled(original))
        assertTrue("copy extras were unparcelled", extrasParcelled((d as Decision.Sanitize).sanitizedIntent))
    }
}
