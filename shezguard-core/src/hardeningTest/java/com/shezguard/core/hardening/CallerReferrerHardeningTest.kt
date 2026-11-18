package com.shezguard.core.hardening

import android.app.Activity
import android.content.Intent
import android.os.Parcel
import com.shezguard.core.Decision
import com.shezguard.core.Delivery
import com.shezguard.core.ShezGuard
import com.shezguard.core.hardening.Hardening.roundTrip
import com.shezguard.core.policy.intentPolicy
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Step 15, areas 5 and 6: the advisory referrer is attacker-controlled text that reaches a regular expression.
 *
 * `ActivityCallerSource.packageOf` runs `PACKAGE_NAME.matches(authority)` on `EXTRA_REFERRER_NAME` /
 * `EXTRA_REFERRER`. `PACKAGE_NAME` is `^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`; on the JVM,
 * `java.util.regex` recurses once per repetition of the group, so a long `a.a.a...` authority throws
 * `StackOverflowError`, which `guarded {}` (RuntimeException only) and `evaluate` do not catch.
 * **Characterisation, not a finding (docs/HARDENING.md H4):** not reproduced on device (emulator API 34, 24),
 * where `java.util.regex` is backed by ICU and returned normally for referrers up to 240 015 chars
 * (`HardeningDeviceTest.recordsH4LongReferrer`). JVM-only (java.util.regex recursion). This test records the JVM
 * behaviour and passes either way.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class CallerReferrerHardeningTest {

    private val policy = intentPolicy {
        entryPoint("partner") {
            allowedPackages { pkg("com.partner.app", "a".repeat(64)) }
        }
    }

    @Test
    fun characterisesH4LongReferrerOnTheJvm() {
        val lines = mutableListOf<String>()
        var overflowed = false
        for (pairs in listOf(1_000, 10_000, 50_000, 120_000)) {
            val referrer = "android-app://" + "a.".repeat(pairs) + "a"
            val sent = Intent("test.OPEN").putExtra(Intent.EXTRA_REFERRER_NAME, referrer)
            val p = Parcel.obtain()
            sent.writeToParcel(p, 0)
            val bytes = p.dataSize()
            p.recycle()
            val received = roundTrip(sent)
            val activity = Robolectric.buildActivity(Activity::class.java, received).create().get()
            var thrown: Throwable? = null
            var decision: Decision? = null
            val t = Thread(null, {
                try {
                    decision = ShezGuard.evaluate(activity, received, Delivery.LAUNCH, policy, "partner")
                } catch (e: Throwable) {
                    thrown = e
                }
            }, "main-like", 8L shl 20) // an Android main thread has an 8 MB stack
            t.start(); t.join()
            val line = "referrer of %7d chars (parcel %7d bytes): %s".format(referrer.length, bytes, thrown?.javaClass?.simpleName ?: "${decision?.outcome} ${decision?.violations?.map { it.code }}")
            println("[caller] $line")
            lines += line
            if (thrown != null) {
                overflowed = thrown is StackOverflowError
                break
            }
        }
        Hardening.report("caller-referrer.txt", "JVM/Robolectric SDK 34 only (characterisation; not reproduced on device).\n" + lines.joinToString("\n") + "\nJVM overflow observed: $overflowed\n")
    }
}
