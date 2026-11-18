package com.shezguard.core.device

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Parcel
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.shezguard.core.Decision
import com.shezguard.core.Delivery
import com.shezguard.core.ShezGuard
import com.shezguard.core.device.probe.HostActivity
import com.shezguard.core.eval.ExtrasFixtures.received
import com.shezguard.core.policy.CharClass
import com.shezguard.core.policy.PACKAGE_NAME
import com.shezguard.core.policy.intentPolicy
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Step 15 follow-up, device-only reproducers for docs/HARDENING.md H1, H2 and H4. They RECORD what happens
 * (tagged `[H1]`, `[H2]`, `[H4]`) and pass either way; the docs state the result per API level.
 *
 * - The received intent is a Parcel round trip with the app's class loader set (`ExtrasFixtures.received`), as
 *   `ActivityThread` delivers it; no real binder IPC.
 * - ShezGuard runs on the real main thread (`runOnMainSync`), whose stack size is the one an app gets.
 * - The attacker-side parcel is built on a thread with a large stack (writing a nested List also recurses).
 */
@RunWith(AndroidJUnit4::class)
class HardeningDeviceTest {

    private val sdk = Build.VERSION.SDK_INT
    private val inst = InstrumentationRegistry.getInstrumentation()

    private val policy = intentPolicy {
        entryPoint("any") {
            allowSchemes("https")
            allowHosts("example.com")
            anyPath()
            param("q") { string(CharClass.TEXT) }
        }
        entryPoint("partner") {
            allowedPackages { pkg("com.partner.app", "a".repeat(64)) }
        }
    }

    private fun onMain(block: () -> Unit): Throwable? {
        var thrown: Throwable? = null
        inst.runOnMainSync { try { block() } catch (t: Throwable) { thrown = t } }
        return thrown
    }

    private fun deepIntent(depth: Int, leaf: Any = "leaf"): Pair<Intent, Int> {
        var out: Intent? = null
        var size = 0
        var failure: Throwable? = null
        val t = Thread(null, {
            try {
                var v: Any = arrayListOf(leaf)
                repeat(depth) { v = arrayListOf(v) }
                val sent = Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com/x")).putExtra("deep", v as java.io.Serializable)
                val p = Parcel.obtain()
                sent.writeToParcel(p, 0)
                size = p.dataSize()
                p.recycle()
                out = received(sent)
            } catch (e: Throwable) {
                failure = e
            }
        }, "attacker", 512L shl 20)
        t.start(); t.join()
        failure?.let { throw AssertionError("attacker-side build failed at depth $depth: ${it.javaClass.simpleName}") }
        return out!! to size
    }

    private fun name(t: Throwable?): String = t?.javaClass?.simpleName ?: "ok"

    /** H1: depth at which `evaluate` overflows on the main thread, the recursing frames, and app-only reads. */
    @Test
    fun recordsH1DeepListOverflowOnMainThread() {
        // Frames without an overflow: a leaf Parcelable records the stack at the deepest point (depth 50 and 100).
        val traces = listOf(50, 100).associateWith { d ->
            DepthProbe.lastTrace = null
            onMain { ShezGuard.evaluate(deepIntent(d, DepthProbe()).first, policy, "any") }
            DepthProbe.lastTrace
        }
        val t50 = traces.getValue(50)
        val t100 = traces.getValue(100)
        if (t50 != null && t100 != null) {
            println("[H1] sdk=$sdk frames per nesting level: %.1f (stack at the leaf: %d at depth 50, %d at depth 100)".format((t100.size - t50.size) / 50.0, t50.size, t100.size))
            println("[H1] sdk=$sdk ${DepthProbe.describe(t50)}")
        } else {
            println("[H1] sdk=$sdk leaf probe CREATOR did not run (depth 50: ${t50 != null}, depth 100: ${t100 != null})")
        }
        onMain { ShezGuard.evaluate(deepIntent(10).first, policy, "any") } // warm-up
        fun crashes(d: Int) = onMain { ShezGuard.evaluate(deepIntent(d).first, policy, "any") } is StackOverflowError
        var lo = 10
        val grid = listOf(500, 1_000, 2_000, 5_000, 10_000, 20_000, 40_000, 80_000)
        val firstCrash = grid.firstOrNull { crashes(it).also { c -> if (!c) lo = it } }
        if (firstCrash == null) {
            println("[H1] sdk=$sdk evaluate did not overflow up to depth ${grid.last()} (parcel ${deepIntent(grid.last()).second} bytes)")
            return
        }
        var hi: Int = firstCrash
        var steps = 0
        while (hi - lo > maxOf(10, lo / 100) && steps++ < 8) {
            val mid = (lo + hi) / 2
            if (crashes(mid)) hi = mid else lo = mid
        }
        val (intent, bytes) = deepIntent(hi)
        val soe = onMain { ShezGuard.evaluate(intent, policy, "any") }
        @Suppress("DEPRECATION")
        val bundleGet = onMain { deepIntent(hi).first.extras!!.get("deep") }
        val appData = onMain { deepIntent(hi).first.let { it.data; it.action } }
        val appOther = onMain { deepIntent(hi).first.getStringExtra("other") }
        println("[H1] sdk=$sdk main thread: evaluate ok at depth $lo, ${name(soe)} at depth $hi (parcel $bytes bytes)")
        println("[H1] sdk=$sdk at depth $hi: Bundle.get alone ${name(bundleGet)}; app reads data/action ${name(appData)}; app reads another extra ${name(appOther)}")
    }

    /** H2: Allow with a getPath() that keeps `//`, and what URL resolution makes of it. */
    @Test
    fun recordsH2DoubleSlashPath() {
        for (s in listOf("https://example.com//evil.example/landing", "https://example.com/a//b")) {
            val intent = received(Intent(Intent.ACTION_VIEW, Uri.parse(s)))
            val d = ShezGuard.evaluate(intent, policy, "any")
            val checked = (d as? Decision.Allow)?.data?.path
            val appPath = intent.data!!.path
            val resolved = java.net.URI("https://example.com/").resolve(appPath)
            println("[H2] sdk=$sdk <$s> ${d.outcome} ${d.violations.map { it.code }} checked=$checked getPath=$appPath resolves=$resolved")
        }
    }

    /** H4: a long caller-chosen referrer through ActivityCallerSource, on the main thread; and the regex alone. */
    @Test
    fun recordsH4LongReferrer() {
        val host = inst.startActivitySync(
            Intent(inst.targetContext, HostActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK),
        ) as Activity
        try {
            for (pairs in listOf(1_000, 10_000, 50_000, 120_000)) {
                val referrer = "android-app://" + "a.".repeat(pairs) + "a"
                val intent = received(Intent("test.OPEN").putExtra(Intent.EXTRA_REFERRER_NAME, referrer))
                var d: Decision? = null
                val t = onMain { d = ShezGuard.evaluate(host, intent, Delivery.LAUNCH, policy, "partner") }
                val regex = onMain { PACKAGE_NAME.matches(referrer.removePrefix("android-app://")) }
                println(
                    "[H4] sdk=$sdk referrer ${referrer.length} chars: evaluate ${t?.let { name(it) } ?: "${d?.outcome} ${d?.violations?.map { it.code }}"}; " +
                        "PACKAGE_NAME.matches alone ${regex?.let { "${name(it)}: ${it.message?.take(80)}" } ?: "returned"}",
                )
            }
        } finally {
            inst.runOnMainSync { host.finish() }
        }
    }
}
