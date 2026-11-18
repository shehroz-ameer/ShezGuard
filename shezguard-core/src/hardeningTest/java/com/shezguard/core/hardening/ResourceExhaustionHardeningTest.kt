package com.shezguard.core.hardening

import android.content.Intent
import android.os.Parcel
import com.shezguard.core.Decision
import com.shezguard.core.Outcome
import com.shezguard.core.ShezGuard
import com.shezguard.core.hardening.Hardening.roundTrip
import com.shezguard.core.hardening.Hardening.view
import com.shezguard.core.policy.CharClass
import com.shezguard.core.policy.IntentPolicy
import com.shezguard.core.policy.PACKAGE_NAME
import com.shezguard.core.policy.Unknown
import com.shezguard.core.policy.intentPolicy
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Step 15, area 5: worst-case time and allocation. **JVM numbers only** (Robolectric SDK 34 on the build
 * machine's HotSpot JVM), indicative, not device numbers. Written to build/hardening/resource.txt.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ResourceExhaustionHardeningTest {

    companion object {
        private val lines = mutableListOf<String>()

        @JvmStatic
        @AfterClass
        fun writeReport() {
            Hardening.report(
                "resource.txt",
                "JVM only (Robolectric SDK 34, HotSpot ${System.getProperty("java.version")}, ${System.getProperty("os.arch")}); " +
                    "indicative, not device numbers.\n" + lines.joinToString("\n") + "\n",
            )
        }

        // java.lang.management is not on the Android compile classpath; it is on the JVM that runs the test.
        private val mx: Any = Class.forName("java.lang.management.ManagementFactory").getMethod("getThreadMXBean").invoke(null)!!
        private val allocated = Class.forName("com.sun.management.ThreadMXBean").getMethod("getThreadAllocatedBytes", Long::class.javaPrimitiveType)

        private fun allocatedBytes(): Long = allocated.invoke(mx, Thread.currentThread().id) as Long

        /** Median wall time (ms) and allocated bytes of the median run, over [reps] runs after one warm-up. */
        fun measure(label: String, reps: Int = 5, f: () -> Unit) {
            f()
            val runs = (1..reps).map {
                val a0 = allocatedBytes()
                val t0 = System.nanoTime()
                f()
                val t = (System.nanoTime() - t0) / 1e6
                t to (allocatedBytes() - a0)
            }.sortedBy { it.first }
            val (ms, bytes) = runs[runs.size / 2]
            val line = "%-78s median %9.2f ms   alloc %8.1f MB   (max %9.2f ms, n=%d)".format(label, ms, bytes / 1e6, runs.last().first, reps)
            println("[resource] $line")
            lines += line
        }
    }

    private fun policy(maxUri: Int? = null): IntentPolicy = intentPolicy {
        entryPoint("any") {
            allowSchemes("https")
            allowHosts("example.com")
            anyPath()
            param("q") { string(CharClass.TEXT) }
            unknownParams(Unknown.Ignore)
            if (maxUri != null) limits(maxUriLength = maxUri)
        }
        entryPoint("bare") { }
    }

    private fun distinctParams(n: Int) = "https://example.com/x?" + (0 until n).joinToString("&") { "p$it=1" }

    @Test
    fun measuresQueryWorstCasesAtTheDefaultLimit() {
        val p = policy()
        var n = 1
        while (distinctParams(n + 1).length <= 2048) n++
        val uri = distinctParams(n)
        assertEquals(Outcome.ALLOW, ShezGuard.evaluate(view(uri), p, "any").outcome)
        measure("default limit: ${uri.length}-char URI, $n distinct params (Allow)", reps = 51) { ShezGuard.evaluate(view(uri), p, "any") }
        val pct = "https://example.com/x?q=" + "%E2%82%AC".repeat((2048 - 24) / 9)
        measure("default limit: ${pct.length}-char URI, one value of %XX runs", reps = 51) { ShezGuard.evaluate(view(pct), p, "any") }
        val huge = distinctParams(50_000)
        measure("default limit: ${huge.length}-char URI (over the limit, still fully parsed)", reps = 5) {
            assertEquals(Outcome.BLOCK, ShezGuard.evaluate(view(huge), p, "any").outcome)
        }
    }

    /**
     * H8. Step 15 (before, historical): with `maxUriLength = 1_000_000`, 2 000 / 4 000 / 8 000 / 16 000 distinct
     * parameters took 19 / 75 / 299 / 1 100 ms (quadratic). Step 16 (after): `maxUriLength` is bounded at 8192 when the
     * policy is built; this records the worst case at the bound, and that the old setting is rejected.
     */
    @Test
    fun measuresParserMismatchWorstCaseAtTheUriLengthBound() {
        val rejected = try { policy(maxUri = 1_000_000); false } catch (e: com.shezguard.core.policy.PolicyDefinitionException) { true }
        lines += "H8 after: limits(maxUriLength = 1_000_000) rejected at build: $rejected"
        val p = policy(maxUri = 8192)
        // Densest URI: 1- and 2-char names from [A-Za-z0-9_.-] without values (same generator as the benchmark's
        // h8_cap_worst scenario). 4 000 distinct names do not fit in 8 192 chars.
        val alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
        val names = (alphabet.map { "$it" } + alphabet.flatMap { a -> alphabet.map { b -> "$a$b" } }).filter { it != "q" } // q is declared
        val sb = StringBuilder("https://example.com/x?")
        var n = 0
        for (name in names) {
            val piece = (if (n == 0) "" else "&") + name
            if (sb.length + piece.length > 8192) break
            sb.append(piece); n++
        }
        val uri = sb.toString()
        val d0 = ShezGuard.evaluate(view(uri), p, "any")
        assertEquals(d0.violations.map { it.code }.toSet().toString(), Outcome.ALLOW, d0.outcome)
        measure("H8 after: bound 8192, ${uri.length}-char URI, $n distinct params (Allow)", reps = 21) { ShezGuard.evaluate(view(uri), p, "any") }
    }

    @Test
    fun measuresHugeAndManyKeyBundles() {
        val p = policy()
        val many = Intent().apply { (0 until 50_000).forEach { putExtra("k$it", it) } }
        val p1 = Parcel.obtain()
        many.writeToParcel(p1, 0)
        val bytes1 = p1.dataSize()
        p1.recycle()
        measure("50000 int extras ($bytes1 parcel bytes): EXTRAS_TOO_MANY after a full keySet()", reps = 5) {
            ShezGuard.evaluate(roundTrip(many), p, "bare")
        }
        measure("(baseline: the Parcel round trip alone for the same intent)", reps = 5) { roundTrip(many) }
        val big = Intent().putExtra("blob", IntArray(240_000))
        measure("one unknown IntArray(240000) extra (~960 KB): read, then removed (Sanitize)", reps = 5) {
            assertEquals(Outcome.SANITIZE, ShezGuard.evaluate(roundTrip(big), p, "bare").outcome)
        }
    }

    /** Measurement only, no overflow (H4's JVM regex overflow is historical, docs/HARDENING.md; not reproduced on device). */
    @Test
    fun measuresRegexOnAttackerControlledReferrer() {
        for ((label, input) in listOf("'aaaa...!'" to "a".repeat(1_000_000) + "!", "'a.a.a...!'" to "a.".repeat(1_000) + "!")) {
            measure("PACKAGE_NAME regex on a ${input.length}-char $label referrer authority", reps = 5) { PACKAGE_NAME.matches(input) }
        }
    }

    // H1 (evaluateMustNotCrashOnDeeplyNestedListExtraTheAppNeverReads): the proof moved in step 16 to the device-only
    // DeepNesting*DeviceTest classes in src/androidTest. Standing rule: overflow tests never run under Robolectric.

    // ---- H1 detail (review question 3): which frames recurse, and at what depth on the JVM ----------------

    private fun deepIntent(depth: Int, leaf: Any = "leaf"): Pair<Intent, Int> {
        var out: Intent? = null
        var size = 0
        val t = Thread(null, {
            var v: Any = arrayListOf(leaf)
            repeat(depth) { v = arrayListOf(v) }
            val sent = view("https://example.com/x").putExtra("deep", v as java.io.Serializable)
            val p = Parcel.obtain()
            sent.writeToParcel(p, 0)
            size = p.dataSize()
            p.recycle()
            out = roundTrip(sent)
        }, "attacker", 2L shl 30)
        t.start(); t.join()
        return out!! to size
    }

    /**
     * The frames come from a leaf Parcelable whose CREATOR records the stack at the deepest point, **without any
     * overflow** (standing rule: overflow tests never run under Robolectric).
     */
    @Test
    fun measuresH1OverflowDepthAndRecursingFrames() {
        val p = policy()
        val found = mutableListOf<String>()
        val sizes = listOf(50, 100).associateWith { d ->
            DepthProbe.lastTrace = null
            ShezGuard.evaluate(deepIntent(d, DepthProbe()).first, p, "any")
            DepthProbe.lastTrace!!
        }
        val perLevel = (sizes.getValue(100).size - sizes.getValue(50).size) / 50.0
        found += "H1 JVM frames per nesting level: %.1f (stack at the leaf: %d frames at depth 50, %d at depth 100)".format(perLevel, sizes.getValue(50).size, sizes.getValue(100).size)
        found += "H1 JVM " + DepthProbe.describe(sizes.getValue(50))
        // The overflow-depth grid was removed in step 16: overflow tests never run under Robolectric (standing rule,
        // docs/HARDENING.md). Step 15's JVM numbers are kept there as historical; the depths come from the emulators.
        found.forEach { println("[resource] $it") }
        lines += found
    }

    /** H8 detail: where the time goes at the bound (canonicaliser, parser-mismatch check, policy validator), JVM. */
    @Test
    fun measuresH8BreakdownAtTheBound() {
        val alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
        val names = (alphabet.map { "$it" } + alphabet.flatMap { a -> alphabet.map { b -> "$a$b" } }).filter { it != "q" }
        for ((bound, valued) in listOf(8192 to false, 8192 to true, 2048 to false, 2048 to true)) {
            val label = "limit $bound, " + if (valued) "with =1 values" else "no values"
            val sb = StringBuilder("https://example.com/x?")
            var n = 0
            for (name in names) {
                val piece = (if (n == 0) "" else "&") + name + (if (valued) "=1" else "")
                if (sb.length + piece.length > bound) break
                sb.append(piece); n++
            }
            val uri = sb.toString()
            val ep = policy(maxUri = bound)["any"]!!
            val c = (com.shezguard.core.canon.UriCanonicalizer.canonicalize(uri, ep.limits) as com.shezguard.core.canon.CanonResult.Ok).uri
            val view = com.shezguard.core.android.AndroidUriView(android.net.Uri.parse(uri))
            measure("H8 breakdown ($label, $n params): canonicalize", reps = 5) { com.shezguard.core.canon.UriCanonicalizer.canonicalize(uri, ep.limits) }
            measure("H8 breakdown ($label, $n params): ParserMismatch.check", reps = 5) { com.shezguard.core.eval.ParserMismatch.check(c, view, ep) }
            measure("H8 breakdown ($label, $n params): getQueryParameter per name only", reps = 5) {
                val u = android.net.Uri.parse(uri); c.query.forEach { u.getQueryParameter(it.first) }
            }
            measure("H8 breakdown ($label, $n params): UriPolicyValidator.validate", reps = 5) { com.shezguard.core.validate.UriPolicyValidator.validate(c, ep) }
            val pol = policy(maxUri = bound)
            measure("H8 breakdown ($label, $n params): full ShezGuard.evaluate", reps = 5) { ShezGuard.evaluate(view(uri), pol, "any") }
        }
    }
}
