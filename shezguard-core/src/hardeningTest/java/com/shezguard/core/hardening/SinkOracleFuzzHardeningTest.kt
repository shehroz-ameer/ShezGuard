package com.shezguard.core.hardening

import android.net.Uri
import com.shezguard.core.Decision
import com.shezguard.core.ShezGuard
import com.shezguard.core.hardening.Hardening.view
import com.shezguard.core.policy.CharClass
import com.shezguard.core.policy.Unknown
import com.shezguard.core.policy.intentPolicy
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import kotlin.random.Random

/**
 * Step 15 follow-up (review item 5): seeded differential fuzz with **sink-model oracles**, JVM only
 * (Robolectric SDK 34, AOSP `android.net.Uri`).
 *
 * Rerun: `./gradlew :shezguard-core:hardeningTest --tests '*SinkOracleFuzzHardeningTest*'`. Seeds [SEEDS], [COUNT]
 * inputs per seed, generator [generate] + [mutate]. Every input is evaluated against two entry points, `anyPath`
 * ("any") and `prefix("/product/")` ("prefix"). For each **Allow**:
 * - **Resolution oracle** (`java.net.URI.resolve` semantics): resolve the app's `Uri.getPath()` and ShezGuard's
 *   checked path (`Decision.data.path`) against `https://<checked host>/`; the resulting host must be the checked host.
 *   A different host from `getPath()` is **H2-like**; from the checked path it is **new**.
 * - **Servlet oracle** (prefix entry point only): take `Uri.getEncodedPath()`, strip `;params` from each segment,
 *   percent-decode each segment, collapse empty segments, remove dot segments; the result must still start with
 *   `/product/`. An escape is **H3-like**.
 * Any other disagreement class is reported as **new**. Results: build/hardening/sink-fuzz.txt.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class SinkOracleFuzzHardeningTest {

    companion object {
        val SEEDS: List<Long> = listOf(0x51_4B_0001, 0x51_4B_0002)
        const val COUNT: Int = 400_000 // 10x the first fuzz run (40 000)
        const val PREFIX = "/product/"
    }

    private val policy = intentPolicy {
        for ((name, prefix) in listOf("any" to false, "prefix" to true)) {
            entryPoint(name) {
                allowSchemes("https", "http")
                allowHosts("example.com", "a.example.com")
                if (prefix) path { prefix(PREFIX) } else anyPath()
                allowFragment()
                param("a") { string(CharClass.TEXT) }
                param("q") { string(CharClass.PRINTABLE_ASCII) }
                unknownParams(Unknown.Ignore)
                allowRepeatedParams()
            }
        }
    }

    private val schemes = listOf("https", "https", "HTTPS", "http")
    private val hosts = listOf("example.com", "example.com", "a.example.com", "EXAMPLE.com")
    private val segs = listOf(
        // first-run tokens
        "", "a", "b", "product", "%41", "%2e", ".", "..", "~", "@", ":", "!", "$", "'", "(", ")", "*", ",", "=", "&",
        "é", "%C3%A9", "%25", "%3F", "%23", "a.b", "-", "_", "evil.example", "+", "%2B", "%20",
        // review item 5: matrix parameters, '//' and encoded slashes
        ";", ";x=1", "a;b", "..;", ".;", "..;x=1", ";jsessionid=abc", "%3B", "..%3B", "%2e%2e;", ".%2e;", "x;/..",
        "%2F", "%2f", "a%2Fb", "%2F..%2F", "%252F", "/", "//", "evil.example;", "..;/..;",
    )
    private val values = listOf("1", "a+b", "%2B", "/", "%2F", "//evil.example", ";", "..;", "é", "%20")
    private val mutAlphabet = "aZ09-._~!$&'()*+,;=:@/?#%".toList()

    private fun <T> Random.pick(l: List<T>): T = l[nextInt(l.size)]

    private fun generate(r: Random): String {
        val sb = StringBuilder()
        sb.append(r.pick(schemes)).append("://").append(r.pick(hosts))
        when (r.nextInt(10)) {
            in 0..5 -> sb.append(PREFIX)
            6 -> sb.append("/")
            7 -> sb.append("//")
            else -> Unit
        }
        repeat(r.nextInt(0, 6)) { if (sb.last() != '/' || r.nextInt(3) == 0) sb.append('/'); sb.append(r.pick(segs)) }
        if (r.nextInt(4) == 0) sb.append('/')
        if (r.nextInt(3) == 0) sb.append("?").append(listOf("a", "q", "x").let { r.pick(it) }).append('=').append(r.pick(values))
        return sb.toString()
    }

    private fun mutate(s0: String, r: Random): String {
        var s = s0
        repeat(r.nextInt(1, 3)) {
            val i = r.nextInt(s.length + 1)
            s = when (r.nextInt(3)) {
                0 -> s.substring(0, i) + r.pick(mutAlphabet) + s.substring(i)
                1 -> if (i < s.length) s.removeRange(i, i + 1) else s
                else -> s.substring(0, i) + r.pick(listOf("//", ";", "..;", "%2F", "/../", ";x=1/")) + s.substring(i)
            }
        }
        return s
    }

    /** Tomcat/Spring-style: strip `;params` per segment, decode, collapse empty segments, remove dot segments. */
    private fun servletPath(encodedPath: String?): String {
        val out = ArrayList<String>()
        for (raw in (encodedPath ?: "").split('/')) {
            val seg = Uri.decode(raw.substringBefore(';'))
            when (seg) {
                "", "." -> Unit
                ".." -> if (out.isNotEmpty()) out.removeAt(out.size - 1)
                else -> out += seg
            }
        }
        val trailing = encodedPath?.endsWith("/") == true && out.isNotEmpty()
        return "/" + out.joinToString("/") + if (trailing) "/" else ""
    }

    private fun resolveHost(host: String, path: String?): String? = try {
        java.net.URI("https://$host/").resolve(java.net.URI(null, null, path ?: "", null)).host
    } catch (e: Exception) {
        "<unresolvable: ${e.javaClass.simpleName}>"
    }

    @Test
    fun allowedPathsStayOnHostAndInsidePrefixUnderSinkModels() {
        val report = StringBuilder()
        val total = LinkedHashMap<String, Int>()
        for (seed in SEEDS) {
            val r = Random(seed)
            val hits = LinkedHashMap<String, MutableList<String>>()
            val allows = mutableMapOf("any" to 0, "prefix" to 0)
            fun hit(c: String, line: String) { hits.getOrPut(c) { mutableListOf() } += line }
            val t0 = System.nanoTime()
            repeat(COUNT) { n ->
                val s = if (n % 2 == 0) generate(r) else mutate(generate(r), r)
                for (ep in listOf("any", "prefix")) {
                    val d = ShezGuard.evaluate(view(s), policy, ep) as? Decision.Allow ?: continue
                    allows[ep] = allows.getValue(ep) + 1
                    val g = d.data!!
                    val u = Uri.parse(s)
                    val fromApp = resolveHost(g.host, u.path)
                    when {
                        fromApp == g.host -> Unit
                        fromApp?.startsWith("<unresolvable") == true || fromApp == null ->
                            hit("H2-related (getPath starts with '//' but names no authority; java.net.URI cannot resolve it)", "$ep <$s> getPath=${u.path} -> $fromApp")
                        else -> hit("H2-like (getPath resolves to another host), entry point $ep", "$ep <$s> getPath=${u.path} -> host $fromApp")
                    }
                    val fromChecked = resolveHost(g.host, g.path)
                    if (fromChecked != g.host) hit("NEW (checked path resolves to another host)", "$ep <$s> checked=${g.path} -> host $fromChecked")
                    if (ep == "prefix") {
                        val sp = servletPath(u.encodedPath)
                        when {
                            sp.startsWith(PREFIX) -> Unit
                            sp == PREFIX.dropLast(1) -> hit("H3-boundary (normalises to ${PREFIX.dropLast(1)}, the prefix without its slash)", "<$s> encodedPath=${u.encodedPath} -> $sp")
                            else -> hit("H3-like (servlet normalisation escapes $PREFIX)", "<$s> encodedPath=${u.encodedPath} -> $sp")
                        }
                        if (!g.path.startsWith(PREFIX)) hit("NEW (checked path outside prefix)", "<$s> checked=${g.path}")
                    }
                }
            }
            val secs = (System.nanoTime() - t0) / 1e9
            report.appendLine("seed=0x${seed.toString(16)} count=$COUNT inputs (x2 entry points) in %.1f s; allow any=${allows["any"]} prefix=${allows["prefix"]}".format(secs))
            for ((c, l) in hits) {
                report.appendLine("  == $c: ${l.size}")
                l.take(6).forEach { report.appendLine("     $it") }
                total.merge(c, l.size, Int::plus)
            }
            if (hits.isEmpty()) report.appendLine("  (no disagreement)")
        }
        val head = "Sink-oracle fuzz, JVM only (Robolectric SDK 34). generator: SinkOracleFuzzHardeningTest.generate on even n, mutate(generate) on odd n.\n"
        Hardening.report("sink-fuzz.txt", head + report)
        println(head + report)
        assertEquals("Allows that a sink model resolves elsewhere (see build/hardening/sink-fuzz.txt)", emptyMap<String, Int>(), total)
    }
}
