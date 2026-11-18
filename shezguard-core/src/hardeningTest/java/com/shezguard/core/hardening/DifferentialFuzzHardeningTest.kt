package com.shezguard.core.hardening

import android.net.Uri
import com.shezguard.core.Decision
import com.shezguard.core.Outcome
import com.shezguard.core.ShezGuard
import com.shezguard.core.ViolationCode
import com.shezguard.core.canon.CanonResult
import com.shezguard.core.canon.UriCanonicalizer
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
 * Step 15, area 8: seeded differential fuzz, JVM (Robolectric SDK 34, AOSP `android.net.Uri`).
 *
 * Rerun: `./gradlew :shezguard-core:hardeningTest --tests '*DifferentialFuzzHardeningTest*'`; [SEED] and [COUNT]
 * are fixed; the generator is [generate] (grammar of token lists below) plus [mutate] (insert, delete,
 * duplicate, percent-encode, percent-decode). Results: build/hardening/fuzz.txt.
 *
 * For every **Allow**, compares ShezGuard's canonical view and `Decision.data` with `Uri.getHost`, `getPath`,
 * `getPathSegments`, `getQueryParameterNames`, `getQueryParameter`, `getQueryParameters`, `getFragment`,
 * and those accessors with each other. Categories documented in docs/LIMITATIONS.md (L11 plural `+`, host and
 * scheme case) are reported but do not fail the test; any other category fails it.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class DifferentialFuzzHardeningTest {

    companion object {
        const val SEED: Long = 0x5EED_0015
        const val COUNT: Int = 40_000

        /** Categories already documented: reported, not failed. */
        val KNOWN = mapOf(
            "PLURAL_PLUS" to "L11: getQueryParameters does not decode '+'",
            "URI_SELF_PLURAL_VS_SINGULAR" to "L11: getQueryParameters(n)[0] != getQueryParameter(n) because of '+'",
            "HOST_CASE" to "by design: canonical host is lowercased; getHost() keeps the sender's case",
        )

        /** Categories that are findings in docs/HARDENING.md: reported and failed. */
        val FINDINGS = mapOf("GETPATH_DUPLICATE_SLASH" to "finding H2: getPath() keeps '//', ShezGuard collapses it; Allow")
    }

    private val policy = intentPolicy {
        entryPoint("fz") {
            allowSchemes("https", "http", "myapp")
            allowHosts("example.com", "a.example.com")
            allowPorts(8443)
            anyPath()
            allowFragment()
            param("a") { string(CharClass.TEXT) }
            param("b") { string(CharClass.PRINTABLE_ASCII) }
            param("id") { string(CharClass.TEXT) }
            param("q") { string(CharClass.TEXT) }
            unknownParams(Unknown.Ignore)
            allowRepeatedParams()
        }
    }

    private val schemes = listOf("https", "https", "HTTPS", "Https", "http", "myapp", "hTtP")
    private val hosts = listOf("example.com", "example.com", "a.example.com", "EXAMPLE.com", "Example.Com", "A.EXAMPLE.COM")
    private val ports = listOf("", "", "", "", ":8443", ":443", ":80")
    private val segs = listOf(
        "", "a", "b", "product", "%41", "%2e", ".", "..", "..;", ";x=1", "a;b", "%3B", "%2F", "%5C", "+", "%2B", "%20",
        "~", "%7E", "@", ":", "!", "$", "'", "(", ")", "*", ",", "=", "&", "é", "%C3%A9", "%E2%82%AC", "%25", "%2525",
        "%3F", "%23", "a.b", "-", "_", "%5F", "€", "a%2Fb", "%2e%2e", "x%00", "evil.example",
    )
    private val names = listOf("a", "b", "id", "q", "x", "utm_source", "A", "a.b", "a-b", "q")
    private val values = listOf(
        "", "1", "a+b", "a%2Bb", "%20", "+", "%2B", "a%26b", "a%3Db", "=", "a=b", "%3F", "?", "/", "%2F", "%25", "é",
        "%C3%A9", "%E2%82%AC", "%7E", "~", "@", ":", ";", "'", "%22", "%3C", "%23", "!", "*", "(", ")", ",", "$", "[",
        "]", "%5B", "|", "^", "`", "a b", "%2B%2B", "++", "%2b",
    )
    private val frags = listOf("", "x", "a+b", "%20", "%23", "a?b", "/x", "é", "%E2%82%AC")
    private val mutAlphabet = "aZ09-._~!$&'()*+,;=:@/?#%[]\\ \t\"<>^`{|}é€ ​".toList()

    private fun <T> Random.pick(l: List<T>): T = l[nextInt(l.size)]

    private fun generate(r: Random): String {
        val sb = StringBuilder()
        sb.append(r.pick(schemes)).append("://").append(r.pick(hosts)).append(r.pick(ports))
        if (r.nextInt(10) == 0) sb.append("/")
        repeat(r.nextInt(0, 5)) { sb.append('/').append(r.pick(segs)) }
        if (r.nextInt(4) == 0) sb.append('/')
        if (r.nextInt(3) != 0) {
            sb.append('?')
            val pieces = List(r.nextInt(1, 5)) {
                when (r.nextInt(8)) {
                    0 -> r.pick(names)
                    1 -> r.pick(names) + "="
                    2 -> r.pick(names) + "=" + r.pick(values) + "=" + r.pick(values)
                    else -> r.pick(names) + "=" + r.pick(values) + (if (r.nextInt(4) == 0) r.pick(values) else "")
                }
            }
            sb.append(pieces.joinToString(if (r.nextInt(12) == 0) ";" else "&"))
        }
        if (r.nextInt(4) == 0) sb.append('#').append(r.pick(frags))
        return sb.toString()
    }

    private fun mutate(s0: String, r: Random): String {
        var s = s0
        repeat(r.nextInt(1, 4)) {
            val i = r.nextInt(s.length + 1)
            s = when (r.nextInt(5)) {
                0 -> s.substring(0, i) + r.pick(mutAlphabet) + s.substring(i)
                1 -> if (i < s.length) s.removeRange(i, i + 1) else s
                2 -> { val j = (i + r.nextInt(1, 6)).coerceAtMost(s.length); s.substring(0, j) + s.substring(i, j) + s.substring(j) }
                3 -> if (i < s.length) s.substring(0, i) + "%%%02X".format(s[i].code and 0xFF) + s.substring(i + 1) else s
                else -> {
                    val k = s.indexOf('%', i)
                    if (k >= 0 && k + 2 < s.length) {
                        val c = s.substring(k + 1, k + 3).toIntOrNull(16)
                        if (c != null) s.substring(0, k) + c.toChar() + s.substring(k + 3) else s
                    } else s
                }
            }
        }
        return s
    }

    private fun asciiLower(s: String?) = s?.map { if (it in 'A'..'Z') it + 32 else it }?.joinToString("")

    @Test
    fun allowedUrisAgreeAcrossShezGuardAndUriAccessors() {
        val r = Random(SEED)
        val hits = LinkedHashMap<String, MutableList<String>>()
        var allows = 0
        var blocks = 0
        var failed = 0
        fun hit(cat: String, s: String, detail: String) {
            val l = hits.getOrPut(cat) { mutableListOf() }
            l += "<$s> $detail"
        }
        repeat(COUNT) { n ->
            val s = if (n % 2 == 0) generate(r) else mutate(generate(r), r)
            val d = try {
                ShezGuard.evaluate(view(s), policy, "fz")
            } catch (t: Throwable) {
                hit("EVALUATE_THREW", s, t.javaClass.name); return@repeat
            }
            if (ViolationCode.EVALUATION_FAILED in Hardening.codes(d)) failed++
            if (d.outcome != Outcome.ALLOW) { blocks++; return@repeat }
            allows++
            d as Decision.Allow
            val c = (UriCanonicalizer.canonicalize(s, policy["fz"]!!.limits) as CanonResult.Ok).uri
            val u = Uri.parse(s)
            val g = d.data!!

            // ShezGuard's own views agree with each other
            if (g.path != c.path || g.host != c.host || g.pathSegments != c.pathSegments) hit("DECISION_VS_CANONICAL", s, "g=${g.path} c=${c.path}")

            // ShezGuard vs Uri
            val uPath = u.path
            val emptyOk = c.pathSegments.isEmpty() && !c.hasTrailingSlash && (uPath == null || uPath == "" || uPath == "/")
            if (!emptyOk && uPath != c.path) {
                // H2: duplicate slashes are collapsed in ShezGuard's view and kept by getPath()
                val collapsed = uPath?.replace(Regex("/{2,}"), "/")
                hit(if (collapsed == c.path) "GETPATH_DUPLICATE_SLASH" else "GETPATH_OTHER", s, "checked=${c.path} getPath=$uPath")
            }
            if (u.pathSegments != c.pathSegments) hit("GETPATHSEGMENTS", s, "checked=${c.pathSegments} uri=${u.pathSegments}")
            if (asciiLower(u.host) != c.host) hit("GETHOST", s, "checked=${c.host} getHost=${u.host}")
            else if (u.host != c.host) hit("HOST_CASE", s, "checked=${c.host} getHost=${u.host}")
            if (u.fragment != c.fragment) hit("GETFRAGMENT", s, "checked=${c.fragment} uri=${u.fragment}")
            val cNames = c.query.map { it.first }.toSet()
            if (u.queryParameterNames != cNames) hit("GETQUERYPARAMETERNAMES", s, "checked=$cNames uri=${u.queryParameterNames}")
            val rawPieces = (u.encodedQuery ?: "").split('&').filter { it.isNotEmpty() }
            for (name in cNames) {
                val all = c.query.filter { it.first == name }.map { it.second }
                // L11: what getQueryParameters returns (Uri.decode, '+' literal) vs getQueryParameter ('+' is a space)
                val raws = rawPieces.filter { it.substringBefore('=') == name }.map { if ('=' in it) it.substringAfter('=') else "" }
                val l11Plural = raws.map { Uri.decode(it) }
                val l11Single = raws.map { Uri.decode(it.replace("+", "%20")) }
                val single = u.getQueryParameter(name)
                val plural = u.getQueryParameters(name)
                if (single != all.first()) hit("GETQUERYPARAMETER", s, "$name checked=${all.first()} uri=$single")
                if (plural != all) hit(if (plural == l11Plural && all == l11Single) "PLURAL_PLUS" else "GETQUERYPARAMETERS", s, "$name checked=$all uri=$plural")
                if (plural.firstOrNull() != single) hit(if (plural.firstOrNull() == l11Plural.firstOrNull() && single == l11Single.firstOrNull()) "URI_SELF_PLURAL_VS_SINGULAR" else "URI_SELF_OTHER", s, "$name plural=$plural single=$single")
                if (name in g.paramNames && g.params(name) != all) hit("DECISION_PARAMS", s, "$name decision=${g.params(name)} checked=$all")
            }
            // Uri vs itself
            if (uPath != null) {
                val fromPath = uPath.split('/').filter { it.isNotEmpty() }
                if (fromPath != u.pathSegments) hit("URI_SELF_PATH_VS_SEGMENTS", s, "getPath=$uPath segments=${u.pathSegments}")
            }
            for (name in u.queryParameterNames) if (u.getQueryParameter(name) == null) hit("URI_SELF_NAME_NOT_FOUND", s, name)
        }

        val report = buildString {
            appendLine("Differential fuzz, JVM (Robolectric SDK 34, AOSP android.net.Uri). seed=0x${SEED.toString(16)} count=$COUNT")
            appendLine("generator: DifferentialFuzzHardeningTest.generate (grammar) on even n, mutate(generate) on odd n")
            appendLine("policy: schemes https/http/myapp, hosts example.com a.example.com, port 8443, anyPath, fragment, params a b id q, Unknown.Ignore, repeated allowed")
            appendLine("allow=$allows block=$blocks evaluation_failed=$failed")
            for ((cat, l) in hits) {
                appendLine()
                appendLine("== $cat: ${l.size} cases${KNOWN[cat]?.let { " (known, $it)" } ?: FINDINGS[cat]?.let { " ($it)" } ?: " (NEW)"}")
                l.take(8).forEach { appendLine("   $it") }
            }
        }
        Hardening.report("fuzz.txt", report)
        println(report)
        assertEquals(0, failed)
        val unknown = hits.filterKeys { it !in KNOWN }.mapValues { it.value.size }
        assertEquals("Allow with disagreeing views outside the documented categories (see build/hardening/fuzz.txt)", emptyMap<String, Int>(), unknown)
    }
}
