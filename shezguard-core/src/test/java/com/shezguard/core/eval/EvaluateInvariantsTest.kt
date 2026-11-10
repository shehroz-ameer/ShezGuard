package com.shezguard.core.eval

import android.content.Intent
import android.net.Uri
import com.shezguard.core.Decision
import com.shezguard.core.Outcome
import com.shezguard.core.ShezGuard
import com.shezguard.core.ViolationCode
import com.shezguard.core.canon.CanonResult
import com.shezguard.core.canon.UriCanonicalizer
import com.shezguard.core.eval.EvalFixtures.entryPointNames
import com.shezguard.core.eval.EvalFixtures.policy
import com.shezguard.core.eval.EvalFixtures.renderedOutput
import com.shezguard.core.eval.EvalFixtures.summary
import com.shezguard.core.eval.EvalFixtures.viewIntent
import com.shezguard.core.policy.Limits
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import kotlin.random.Random

/**
 * Properties that must hold for every input: the input Intent is never modified, the same
 * input always gives the same Decision, evaluate() never throws (and never needs the
 * EVALUATION_FAILED safety net on the fuzz corpus), and no Decision output contains raw
 * URI or parameter values.
 */
@RunWith(RobolectricTestRunner::class)
class EvaluateInvariantsTest {

    // ---- Fixed-seed fuzz corpus ------------------------------------------------------

    private val tokens = listOf(
        "https://", "http://", "HTTPS://", "myapp://", "intent:", "javascript:", "https:", "//",
        "example.com", "EXAMPLE.COM", "evil.com", "example.com.evil.com", "exаmple.com", "[::1]",
        "@", ":", ":443", ":8443", ":0", ":99999", "/", "\\", "?", "#", "&", "=", ";", "%", "+", " ",
        "%2e", "%2E", "%252e", "%2F", "%5C", "%00", "%0d%0a", "%E2%80%AE", "%C0%AE", "%ZZ", "%2", "%25",
        "%3F", "%23", "%26", "%3D", "%20", "%2B", "%C3%A9", "..", ".", "product", "product/", "search",
        "id", "q", "ref", "next", "utm", "42", "a", "\u0000", "\n", "‮", "​", "\uD800", "é",
        "／", "∕", " ", "￿", "a".repeat(300), "id=1", "q=x", "next=https%3A%2F%2Fevil.com",
    )

    private fun randomUriString(r: Random): String {
        val sb = StringBuilder()
        when (r.nextInt(4)) {
            0, 1 -> sb.append("https://example.com/")
            2 -> sb.append("https://example.com/product/1?id=1")
            else -> Unit
        }
        repeat(r.nextInt(1, 12)) {
            if (r.nextInt(10) == 0) sb.append(r.nextInt(0, 0xFFFF).toChar()) else sb.append(tokens[r.nextInt(tokens.size)])
        }
        return sb.toString()
    }

    /** Mostly well-formed links with a mix of declared and undeclared parameters, so every outcome is reached. */
    private fun structuredUriString(r: Random): String {
        val path = listOf("search", "x/y", "product/1", "product/1/")[r.nextInt(4)]
        val names = listOf("q", "id", "ref", "next", "utm", "fbclid", "a.b", "x-y")
        val values = listOf("1", "42", "a+b", "%20", "%2B", "shoes", "", "abc-1") + tokens
        val query = List(r.nextInt(0, 5)) {
            val v = if (r.nextInt(3) == 0) values[r.nextInt(values.size)] else values[r.nextInt(8)]
            names[r.nextInt(names.size)] + "=" + v
        }.joinToString("&")
        val fragment = listOf("", "", "#f", "#" + tokens[r.nextInt(tokens.size)])[r.nextInt(4)]
        return "https://example.com/$path" + (if (query.isEmpty()) "" else "?$query") + fragment
    }

    private fun randomIntent(r: Random): Intent = when (r.nextInt(20)) {
        0 -> Intent(Intent.ACTION_VIEW) // no data
        1, 2 -> {
            val b = Uri.Builder().scheme(listOf("https", "http", "myapp", "")[r.nextInt(4)])
                .authority(tokens[r.nextInt(tokens.size)])
            repeat(r.nextInt(4)) { b.appendPath(tokens[r.nextInt(tokens.size)]) }
            repeat(r.nextInt(4)) { b.appendQueryParameter(tokens[r.nextInt(tokens.size)], tokens[r.nextInt(tokens.size)]) }
            if (r.nextBoolean()) b.fragment(tokens[r.nextInt(tokens.size)])
            Intent(Intent.ACTION_VIEW, b.build())
        }
        3 -> Intent(Intent.ACTION_VIEW, Uri.fromParts("https", tokens[r.nextInt(tokens.size)], tokens[r.nextInt(tokens.size)]))
        4, 5, 6 -> viewIntent(structuredUriString(r))
        else -> viewIntent(randomUriString(r))
    }

    private val fuzzCount = 4000

    @Test
    fun evaluateNeverThrowsOnFuzzedIntents() {
        val r = Random(0x5EED_5B)
        val outcomes = HashMap<Outcome, Int>()
        repeat(fuzzCount) { i ->
            val intent = randomIntent(r)
            val ep = entryPointNames[r.nextInt(entryPointNames.size)]
            val d = ShezGuard.evaluate(intent, policy, ep)
            assertFalse(
                "EVALUATION_FAILED on fuzz case $i (ep=$ep, data=${intent.dataString?.let(::escape)})",
                d.violations.any { it.code == ViolationCode.EVALUATION_FAILED },
            )
            outcomes.merge(d.outcome, 1, Int::plus)
        }
        // The corpus must reach every outcome, or it is not exercising the pipeline.
        println("[fuzz] seed=0x5EED5B n=$fuzzCount outcomes=$outcomes")
        assertEquals(Outcome.entries.toSet(), outcomes.keys)
    }

    @Test
    fun sameInputAlwaysGivesSameDecision() {
        val r = Random(0xD5_7E)
        repeat(1000) {
            val intent = randomIntent(r)
            val ep = entryPointNames[r.nextInt(entryPointNames.size)]
            val first = summary(ShezGuard.evaluate(intent, policy, ep))
            val copy = Intent(intent)
            assertEquals(first, summary(ShezGuard.evaluate(intent, policy, ep)))
            assertEquals(first, summary(ShezGuard.evaluate(copy, policy, ep)))
        }
    }

    @Test
    fun inputIntentIsNeverModified() {
        val r = Random(0x1D_E7)
        repeat(1000) {
            val intent = randomIntent(r).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                addCategory(Intent.CATEGORY_BROWSABLE)
                putExtra("k", "v")
            }
            val before = snapshot(intent)
            val dataRef = intent.data
            ShezGuard.evaluate(intent, policy, entryPointNames[r.nextInt(entryPointNames.size)])
            assertTrue(dataRef === intent.data)
            assertEquals(before, snapshot(intent))
        }
    }

    /** Test-only snapshot; reading the extra here is the test's doing, not ShezGuard's. */
    private fun snapshot(i: Intent): List<Any?> =
        listOf(i.action, i.dataString, i.type, i.flags, i.categories?.toSet(), i.component, i.`package`, i.getStringExtra("k"))

    @Test
    fun sanitizedIntentAlwaysReCanonicalisesToTheRetainedQuery() {
        val r = Random(0x5A_17)
        var sanitized = 0
        repeat(3000) {
            val raw = "https://example.com/search?" + List(r.nextInt(1, 6)) {
                val name = listOf("q", "utm", "fbclid", "a.b", "x-y", "Q")[r.nextInt(6)]
                val value = listOf("", "1", "a+b", "%20", "%2B", "x%26y", "%3D", "caf%C3%A9")[r.nextInt(8)]
                if (r.nextInt(5) == 0) name else "$name=$value"
            }.joinToString("&") + listOf("", "#f", "#a%20b", "#")[r.nextInt(4)]
            val d = ShezGuard.evaluate(viewIntent(raw), policy, "search")
            if (d is Decision.Sanitize) {
                sanitized++
                val again = UriCanonicalizer.canonicalize(d.sanitizedIntent.dataString!!, Limits.DEFAULT)
                assertTrue(raw, again is CanonResult.Ok)
                assertTrue(raw, (again as CanonResult.Ok).uri.query.none { it.first != "q" })
            }
        }
        assertTrue("corpus produced no Sanitize decisions", sanitized > 100)
    }

    // ---- Redaction ---------------------------------------------------------------------

    @Test
    fun noDecisionOutputContainsRawUriOrParamValues() {
        val marker = "zqx"
        val cases = listOf(
            "product" to "https://example.com/product/${marker}p?id=1&ref=${marker}v",                 // Allow
            "product" to "https://example.com/product/${marker}p?id=${marker}&${marker}n=${marker}v",   // Block
            "product" to "https://${marker}h.example.com/${marker}p?${marker}n=1#${marker}f",           // Block
            "product" to "https://example.com/product/%252e${marker}?id=1%00${marker}",                 // Block (canon)
            "search" to "https://example.com/search?q=${marker}v&${marker}n=1#${marker}f",              // Sanitize
            "browse" to "https://example.com/${marker}p/?q=${marker}v&${marker}n=${marker}v",           // Allow + ignored
            "nodata" to "https://example.com/${marker}",                                                // DATA_FORBIDDEN
            "notRegistered" to "https://example.com/${marker}",                                         // unknown ep
        )
        val seen = HashSet<Outcome>()
        for ((ep, uri) in cases) {
            val d = ShezGuard.evaluate(viewIntent(uri), policy, ep)
            seen += d.outcome
            val out = renderedOutput(d)
            assertFalse("raw value leaked for <$uri>: $out", out.contains(marker, ignoreCase = true))
        }
        assertEquals(Outcome.entries.toSet(), seen)
    }

    private fun escape(s: String): String =
        s.map { if (it.code in 0x20..0x7E) it.toString() else "\\u%04X".format(it.code) }.joinToString("")
}
