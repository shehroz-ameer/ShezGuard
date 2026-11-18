package com.shezguard.core.hardening

import com.shezguard.core.Decision
import com.shezguard.core.Outcome
import com.shezguard.core.ShezGuard
import com.shezguard.core.android.ActivityCallerSource
import com.shezguard.core.hardening.Hardening.view
import com.shezguard.core.policy.CharClass
import com.shezguard.core.policy.IntentPolicy
import com.shezguard.core.policy.intentPolicy
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.MessageDigest
import java.util.Locale

/** Step 15, area 2: canonicaliser attacks (Robolectric SDK 34, real AOSP `android.net.Uri`). */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class CanonicaliserHardeningTest {

    private fun policy(): IntentPolicy = intentPolicy {
        entryPoint("product") {
            allowSchemes("https")
            allowHosts("example.com")
            path { prefix("/product/") }
            param("id") { digitsOnly(maxLength = 10) }
            param("name") { oneOf("café") }
            param("next") { url { allowSchemes("https"); allowHosts("example.com") } }
        }
        entryPoint("any") {
            allowSchemes("https")
            allowHosts("example.com", "links.example.com")
            anyPath()
            param("q") { string(CharClass.TEXT) }
        }
    }

    private val policy = policy()

    private fun eval(uri: String, ep: String, p: IntentPolicy = policy): Decision = ShezGuard.evaluate(view(uri), p, ep)

    private fun notBlocked(cases: List<String>, ep: String): List<String> =
        cases.filter { eval(it, ep).outcome != Outcome.BLOCK }

    // ---- H: path prefix vs `;` path parameters ------------------------------------------------------------

    /**
     * Finding. A prefix pattern is documented as confining the path to a segment boundary, and `..` segments
     * (raw and encoded) are rejected. A segment `..;` (or `..;jsessionid=x`) is not `..` to ShezGuard or to
     * `android.net.Uri`, but servlet-style path normalisation (Tomcat, Spring, many Java backends) strips the
     * `;...` path parameter and then resolves `..`. An app that loads the allowed path on its own origin in a
     * WebView or forwards it to such a backend therefore escapes `/product/`.
     */
    @Test
    fun blocksMatrixParamDotDotSegmentEscapingPathPrefix() {
        val cases = listOf(
            "https://example.com/product/..;/admin",
            "https://example.com/product/..;jsessionid=1/admin",
            "https://example.com/product/%2e%2e;/admin",
            "https://example.com/product/..%3B/admin",
            "https://example.com/product/.;/..;/admin",
        )
        assertEquals("allowed under prefix(\"/product/\"), but resolve outside it in a servlet-style sink", emptyList<String>(), notBlocked(cases, "product"))
    }

    // ---- negative results ---------------------------------------------------------------------------------

    @Test
    fun holdsUnderTurkishDefaultLocale() {
        val saved = Locale.getDefault()
        try {
            Locale.setDefault(Locale("tr", "TR"))
            val p = policy() // built under tr as well
            assertEquals(Outcome.ALLOW, eval("HTTPS://LINKS.EXAMPLE.COM/INFO?q=I", "any", p).outcome)
            assertEquals("links.example.com", (eval("HTTPS://LINKS.EXAMPLE.COM/x", "any", p) as Decision.Allow).data!!.host)
            // dotless ı, dotted İ, and the Kelvin sign never fold into an allowed ASCII host
            for (h in listOf("lınks.example.com", "LİNKS.example.com", "lİnks.example.com", "Kexample.com")) {
                assertEquals(h, Outcome.BLOCK, eval("https://$h/x", "any", p).outcome)
            }
            assertEquals(Outcome.BLOCK, eval("https://example.com/x", "Any", p).outcome) // names are case-sensitive
        } finally {
            Locale.setDefault(saved)
        }
    }

    /** `ActivityCallerSource` formats digests with `"%02x".format(...)`, which uses the default locale. */
    @Test
    fun holdsSigningDigestHexUnderNonLatinDigitLocales() {
        val companion = ActivityCallerSource::class.java.getDeclaredField("Companion").apply { isAccessible = true }.get(null)
        val m = companion.javaClass.getDeclaredMethod("sha256Hex", ByteArray::class.java).apply { isAccessible = true }
        val input = ByteArray(64) { (it * 37).toByte() }
        val expected = MessageDigest.getInstance("SHA-256").digest(input).joinToString("") { b -> Integer.toHexString((b.toInt() and 0xff) or 0x100).substring(1) }
        val saved = Locale.getDefault()
        try {
            for (tag in listOf("tr-TR", "ar-EG", "fa-IR", "hi-IN-u-nu-deva", "th-TH-u-nu-thai", "ar-SA-u-nu-arab")) {
                Locale.setDefault(Locale.forLanguageTag(tag))
                assertEquals(tag, expected, m.invoke(companion, input))
            }
        } finally {
            Locale.setDefault(saved)
        }
    }

    @Test
    fun holdsUnicodeLookalikeBidiAndIdnTricks() {
        val blocked = listOf(
            "https://еxample.com/product/1", // Cyrillic е
            "https://xn--xample-2of.com/product/1", // punycode lookalike
            "https://example.com./product/1", // trailing dot
            "https://ｅｘａｍｐｌｅ.com/product/1", // fullwidth host
            "https://example.com/product/1?id=１２", // fullwidth digits
            "https://example.com/product/1?id=%D9%A1", // Arabic-Indic digit
            "https://example.com/product/%E2%80%AE1", // RLO in path
            "https://example.com/product/1?id=1%E2%80%8F", // RLM in value
            "https://example.com/product/%EF%BC%8E%EF%BC%8E/x", // fullwidth dots
            "https://example.com/product/1?name=cafe%CC%81", // NFD form of an allowed NFC value: no normalisation
            "https://example.com/product/1#frag", // fragment not allowed
        )
        assertEquals(emptyList<String>(), notBlocked(blocked, "product"))
    }

    @Test
    fun holdsSchemeAndAuthorityTricks() {
        val blocked = listOf(
            "javascript://example.com/product/%0aalert(1)",
            "intent://example.com/product/1#Intent;scheme=https;end",
            "content://example.com/product/1",
            "file:///product/1",
            "data:text/html,<script>",
            "https:example.com/product/1",
            "https:/\\example.com/product/1",
            "https://user@example.com/product/1",
            "https://evil.com\\@example.com/product/1",
            "https://example.com:0443/product/1",
            "https://example.com:80/product/1",
            "https://example.com:/product/1",
            "https://example.com:443:443/product/1",
            "https://[::1]/product/1",
            "https://example.com/product/1?next=javascript:alert(1)",
            "https://example.com/product/1?next=%2F%2Fevil.com",
            "https://example.com/product/1?next=https:evil.com",
            "https://example.com/product/1?next=https://example.com%5C@evil.com",
            "https://example.com/product/1?next=https://evil.com%23@example.com",
            "https://example.com/product/1?next=https://example.com.evil.com/",
            "https://example.com/product/1?next=data:text/html,x",
        )
        assertEquals(emptyList<String>(), notBlocked(blocked, "product"))
        // the explicit default port is normalised away and only scored (URI_NON_CANONICAL): accepted by design
        assertEquals(Outcome.ALLOW, eval("https://example.com:443/product/1", "product").outcome)
    }

    @Test
    fun holdsEncodedTraversalAndSeparatorTricks() {
        val blocked = listOf(
            "https://example.com/product/../admin",
            "https://example.com/product/%2e%2e/admin",
            "https://example.com/product/.%2E/admin",
            "https://example.com/product/%252e%252e/admin",
            "https://example.com/product/a%2F..%2F..%2Fadmin",
            "https://example.com/product/a%5C..%5Cadmin",
            "https://example.com/product/%C0%AE%C0%AE/admin", // overlong UTF-8
            "https://example.com/product/%E2%88%95admin", // U+2215
            "https://example.com/product/..%00/admin",
            "https://example.com/product/.%09./admin", // a tab WHATWG would strip
            "https://example.com/product/%u002e%u002e/admin",
            "https://example.com/product/1?id=1&id=2",
            "https://example.com/product/1?id=1&",
            "https://example.com/product/1?%69d=1",
        )
        assertEquals(emptyList<String>(), notBlocked(blocked, "product"))
    }

    @Test
    fun holdsVeryLongPercentRuns() {
        val run = "%41".repeat(700) // 2100 chars: over the URI limit, and 700 > 256 decoded
        assertEquals(Outcome.BLOCK, eval("https://example.com/x?q=$run", "any").outcome)
        val path = "%E2%82%AC".repeat(220) // 1980 chars, decodes to 220 euro signs: allowed by anyPath + under the limit
        assertEquals(Outcome.ALLOW, eval("https://example.com/$path", "any").outcome)
        val broken = "%E2%82".repeat(300) // truncated UTF-8 sequences
        assertEquals(Outcome.BLOCK, eval("https://example.com/$broken", "any").outcome)
    }
}
