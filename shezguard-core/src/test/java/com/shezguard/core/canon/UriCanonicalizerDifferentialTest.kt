package com.shezguard.core.canon

import android.content.Intent
import android.net.Uri
import android.os.Parcel
import com.shezguard.core.policy.Limits
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Section B of `docs/CANONICALISER_TESTS.md`: compares the pure-Kotlin canonicaliser with
 * the real AOSP `android.net.Uri` code (Robolectric, SDK 34). Robolectric is not a device;
 * this class must also run as an instrumented test (step 14 of `docs/PROMPTS.md`).
 */
@RunWith(RobolectricTestRunner::class)
class UriCanonicalizerDifferentialTest {

    private val base = "https://example.com"

    private fun ours(s: String): CanonicalUri {
        val r = UriCanonicalizer.canonicalize(s, Limits.DEFAULT)
        if (r !is CanonResult.Ok) fail("expected Ok for <$s>, got ${r.findings}")
        return (r as CanonResult.Ok).uri
    }

    /**
     * URIs the canonicaliser accepts. Parameter names contain no `+` and only characters
     * that `Uri.encode` leaves alone, because `getQueryParameterNames()` does not decode
     * `+` and `getQueryParameter(name)` matches the name against the raw, still-encoded
     * query (`docs/LIMITATIONS.md` L11, L12; recorded by test 111).
     * No explicit default ports: the canonicaliser normalises them away by design.
     */
    private val acceptedCorpus = listOf(
        "$base/product/42?id=42",
        "HTTPS://EXAMPLE.COM/Product?Id=A",
        "$base/a%20b?q=x%26y",
        "$base/?a=1%26b%3D2",
        "$base/caf%C3%A9",
        "$base/a%3Fb", // test 107
        "$base/a%23b", // test 108
        "$base/a+b?q=a+b",
        "$base/?q=a%2Bb",
        "$base/?q=100%25",
        "$base/file..txt",
        "$base/v1.2/",
        "$base/.well-known/x",
        "$base/?f=../x",
        "$base/?q=a\\b",
        "$base/a//b",
        "https://example.com:8443/p",
        "https://xn--80ak6aa92e.com/",
        "myapp://product/1",
        "$base/a/b?x=1&x=2&y=3",
        "$base/?a=1;b=2",
        "$base/?flag",
        "$base/p#section",
        "https://evil.com#@example.com",
        "$base/%41",
    )

    @Test // 99
    fun agreesWithAndroidUriOnAcceptedInputs() {
        for (s in acceptedCorpus) {
            val o = ours(s)
            val a = Uri.parse(s)
            assertEquals("scheme of <$s>", a.scheme?.lowercase(), o.scheme)
            assertEquals("host of <$s>", a.host?.lowercase(), o.host)
            assertEquals("port of <$s>", a.port.takeIf { it != -1 }, o.port)
            assertEquals("path segments of <$s>", a.pathSegments, o.pathSegments)
            val ourNames = o.query.map { it.first }.distinct()
            assertEquals("query names of <$s>", a.queryParameterNames.toList(), ourNames)
            // Values are compared through getQueryParameter (singular), the accessor the
            // SPEC names. It returns the first value, so compare with our first value.
            // getQueryParameters (plural) does not decode `+` (author decision, test 111).
            for (n in ourNames) {
                assertEquals(
                    "first value of <$n> in <$s>",
                    a.getQueryParameter(n),
                    o.query.first { it.first == n }.second,
                )
            }
            assertEquals("fragment of <$s>", a.fragment, o.fragment)
        }
    }

    @Test // 110
    fun encodedQuestionMarkAndHashInPathMatchAndroid() {
        for (s in listOf("$base/a%3Fb", "$base/a%23b")) {
            val a = Uri.parse(s)
            val o = ours(s)
            assertEquals(1, a.pathSegments.size)
            assertNull(a.query)
            assertNull(a.fragment)
            assertEquals(a.pathSegments, o.pathSegments)
            assertTrue(o.query.isEmpty())
            assertNull(o.fragment)
        }
    }

    // ---- The + rule. On disagreement these fail naming both results; the rule then goes
    // ---- back to the author instead of being adjusted here.

    @Test // 100
    fun plusInQueryDecodesToSpaceLikeAndroid() {
        val s = "$base/?q=a+b"
        val android = Uri.parse(s).getQueryParameter("q")
        val shez = ours(s).query.single().second
        assertEquals("android=<$android> shezguard=<$shez>", android, shez)
        assertEquals("a b", shez)
    }

    @Test // 101
    fun plusInPathStaysLiteralLikeAndroid() {
        val s = "$base/a+b"
        val android = Uri.parse(s).pathSegments
        val shez = ours(s).pathSegments
        assertEquals("android=<$android> shezguard=<$shez>", android, shez)
        assertEquals(listOf("a+b"), shez)
    }

    @Test // 102
    fun encodedPlusDecodesToLiteralPlusLikeAndroid() {
        val s = "$base/?q=a%2Bb"
        val android = Uri.parse(s).getQueryParameter("q")
        val shez = ours(s).query.single().second
        assertEquals("android=<$android> shezguard=<$shez>", android, shez)
        assertEquals("a+b", shez)
    }

    // ---- Input contract --------------------------------------------------------------

    private val trickyParseable = listOf(
        "https://Example.COM/%2e%2E/a%2fB?q=a+b&r=a%2Bb#Frag",
        "$base//a//b",
        "$base/a%3Fb",
        "$base/p?",
        "$base/p#",
        "$base/%7e%7E?x=%41",
    )

    @Test // 104
    fun parsedUriToStringIsOriginalString() {
        for (s in trickyParseable) {
            assertEquals(s, Uri.parse(s).toString())
            assertEquals(s, Intent(Intent.ACTION_VIEW, Uri.parse(s)).dataString)
        }
    }

    @Test // 105
    fun dataStringSurvivesParcelRoundTrip() {
        for (s in trickyParseable) {
            val parcel = Parcel.obtain()
            try {
                Intent(Intent.ACTION_VIEW, Uri.parse(s)).writeToParcel(parcel, 0)
                parcel.setDataPosition(0)
                assertEquals(s, Intent.CREATOR.createFromParcel(parcel).dataString)
            } finally {
                parcel.recycle()
            }
        }
    }

    @Test // 106
    fun builderMadeUriToStringIsAndroidsEncodedForm() {
        val built = Uri.Builder()
            .scheme("https")
            .authority("example.com")
            .appendPath("a b")
            .appendQueryParameter("q", "a+b")
            .build()
        val s = built.toString()
        assertEquals("https://example.com/a%20b?q=a%2Bb", s)
        val o = ours(s)
        assertEquals(built.pathSegments, o.pathSegments)
        assertEquals(built.getQueryParameter("q"), o.query.single().second)
    }

    @Test // 116 (added 2026-11-10)
    fun androidAccessorsAgreeOnNamesInConservativeSet() {
        val set = ('A'..'Z') + ('a'..'z') + ('0'..'9') + listOf('_', '.', '-')
        val rnd = kotlin.random.Random(20261110)
        val fixed = listOf("id", "utm_source", "a.b", "a-b", "_", ".", "..", "-", "x".repeat(64))
        val random = List(300) { List(rnd.nextInt(1, 65)) { set[rnd.nextInt(set.size)] }.joinToString("") }
        for (name in (fixed + random).distinct()) {
            val s = "$base/?$name=v1"
            val a = Uri.parse(s)
            assertEquals("getQueryParameterNames for <$name>", listOf(name), a.queryParameterNames.toList())
            assertEquals("getQueryParameter for <$name>", "v1", a.getQueryParameter(name))
            assertEquals("getQueryParameters for <$name>", listOf("v1"), a.getQueryParameters(name))
            assertEquals("ShezGuard for <$name>", listOf(name to "v1"), ours(s).query)
        }
    }

    // ---- Characterisation: records Android's behaviour, asserts nothing about agreement.

    @Test // 117 (added 2026-11-10)
    fun characterisesAndroidAccessorsForNamesOutsideConservativeSet() {
        for (c in listOf("@", "!", "'", "(", ")", "*", "~", "[", "]")) {
            val name = "a${c}b"
            val s = "$base/?$name=1"
            val a = Uri.parse(s)
            val shez = UriCanonicalizer.canonicalize(s, Limits.DEFAULT)
            println(
                "[117] <$s> android: getQueryParameterNames()=${a.queryParameterNames} " +
                    "getQueryParameter(\"$name\")=<${a.getQueryParameter(name)}> " +
                    "getQueryParameters(\"$name\")=${a.getQueryParameters(name)} " +
                    "Uri.encode(\"$name\")=${Uri.encode(name)} " +
                    "| shezguard: ${if (shez is CanonResult.Ok) "Ok" else "Rejected"} " +
                    shez.findings.map { it.code.id }.distinct(),
            )
        }
    }

    @Test // 111
    fun characterisesAndroidQueryAccessorInconsistency() {
        val inputs = listOf(
            "$base/?q=a+b" to listOf("q"),
            "$base/?a+b=1" to listOf("a+b", "a b"),
            "$base/?%69d=5" to listOf("id"),
        )
        for ((s, names) in inputs) {
            val a = Uri.parse(s)
            val shez = UriCanonicalizer.canonicalize(s, Limits.DEFAULT)
            val shezQuery = if (shez is CanonResult.Ok) shez.uri.query.toString() else "Rejected"
            val perName = names.joinToString(" ") { n ->
                "getQueryParameter(\"$n\")=<${a.getQueryParameter(n)}> " +
                    "getQueryParameters(\"$n\")=${a.getQueryParameters(n)}"
            }
            println(
                "[111] <$s> android: getQueryParameterNames()=${a.queryParameterNames} $perName " +
                    "| shezguard: $shezQuery",
            )
        }
    }

    @Test // 103
    fun characterisesAndroidParsingOfRejectedTricks() {
        val tricks = listOf(
            "https:\\\\evil.com",
            "https:/\\evil.com",
            "https://example.com\\@evil.com",
            "https://user:pass@example.com/",
            "https://example.com@evil.com/",
            "https://example.com:443@evil.com/",
            "https://evil.com#@example.com",
            "https:evil.com",
            "http:example.com",
        )
        for (s in tricks) {
            val a = Uri.parse(s)
            val shez = UriCanonicalizer.canonicalize(s, Limits.DEFAULT)
            val verdict = if (shez is CanonResult.Ok) "Ok(host=${shez.uri.host})" else "Rejected"
            println(
                "[103] <$s> android: opaque=${a.isOpaque} scheme=${a.scheme} " +
                    "authority=${a.authority} userInfo=${a.userInfo} host=${a.host} " +
                    "port=${a.port} path=${a.path} fragment=${a.fragment} | shezguard: $verdict " +
                    shez.findings.map { it.code.id }.distinct(),
            )
        }
    }
}
