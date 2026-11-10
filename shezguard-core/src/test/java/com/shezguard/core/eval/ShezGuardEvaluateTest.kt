package com.shezguard.core.eval

import android.content.Intent
import android.net.Uri
import com.shezguard.core.Decision
import com.shezguard.core.Field
import com.shezguard.core.Outcome
import com.shezguard.core.ShezGuard
import com.shezguard.core.UriComponent
import com.shezguard.core.Violation
import com.shezguard.core.ViolationCode
import com.shezguard.core.ViolationCode.DATA_FORBIDDEN
import com.shezguard.core.ViolationCode.DATA_MISSING
import com.shezguard.core.ViolationCode.ENTRY_POINT_UNKNOWN
import com.shezguard.core.ViolationCode.FRAGMENT_NOT_ALLOWED
import com.shezguard.core.ViolationCode.HOST_NOT_ALLOWED
import com.shezguard.core.ViolationCode.PARAM_INVALID_FORMAT
import com.shezguard.core.ViolationCode.PARAM_MISSING
import com.shezguard.core.ViolationCode.PARAM_REPEATED
import com.shezguard.core.ViolationCode.PARAM_TOO_LONG
import com.shezguard.core.ViolationCode.PARAM_UNKNOWN
import com.shezguard.core.ViolationCode.PARAM_UNKNOWN_IGNORED
import com.shezguard.core.ViolationCode.PARAM_URL_NOT_ALLOWED
import com.shezguard.core.ViolationCode.PATH_NOT_ALLOWED
import com.shezguard.core.ViolationCode.PORT_NOT_ALLOWED
import com.shezguard.core.ViolationCode.SCHEME_NOT_ALLOWED
import com.shezguard.core.ViolationCode.URI_BACKSLASH
import com.shezguard.core.ViolationCode.URI_CONTROL_CHAR
import com.shezguard.core.ViolationCode.URI_DOUBLE_ENCODING
import com.shezguard.core.ViolationCode.URI_EMPTY
import com.shezguard.core.ViolationCode.URI_FORMAT_CHAR
import com.shezguard.core.ViolationCode.URI_HOST_NON_ASCII
import com.shezguard.core.ViolationCode.URI_INVALID_UTF8
import com.shezguard.core.ViolationCode.URI_NON_CANONICAL
import com.shezguard.core.ViolationCode.URI_NULL_BYTE
import com.shezguard.core.ViolationCode.URI_OPAQUE
import com.shezguard.core.ViolationCode.URI_PATH_ENCODED_SEPARATOR
import com.shezguard.core.ViolationCode.URI_PATH_TRAVERSAL
import com.shezguard.core.ViolationCode.URI_TOO_LONG
import com.shezguard.core.ViolationCode.URI_USERINFO
import com.shezguard.core.eval.EvalFixtures.codes
import com.shezguard.core.eval.EvalFixtures.policy
import com.shezguard.core.eval.EvalFixtures.viewIntent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Step 5b: `ShezGuard.evaluate` with real `Intent` and `Uri` objects (Robolectric, SDK 34).
 * Tests are grouped by the in-scope threats of SPEC section 2. Extras, nested intents,
 * scoring and caller signals are later steps and are not exercised here.
 */
@RunWith(RobolectricTestRunner::class)
class ShezGuardEvaluateTest {

    private fun eval(uri: String, ep: String = "product"): Decision = ShezGuard.evaluate(viewIntent(uri), policy, ep)

    private fun assertBlockedWith(d: Decision, vararg expected: ViolationCode) {
        assertEquals("outcome for $d", Outcome.BLOCK, d.outcome)
        assertTrue("expected ${expected.toList()} in ${codes(d)}", codes(d).containsAll(expected.toList()))
    }

    private val base = "https://example.com/product/1"

    // ---- Deny by default and the data rule (SPEC 4, 5) --------------------------------

    @Test
    fun blocksUnknownEntryPointByDefault() {
        val d = eval("$base?id=1", ep = "notRegistered")
        assertEquals(Outcome.BLOCK, d.outcome)
        assertEquals("notRegistered", d.entryPoint)
        assertEquals(listOf(Violation(ENTRY_POINT_UNKNOWN, "notRegistered", Field.EntryPoint)), d.violations)
    }

    @Test
    fun blocksMissingDataOnRequiredEntryPoint() {
        val d = ShezGuard.evaluate(Intent(Intent.ACTION_VIEW), policy, "product")
        assertEquals(listOf(DATA_MISSING), d.violations.map { it.code })
        assertEquals(Outcome.BLOCK, d.outcome)
    }

    @Test
    fun allowsMissingDataOnOptionalEntryPoint() {
        val d = ShezGuard.evaluate(Intent(Intent.ACTION_VIEW), policy, "optional")
        assertTrue(d is Decision.Allow)
        assertNull((d as Decision.Allow).data)
        assertTrue(d.violations.isEmpty())
    }

    @Test
    fun checksDataInFullOnOptionalEntryPoint() {
        assertBlockedWith(eval("https://evil.com/", ep = "optional"), HOST_NOT_ALLOWED)
    }

    @Test
    fun allowsMissingDataOnForbiddenEntryPoint() {
        val d = ShezGuard.evaluate(Intent("com.example.ACTION"), policy, "nodata")
        assertTrue(d is Decision.Allow)
        assertTrue(d.violations.isEmpty())
    }

    /** Approved decision 2: only DATA_FORBIDDEN, the URI is not canonicalised. */
    @Test
    fun blocksUnexpectedDataOnForbiddenEntryPointWithDataForbiddenOnly() {
        for (uri in listOf("https://example.com/", "https://evil.com/%252e%252e?x=%00", "%%%", "intent:#Intent;end")) {
            val d = eval(uri, ep = "nodata")
            assertEquals(uri, listOf(Violation(DATA_FORBIDDEN, "nodata", Field.UriPart(UriComponent.WHOLE))), d.violations)
            assertEquals(Outcome.BLOCK, d.outcome)
        }
    }

    @Test
    fun blocksEmptyDataUri() {
        assertBlockedWith(eval("", ep = "product"), URI_EMPTY)
    }

    // ---- Threat 2: deep link parameter abuse (injection values) -----------------------

    @Test
    fun blocksSqlInjectionInDigitsParam() {
        val d = eval("$base?id=1%27%20OR%20%271%27%3D%271")
        assertBlockedWith(d, PARAM_INVALID_FORMAT)
        assertTrue(d.violations.any { it.field == Field.Param("id", declared = true) })
    }

    @Test
    fun blocksScriptInjectionInSlugParam() {
        assertBlockedWith(eval("$base?id=1&ref=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"), PARAM_INVALID_FORMAT)
    }

    @Test
    fun blocksCrlfInjectionInParam() {
        assertBlockedWith(eval("$base?id=1&ref=a%0D%0ASet-Cookie:x"), URI_CONTROL_CHAR)
    }

    @Test
    fun blocksNullByteTruncationInPath() {
        assertBlockedWith(eval("https://example.com/product/1%00.jpg?id=1"), URI_NULL_BYTE)
    }

    @Test
    fun blocksOversizedParamValue() {
        assertBlockedWith(eval("$base?id=1&ref=" + "a".repeat(300)), PARAM_TOO_LONG)
    }

    @Test
    fun blocksOversizedUri() {
        assertBlockedWith(eval("https://example.com/product/" + "a".repeat(3000) + "?id=1"), URI_TOO_LONG)
    }

    @Test
    fun blocksParameterPollution() {
        assertBlockedWith(eval("$base?id=1&id=2"), PARAM_REPEATED)
    }

    @Test
    fun blocksMissingRequiredParam() {
        assertBlockedWith(eval("$base?ref=abc"), PARAM_MISSING)
    }

    @Test
    fun blocksUndeclaredParamUnderDefaultUnknownBlock() {
        assertBlockedWith(eval("$base?id=1&debug=1"), PARAM_UNKNOWN)
    }

    // ---- Threat 2: path traversal ---------------------------------------------------

    @Test
    fun blocksRawPathTraversal() {
        assertBlockedWith(eval("https://example.com/product/../admin?id=1"), URI_PATH_TRAVERSAL)
    }

    @Test
    fun blocksEncodedPathTraversal() {
        assertBlockedWith(eval("https://example.com/product/%2e%2e/admin?id=1"), URI_PATH_TRAVERSAL)
    }

    @Test
    fun blocksPathTraversalBuiltWithUriBuilder() {
        val uri = Uri.Builder().scheme("https").authority("example.com")
            .appendPath("product").appendPath("..").appendPath("admin").appendQueryParameter("id", "1").build()
        assertBlockedWith(ShezGuard.evaluate(Intent(Intent.ACTION_VIEW, uri), policy, "product"), URI_PATH_TRAVERSAL)
    }

    @Test
    fun blocksBackslashPathTraversal() {
        assertBlockedWith(eval("https://example.com/product\\..\\admin?id=1"), URI_BACKSLASH)
    }

    @Test
    fun blocksEncodedSlashInPathSegment() {
        assertBlockedWith(eval("https://example.com/product/a%2Fb?id=1"), URI_PATH_ENCODED_SEPARATOR)
    }

    @Test
    fun blocksPathOutsideAllowedPrefix() {
        assertBlockedWith(eval("https://example.com/admin?id=1"), PATH_NOT_ALLOWED)
    }

    // ---- Threat 6: encoding evasion -------------------------------------------------

    @Test
    fun blocksDoubleEncodedPathTraversal() {
        assertBlockedWith(eval("https://example.com/product/%252e%252e/admin?id=1"), URI_DOUBLE_ENCODING)
    }

    @Test
    fun blocksDoubleEncodedParamValue() {
        assertBlockedWith(eval("$base?id=%2531"), URI_DOUBLE_ENCODING)
    }

    @Test
    fun blocksOverlongUtf8DotEncoding() {
        assertBlockedWith(eval("https://example.com/product/%C0%AE%C0%AE/admin?id=1"), URI_INVALID_UTF8)
    }

    @Test
    fun blocksBidiOverrideInParam() {
        assertBlockedWith(eval("$base?id=1&ref=abc%E2%80%AEgpj"), URI_FORMAT_CHAR)
    }

    @Test
    fun blocksCyrillicLookalikeHost() {
        assertBlockedWith(eval("https://exаmple.com/product/1?id=1"), URI_HOST_NON_ASCII)
    }

    @Test
    fun blocksPunycodeLookalikeHost() {
        assertBlockedWith(eval("https://xn--exmple-cua.com/product/1?id=1"), HOST_NOT_ALLOWED)
    }

    @Test
    fun allowsSchemeAndHostCaseVariationWithoutSignal() {
        val d = eval("HTTPS://EXAMPLE.COM/product/1?id=1")
        assertEquals(Outcome.ALLOW, d.outcome)
        assertTrue(d.violations.isEmpty())
    }

    @Test
    fun allowsDuplicateSlashesButListsNonCanonicalSignal() {
        val d = eval("https://example.com/product//1?id=1")
        assertEquals(Outcome.ALLOW, d.outcome)
        assertEquals(listOf(URI_NON_CANONICAL), d.violations.map { it.code })
        assertEquals(listOf("product", "1"), (d as Decision.Allow).data!!.pathSegments)
    }

    // ---- Threats 2 and 3: attacker-controlled URLs and open redirect ----------------

    @Test
    fun blocksOpenRedirectViaUrlParam() {
        assertBlockedWith(eval("$base?id=1&next=https%3A%2F%2Fevil.com%2F"), PARAM_URL_NOT_ALLOWED)
    }

    @Test
    fun blocksOpenRedirectViaUnencodedUrlParam() {
        assertBlockedWith(eval("$base?id=1&next=https://evil.com/"), PARAM_URL_NOT_ALLOWED)
    }

    @Test
    fun blocksJavascriptUrlInRedirectParam() {
        assertBlockedWith(eval("$base?id=1&next=javascript%3Aalert%281%29"), PARAM_URL_NOT_ALLOWED)
    }

    @Test
    fun blocksProtocolRelativeRedirectParam() {
        assertBlockedWith(eval("$base?id=1&next=%2F%2Fevil.com%2F"), PARAM_URL_NOT_ALLOWED)
    }

    @Test
    fun blocksUserinfoHostConfusion() {
        assertBlockedWith(eval("https://example.com@evil.com/product/1?id=1"), URI_USERINFO)
    }

    @Test
    fun blocksLookalikeSubdomainAndSuffixHosts() {
        assertBlockedWith(eval("https://evil.example.com/product/1?id=1"), HOST_NOT_ALLOWED)
        assertBlockedWith(eval("https://example.com.evil.com/product/1?id=1"), HOST_NOT_ALLOWED)
    }

    @Test
    fun blocksNonDefaultPort() {
        assertBlockedWith(eval("https://example.com:8443/product/1?id=1"), PORT_NOT_ALLOWED)
    }

    @Test
    fun blocksFragmentSmuggling() {
        assertBlockedWith(eval("$base?id=1#@evil.com"), FRAGMENT_NOT_ALLOWED)
    }

    // ---- Threat 4: unverified or hijackable deep links -----------------------------

    @Test
    fun blocksUnverifiedCustomSchemeOnHttpsEntryPoint() {
        val d = eval("myapp://example.com/product/1?id=1")
        assertEquals(listOf(SCHEME_NOT_ALLOWED), d.violations.map { it.code })
    }

    @Test
    fun blocksCleartextHttpDowngrade() {
        assertEquals(listOf(SCHEME_NOT_ALLOWED), eval("http://example.com/product/1?id=1").violations.map { it.code })
    }

    @Test
    fun blocksOpaqueIntentSchemeUri() {
        assertBlockedWith(eval("intent:#Intent;component=com.victim/.Admin;end"), URI_OPAQUE)
    }

    // ---- Collect all violations ----------------------------------------------------

    @Test
    fun collectsAllViolationsNotJustTheFirst() {
        val d = eval("http://evil.com:8443/admin?id=abc&id=2&x=1&next=https%3A%2F%2Fevil.com#f")
        assertBlockedWith(
            d,
            SCHEME_NOT_ALLOWED, HOST_NOT_ALLOWED, PORT_NOT_ALLOWED, PATH_NOT_ALLOWED, FRAGMENT_NOT_ALLOWED,
            PARAM_REPEATED, PARAM_INVALID_FORMAT, PARAM_UNKNOWN, PARAM_URL_NOT_ALLOWED,
        )
    }

    @Test
    fun collectsAllCanonicalisationFindings() {
        val d = eval("https://example.com/product/%2e%2e/%00?id=%2531")
        assertBlockedWith(d, URI_PATH_TRAVERSAL, URI_NULL_BYTE, URI_DOUBLE_ENCODING)
    }

    // ---- Allow and reading canonical values from the Decision ----------------------

    @Test
    fun allowsCleanDeepLinkAndExposesCanonicalValues() {
        val intent = viewIntent("https://example.com/product/42?id=42&ref=summer-sale&next=https%3A%2F%2Fexample.com%2Fcart")
        val d = ShezGuard.evaluate(intent, policy, "product")
        assertTrue(d.toString(), d is Decision.Allow)
        d as Decision.Allow
        assertSame(intent, d.intent)
        assertTrue(d.violations.isEmpty())
        val data = d.data!!
        assertEquals("https", data.scheme)
        assertEquals("example.com", data.host)
        assertNull(data.port)
        assertEquals(listOf("product", "42"), data.pathSegments)
        assertEquals("/product/42", data.path)
        assertNull(data.fragment)
        assertEquals("42", data.param("id"))
        assertEquals("summer-sale", data.param("ref"))
        assertEquals("https://example.com/cart", data.param("next"))
        assertEquals(setOf("id", "ref", "next"), data.paramNames)
    }

    @Test
    fun allowsUriBuiltWithUriBuilder() {
        val uri = Uri.Builder().scheme("https").authority("example.com")
            .appendPath("product").appendPath("42").appendQueryParameter("id", "42").build()
        val d = ShezGuard.evaluate(Intent(Intent.ACTION_VIEW, uri), policy, "product")
        assertEquals(d.toString(), Outcome.ALLOW, d.outcome)
    }

    /** L11: values follow `getQueryParameter`, where `+` is a space. */
    @Test
    fun plusInParamValueReadsAsSpaceLikeGetQueryParameter() {
        val intent = viewIntent("https://example.com/x?q=a+b%2Bc")
        val d = ShezGuard.evaluate(intent, policy, "browse") as Decision.Allow
        assertEquals("a b+c", d.data!!.param("q"))
        assertEquals(intent.data!!.getQueryParameter("q"), d.data!!.param("q"))
    }

    /** Approved decision 3: ignored parameters are listed as signals but not readable from the Decision. */
    @Test
    fun ignoredUnknownParamIsSignalledButNotReadable() {
        val intent = viewIntent("https://example.com/x?q=shoes&utm_source=mail")
        val d = ShezGuard.evaluate(intent, policy, "browse")
        assertTrue(d is Decision.Allow)
        d as Decision.Allow
        assertEquals(listOf(Violation(PARAM_UNKNOWN_IGNORED, "browse", Field.Param("utm_source", declared = false))), d.violations)
        assertNull(d.data!!.param("utm_source"))
        assertEquals(emptyList<String>(), d.data!!.params("utm_source"))
        assertEquals(setOf("q"), d.data!!.paramNames)
        // It stays in the original intent, which the app must not read from.
        assertEquals("mail", d.intent.data!!.getQueryParameter("utm_source"))
    }

    @Test
    fun absentOptionalParamReadsAsNull() {
        val d = eval("$base?id=1") as Decision.Allow
        assertNull(d.data!!.param("ref"))
        assertEquals(emptyList<String>(), d.data!!.params("ref"))
    }
}
