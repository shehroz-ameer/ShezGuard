package com.shezguard.core.canon

import com.shezguard.core.UriComponent
import com.shezguard.core.ViolationCode
import com.shezguard.core.ViolationCode.PARAM_NAME_INVALID
import com.shezguard.core.ViolationCode.PARAM_TOO_LONG
import com.shezguard.core.ViolationCode.URI_BACKSLASH
import com.shezguard.core.ViolationCode.URI_CONTROL_CHAR
import com.shezguard.core.ViolationCode.URI_DOUBLE_ENCODING
import com.shezguard.core.ViolationCode.URI_EMPTY
import com.shezguard.core.ViolationCode.URI_FORMAT_CHAR
import com.shezguard.core.ViolationCode.URI_HOST_EMPTY
import com.shezguard.core.ViolationCode.URI_HOST_INVALID
import com.shezguard.core.ViolationCode.URI_HOST_NON_ASCII
import com.shezguard.core.ViolationCode.URI_HOST_PERCENT_ENCODED
import com.shezguard.core.ViolationCode.URI_HOST_TRAILING_DOT
import com.shezguard.core.ViolationCode.URI_INVALID_UTF8
import com.shezguard.core.ViolationCode.URI_NON_CANONICAL
import com.shezguard.core.ViolationCode.URI_NULL_BYTE
import com.shezguard.core.ViolationCode.URI_OPAQUE
import com.shezguard.core.ViolationCode.URI_PATH_DOT_SEGMENT
import com.shezguard.core.ViolationCode.URI_PATH_ENCODED_SEPARATOR
import com.shezguard.core.ViolationCode.URI_PATH_TRAVERSAL
import com.shezguard.core.ViolationCode.URI_PATH_UNICODE_SEPARATOR
import com.shezguard.core.ViolationCode.URI_PERCENT_MALFORMED
import com.shezguard.core.ViolationCode.URI_PORT_INVALID
import com.shezguard.core.ViolationCode.URI_SCHEME_INVALID
import com.shezguard.core.ViolationCode.URI_TOO_LONG
import com.shezguard.core.ViolationCode.URI_USERINFO
import com.shezguard.core.ViolationCode.URI_WHITESPACE
import com.shezguard.core.policy.Limits
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.lang.reflect.Modifier
import kotlin.random.Random

/**
 * Section A of `docs/CANONICALISER_TESTS.md`. Test names follow the approved list; the
 * number in each comment is the stable test identifier from that file.
 */
class UriCanonicalizerTest {

    private val base = "https://example.com"

    // ---- helpers -------------------------------------------------------------------

    private fun canon(raw: String, limits: Limits = Limits.DEFAULT): CanonResult =
        UriCanonicalizer.canonicalize(raw, limits)

    private fun ok(raw: String, limits: Limits = Limits.DEFAULT): CanonResult.Ok {
        val r = canon(raw, limits)
        if (r !is CanonResult.Ok) fail("expected Ok for <${show(raw)}>, got ${r.findings}")
        return r as CanonResult.Ok
    }

    private fun assertRejected(raw: String, vararg expected: ViolationCode, limits: Limits = Limits.DEFAULT) {
        val r = canon(raw, limits)
        val codes = r.findings.map { it.code }.toSet()
        assertTrue("expected Rejected for <${show(raw)}>, got $r", r is CanonResult.Rejected)
        for (e in expected) assertTrue("expected $e for <${show(raw)}>, got $codes", e in codes)
    }

    private fun assertFinding(raw: String, code: ViolationCode, component: UriComponent) {
        val r = canon(raw)
        assertTrue(
            "expected $code in $component for <${show(raw)}>, got ${r.findings}",
            Finding(code, component) in r.findings,
        )
    }

    /** Makes control and non-ASCII characters visible in failure messages. */
    private fun show(raw: String): String = buildString {
        for (c in raw) if (c.code in 0x20..0x7E) append(c) else append("\\u%04X".format(c.code))
    }

    private fun ch(code: Int): String = code.toChar().toString()

    // ---- 1. Mixed case -------------------------------------------------------------

    @Test // 1
    fun lowercasesSchemeAndHost() {
        val u = ok("HTTPS://EXAMPLE.COM/p").uri
        assertEquals("https", u.scheme)
        assertEquals("example.com", u.host)
        assertEquals(listOf("p"), u.pathSegments)
    }

    @Test // 2
    fun preservesPathAndQueryCase() {
        val u = ok("$base/Product?Id=A").uri
        assertEquals(listOf("Product"), u.pathSegments)
        assertEquals(listOf("Id" to "A"), u.query)
    }

    @Test // 3
    fun lowercasesPunycodePrefix() {
        assertEquals("xn--80ak6aa92e.com", ok("https://XN--80AK6AA92E.COM/").uri.host)
    }

    @Test // 4
    fun treatsUpperAndLowerHexEscapesAlike() {
        assertRejected("$base/a%2fb", URI_PATH_ENCODED_SEPARATOR)
        assertRejected("$base/a%2Fb", URI_PATH_ENCODED_SEPARATOR)
        assertRejected("$base/%2e%2e/x", URI_PATH_TRAVERSAL)
        assertRejected("$base/%2E%2E/x", URI_PATH_TRAVERSAL)
        assertEquals(ok("$base/caf%c3%a9").uri, ok("$base/caf%C3%A9").uri)
    }

    @Test // 5
    fun doesNotFlagSchemeOrHostCaseAsNonCanonical() {
        assertEquals(emptyList<Finding>(), ok("HTTPS://EXAMPLE.COM/p").findings)
    }

    // ---- 2. Single percent-encoding -----------------------------------------------

    @Test // 6
    fun decodesEachComponentOnce() {
        val u = ok("$base/a%20b?q=x%26y").uri
        assertEquals(listOf("a b"), u.pathSegments)
        assertEquals(listOf("q" to "x&y"), u.query)
    }

    @Test // 7
    fun decodesQueryOnlyAfterSplitting() {
        assertEquals(listOf("a" to "1&b=2"), ok("$base/?a=1%26b%3D2").uri.query)
    }

    @Test // 8
    fun blocksEncodedSlashInPathSegment() {
        assertRejected("$base/a%2Fb", URI_PATH_ENCODED_SEPARATOR)
    }

    @Test // 9
    fun blocksEncodedBackslashInPathSegment() {
        assertRejected("$base/a%5Cb", URI_BACKSLASH)
    }

    @Test // 10
    fun flagsNeedlesslyEncodedUnreservedCharAsNonCanonical() {
        val r = ok("$base/%41")
        assertEquals(listOf("A"), r.uri.pathSegments)
        assertEquals(listOf(Finding(URI_NON_CANONICAL, UriComponent.PATH)), r.findings)
    }

    @Test // 11
    fun blocksMalformedPercentEscapes() {
        for (bad in listOf("%", "%2", "%G1", "%u002e")) assertRejected("$base/a$bad", URI_PERCENT_MALFORMED)
    }

    @Test // 12
    fun blocksInvalidUtf8AfterDecoding() {
        assertRejected("$base/a%FF", URI_INVALID_UTF8)
        assertRejected("$base/a%C3", URI_INVALID_UTF8)
    }

    @Test // 13
    fun blocksOverlongUtf8Encoding() {
        assertRejected("$base/%C0%AE", URI_INVALID_UTF8)
        assertRejected("$base/%E0%80%AE", URI_INVALID_UTF8)
    }

    @Test // 14
    fun blocksEncodedSurrogateCodePoints() {
        assertRejected("$base/%ED%A0%80", URI_INVALID_UTF8)
    }

    @Test // 15
    fun decodesValidMultibyteUtf8InPath() {
        assertEquals(listOf("café"), ok("$base/caf%C3%A9").uri.pathSegments)
    }

    @Test // 107
    fun decodesEncodedQuestionMarkIntoPathSegmentWithoutSplitting() {
        val u = ok("$base/a%3Fb").uri
        assertEquals(listOf("a?b"), u.pathSegments)
        assertTrue(u.query.isEmpty())
        assertNull(u.fragment)
    }

    @Test // 108
    fun decodesEncodedHashIntoPathSegmentWithoutSplitting() {
        val u = ok("$base/a%23b").uri
        assertEquals(listOf("a#b"), u.pathSegments)
        assertTrue(u.query.isEmpty())
        assertNull(u.fragment)
    }

    @Test // 109
    fun blocksRawUnpairedSurrogate() {
        val bad = listOf(ch(0xD800), ch(0xDC00), ch(0xDC00) + ch(0xD800))
        for (b in bad) {
            assertFinding("$base/a${b}b", URI_INVALID_UTF8, UriComponent.PATH)
            assertFinding("$base/?q=a${b}b", URI_INVALID_UTF8, UriComponent.QUERY)
            assertFinding("$base/#a${b}b", URI_INVALID_UTF8, UriComponent.FRAGMENT)
            assertRejected("$base/a${b}b")
        }
    }

    // ---- 3. + versus %20 -------------------------------------------------------------

    @Test // 16
    fun decodesPlusAsSpaceInQueryValue() {
        assertEquals(listOf("q" to "a b"), ok("$base/?q=a+b").uri.query)
    }

    @Test // 17 (changed 2026-11-10: was decodesPlusAsSpaceInQueryName)
    fun blocksPlusInQueryName() {
        // Android's accessors disagree about `+` in names (LIMITATIONS L11), so it is blocked.
        assertFinding("$base/?a+b=1", PARAM_NAME_INVALID, UriComponent.QUERY)
        assertRejected("$base/?a+b=1")
    }

    @Test // 18
    fun keepsPlusLiteralInPath() {
        assertEquals(listOf("a+b"), ok("$base/a+b").uri.pathSegments)
    }

    @Test // 19
    fun decodesEncodedPlusAsLiteralPlusInQuery() {
        assertEquals(listOf("q" to "a+b"), ok("$base/?q=a%2Bb").uri.query)
    }

    @Test // 20
    fun treatsPlusAndPercent20AsEquivalentInQuery() {
        assertEquals(ok("$base/?q=a+b").uri.query, ok("$base/?q=a%20b").uri.query)
    }

    // ---- 4. Double encoding ----------------------------------------------------------

    @Test // 21
    fun blocksDoubleEncodedPathTraversal() {
        assertRejected("$base/%252e%252e/etc", URI_DOUBLE_ENCODING)
    }

    @Test // 22
    fun blocksDoubleEncodedSlash() {
        assertRejected("$base/a%252Fb", URI_DOUBLE_ENCODING)
    }

    @Test // 23
    fun blocksTripleEncoding() {
        assertRejected("$base/%25252e", URI_DOUBLE_ENCODING)
    }

    @Test // 24
    fun blocksDoubleEncodingInQueryValue() {
        assertFinding("$base/?next=%2568ttp", URI_DOUBLE_ENCODING, UriComponent.QUERY)
        assertRejected("$base/?next=%2568ttp")
    }

    @Test // 25
    fun blocksDoubleEncodingInFragment() {
        assertFinding("$base/#%2541", URI_DOUBLE_ENCODING, UriComponent.FRAGMENT)
        assertRejected("$base/#%2541")
    }

    @Test // 26
    fun blocksDoubleEncodedLiteralPercentAsKnownFalsePositive() {
        // docs/LIMITATIONS.md L2: a user really searching for the text "%41" is blocked.
        assertRejected("$base/?q=%2541", URI_DOUBLE_ENCODING)
    }

    @Test // 27
    fun acceptsEncodedPercentNotFollowedByHex() {
        assertEquals(listOf("q" to "100%"), ok("$base/?q=100%25").uri.query)
    }

    // ---- 5. . and .. segments, raw and encoded --------------------------------------

    @Test // 28
    fun blocksRawDotDotSegment() {
        for (p in listOf("/a/../b", "/..", "/a/..")) assertRejected("$base$p", URI_PATH_TRAVERSAL)
    }

    @Test // 29
    fun blocksEncodedDotDotSegment() {
        for (s in listOf("%2e%2e", "%2E%2E", ".%2e", "%2e.")) assertRejected("$base/$s/etc", URI_PATH_TRAVERSAL)
    }

    @Test // 30
    fun blocksEncodedDotDotWithEncodedSeparator() {
        assertRejected("$base/%2e%2e%2fetc", URI_PATH_TRAVERSAL)
    }

    @Test // 31
    fun blocksRawSingleDotSegment() {
        for (p in listOf("/./a", "/a/.")) assertRejected("$base$p", URI_PATH_DOT_SEGMENT)
    }

    @Test // 32
    fun blocksEncodedSingleDotSegment() {
        assertRejected("$base/%2e/a", URI_PATH_DOT_SEGMENT)
    }

    @Test // 33
    fun blocksFullwidthDotTraversal() {
        assertRejected("$base/%EF%BC%8E%EF%BC%8E/", URI_PATH_UNICODE_SEPARATOR)
    }

    @Test // 34
    fun blocksUnicodeSlashLookalikesInPath() {
        // U+2215 DIVISION SLASH, U+2044 FRACTION SLASH, U+FF0F FULLWIDTH SOLIDUS
        for (s in listOf("%E2%88%95", "%E2%81%84", "%EF%BC%8F")) {
            assertRejected("$base/a${s}b", URI_PATH_UNICODE_SEPARATOR)
        }
    }

    @Test // 35
    fun allowsDotsInsideSegmentNames() {
        assertEquals(listOf("file..txt"), ok("$base/file..txt").uri.pathSegments)
        assertEquals(listOf("v1.2"), ok("$base/v1.2/").uri.pathSegments)
        assertEquals(listOf(".well-known", "x"), ok("$base/.well-known/x").uri.pathSegments)
    }

    @Test // 36
    fun leavesDotDotInQueryValueToParameterRules() {
        assertEquals(listOf("f" to "../x"), ok("$base/?f=../x").uri.query)
    }

    // ---- 6. Null bytes and control characters --------------------------------------

    @Test // 37
    fun blocksRawNullByte() {
        assertRejected("$base/a${ch(0)}b", URI_NULL_BYTE)
    }

    @Test // 38
    fun blocksEncodedNullByteInEveryComponent() {
        assertFinding("$base/a%00b", URI_NULL_BYTE, UriComponent.PATH)
        assertFinding("$base/?a%00=1", URI_NULL_BYTE, UriComponent.QUERY)
        assertFinding("$base/?a=1%00", URI_NULL_BYTE, UriComponent.QUERY)
        assertFinding("$base/#a%00", URI_NULL_BYTE, UriComponent.FRAGMENT)
        for (s in listOf("$base/a%00b", "$base/?a%00=1", "$base/?a=1%00", "$base/#a%00")) assertRejected(s)
    }

    @Test // 39
    fun blocksCrLfInjection() {
        assertRejected("$base/a\r\nb", URI_CONTROL_CHAR)
        assertRejected("$base/?q=a%0D%0ASet-Cookie:x", URI_CONTROL_CHAR)
    }

    @Test // 40
    fun blocksTabAndNewlineInsideScheme() {
        assertFinding("jav\tascript:alert(1)", URI_CONTROL_CHAR, UriComponent.SCHEME)
        assertFinding("java\nscript:alert(1)", URI_CONTROL_CHAR, UriComponent.SCHEME)
        assertRejected("jav\tascript:alert(1)")
        assertRejected("java\nscript:alert(1)")
    }

    @Test // 41
    fun blocksDelCharacter() {
        assertRejected("$base/a%7Fb", URI_CONTROL_CHAR)
    }

    @Test // 42
    fun blocksC1ControlCharacters() {
        for (s in listOf("%C2%85", "%C2%80", "%C2%9F")) assertRejected("$base/a${s}b", URI_CONTROL_CHAR)
    }

    // ---- 7. Unicode format characters (Cf) ------------------------------------------

    @Test // 43
    fun blocksBidiOverrideInPath() {
        assertRejected("$base/%E2%80%AE", URI_FORMAT_CHAR)
    }

    @Test // 44
    fun blocksBidiOverrideInQueryValue() {
        assertRejected("$base/?name=%E2%80%AEtxt.exe", URI_FORMAT_CHAR)
    }

    @Test // 45
    fun blocksZeroWidthSpaceInQueryValue() {
        assertRejected("$base/?q=a%E2%80%8Bb", URI_FORMAT_CHAR)
    }

    @Test // 46
    fun blocksZeroWidthJoinerInQueryValueAsKnownFalsePositive() {
        // docs/LIMITATIONS.md L8: the emoji "man technologist" (U+1F468 U+200D U+1F4BB) is blocked.
        assertRejected("$base/?e=%F0%9F%91%A8%E2%80%8D%F0%9F%92%BB", URI_FORMAT_CHAR)
    }

    @Test // 47
    fun blocksSoftHyphenAndByteOrderMark() {
        assertRejected("$base/?q=a%C2%ADb", URI_FORMAT_CHAR)
        assertRejected("$base/?q=a%EF%BB%BFb", URI_FORMAT_CHAR)
    }

    @Test // 48
    fun blocksFormatCharInFragment() {
        assertFinding("$base/#a%E2%80%AEb", URI_FORMAT_CHAR, UriComponent.FRAGMENT)
        assertRejected("$base/#a%E2%80%AEb")
    }

    @Test // 49
    fun blocksRawFormatCharWithoutEncoding() {
        assertRejected("$base/a${ch(0x202E)}b", URI_FORMAT_CHAR)
    }

    // ---- 8. Whitespace ---------------------------------------------------------------

    @Test // 50
    fun blocksLeadingOrTrailingWhitespace() {
        assertRejected(" $base/", URI_WHITESPACE)
        assertRejected("$base/ ", URI_WHITESPACE)
    }

    @Test // 51
    fun blocksRawSpaceInsideUri() {
        assertRejected("$base/a b", URI_WHITESPACE)
        assertRejected("$base/?q=a b", URI_WHITESPACE)
    }

    @Test // 112
    fun blocksNonAsciiWhitespace() {
        // U+00A0 NO-BREAK SPACE (Zs), U+3000 IDEOGRAPHIC SPACE (Zs),
        // U+2028 LINE SEPARATOR (Zl), U+2029 PARAGRAPH SEPARATOR (Zp).
        val encoded = mapOf(0x00A0 to "%C2%A0", 0x3000 to "%E3%80%80", 0x2028 to "%E2%80%A8", 0x2029 to "%E2%80%A9")
        for ((cp, enc) in encoded) {
            val raw = ch(cp)
            assertFinding("$base/a${raw}b", URI_WHITESPACE, UriComponent.PATH)
            assertFinding("$base/a${enc}b", URI_WHITESPACE, UriComponent.PATH)
            assertFinding("$base/?q=a${raw}b", URI_WHITESPACE, UriComponent.QUERY)
            assertFinding("$base/?q=a${enc}b", URI_WHITESPACE, UriComponent.QUERY)
            assertFinding("$base/#a${enc}b", URI_WHITESPACE, UriComponent.FRAGMENT)
            assertRejected("$base/?q=a${enc}b")
        }
        // An encoded U+0020 is still a plain space after decoding and stays allowed (test 6).
        ok("$base/?q=a%20b")
    }

    // ---- 9. Backslashes --------------------------------------------------------------

    @Test // 52
    fun blocksRawBackslashInPath() {
        assertRejected("$base/a\\b", URI_BACKSLASH)
    }

    @Test // 53
    fun blocksBackslashAuthorityTrick() {
        assertRejected("https:\\\\evil.com", URI_BACKSLASH)
        assertRejected("https:/\\evil.com", URI_BACKSLASH)
    }

    @Test // 54
    fun blocksBackslashBeforeAt() {
        assertRejected("https://example.com\\@evil.com", URI_BACKSLASH)
    }

    @Test // 55
    fun allowsBackslashInQueryValueForParameterRules() {
        assertEquals(listOf("q" to "a\\b"), ok("$base/?q=a\\b").uri.query)
    }

    // ---- 10. Userinfo tricks ---------------------------------------------------------

    @Test // 56
    fun blocksUserInfoWithPassword() {
        assertRejected("https://user:pass@example.com/", URI_USERINFO)
    }

    @Test // 57
    fun blocksHostLookingUserInfo() {
        assertRejected("https://example.com@evil.com/", URI_USERINFO)
    }

    @Test // 58
    fun blocksPortLookingUserInfo() {
        assertRejected("https://example.com:443@evil.com/", URI_USERINFO)
    }

    @Test // 59
    fun blocksEmptyUserInfo() {
        assertRejected("https://@example.com/", URI_USERINFO)
    }

    @Test // 60
    fun blocksPercentEncodedAtInHost() {
        assertRejected("https://example.com%40evil.com/", URI_HOST_PERCENT_ENCODED)
    }

    @Test // 61
    fun parsesAtAfterHashAsFragmentNotUserInfo() {
        val u = ok("https://evil.com#@example.com").uri
        assertEquals("evil.com", u.host)
        assertEquals("@example.com", u.fragment)
    }

    @Test // 62 (changed 2026-11-10: the `@` moved into a value, names may no longer hold it)
    fun parsesAtAfterQuestionMarkAsQueryNotUserInfo() {
        val u = ok("https://evil.com?x=@example.com").uri
        assertEquals("evil.com", u.host)
        assertEquals(listOf("x" to "@example.com"), u.query)
    }

    // ---- 11. Overlong input ----------------------------------------------------------

    @Test // 63
    fun acceptsUriAtExactly2048Chars() {
        val s = "$base/" + "a".repeat(2048 - "$base/".length)
        assertEquals(2048, s.length)
        ok(s)
    }

    @Test // 64
    fun blocksUriAt2049Chars() {
        val s = "$base/" + "a".repeat(2049 - "$base/".length)
        assertEquals(2049, s.length)
        assertRejected(s, URI_TOO_LONG)
    }

    @Test // 65
    fun measuresUriLimitOnRawNotDecodedForm() {
        // 2120 raw characters that decode to a 720-character path.
        val s = "$base/" + "%20".repeat(700)
        assertTrue(s.length > 2048)
        assertRejected(s, URI_TOO_LONG)
    }

    @Test // 66
    fun acceptsParamValueAtExactly256DecodedChars() {
        assertEquals(256, ok("$base/?q=" + "a".repeat(256)).uri.query.single().second.length)
        // 768 raw characters, 256 decoded: the parameter limit applies to the decoded form.
        assertEquals(256, ok("$base/?q=" + "%20".repeat(256)).uri.query.single().second.length)
    }

    @Test // 67
    fun blocksParamValueAt257DecodedChars() {
        assertRejected("$base/?q=" + "a".repeat(257), PARAM_TOO_LONG)
    }

    @Test // 68 (changed 2026-11-10: names have a fixed 64-character limit, as ParamRule.name)
    fun blocksParamNameOverLimit() {
        ok("$base/?" + "n".repeat(64) + "=1")
        assertRejected("$base/?" + "n".repeat(65) + "=1", PARAM_TOO_LONG)
        // The name limit does not follow maxParamLength, which applies to values only.
        ok("$base/?" + "n".repeat(64) + "=1", Limits(maxParamLength = 3))
    }

    @Test // 69
    fun honoursCustomLimits() {
        val limits = Limits(maxUriLength = 40, maxParamLength = 3)
        ok("$base/?q=abc", limits)
        assertRejected("$base/?q=abcd", PARAM_TOO_LONG, limits = limits)
        val long = "$base/" + "a".repeat(21)
        assertEquals(41, long.length)
        assertRejected(long, URI_TOO_LONG, limits = limits)
    }

    @Test // 70
    fun blocksEmptyInput() {
        assertRejected("", URI_EMPTY)
    }

    // ---- 12. Unicode lookalike hosts -------------------------------------------------

    @Test // 71
    fun blocksCyrillicLookalikeHost() {
        assertRejected("https://${ch(0x0435)}xample.com/", URI_HOST_NON_ASCII)
    }

    @Test // 72
    fun blocksFullwidthHost() {
        val fullwidth = "example".map { (it.code - 'a'.code + 0xFF41).toChar() }.joinToString("")
        assertRejected("https://$fullwidth.com/", URI_HOST_NON_ASCII)
    }

    @Test // 73
    fun blocksIdeographicFullStopInHost() {
        assertRejected("https://example${ch(0x3002)}com/", URI_HOST_NON_ASCII)
    }

    @Test // 74
    fun blocksPercentEncodedNonAsciiHost() {
        assertRejected("https://%D0%B5xample.com/", URI_HOST_PERCENT_ENCODED)
    }

    @Test // 75
    fun blocksZeroWidthCharInHost() {
        assertRejected("https://exam${ch(0x200B)}ple.com/", URI_HOST_NON_ASCII, URI_FORMAT_CHAR)
    }

    @Test // 76
    fun passesPunycodeHostThroughUnchanged() {
        // Accepted here; step 4's exact host matching is what rejects it.
        assertEquals("xn--80ak6aa92e.com", ok("https://xn--80ak6aa92e.com/").uri.host)
    }

    // ---- 13. Host, port and structure ------------------------------------------------

    @Test // 77
    fun blocksEmptyHost() {
        assertRejected("https:///path", URI_HOST_EMPTY)
        assertRejected("https://:443/", URI_HOST_EMPTY)
    }

    @Test // 78
    fun blocksTrailingDotHost() {
        assertRejected("https://example.com./", URI_HOST_TRAILING_DOT)
    }

    @Test // 79
    fun blocksEmptyHostLabel() {
        assertRejected("https://a..b.com/", URI_HOST_INVALID)
    }

    @Test // 80
    fun blocksInvalidHostCharacters() {
        assertRejected("https://exa!mple.com/", URI_HOST_INVALID)
    }

    @Test // 81
    fun blocksIpv6Literal() {
        // docs/LIMITATIONS.md L9
        assertRejected("https://[::1]/", URI_HOST_INVALID)
    }

    @Test // 82
    fun blocksInvalidPort() {
        for (p in listOf(":abc", ":99999", ":0", ":")) assertRejected("https://example.com$p/", URI_PORT_INVALID)
    }

    @Test // 83
    fun flagsExplicitDefaultPortAsNonCanonical() {
        val r = ok("https://example.com:443/")
        assertNull(r.uri.port)
        assertEquals(listOf(Finding(URI_NON_CANONICAL, UriComponent.PORT)), r.findings)
    }

    @Test // 84
    fun keepsNonDefaultPortForPolicyStage() {
        assertEquals(8443, ok("https://example.com:8443/").uri.port)
    }

    @Test // 85
    fun blocksOpaqueUri() {
        // docs/LIMITATIONS.md L10
        val inputs = listOf(
            "myapp:product", "mailto:x", "intent:#Intent;end",
            "javascript:alert(1)", "https:evil.com", "http:example.com",
        )
        for (s in inputs) assertRejected(s, URI_OPAQUE)
    }

    @Test // 86
    fun blocksInvalidSchemeSyntax() {
        for (s in listOf("1http://x", "ht tp://x", "://x")) assertRejected(s, URI_SCHEME_INVALID)
    }

    @Test // 87
    fun acceptsCustomHierarchicalScheme() {
        val u = ok("myapp://product/1").uri
        assertEquals("myapp", u.scheme)
        assertEquals("product", u.host)
        assertEquals(listOf("1"), u.pathSegments)
    }

    // ---- 14. Paths, queries and fragments --------------------------------------------

    @Test // 88
    fun collapsesDuplicateSlashesAndFlagsNonCanonical() {
        val r = ok("$base/a//b")
        assertEquals(listOf("a", "b"), r.uri.pathSegments)
        assertEquals(listOf(Finding(URI_NON_CANONICAL, UriComponent.PATH)), r.findings)
    }

    @Test // 89
    fun preservesTrailingSlash() {
        val withSlash = ok("$base/a/b/").uri
        val without = ok("$base/a/b").uri
        assertEquals(listOf("a", "b"), withSlash.pathSegments)
        assertEquals(listOf("a", "b"), without.pathSegments)
        assertTrue(withSlash.hasTrailingSlash)
        assertFalse(without.hasTrailingSlash)
    }

    @Test // 90
    fun preservesQueryOrderAndDuplicates() {
        assertEquals(
            listOf("b" to "2", "a" to "1", "b" to "3"),
            ok("$base/?b=2&a=1&b=3").uri.query,
        )
    }

    @Test // 91
    fun treatsSemicolonAsLiteralNotSeparator() {
        assertEquals(listOf("a" to "1;b=2"), ok("$base/?a=1;b=2").uri.query)
    }

    @Test // 92
    fun parsesParamWithoutEqualsAsEmptyValue() {
        assertEquals(listOf("flag" to ""), ok("$base/?flag").uri.query)
    }

    @Test // 93
    fun blocksEmptyParamName() {
        assertRejected("$base/?=x", PARAM_NAME_INVALID)
    }

    @Test // 94
    fun keepsFragmentForPolicyStage() {
        assertEquals("Section-2", ok("$base/p#Section-2").uri.fragment)
    }

    @Test // 113 (added 2026-11-10)
    fun blocksPercentEncodedQueryName() {
        // `%69d` decodes to `id`, but getQueryParameter("id") cannot see it (LIMITATIONS L12).
        for (s in listOf("$base/?%69d=5", "$base/?a%20b=1", "$base/?a%2Bb=1")) {
            assertFinding(s, PARAM_NAME_INVALID, UriComponent.QUERY)
            assertRejected(s)
        }
    }

    @Test // 114 (added 2026-11-10)
    fun blocksQueryNameOutsideConservativeSet() {
        val bad = listOf("a@b", "a!b", "a'b", "a(b", "a)b", "a*b", "a~b", "ids[]", "a[0]", "caf${ch(0xE9)}", "a:b", "a/b")
        for (name in bad) {
            assertFinding("$base/?$name=1", PARAM_NAME_INVALID, UriComponent.QUERY)
            assertRejected("$base/?$name=1")
        }
    }

    @Test // 115 (added 2026-11-10)
    fun acceptsQueryNamesInConservativeSet() {
        val names = listOf("id", "ID", "utm_source", "a.b", "a-b", "_", "Z9", "fbclid")
        val u = ok("$base/?" + names.joinToString("&") { "$it=1" }).uri
        assertEquals(names, u.query.map { it.first })
    }

    // ---- 15. Pipeline properties -----------------------------------------------------

    @Test // 95
    fun reportsAllFindingsNotJustFirst() {
        assertRejected("$base/a%0Ab\\c/%252e", URI_CONTROL_CHAR, URI_BACKSLASH, URI_DOUBLE_ENCODING)
    }

    @Test // 96
    fun isDeterministicForSameInput() {
        val inputs = listOf(
            "HTTPS://EXAMPLE.COM/a//b?x=1&x=2#f", "$base/%252e", "https://u@h/",
            "", "mailto:x", "$base/a%C3",
        )
        for (s in inputs) assertEquals(canon(s), canon(s))
    }

    @Test // 97
    fun neverThrowsOnArbitraryInput() {
        val rnd = Random(20261110)
        val alphabet = "aZ09:/?#@%&=+.;-_~[]\\ \t\r\n" +
            ch(0) + ch(0x7F) + ch(0x85) + ch(0x202E) + ch(0x200B) + ch(0xFF0E) + "é" +
            ch(0xD800) + ch(0xDC00)
        val prefixes = listOf("", "https://", "https://example.com/", "myapp://", "https:")
        repeat(10_000) {
            val s = buildString {
                append(prefixes[rnd.nextInt(prefixes.size)])
                repeat(rnd.nextInt(0, 60)) {
                    when (rnd.nextInt(4)) {
                        0 -> append(rnd.nextInt(0, 0x10000).toChar()) // any UTF-16 unit, incl. lone surrogates
                        1 -> append("%").append("%02X".format(rnd.nextInt(256)))
                        else -> append(alphabet[rnd.nextInt(alphabet.length)])
                    }
                }
            }
            try {
                val r = canon(s)
                val hard = r.findings.any { it.code.tier == com.shezguard.core.Tier.HARD }
                assertEquals("Ok iff no hard finding for <${show(s)}>", !hard, r is CanonResult.Ok)
            } catch (e: Throwable) {
                if (e is AssertionError) throw e
                throw AssertionError("threw on <${show(s)}>", e)
            }
        }
    }

    @Test // 98
    fun findingsNeverContainRawValues() {
        // Structural: a Finding can only ever hold a code and a component.
        val fieldTypes = Finding::class.java.declaredFields
            .filterNot { Modifier.isStatic(it.modifiers) }
            .map { it.type }
            .toSet()
        assertEquals(setOf(ViolationCode::class.java, UriComponent::class.java), fieldTypes)

        // Behavioural: a marker placed in every component never shows up in a finding.
        val marker = "s3cr3t"
        val inputs = listOf(
            "https://$marker:x@example.com/$marker%00?$marker=$marker%2541#$marker${ch(0x202E)}",
            "$marker://$marker./$marker/../\\$marker",
            "$marker:$marker",
            "https://${ch(0x0435)}$marker.com/?$marker=" + "a".repeat(300),
        )
        for (s in inputs) {
            val r = canon(s)
            assertTrue(r is CanonResult.Rejected)
            for (f in r.findings) assertFalse(f.toString().lowercase().contains(marker))
        }
    }
}
