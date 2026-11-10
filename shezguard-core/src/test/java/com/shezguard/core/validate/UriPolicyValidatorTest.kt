package com.shezguard.core.validate

import com.shezguard.core.Field
import com.shezguard.core.UriComponent
import com.shezguard.core.Violation
import com.shezguard.core.ViolationCode
import com.shezguard.core.ViolationCode.FRAGMENT_NOT_ALLOWED
import com.shezguard.core.ViolationCode.HOST_NOT_ALLOWED
import com.shezguard.core.ViolationCode.PARAM_INVALID_FORMAT
import com.shezguard.core.ViolationCode.PARAM_MISSING
import com.shezguard.core.ViolationCode.PARAM_REPEATED
import com.shezguard.core.ViolationCode.PARAM_TOO_LONG
import com.shezguard.core.ViolationCode.PARAM_UNKNOWN
import com.shezguard.core.ViolationCode.PARAM_UNKNOWN_DROPPED
import com.shezguard.core.ViolationCode.PARAM_UNKNOWN_IGNORED
import com.shezguard.core.ViolationCode.PARAM_URL_NOT_ALLOWED
import com.shezguard.core.ViolationCode.PATH_NOT_ALLOWED
import com.shezguard.core.ViolationCode.PORT_NOT_ALLOWED
import com.shezguard.core.ViolationCode.SCHEME_NOT_ALLOWED
import com.shezguard.core.ViolationCode.URI_DOUBLE_ENCODING
import com.shezguard.core.canon.CanonResult
import com.shezguard.core.canon.UriCanonicalizer
import com.shezguard.core.policy.CharClass
import com.shezguard.core.policy.Data
import com.shezguard.core.policy.EntryPointPolicy
import com.shezguard.core.policy.HostPattern
import com.shezguard.core.policy.Limits
import com.shezguard.core.policy.ParamRule
import com.shezguard.core.policy.ParamType
import com.shezguard.core.policy.PathPattern
import com.shezguard.core.policy.Unknown
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Step 4: scheme, host, port, path and fragment allow-lists, parameter rule types,
 * repeated and unknown parameters. Inputs are canonicalised first, as in the evaluator.
 */
class UriPolicyValidatorTest {

    private val base = "https://example.com"

    // ---- helpers -------------------------------------------------------------------

    private fun policy(
        schemes: Set<String> = setOf("https"),
        hosts: Set<HostPattern> = setOf(HostPattern.Exact("example.com")),
        ports: Set<Int> = emptySet(),
        paths: List<PathPattern> = listOf(PathPattern.AnyPath),
        allowFragment: Boolean = false,
        params: List<ParamRule> = emptyList(),
        unknown: Unknown = Unknown.Block,
        allowRepeated: Boolean = false,
    ) = EntryPointPolicy(
        name = "product",
        data = Data.Required,
        schemes = schemes,
        hosts = hosts,
        ports = ports,
        paths = paths,
        allowFragment = allowFragment,
        params = params,
        unknownParams = unknown,
        allowRepeatedParams = allowRepeated,
    )

    private fun validate(raw: String, p: EntryPointPolicy = policy()): UriValidation {
        val r = UriCanonicalizer.canonicalize(raw, p.limits)
        if (r !is CanonResult.Ok) throw AssertionError("test input must canonicalise: <$raw> ${r.findings}")
        return UriPolicyValidator.validate(r.uri, p)
    }

    private fun codes(raw: String, p: EntryPointPolicy = policy()): List<ViolationCode> =
        validate(raw, p).violations.map { it.code }

    private fun assertClean(raw: String, p: EntryPointPolicy = policy()) {
        assertEquals("expected no violations for <$raw>", emptyList<Violation>(), validate(raw, p).violations)
    }

    private fun assertViolation(raw: String, p: EntryPointPolicy, code: ViolationCode, field: Field) {
        val v = validate(raw, p).violations
        assertTrue("expected $code on $field for <$raw>, got $v", Violation(code, "product", field) in v)
    }

    private fun param(name: String, type: ParamType, maxLength: Int = Limits.DEFAULT_MAX_PARAM_LENGTH, required: Boolean = false) =
        ParamRule(name, type, maxLength, required)

    private val uriField = { c: UriComponent -> Field.UriPart(c) }
    private fun declared(name: String) = Field.Param(name, declared = true)
    private fun undeclared(name: String) = Field.Param(name, declared = false)

    // ---- Scheme ----------------------------------------------------------------------

    @Test
    fun allowsListedScheme() = assertClean("$base/p")

    @Test
    fun blocksDowngradeToHttp() {
        assertViolation("http://example.com/p", policy(), SCHEME_NOT_ALLOWED, uriField(UriComponent.SCHEME))
    }

    @Test
    fun blocksUnlistedCustomScheme() {
        val p = policy(schemes = setOf("myapp"), hosts = setOf(HostPattern.Exact("product")))
        assertClean("myapp://product/1", p)
        assertEquals(listOf(SCHEME_NOT_ALLOWED), codes("evilapp://product/1", p))
    }

    @Test
    fun blocksEverySchemeWhenNoneListed() {
        assertTrue(SCHEME_NOT_ALLOWED in codes("$base/p", policy(schemes = emptySet())))
    }

    // ---- Host ------------------------------------------------------------------------

    @Test
    fun allowsExactHostAfterCaseFolding() = assertClean("HTTPS://EXAMPLE.COM/p")

    @Test
    fun blocksSubdomainWithoutExplicitOptIn() {
        assertViolation("https://evil.example.com/p", policy(), HOST_NOT_ALLOWED, uriField(UriComponent.HOST))
    }

    @Test
    fun blocksSuffixAndPrefixConfusionHosts() {
        for (h in listOf("notexample.com", "example.com.evil.com", "example.co", "www.example.com")) {
            assertEquals("host <$h>", listOf(HOST_NOT_ALLOWED), codes("https://$h/p"))
        }
    }

    @Test
    fun blocksPunycodeLookalikeHost() {
        // Canonicaliser test 76 accepts the punycode host; exact matching is what rejects it.
        assertEquals(listOf(HOST_NOT_ALLOWED), codes("https://xn--xample-2of.com/p"))
    }

    @Test
    fun blocksAlternativeIpv4Spellings() {
        val p = policy(hosts = setOf(HostPattern.Exact("127.0.0.1")))
        assertClean("https://127.0.0.1/p", p)
        for (h in listOf("2130706433", "0x7f.1", "127.1")) assertEquals(listOf(HOST_NOT_ALLOWED), codes("https://$h/p", p))
    }

    @Test
    fun subdomainsOfMatchesOnlyStrictSubdomainsAtLabelBoundary() {
        val p = policy(hosts = setOf(HostPattern.SubdomainsOf("example.com")))
        assertClean("https://shop.example.com/p", p)
        assertClean("https://a.b.example.com/p", p)
        for (h in listOf("example.com", "evilexample.com", "example.com.evil.com")) {
            assertEquals("host <$h>", listOf(HOST_NOT_ALLOWED), codes("https://$h/p", p))
        }
    }

    // ---- Port ------------------------------------------------------------------------

    @Test
    fun blocksNonDefaultPortUnlessAllowed() {
        assertViolation("https://example.com:8443/p", policy(), PORT_NOT_ALLOWED, uriField(UriComponent.PORT))
        assertClean("https://example.com:8443/p", policy(ports = setOf(8443)))
        assertEquals(listOf(PORT_NOT_ALLOWED), codes("https://example.com:8080/p", policy(ports = setOf(8443))))
    }

    @Test
    fun allowsExplicitDefaultPortBecauseCanonicalisationRemovesIt() = assertClean("https://example.com:443/p")

    // ---- Path ------------------------------------------------------------------------

    @Test
    fun blocksPathOutsideExactPattern() {
        val p = policy(paths = listOf(PathPattern.Exact("/settings")))
        assertClean("$base/settings", p)
        assertViolation("$base/admin", p, PATH_NOT_ALLOWED, uriField(UriComponent.PATH))
    }

    @Test
    fun exactPatternDistinguishesTrailingSlash() {
        val p = policy(paths = listOf(PathPattern.Exact("/settings")))
        assertEquals(listOf(PATH_NOT_ALLOWED), codes("$base/settings/", p))
    }

    @Test
    fun prefixPatternStopsAtSegmentBoundary() {
        val p = policy(paths = listOf(PathPattern.Prefix("/product/")))
        assertClean("$base/product/42", p)
        assertClean("$base/product/42/reviews", p)
        assertEquals(listOf(PATH_NOT_ALLOWED), codes("$base/product-admin", p))
        assertEquals(listOf(PATH_NOT_ALLOWED), codes("$base/product", p))
    }

    @Test
    fun blocksEncodedQuestionMarkSmuggledPastExactPath() {
        // `/settings%3Fx` is one segment `settings?x` (canonicaliser test 107), not `/settings`.
        assertEquals(listOf(PATH_NOT_ALLOWED), codes("$base/settings%3Fx", policy(paths = listOf(PathPattern.Exact("/settings")))))
    }

    @Test
    fun matchesPathAfterDuplicateSlashCollapse() {
        assertClean("$base//settings", policy(paths = listOf(PathPattern.Exact("/settings"))))
    }

    @Test
    fun blocksEveryPathWhenNoPatternsDeclared() {
        assertEquals(listOf(PATH_NOT_ALLOWED), codes("$base/anything", policy(paths = emptyList())))
        assertEquals(listOf(PATH_NOT_ALLOWED), codes(base, policy(paths = emptyList())))
    }

    @Test
    fun emptyPathMatchesRootPattern() {
        assertClean(base, policy(paths = listOf(PathPattern.Exact("/"))))
        assertClean("$base/", policy(paths = listOf(PathPattern.Exact("/"))))
    }

    @Test
    fun anyPathAcceptsAnyCanonicalPath() = assertClean("$base/a/b/c/", policy(paths = listOf(PathPattern.AnyPath)))

    // ---- Fragment --------------------------------------------------------------------

    @Test
    fun blocksFragmentUnlessAllowed() {
        assertViolation("$base/p#top", policy(), FRAGMENT_NOT_ALLOWED, uriField(UriComponent.FRAGMENT))
        assertClean("$base/p#top", policy(allowFragment = true))
    }

    @Test
    fun blocksEmptyFragment() {
        assertEquals(listOf(FRAGMENT_NOT_ALLOWED), codes("$base/p#"))
    }

    // ---- Digits ----------------------------------------------------------------------

    private val idDigits = policy(params = listOf(param("id", ParamType.Digits)))

    @Test
    fun allowsDigitsOnlyValue() = assertClean("$base/p?id=42", idDigits)

    @Test
    fun blocksSqlInjectionInDigitsParam() {
        assertViolation("$base/p?id=1+OR+1%3D1", idDigits, PARAM_INVALID_FORMAT, declared("id"))
        assertViolation("$base/p?id=1;DROP", idDigits, PARAM_INVALID_FORMAT, declared("id"))
    }

    @Test
    fun blocksSignedHexAndExponentNumbers() {
        for (v in listOf("-1", "%2B1", "0x10", "1e3", "1.5")) {
            assertEquals("value <$v>", listOf(PARAM_INVALID_FORMAT), codes("$base/p?id=$v", idDigits))
        }
    }

    @Test
    fun blocksNonAsciiDigitsInDigitsParam() {
        // U+0661 ARABIC-INDIC DIGIT ONE and U+FF11 FULLWIDTH DIGIT ONE parse as numbers in some APIs.
        for (v in listOf("%D9%A1", "%EF%BC%91")) {
            assertEquals("value <$v>", listOf(PARAM_INVALID_FORMAT), codes("$base/p?id=$v", idDigits))
        }
    }

    @Test
    fun blocksEmptyValueForEveryType() {
        val types = listOf(
            ParamType.Digits, ParamType.OneOf(setOf("a")), ParamType.Uuid, ParamType.BoundedString(),
            ParamType.BoundedString(CharClass.TEXT),
        )
        for (t in types) {
            val p = policy(params = listOf(param("x", t)))
            assertEquals("$t with ?x=", listOf(PARAM_INVALID_FORMAT), codes("$base/p?x=", p))
            assertEquals("$t with ?x", listOf(PARAM_INVALID_FORMAT), codes("$base/p?x", p))
        }
        val url = policy(params = listOf(param("x", ParamType.Url(setOf("https"), setOf(HostPattern.Exact("example.com"))))))
        assertEquals(listOf(PARAM_URL_NOT_ALLOWED), codes("$base/p?x=", url))
    }

    // ---- OneOf -----------------------------------------------------------------------

    private val sortOneOf = policy(params = listOf(param("sort", ParamType.OneOf(setOf("price", "name")))))

    @Test
    fun allowsListedEnumValue() = assertClean("$base/p?sort=price", sortOneOf)

    @Test
    fun blocksInjectedValueOutsideEnum() {
        assertViolation("$base/p?sort=price;DROP+TABLE", sortOneOf, PARAM_INVALID_FORMAT, declared("sort"))
    }

    @Test
    fun enumMatchingIsExactAndCaseSensitive() {
        for (v in listOf("Price", "PRICE", "price%20", "pric")) {
            assertEquals("value <$v>", listOf(PARAM_INVALID_FORMAT), codes("$base/p?sort=$v", sortOneOf))
        }
    }

    // ---- Uuid ------------------------------------------------------------------------

    private val tokenUuid = policy(params = listOf(param("t", ParamType.Uuid)))

    @Test
    fun acceptsUuidInEitherCaseAndLeavesItUnchanged() {
        for (v in listOf("123e4567-e89b-12d3-a456-426614174000", "123E4567-E89B-12D3-A456-426614174000")) {
            val r = validate("$base/p?t=$v", tokenUuid)
            assertEquals(emptyList<Violation>(), r.violations)
            assertEquals(listOf("t" to v), r.retainedQuery)
        }
    }

    @Test
    fun blocksMalformedUuid() {
        val bad = listOf(
            "123e4567e89b12d3a456426614174000", "{123e4567-e89b-12d3-a456-426614174000}",
            "123e4567-e89b-12d3-a456-42661417400", "123e4567-e89b-12d3-a456-4266141740000",
            "g23e4567-e89b-12d3-a456-426614174000", "123e4567-e89b-12d3-a456-426614174000'--",
        )
        for (v in bad) assertEquals("value <$v>", listOf(PARAM_INVALID_FORMAT), codes("$base/p?t=$v", tokenUuid))
    }

    // ---- BoundedString ---------------------------------------------------------------

    private val slugDefault = policy(params = listOf(param("tag", ParamType.BoundedString())))

    @Test
    fun allowsSlugValueUnderDefaultCharClass() = assertClean("$base/p?tag=summer-sale_2026", slugDefault)

    @Test
    fun defaultSlugBlocksTraversalInjectionAndEncodingCharacters() {
        // '.', '/', '\', both quotes, '<', space (as %20 and +) and '%', as they arrive in a URI.
        val values = listOf("a.b", "a/b", "a\\b", "a%27b", "a%22b", "a%3Cb", "a%20b", "a+b", "100%25")
        for (v in values) assertEquals("value <$v>", listOf(PARAM_INVALID_FORMAT), codes("$base/p?tag=$v", slugDefault))
    }

    @Test
    fun blocksPathTraversalInSlugParam() {
        assertViolation("$base/p?tag=../../etc/passwd", slugDefault, PARAM_INVALID_FORMAT, declared("tag"))
    }

    @Test
    fun blocksScriptInjectionInSlugParam() {
        assertViolation("$base/p?tag=%3Cscript%3Ealert(1)%3C/script%3E", slugDefault, PARAM_INVALID_FORMAT, declared("tag"))
    }

    @Test
    fun blocksUnicodeSeparatorLookalikeInSlugParam() {
        // docs/LIMITATIONS.md L14: U+2215 DIVISION SLASH passes the canonicaliser in a query value.
        assertEquals(listOf(PARAM_INVALID_FORMAT), codes("$base/p?tag=a%E2%88%95b", slugDefault))
    }

    @Test
    fun textCharClassAcceptsUnicodeOnlyByExplicitOptIn() {
        val text = policy(params = listOf(param("q", ParamType.BoundedString(CharClass.TEXT))))
        assertClean("$base/p?q=caf%C3%A9+cr%C3%A8me", text)
        val default = policy(params = listOf(param("q", ParamType.BoundedString())))
        assertEquals(listOf(PARAM_INVALID_FORMAT), codes("$base/p?q=caf%C3%A9", default))
    }

    // ---- Length ----------------------------------------------------------------------

    @Test
    fun blocksValueOverRuleMaxLength() {
        val p = policy(params = listOf(param("id", ParamType.Digits, maxLength = 5)))
        assertClean("$base/p?id=12345", p)
        assertViolation("$base/p?id=123456", p, PARAM_TOO_LONG, declared("id"))
    }

    // ---- Required and repeated -------------------------------------------------------

    @Test
    fun blocksMissingRequiredParam() {
        val p = policy(params = listOf(param("id", ParamType.Digits, required = true)))
        assertViolation("$base/p", p, PARAM_MISSING, declared("id"))
        assertClean("$base/p?id=1", p)
    }

    @Test
    fun optionalParamMayBeAbsent() = assertClean("$base/p", idDigits)

    @Test
    fun blocksParameterPollution() {
        assertViolation("$base/p?id=1&id=2", idDigits, PARAM_REPEATED, declared("id"))
    }

    @Test
    fun blocksParameterPollutionEvenWhenEveryCopyIsValid() {
        assertEquals(listOf(PARAM_REPEATED), codes("$base/p?id=1&id=1", idDigits))
    }

    @Test
    fun allowsRepeatedParamOnlyWhenPolicyAllows() {
        val p = policy(params = listOf(param("id", ParamType.Digits)), allowRepeated = true)
        assertClean("$base/p?id=1&id=2", p)
        // Every copy is still checked.
        assertEquals(listOf(PARAM_INVALID_FORMAT), codes("$base/p?id=1&id=x", p))
    }

    // ---- Url (open redirect) ---------------------------------------------------------

    private val nextUrl = policy(
        params = listOf(param("next", ParamType.Url(setOf("https"), setOf(HostPattern.Exact("example.com"))))),
    )

    @Test
    fun allowsRedirectToListedHost() {
        assertClean("$base/p?next=https://example.com/account", nextUrl)
        assertClean("$base/p?next=https%3A%2F%2Fexample.com%2Faccount", nextUrl)
        // A nested query whose separators are encoded once (docs/LIMITATIONS.md L17).
        assertClean("$base/p?next=https://example.com/p%3Fa%3D1%26b%3D2", nextUrl)
    }

    @Test
    fun blocksOpenRedirectToUnlistedHost() {
        assertViolation("$base/p?next=https://evil.com/", nextUrl, PARAM_URL_NOT_ALLOWED, declared("next"))
        assertEquals(listOf(PARAM_URL_NOT_ALLOWED), codes("$base/p?next=https://example.com.evil.com/", nextUrl))
    }

    @Test
    fun blocksRedirectWithUnlistedScheme() {
        assertEquals(listOf(PARAM_URL_NOT_ALLOWED), codes("$base/p?next=http://example.com/", nextUrl))
    }

    @Test
    fun blocksJavascriptAndDataUrls() {
        for (v in listOf("javascript:alert(1)", "JAVASCRIPT:alert(1)", "data:text/html,%3Cscript%3E")) {
            assertEquals("value <$v>", listOf(PARAM_URL_NOT_ALLOWED), codes("$base/p?next=$v", nextUrl))
        }
    }

    @Test
    fun blocksProtocolRelativeAndSchemeColonHostForms() {
        for (v in listOf("//evil.com/", "https:evil.com", "https:/evil.com", "/relative")) {
            assertEquals("value <$v>", listOf(PARAM_URL_NOT_ALLOWED), codes("$base/p?next=$v", nextUrl))
        }
    }

    @Test
    fun blocksUserinfoTrickInRedirect() {
        assertEquals(listOf(PARAM_URL_NOT_ALLOWED), codes("$base/p?next=https://example.com%40evil.com/", nextUrl))
        assertEquals(listOf(PARAM_URL_NOT_ALLOWED), codes("$base/p?next=https://example.com:443%40evil.com/", nextUrl))
    }

    @Test
    fun blocksBackslashTrickInRedirect() {
        assertEquals(listOf(PARAM_URL_NOT_ALLOWED), codes("$base/p?next=https:\\\\evil.com", nextUrl))
        assertEquals(listOf(PARAM_URL_NOT_ALLOWED), codes("$base/p?next=https://example.com\\@evil.com", nextUrl))
    }

    @Test
    fun blocksRedirectWithExplicitNonDefaultPort() {
        assertEquals(listOf(PARAM_URL_NOT_ALLOWED), codes("$base/p?next=https://example.com:8443/", nextUrl))
        assertClean("$base/p?next=https://example.com:443/", nextUrl)
    }

    @Test
    fun blocksRedirectToSubdomainWithoutOptIn() {
        assertEquals(listOf(PARAM_URL_NOT_ALLOWED), codes("$base/p?next=https://evil.example.com/", nextUrl))
    }

    @Test
    fun nestedUrlCannotCarryPercentEscapesKnownLimitation() {
        // docs/LIMITATIONS.md L17: `%2520` decodes once to `%20`, which the outer canonicaliser
        // reports as double encoding before the Url rule runs.
        val r = UriCanonicalizer.canonicalize("$base/p?next=https://example.com/a%2520b", Limits.DEFAULT)
        assertTrue(r is CanonResult.Rejected)
        assertTrue(r.findings.any { it.code == URI_DOUBLE_ENCODING })
    }

    // ---- Unknown parameters ----------------------------------------------------------

    @Test
    fun blocksUnknownParamByDefault() {
        val r = validate("$base/p?id=1&debug=1", idDigits)
        assertEquals(listOf(Violation(PARAM_UNKNOWN, "product", undeclared("debug"))), r.violations)
    }

    @Test
    fun dropsUnknownParamUnderDropAndKeepsTheRest() {
        val p = policy(params = listOf(param("id", ParamType.Digits)), unknown = Unknown.Drop)
        val r = validate("$base/p?utm_source=x&id=1&debug=1&utm_source=y", p)
        assertEquals(
            listOf(
                Violation(PARAM_UNKNOWN_DROPPED, "product", undeclared("utm_source")),
                Violation(PARAM_UNKNOWN_DROPPED, "product", undeclared("debug")),
            ),
            r.violations,
        )
        // A dropped parameter is removed, so its repetition is not a violation of its own.
        assertEquals(listOf("id" to "1"), r.retainedQuery)
    }

    @Test
    fun keepsUnknownParamUnderIgnoreAsSoftSignal() {
        val p = policy(params = listOf(param("id", ParamType.Digits)), unknown = Unknown.Ignore)
        val r = validate("$base/p?id=1&ref=home", p)
        assertEquals(listOf(Violation(PARAM_UNKNOWN_IGNORED, "product", undeclared("ref"))), r.violations)
        assertEquals(listOf("id" to "1", "ref" to "home"), r.retainedQuery)
    }

    @Test
    fun blocksRepeatedUnknownParamUnderIgnore() {
        val p = policy(unknown = Unknown.Ignore)
        assertEquals(listOf(PARAM_UNKNOWN_IGNORED, PARAM_REPEATED), codes("$base/p?ref=a&ref=b", p))
    }

    @Test
    fun undeclaredParamNameIsRedactedInViolationText() {
        val v = validate("$base/p?s3cr3t=1").violations.single()
        assertFalse(v.toString().contains("s3cr3t"))
    }

    // ---- Several violations at once --------------------------------------------------

    @Test
    fun reportsAllViolationsAtOnce() {
        val p = policy(
            paths = listOf(PathPattern.Prefix("/product/")),
            params = listOf(param("id", ParamType.Digits, required = true), param("sort", ParamType.OneOf(setOf("price")))),
        )
        val got = codes("http://evil.com:8443/admin?sort=x&sort=price&debug=1#frag", p).toSet()
        assertEquals(
            setOf(
                SCHEME_NOT_ALLOWED, HOST_NOT_ALLOWED, PORT_NOT_ALLOWED, PATH_NOT_ALLOWED, FRAGMENT_NOT_ALLOWED,
                PARAM_MISSING, PARAM_REPEATED, PARAM_INVALID_FORMAT, PARAM_UNKNOWN,
            ),
            got,
        )
    }

    @Test
    fun reportsEachViolationOnceEvenForRepeatedInvalidCopies() {
        val p = policy(params = listOf(param("id", ParamType.Digits)), allowRepeated = true)
        assertEquals(listOf(PARAM_INVALID_FORMAT), codes("$base/p?id=x&id=y", p))
    }

    @Test
    fun violationsNeverContainValues() {
        val p = policy(params = listOf(param("id", ParamType.Digits), param("next", ParamType.Url(setOf("https"), setOf(HostPattern.Exact("example.com"))))))
        val v = validate("$base/p?id=s3cr3t&next=https://s3cr3t.com/", p).violations
        assertEquals(2, v.size)
        for (x in v) assertFalse(x.toString().contains("s3cr3t"))
    }

    @Test
    fun violationsCarryTheEntryPointName() {
        assertTrue(validate("http://evil.com/p").violations.all { it.entryPoint == "product" })
    }
}
