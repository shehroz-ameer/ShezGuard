package com.shezguard.core.policy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Step 5: the `intentPolicy { }` DSL. Building a policy is where misconfiguration is caught,
 * so every build-time rule has a test that checks the message tells the developer what to fix.
 */
class PolicyDslTest {

    private val digest = "a".repeat(64)

    // ---- helpers -------------------------------------------------------------------

    private fun problems(block: IntentPolicyBuilder.() -> Unit): List<String> {
        try {
            intentPolicy(block)
        } catch (e: PolicyDefinitionException) {
            return e.problems
        }
        fail("expected PolicyDefinitionException")
        throw AssertionError()
    }

    /** Asserts that some problem contains every fragment (what is wrong and how to fix it). */
    private fun assertProblem(vararg fragments: String, block: IntentPolicyBuilder.() -> Unit) {
        val p = problems(block)
        assertTrue(
            "expected a problem containing ${fragments.toList()}, got:\n${p.joinToString("\n")}",
            p.any { msg -> fragments.all { it in msg } },
        )
    }

    /** A minimal valid data-accepting entry point, for tests that add one more thing. */
    private fun EntryPointBuilder.validData() {
        allowSchemes("https")
        allowHosts("example.com")
        anyPath()
    }

    private fun single(block: EntryPointBuilder.() -> Unit): EntryPointPolicy =
        intentPolicy { entryPoint("p", block) }["p"]!!

    // ---- Building: the SPEC section 7 sketch -----------------------------------------

    @Test
    fun buildsTheSpecSketchPolicy() {
        val policy = intentPolicy {
            entryPoint("product") {
                allowSchemes("https")
                allowHosts("example.com")
                path { prefix("/product/") }
                param("id") { digitsOnly(maxLength = 10); required() }
                unknownParams(Unknown.Block)
                nestedIntents(Nested.Deny)
                caller(Caller.Any)
                threshold(block = 70)
            }
        }
        val ep = policy["product"]!!
        assertEquals(Data.Required, ep.data)
        assertEquals(setOf("https"), ep.schemes)
        assertEquals(setOf(HostPattern.Exact("example.com")), ep.hosts)
        assertEquals(listOf(PathPattern.Prefix("/product/")), ep.paths)
        assertEquals(ParamRule("id", ParamType.Digits, maxLength = 10, required = true), ep.param("id"))
        assertEquals(Unknown.Block, ep.unknownParams)
        assertEquals(Nested.Deny, ep.nestedIntents)
        assertEquals(Caller.Any, ep.caller)
        assertEquals(Threshold(70), ep.threshold)
    }

    @Test
    fun defaultsAreFailClosed() {
        val ep = single { }
        assertEquals(Data.Forbidden, ep.data)
        assertTrue(ep.schemes.isEmpty())
        assertTrue(ep.hosts.isEmpty())
        assertTrue(ep.ports.isEmpty())
        assertTrue(ep.paths.isEmpty())
        assertEquals(false, ep.allowFragment)
        assertTrue(ep.params.isEmpty())
        assertEquals(Unknown.Block, ep.unknownParams)
        assertEquals(false, ep.allowRepeatedParams)
        assertEquals(Nested.Deny, ep.nestedIntents)
        assertEquals(ExtrasRule.NONE, ep.extras)
        assertEquals(Caller.Any, ep.caller)
        assertEquals(Threshold.DEFAULT, ep.threshold)
        assertEquals(Limits.DEFAULT, ep.limits)
    }

    @Test
    fun allowSchemesSwitchesDataToRequired() {
        assertEquals(Data.Required, single { validData() }.data)
    }

    @Test
    fun explicitDataBeatsTheAllowSchemesSwitchInEitherOrder() {
        assertEquals(Data.Optional, single { data(Data.Optional); validData() }.data)
        assertEquals(Data.Optional, single { validData(); data(Data.Optional) }.data)
    }

    @Test
    fun buildsEveryUriRule() {
        val ep = single {
            allowSchemes("https", "myapp")
            allowHosts("example.com", "product")
            subdomainsOf("example.org")
            allowPorts(8443)
            path { exact("/settings"); prefix("/product/") }
            allowFragment()
            unknownParams(Unknown.Drop)
            allowRepeatedParams()
            limits(maxUriLength = 1024, maxParamLength = 128)
        }
        assertEquals(setOf("https", "myapp"), ep.schemes)
        assertEquals(
            setOf(HostPattern.Exact("example.com"), HostPattern.Exact("product"), HostPattern.SubdomainsOf("example.org")),
            ep.hosts,
        )
        assertEquals(setOf(8443), ep.ports)
        assertEquals(listOf(PathPattern.Exact("/settings"), PathPattern.Prefix("/product/")), ep.paths)
        assertTrue(ep.allowFragment)
        assertEquals(Unknown.Drop, ep.unknownParams)
        assertTrue(ep.allowRepeatedParams)
        assertEquals(Limits(1024, 128), ep.limits)
    }

    @Test
    fun anyPathBuildsTheAnyPathPattern() {
        assertEquals(listOf(PathPattern.AnyPath), single { validData() }.paths)
    }

    // ---- Parameters ------------------------------------------------------------------

    @Test
    fun buildsEveryParamType() {
        val ep = single {
            validData()
            param("id") { digitsOnly() }
            param("sort") { oneOf("price", "name") }
            param("t") { uuid() }
            param("tag") { string() }
            param("q") { string(chars = CharClass.TEXT, maxLength = 100) }
            param("next") { url { allowSchemes("https"); allowHosts("example.com"); subdomainsOf("example.org") } }
        }
        assertEquals(ParamType.Digits, ep.param("id")!!.type)
        assertEquals(ParamType.OneOf(setOf("price", "name")), ep.param("sort")!!.type)
        assertEquals(ParamType.Uuid, ep.param("t")!!.type)
        assertEquals(ParamType.BoundedString(CharClass.SLUG), ep.param("tag")!!.type)
        assertEquals(ParamType.BoundedString(CharClass.TEXT), ep.param("q")!!.type)
        assertEquals(100, ep.param("q")!!.maxLength)
        assertEquals(
            ParamType.Url(setOf("https"), setOf(HostPattern.Exact("example.com"), HostPattern.SubdomainsOf("example.org"))),
            ep.param("next")!!.type,
        )
        assertEquals(false, ep.param("id")!!.required)
    }

    @Test
    fun stringDefaultsToSlugCharClass() {
        assertEquals(ParamType.BoundedString(CharClass.SLUG), single { validData(); param("tag") { string() } }.param("tag")!!.type)
    }

    @Test
    fun unsetMaxLengthDefaultsToEntryPointMaxParamLengthEvenWhenLimitsComeLater() {
        assertEquals(Limits.DEFAULT_MAX_PARAM_LENGTH, single { validData(); param("id") { digitsOnly() } }.param("id")!!.maxLength)
        val ep = single {
            validData()
            param("id") { digitsOnly() }
            limits(maxParamLength = 40)
        }
        assertEquals(40, ep.param("id")!!.maxLength)
    }

    // ---- Caller ----------------------------------------------------------------------

    @Test
    fun buildsCallerShorthands() {
        assertEquals(Caller.RequireVerifiedDomain, single { requireVerifiedDomain() }.caller)
        val ep = single { allowedPackages { pkg("com.partner.app", digest) } }
        assertEquals(Caller.AllowedPackages(mapOf("com.partner.app" to setOf(CertificateDigest(digest)))), ep.caller)
    }

    @Test
    fun normalisesKeytoolStyleCertificateDigests() {
        val lower = (0 until 32).joinToString("") { "%02x".format(it * 7 % 256) }
        val colonUpper = lower.uppercase().chunked(2).joinToString(":")
        val variants = listOf(lower, lower.uppercase(), colonUpper, colonUpper.lowercase())
        for (v in variants) {
            val caller = single { allowedPackages { pkg("com.partner.app", v) } }.caller as Caller.AllowedPackages
            assertEquals("digest <$v>", setOf(CertificateDigest(lower)), caller.packages["com.partner.app"])
        }
    }

    @Test
    fun rejectsMalformedCertificateDigestsWithFormatHint() {
        val bad = listOf(
            "a".repeat(63),                                  // too short
            "g".repeat(64),                                  // not hex
            List(20) { "AB" }.joinToString(":"),             // a SHA-1 fingerprint
            "AB:" + "c".repeat(62),                          // mixed forms
            List(32) { "AB" }.joinToString("-"),             // wrong separator
            List(32) { "AB" }.joinToString(":") + ":",       // trailing colon
        )
        for (d in bad) {
            assertProblem("com.partner.app", "SHA-256", "64 hex characters", "colon-separated", "keytool") {
                entryPoint("p") { allowedPackages { pkg("com.partner.app", d) } }
            }
        }
    }

    // ---- Extras and nested intents ---------------------------------------------------

    @Test
    fun buildsExtrasRule() {
        val ep = single {
            extras { allow("source", ExtraType.STRING); allow("count", ExtraType.INT); maxKeys(4); maxStringLength(64); maxArrayLength(8) }
        }
        assertEquals(
            ExtrasRule(mapOf("source" to ExtraType.STRING, "count" to ExtraType.INT), maxKeys = 4, maxStringLength = 64, maxArrayLength = 8),
            ep.extras,
        )
    }

    // ---- Build-time rules (proposal (b)) ---------------------------------------------

    @Test // rule 1
    fun rejectsPolicyWithNoEntryPoints() {
        assertProblem("declares no entry points", "entryPoint(") { }
    }

    @Test // rule 1
    fun rejectsDuplicateEntryPointNames() {
        assertProblem("entryPoint(\"p\")", "more than once", "unique") {
            entryPoint("p") { }
            entryPoint("p") { }
        }
    }

    @Test // rule 1
    fun rejectsInvalidEntryPointName() {
        assertProblem("entryPoint(\"a b\")", "A-Z a-z 0-9 _ . -") { entryPoint("a b") { } }
    }

    @Test // rule 2
    fun rejectsDataAcceptingEntryPointWithoutScheme() {
        assertProblem("entryPoint(\"p\")", "allows no scheme", "allowSchemes(") {
            entryPoint("p") { data(Data.Required); allowHosts("example.com"); anyPath() }
        }
    }

    @Test // rule 3
    fun rejectsHttpsEntryPointWithoutHosts() {
        assertProblem("entryPoint(\"p\")", "allows no host", "allowHosts(", "subdomainsOf(") {
            entryPoint("p") { allowSchemes("https"); anyPath() }
        }
    }

    @Test // rule 3
    fun rejectsOptionalDataEntryPointWithoutHosts() {
        assertProblem("allows no host") {
            entryPoint("p") { data(Data.Optional); allowSchemes("myapp"); anyPath() }
        }
    }

    @Test // rule 4
    fun rejectsDataAcceptingEntryPointWithoutPathPattern() {
        assertProblem("entryPoint(\"p\")", "no path pattern", "path {", "anyPath()") {
            entryPoint("p") { allowSchemes("https"); allowHosts("example.com") }
        }
    }

    @Test // rule 5
    fun rejectsAnyPathCombinedWithPatterns() {
        assertProblem("anyPath()", "path {", "either") {
            entryPoint("p") { validData(); path { exact("/x") } }
        }
    }

    @Test // rule 6, as changed by the author: also when Forbidden is only the default
    fun rejectsUriRulesWhenDataIsForbiddenByDefault() {
        assertProblem("entryPoint(\"p\")", "allowHosts", "param", "Forbidden", "default", "allowSchemes(...)", "data(...)") {
            entryPoint("p") { allowHosts("example.com"); param("id") { digitsOnly() } }
        }
    }

    @Test // rule 6
    fun rejectsEachKindOfUriRuleWhenDataIsForbidden() {
        val rules: List<Pair<String, EntryPointBuilder.() -> Unit>> = listOf(
            "allowHosts" to { allowHosts("example.com") },
            "subdomainsOf" to { subdomainsOf("example.com") },
            "allowPorts" to { allowPorts(8443) },
            "path" to { path { exact("/x") } },
            "anyPath" to { anyPath() },
            "allowFragment" to { allowFragment() },
            "param" to { param("id") { digitsOnly() } },
            "unknownParams" to { unknownParams(Unknown.Drop) },
            "allowRepeatedParams" to { allowRepeatedParams() },
        )
        for ((name, rule) in rules) {
            assertProblem(name, "Forbidden", "allowSchemes(...)") { entryPoint("p") { rule() } }
        }
    }

    @Test // rule 6
    fun rejectsAllowSchemesWithExplicitDataForbidden() {
        assertProblem("allowSchemes", "data(Data.Forbidden)") {
            entryPoint("p") { data(Data.Forbidden); validData() }
        }
    }

    @Test // rule 7
    fun rejectsSingleValuedOptionSetTwice() {
        val twice: List<Pair<String, EntryPointBuilder.() -> Unit>> = listOf(
            "data(" to { data(Data.Required); data(Data.Optional) },
            "threshold(" to { threshold(block = 50); threshold(block = 60) },
            "unknownParams(" to { unknownParams(Unknown.Block); unknownParams(Unknown.Drop) },
            "nestedIntents(" to { nestedIntents(Nested.Deny); nestedIntents(Nested.Deny) },
            "limits(" to { limits(); limits() },
            "extras {" to { extras { }; extras { } },
        )
        for ((name, block) in twice) {
            assertProblem(name, "more than once", "not an override") { entryPoint("p") { validData(); block() } }
        }
    }

    @Test // rule 7
    fun rejectsCallerRuleSetTwice() {
        assertProblem("caller rule is set more than once", "Choose one") {
            entryPoint("p") { requireVerifiedDomain(); allowedPackages { pkg("com.partner.app", digest) } }
        }
        assertProblem("caller rule is set more than once") {
            entryPoint("p") { caller(Caller.Any); requireVerifiedDomain() }
        }
    }

    @Test // rule 8
    fun rejectsAllowedPackagesWithoutPackagesOrDigests() {
        assertProblem("allowedPackages", "lists no package", "pkg(") {
            entryPoint("p") { allowedPackages { } }
        }
        assertProblem("com.partner.app", "no certificate digest", "pkg(") {
            entryPoint("p") { allowedPackages { pkg("com.partner.app") } }
        }
    }

    @Test // rule 8
    fun rejectsInvalidOrDuplicatePackageNames() {
        assertProblem("\"partner\"", "package name") {
            entryPoint("p") { allowedPackages { pkg("partner", digest) } }
        }
        assertProblem("com.partner.app", "more than once") {
            entryPoint("p") { allowedPackages { pkg("com.partner.app", digest); pkg("com.partner.app", digest) } }
        }
    }

    @Test // rule 9
    fun rejectsParamWithoutType() {
        assertProblem("param(\"id\")", "no type", "digitsOnly()", "oneOf(", "uuid()", "string(", "url {") {
            entryPoint("p") { validData(); param("id") { required() } }
        }
    }

    @Test // rule 9
    fun rejectsParamWithMoreThanOneType() {
        assertProblem("param(\"id\")", "2 types", "digitsOnly", "uuid", "keep one") {
            entryPoint("p") { validData(); param("id") { digitsOnly(); uuid() } }
        }
    }

    @Test // rule 9
    fun rejectsDuplicateParamNames() {
        assertProblem("param(\"id\")", "more than once") {
            entryPoint("p") { validData(); param("id") { digitsOnly() }; param("id") { uuid() } }
        }
    }

    @Test // rule 9
    fun rejectsParamNameOutsideConservativeSet() {
        for (bad in listOf("a+b", "ids[]", "a b", "", "x".repeat(65))) {
            assertProblem("param(\"$bad\")", "A-Z a-z 0-9 _ . -", "1 to 64", "L16") {
                entryPoint("p") { validData(); param(bad) { digitsOnly() } }
            }
        }
    }

    @Test // rule 9
    fun rejectsUnusableOneOf() {
        assertProblem("param(\"s\")", "oneOf", "no values") {
            entryPoint("p") { validData(); param("s") { oneOf() } }
        }
        assertProblem("param(\"s\")", "oneOf", "empty value") {
            entryPoint("p") { validData(); param("s") { oneOf("a", "") } }
        }
        assertProblem("param(\"s\")", "oneOf", "longer than maxLength 3", "never match") {
            entryPoint("p") { validData(); param("s") { oneOf("abc", "abcd", maxLength = 3) } }
        }
    }

    @Test // rule 10, as changed by the author: only an explicit maxLength can exceed the limit
    fun rejectsExplicitMaxLengthAboveEntryPointMaxParamLength() {
        assertProblem("param(\"id\")", "maxLength 500", "maxParamLength 256", "limits(maxParamLength") {
            entryPoint("p") { validData(); param("id") { digitsOnly(maxLength = 500) } }
        }
        assertProblem("maxLength 50", "maxParamLength 40") {
            entryPoint("p") { validData(); limits(maxParamLength = 40); param("id") { digitsOnly(maxLength = 50) } }
        }
        // Unset maxLength follows the limit, so this is valid.
        single { validData(); limits(maxParamLength = 40); param("id") { digitsOnly() } }
    }

    @Test // rule 11
    fun rejectsUrlParamWithoutSchemeOrHost() {
        assertProblem("param(\"next\")", "url { }", "allows no scheme", "allowSchemes(") {
            entryPoint("p") { validData(); param("next") { url { allowHosts("example.com") } } }
        }
        assertProblem("param(\"next\")", "url { }", "allows no host", "allowHosts(") {
            entryPoint("p") { validData(); param("next") { url { allowSchemes("https") } } }
        }
    }

    @Test // rule 13
    fun rejectsOutOfRangeNumbers() {
        assertProblem("threshold(block = 0)", "1..100") { entryPoint("p") { threshold(block = 0) } }
        assertProblem("threshold(block = 101)", "1..100") { entryPoint("p") { threshold(block = 101) } }
        assertProblem("limits(", "positive") { entryPoint("p") { limits(maxUriLength = 0) } }
        assertProblem("param(\"id\")", "maxLength", "positive") {
            entryPoint("p") { validData(); param("id") { digitsOnly(maxLength = 0) } }
        }
        assertProblem("extras", "maxKeys", "positive") { entryPoint("p") { extras { maxKeys(0) } } }
        assertProblem("allowPorts(70000)", "1..65535") { entryPoint("p") { validData(); allowPorts(70000) } }
    }

    @Test
    fun reportsInvalidSchemesHostsAndPathPatternsWithTheirCall() {
        assertProblem("allowSchemes(\"HTTPS\")", "lowercase") { entryPoint("p") { allowSchemes("HTTPS"); allowHosts("example.com"); anyPath() } }
        assertProblem("allowHosts(\"Example.com\")", "lowercase") { entryPoint("p") { allowSchemes("https"); allowHosts("Example.com"); anyPath() } }
        assertProblem("subdomainsOf(\"com\")", "two labels") { entryPoint("p") { allowSchemes("https"); subdomainsOf("com"); anyPath() } }
        assertProblem("prefix(\"/product\")", "must end with '/'") {
            entryPoint("p") { allowSchemes("https"); allowHosts("example.com"); path { prefix("/product") } }
        }
        assertProblem("exact(\"/a/../b\")", "invalid path pattern") {
            entryPoint("p") { allowSchemes("https"); allowHosts("example.com"); path { exact("/a/../b") } }
        }
    }

    @Test
    fun rejectsExtraKeyAllowedTwice() {
        assertProblem("extras", "\"k\"", "more than once") {
            entryPoint("p") { extras { allow("k", ExtraType.STRING); allow("k", ExtraType.INT) } }
        }
    }

    // ---- Reporting -------------------------------------------------------------------

    @Test
    fun collectsAllProblemsAcrossAllEntryPoints() {
        val p = problems {
            entryPoint("a") { allowSchemes("https") }                      // no host, no path
            entryPoint("b") { param("id") { }; threshold(block = 0) }        // forbidden data with param, no type, bad threshold
        }
        assertTrue(p.joinToString("\n"), p.size >= 5)
        assertTrue(p.any { it.startsWith("entryPoint(\"a\")") })
        assertTrue(p.any { it.startsWith("entryPoint(\"b\")") })
    }

    @Test
    fun exceptionIsAnIllegalArgumentExceptionListingEveryProblem() {
        val e = try {
            intentPolicy { entryPoint("a") { allowSchemes("https") } }
            null
        } catch (e: PolicyDefinitionException) {
            e
        }
        val ex = e ?: throw AssertionError("expected PolicyDefinitionException")
        assertTrue(ex is IllegalArgumentException)
        assertTrue(ex.message!!.startsWith("Invalid ShezGuard policy (2 problems):"))
        for (problem in ex.problems) assertTrue(ex.message!!.contains(problem))
    }

    // ---- @DslMarker -------------------------------------------------------------------

    @Test
    fun everyBuilderCarriesTheDslMarker() {
        val builders = listOf(
            IntentPolicyBuilder::class.java, EntryPointBuilder::class.java, PathBuilder::class.java,
            ParamBuilder::class.java, UrlBuilder::class.java, ExtrasBuilder::class.java,
            AllowedPackagesBuilder::class.java,
        )
        for (b in builders) {
            assertTrue("${b.simpleName} lacks @ShezGuardDsl", b.isAnnotationPresent(ShezGuardDsl::class.java))
        }
        // That ShezGuardDsl is itself a @DslMarker cannot be checked here: kotlin.DslMarker has
        // BINARY retention, so it is invisible to runtime reflection. The compiler enforces it;
        // see the compile-failure check recorded in docs/SPEC.md section 7.
    }
}
