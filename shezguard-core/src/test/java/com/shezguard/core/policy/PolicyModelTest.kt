package com.shezguard.core.policy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class PolicyModelTest {

    private fun rejects(block: () -> Unit) {
        assertThrows(IllegalArgumentException::class.java) { block() }
    }

    // ---- Entry point defaults (deny by default) ----------------------------------------

    @Test
    fun entryPointDefaultsAreMostRestrictive() {
        val p = EntryPointPolicy("product")
        assertEquals(Data.Forbidden, p.data)
        assertTrue(p.schemes.isEmpty())
        assertTrue(p.hosts.isEmpty())
        assertTrue(p.ports.isEmpty())
        assertFalse(p.allowFragment)
        assertEquals(Unknown.Block, p.unknownParams)
        assertFalse(p.allowRepeatedParams)
        assertSame(Nested.Deny, p.nestedIntents)
        assertSame(ExtrasRule.NONE, p.extras)
        assertTrue(p.extras.allowed.isEmpty())
        assertEquals(Threshold(block = 70), p.threshold)
        assertTrue("no path patterns means no path matches", p.paths.isEmpty())
        assertEquals(2048, p.limits.maxUriLength)
        assertEquals(256, p.limits.maxParamLength)
    }

    @Test
    fun unknownEntryPointLookupReturnsNull() {
        val policy = IntentPolicy(listOf(EntryPointPolicy("product")))
        assertNotNull(policy["product"])
        assertNull(policy["admin"])
    }

    @Test
    fun rejectsDuplicateEntryPointNames() {
        rejects { IntentPolicy(listOf(EntryPointPolicy("product"), EntryPointPolicy("product"))) }
    }

    @Test
    fun rejectsInvalidEntryPointNames() {
        rejects { EntryPointPolicy("") }
        rejects { EntryPointPolicy("has space") }
        rejects { EntryPointPolicy("a".repeat(65)) }
    }

    @Test
    fun rejectsDuplicateParamRules() {
        rejects {
            EntryPointPolicy(
                "product",
                params = listOf(ParamRule("id", ParamType.Digits), ParamRule("id", ParamType.Uuid)),
            )
        }
    }

    @Test
    fun rejectsUppercaseOrInvalidScheme() {
        rejects { EntryPointPolicy("p", schemes = setOf("HTTPS")) }
        rejects { EntryPointPolicy("p", schemes = setOf("1http")) }
    }

    @Test
    fun rejectsOutOfRangePort() {
        rejects { EntryPointPolicy("p", ports = setOf(0)) }
        rejects { EntryPointPolicy("p", ports = setOf(65536)) }
    }

    // ---- Threshold ---------------------------------------------------------------------

    @Test
    fun thresholdAcceptsEdges1And100() {
        Threshold(block = 1)
        Threshold(block = 100)
    }

    /** block = 0 would block every intent, even one with no signals: a misconfiguration, not a policy. */
    @Test
    fun thresholdRejectsZero() = rejects { Threshold(block = 0) }

    @Test
    fun thresholdRejectsAbove100() = rejects { Threshold(block = 101) }

    @Test
    fun limitsRejectNonPositiveValues() {
        rejects { Limits(maxUriLength = 0) }
        rejects { Limits(maxParamLength = 0) }
    }

    // ---- Hosts (lookalikes and tricks cannot be expressed in a policy) ------------------

    @Test
    fun exactHostAcceptsSingleLabelForCustomSchemes() {
        HostPattern.Exact("product")
        HostPattern.Exact("shop.example.com")
    }

    @Test
    fun hostRejectsUppercase() = rejects { HostPattern.Exact("Example.com") }

    @Test
    fun hostRejectsTrailingDot() = rejects { HostPattern.Exact("example.com.") }

    @Test
    fun hostRejectsCyrillicLookalike() = rejects { HostPattern.Exact("еxample.com") }

    @Test
    fun hostRejectsUserInfoTrick() = rejects { HostPattern.Exact("example.com@evil.com") }

    @Test
    fun hostRejectsPortOrPath() {
        rejects { HostPattern.Exact("example.com:443") }
        rejects { HostPattern.Exact("example.com/x") }
    }

    @Test
    fun subdomainsOfRejectsBareTopLevelDomain() = rejects { HostPattern.SubdomainsOf("com") }

    // ---- Paths ------------------------------------------------------------------------

    @Test
    fun prefixMustEndWithSlashToKeepSegmentBoundary() {
        PathPattern.Prefix("/product/")
        rejects { PathPattern.Prefix("/product") }
    }

    @Test
    fun pathPatternRejectsTraversalAndDotSegments() {
        rejects { PathPattern.Exact("/a/../b") }
        rejects { PathPattern.Prefix("/a/./") }
    }

    @Test
    fun pathPatternRejectsEncodingBackslashAndDuplicateSlash() {
        rejects { PathPattern.Exact("/a%2Fb") }
        rejects { PathPattern.Exact("/a\\b") }
        rejects { PathPattern.Exact("/a//b") }
    }

    @Test
    fun pathPatternMustStartWithSlash() = rejects { PathPattern.Exact("product") }

    @Test
    fun anyPathIsAnExplicitPattern() {
        val p = EntryPointPolicy("p", data = Data.Required, paths = listOf(PathPattern.AnyPath))
        assertEquals(listOf(PathPattern.AnyPath), p.paths)
    }

    @Test
    fun pathPatternAllowsDotsInsideSegmentNames() {
        PathPattern.Exact("/file..txt")
        PathPattern.Prefix("/v1.2/")
    }

    // ---- Parameters -------------------------------------------------------------------

    @Test
    fun paramRuleRejectsInvalidNames() {
        rejects { ParamRule("", ParamType.Digits) }
        rejects { ParamRule("a=b", ParamType.Digits) }
        rejects { ParamRule("a b", ParamType.Digits) }
        rejects { ParamRule("a%20", ParamType.Digits) }
    }

    @Test
    fun paramRuleRejectsNonPositiveMaxLength() = rejects { ParamRule("id", ParamType.Digits, maxLength = 0) }

    @Test
    fun oneOfRejectsEmptySetOrEmptyValue() {
        rejects { ParamType.OneOf(emptySet()) }
        rejects { ParamType.OneOf(setOf("")) }
    }

    @Test
    fun urlParamRequiresSchemesAndHosts() {
        rejects { ParamType.Url(emptySet(), setOf(HostPattern.Exact("example.com"))) }
        rejects { ParamType.Url(setOf("https"), emptySet()) }
    }

    // ---- Extras, nested intents, caller -------------------------------------------------

    @Test
    fun extrasRuleRejectsNonPositiveLimits() {
        rejects { ExtrasRule(maxKeys = 0) }
        rejects { ExtrasRule(maxStringLength = 0) }
        rejects { ExtrasRule(maxArrayLength = 0) }
    }

    @Test
    fun allowedPackagesRequireAtLeastOneDigest() {
        rejects { Caller.AllowedPackages(mapOf("com.partner.app" to emptySet())) }
    }

    @Test
    fun allowedPackagesRejectInvalidPackageName() {
        val digest = CertificateDigest("a".repeat(64))
        rejects { Caller.AllowedPackages(mapOf("nodots" to setOf(digest))) }
    }

    @Test
    fun certificateDigestRejectsMalformedHex() {
        CertificateDigest("0123456789abcdef".repeat(4))
        rejects { CertificateDigest("AB".repeat(32)) }
        rejects { CertificateDigest("ab:".repeat(31) + "ab") }
        rejects { CertificateDigest("a".repeat(63)) }
    }
}
