package com.shezguard.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ViolationModelTest {

    // ---- Stable codes ---------------------------------------------------------------

    /**
     * Snapshot of every code id. If this fails, a public code was added, removed or renamed:
     * that breaks the contract cited in tests, the attack matrix and the paper. Update the
     * snapshot only on purpose.
     */
    @Test
    fun violationCodeIdsAreStable() {
        val expected = listOf(
            "ENTRY_POINT_UNKNOWN", "EVALUATION_FAILED",
            "URI_EMPTY", "URI_TOO_LONG", "URI_MALFORMED", "URI_OPAQUE", "URI_SCHEME_INVALID",
            "URI_HOST_EMPTY", "URI_HOST_NON_ASCII", "URI_HOST_INVALID", "URI_HOST_PERCENT_ENCODED",
            "URI_HOST_TRAILING_DOT", "URI_USERINFO", "URI_PORT_INVALID", "URI_PERCENT_MALFORMED",
            "URI_DOUBLE_ENCODING", "URI_INVALID_UTF8", "URI_NULL_BYTE", "URI_CONTROL_CHAR",
            "URI_FORMAT_CHAR", "URI_WHITESPACE", "URI_BACKSLASH", "URI_PATH_TRAVERSAL",
            "URI_PATH_DOT_SEGMENT", "URI_PATH_ENCODED_SEPARATOR", "URI_PATH_UNICODE_SEPARATOR",
            "URI_PARSER_MISMATCH", "URI_NON_CANONICAL",
            "DATA_MISSING", "DATA_FORBIDDEN", "SCHEME_NOT_ALLOWED", "HOST_NOT_ALLOWED",
            "PORT_NOT_ALLOWED", "PATH_NOT_ALLOWED", "FRAGMENT_NOT_ALLOWED",
            "PARAM_MISSING", "PARAM_TOO_LONG", "PARAM_NAME_INVALID", "PARAM_INVALID_FORMAT",
            "PARAM_URL_NOT_ALLOWED", "PARAM_REPEATED", "PARAM_UNKNOWN", "PARAM_UNKNOWN_DROPPED",
            "PARAM_UNKNOWN_IGNORED",
            "EXTRAS_UNPARCEL_FAILED", "EXTRAS_TOO_MANY", "EXTRAS_TOO_DEEP", "EXTRA_NOT_ALLOWED", "EXTRA_WRONG_TYPE",
            "EXTRA_TOO_LARGE", "NESTED_INTENT_DENIED", "NESTED_INTENT_SANITIZED",
            "CALLER_UNIDENTIFIED", "CALLER_NOT_ALLOWED", "CALLER_NOT_ALLOWED_RELIABLE",
            "DOMAIN_NOT_VERIFIED", "DOMAIN_VERIFICATION_UNAVAILABLE",
        )
        assertEquals(expected, ViolationCode.entries.map { it.id })
    }

    /** Step 5b, author decision 1: the fail-closed safety net always blocks. */
    @Test
    fun evaluationFailedIsHardAndCritical() {
        assertEquals(Tier.HARD, ViolationCode.EVALUATION_FAILED.tier)
        assertEquals(Severity.CRITICAL, ViolationCode.EVALUATION_FAILED.defaultSeverity)
    }

    /** Step 6, author decision 2: extras nested too deep fail closed (absence of an intent cannot be shown). */
    @Test
    fun extrasTooDeepIsHardAndHigh() {
        assertEquals(Tier.HARD, ViolationCode.EXTRAS_TOO_DEEP.tier)
        assertEquals(Severity.HIGH, ViolationCode.EXTRAS_TOO_DEEP.defaultSeverity)
    }

    /** Step 6: every extras and nested-intent code except the two removable ones blocks. */
    @Test
    fun extrasAndNestedIntentCodesHaveTheApprovedTiers() {
        val expected = mapOf(
            ViolationCode.EXTRAS_UNPARCEL_FAILED to Tier.HARD,
            ViolationCode.EXTRAS_TOO_MANY to Tier.HARD,
            ViolationCode.EXTRAS_TOO_DEEP to Tier.HARD,
            ViolationCode.EXTRA_NOT_ALLOWED to Tier.REMOVABLE,
            ViolationCode.EXTRA_WRONG_TYPE to Tier.HARD,
            ViolationCode.EXTRA_TOO_LARGE to Tier.HARD,
            ViolationCode.NESTED_INTENT_DENIED to Tier.HARD,
            ViolationCode.NESTED_INTENT_SANITIZED to Tier.REMOVABLE,
        )
        expected.forEach { (code, tier) -> assertEquals(code.id, tier, code.tier) }
    }

    @Test
    fun violationCodeIdsAreUnique() {
        val ids = ViolationCode.entries.map { it.id }
        assertEquals(ids.size, ids.toSet().size)
    }

    @Test
    fun violationCodeFromIdRoundTrips() {
        ViolationCode.entries.forEach { assertSame(it, ViolationCode.fromId(it.id)) }
        assertNull(ViolationCode.fromId("NOT_A_CODE"))
    }

    /** SPEC 4.1: Sanitize may only remove unknown params, disallowed extras and nested-intent parts. */
    @Test
    fun onlySpecifiedCodesAreRemovable() {
        val removable = ViolationCode.entries.filter { it.tier == Tier.REMOVABLE }.toSet()
        assertEquals(
            setOf(
                ViolationCode.PARAM_UNKNOWN_DROPPED,
                ViolationCode.EXTRA_NOT_ALLOWED,
                ViolationCode.NESTED_INTENT_SANITIZED,
            ),
            removable,
        )
    }

    /** SPEC 5.1: only advisory signals are soft; everything structural or content-related is hard. */
    @Test
    fun onlyAdvisoryCodesAreSoft() {
        val soft = ViolationCode.entries.filter { it.tier == Tier.SOFT }.toSet()
        assertEquals(
            setOf(
                ViolationCode.URI_NON_CANONICAL,
                ViolationCode.PARAM_UNKNOWN_IGNORED,
                ViolationCode.CALLER_UNIDENTIFIED,
                ViolationCode.CALLER_NOT_ALLOWED,
                ViolationCode.DOMAIN_NOT_VERIFIED,
                ViolationCode.DOMAIN_VERIFICATION_UNAVAILABLE,
            ),
            soft,
        )
    }

    @Test
    fun violationTierFollowsCodeAndSeverityDefaultsToCode() {
        val v = Violation(ViolationCode.URI_PATH_TRAVERSAL, "product", Field.UriPart(UriComponent.PATH))
        assertEquals(Tier.HARD, v.tier)
        assertEquals(Severity.CRITICAL, v.severity)
    }

    // ---- Redaction --------------------------------------------------------------------

    @Test
    fun undeclaredParamNameIsRedactedInToString() {
        val field = Field.Param("<script>alert(1)</script>", declared = false)
        assertEquals("param:<undeclared>", field.toString())
    }

    @Test
    fun undeclaredExtraKeyIsRedactedInToString() {
        val field = Field.Extra("attacker_key", declared = false)
        assertEquals("extra:<undeclared>", field.toString())
    }

    @Test
    fun declaredNamesAreShownInToString() {
        assertEquals("param:id", Field.Param("id", declared = true).toString())
        assertEquals("extra:mode", Field.Extra("mode", declared = true).toString())
        assertEquals("uri.host", Field.UriPart(UriComponent.HOST).toString())
    }

    @Test
    fun violationToStringNeverContainsUndeclaredName() {
        val v = Violation(ViolationCode.PARAM_UNKNOWN, "product", Field.Param("secret_token", declared = false))
        assertFalse(v.toString().contains("secret_token"))
    }

    // ---- Risk score -------------------------------------------------------------------

    private fun soft(code: ViolationCode = ViolationCode.CALLER_NOT_ALLOWED) =
        Violation(code, "product", Field.CallerSignal)

    @Test
    fun scoreSumsContributionWeights() {
        val score = RiskScore.of(listOf(ScoreContribution(soft(), 20), ScoreContribution(soft(), 15)))
        assertEquals(35, score.total)
        assertEquals(2, score.contributions.size)
    }

    @Test
    fun scoreIsCappedAt100() {
        val score = RiskScore.of(List(5) { ScoreContribution(soft(), Int.MAX_VALUE) })
        assertEquals(100, score.total)
    }

    @Test
    fun zeroScoreHasNoContributions() {
        assertEquals(0, RiskScore.ZERO.total)
        assertTrue(RiskScore.ZERO.contributions.isEmpty())
    }

    /** SPEC 5.1: weights can never turn a hard violation into a scored one. */
    @Test
    fun hardViolationCannotContributeToScore() {
        val hard = Violation(ViolationCode.URI_DOUBLE_ENCODING, "product", Field.UriPart(UriComponent.PATH))
        assertThrows(IllegalArgumentException::class.java) { ScoreContribution(hard, 10) }
    }

    @Test
    fun removableViolationCannotContributeToScore() {
        val removable = Violation(ViolationCode.EXTRA_NOT_ALLOWED, "product", Field.Extra("k", false))
        assertThrows(IllegalArgumentException::class.java) { ScoreContribution(removable, 10) }
    }

    @Test
    fun negativeWeightIsRejected() {
        assertThrows(IllegalArgumentException::class.java) { ScoreContribution(soft(), -1) }
    }
}
