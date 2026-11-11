package com.shezguard.core.audit

import com.shezguard.core.Field
import com.shezguard.core.IdentitySource
import com.shezguard.core.Outcome
import com.shezguard.core.RiskScore
import com.shezguard.core.ScoreContribution
import com.shezguard.core.Severity
import com.shezguard.core.Tier
import com.shezguard.core.UriComponent
import com.shezguard.core.Violation
import com.shezguard.core.ViolationCode
import com.shezguard.core.policy.PolicyDefinitionException
import com.shezguard.core.policy.intentPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Step 9: the AuditEvent model and the DSL setting. Pure JVM. */
class AuditEventTest {

    private val canary = "zqxcanary"

    private fun event(
        ep: String = "product",
        violations: List<Violation> = emptyList(),
        score: RiskScore = RiskScore.ZERO,
        outcome: Outcome = Outcome.BLOCK,
        source: IdentitySource? = null,
    ) = AuditEvent.from(ep, outcome, violations, score, source)

    @Test
    fun carriesRedactedFieldsOnly() {
        val vs = listOf(
            Violation(ViolationCode.PARAM_UNKNOWN, "product", Field.Param("${canary}name", declared = false)),
            Violation(ViolationCode.EXTRA_NOT_ALLOWED, "product", Field.Extra("${canary}key", declared = false)),
            Violation(ViolationCode.PARAM_INVALID_FORMAT, "product", Field.Param("id", declared = true)),
            Violation(ViolationCode.HOST_NOT_ALLOWED, "product", Field.UriPart(UriComponent.HOST)),
        )
        val e = event(violations = vs)
        assertEquals(listOf("param:<undeclared>", "extra:<undeclared>", "param:id", "uri.host"), e.violations.map { it.field })
        assertEquals(vs.map { it.code }, e.violations.map { it.code })
        assertEquals(vs.map { it.tier }, e.violations.map { it.tier })
        assertEquals(vs.map { it.severity }, e.violations.map { it.severity })
        assertFalse(e.toString(), e.toString().contains(canary))
    }

    @Test
    fun carriesScoreThresholdContributionsAndSource() {
        val soft = Violation(ViolationCode.PARAM_UNKNOWN_IGNORED, "browse", Field.Param("${canary}p", declared = false))
        val score = RiskScore.of(listOf(ScoreContribution(soft, 5, occurrences = 3)), threshold = 70)
        val e = event("browse", listOf(soft, soft, soft), score, Outcome.ALLOW, IdentitySource.REFERRER_EXTRA)
        assertEquals(5, e.scoreTotal)
        assertEquals(70, e.threshold)
        assertEquals(listOf(Triple(ViolationCode.PARAM_UNKNOWN_IGNORED, 5, 3)), e.contributions.map { Triple(it.code, it.weight, it.occurrences) })
        assertEquals(IdentitySource.REFERRER_EXTRA, e.callerIdentitySource)
        assertEquals(Outcome.ALLOW, e.outcome)
        assertFalse(e.toString().contains(canary))
    }

    @Test
    fun invalidEntryPointNameIsReplaced() {
        assertEquals("<invalid>", event(ep = "bad name/$canary").entryPoint)
        assertEquals("<invalid>", event(ep = "").entryPoint)
        assertEquals("<invalid>", event(ep = "a".repeat(65)).entryPoint)
        assertEquals("product.v2", event(ep = "product.v2").entryPoint)
    }

    @Test
    fun noThresholdWhenNoPolicyApplied() {
        val e = event(ep = "missing", violations = listOf(Violation(ViolationCode.ENTRY_POINT_UNKNOWN, "missing", Field.EntryPoint)))
        assertEquals(null, e.threshold)
        assertTrue(e.toString().contains("threshold=null"))
    }

    @Test
    fun eventListsCannotBeModified() {
        val e = event(violations = listOf(Violation(ViolationCode.URI_EMPTY, "product", Field.UriPart(UriComponent.WHOLE))))
        @Suppress("UNCHECKED_CAST")
        assertThrows(UnsupportedOperationException::class.java) { (e.violations as MutableList<AuditViolation>).clear() }
        @Suppress("UNCHECKED_CAST")
        assertThrows(UnsupportedOperationException::class.java) { (e.contributions as MutableList<AuditContribution>).clear() }
    }

    @Test
    fun eventsWithTheSameContentAreEqual() {
        val vs = listOf(Violation(ViolationCode.URI_EMPTY, "product", Field.UriPart(UriComponent.WHOLE), Severity.HIGH))
        assertEquals(event(violations = vs), event(violations = vs))
        assertEquals(event(violations = vs).hashCode(), event(violations = vs).hashCode())
        assertEquals(Tier.HARD, event(violations = vs).violations.single().tier)
    }

    // ---- DSL -------------------------------------------------------------------------

    @Test
    fun noOpSinkIsTheDefault() {
        val p = intentPolicy { entryPoint("p") { } }
        assertSame(AuditSink.NONE, p.auditSink)
        AuditSink.NONE.onDecision(event()) // does nothing, never throws
    }

    @Test
    fun dslRegistersOneSink() {
        val sink = AuditSink { }
        assertSame(sink, intentPolicy { auditSink(sink); entryPoint("p") { } }.auditSink)
    }

    @Test
    fun dslRejectsSinkSetTwice() {
        val e = assertThrows(PolicyDefinitionException::class.java) {
            intentPolicy { auditSink { }; auditSink { }; entryPoint("p") { } }
        }
        assertEquals(
            listOf("intentPolicy: auditSink(...) is set more than once. Set it once; a second call is an error, not an override."),
            e.problems,
        )
    }
}
