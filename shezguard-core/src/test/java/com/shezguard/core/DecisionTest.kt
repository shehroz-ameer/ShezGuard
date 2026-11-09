package com.shezguard.core

import android.content.Intent
import android.net.Uri
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/** Decision holds a real `Intent`, so these run under Robolectric. */
@RunWith(RobolectricTestRunner::class)
class DecisionTest {

    private val ep = "product"
    private val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com/secret-path?token=abc123"))

    private fun v(code: ViolationCode, entryPoint: String = ep) =
        Violation(code, entryPoint, Field.UriPart(UriComponent.WHOLE))

    private fun rejects(block: () -> Unit) {
        assertThrows(IllegalArgumentException::class.java) { block() }
    }

    @Test
    fun decisionToStringNeverContainsIntentData() {
        val decisions = listOf(
            Decision.Allow(intent, ep, emptyList(), RiskScore.ZERO),
            Decision.Sanitize(intent, ep, listOf(v(ViolationCode.PARAM_UNKNOWN_DROPPED)), RiskScore.ZERO),
            Decision.Block(ep, listOf(v(ViolationCode.URI_DOUBLE_ENCODING)), RiskScore.ZERO),
        )
        decisions.forEach { d ->
            val text = d.toString()
            assertFalse(text, text.contains("secret-path"))
            assertFalse(text, text.contains("abc123"))
            assertFalse(text, text.contains("example.com"))
        }
    }

    @Test
    fun outcomeMatchesSubtype() {
        assertEquals(Outcome.ALLOW, Decision.Allow(intent, ep, emptyList(), RiskScore.ZERO).outcome)
        assertEquals(
            Outcome.SANITIZE,
            Decision.Sanitize(intent, ep, listOf(v(ViolationCode.EXTRA_NOT_ALLOWED)), RiskScore.ZERO).outcome,
        )
        assertEquals(Outcome.BLOCK, Decision.Block(ep, listOf(v(ViolationCode.ENTRY_POINT_UNKNOWN)), RiskScore.ZERO).outcome)
    }

    @Test
    fun allowMayCarrySoftSignals() {
        Decision.Allow(intent, ep, listOf(v(ViolationCode.URI_NON_CANONICAL)), RiskScore.ZERO)
    }

    /** Two-tier rule: a hard violation can never end in Allow, whatever the score. */
    @Test
    fun allowRejectsHardViolation() = rejects {
        Decision.Allow(intent, ep, listOf(v(ViolationCode.URI_PATH_TRAVERSAL)), RiskScore.ZERO)
    }

    @Test
    fun allowRejectsRemovableViolation() = rejects {
        Decision.Allow(intent, ep, listOf(v(ViolationCode.EXTRA_NOT_ALLOWED)), RiskScore.ZERO)
    }

    @Test
    fun sanitizeRejectsHardViolation() = rejects {
        Decision.Sanitize(intent, ep, listOf(v(ViolationCode.NESTED_INTENT_DENIED)), RiskScore.ZERO)
    }

    @Test
    fun sanitizeRequiresAViolation() = rejects {
        Decision.Sanitize(intent, ep, emptyList(), RiskScore.ZERO)
    }

    /** Soft signals have nothing to remove, so they alone can never produce Sanitize. */
    @Test
    fun sanitizeRejectsSoftSignalsWithoutRemovableViolation() = rejects {
        Decision.Sanitize(intent, ep, listOf(v(ViolationCode.CALLER_NOT_ALLOWED)), RiskScore.ZERO)
    }

    @Test
    fun sanitizeMayListSoftSignalsAlongsideRemovableViolation() {
        Decision.Sanitize(
            intent,
            ep,
            listOf(v(ViolationCode.EXTRA_NOT_ALLOWED), v(ViolationCode.DOMAIN_NOT_VERIFIED)),
            RiskScore.ZERO,
        )
    }

    /** Every block is explained. */
    @Test
    fun blockRequiresAtLeastOneViolation() = rejects {
        Decision.Block(ep, emptyList(), RiskScore.ZERO)
    }

    @Test
    fun violationsMustBelongToTheDecisionsEntryPoint() = rejects {
        Decision.Block(ep, listOf(v(ViolationCode.URI_EMPTY, entryPoint = "other")), RiskScore.ZERO)
    }
}
