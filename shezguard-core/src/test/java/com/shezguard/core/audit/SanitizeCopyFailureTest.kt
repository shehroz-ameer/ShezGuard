package com.shezguard.core.audit

import com.shezguard.core.Decision
import com.shezguard.core.Outcome
import com.shezguard.core.ShezGuard
import com.shezguard.core.ViolationCode
import com.shezguard.core.eval.CallerSource
import com.shezguard.core.eval.DomainVerifier
import com.shezguard.core.eval.EvalFixtures.renderedOutput
import com.shezguard.core.eval.EvalFixtures.viewIntent
import com.shezguard.core.policy.CharClass
import com.shezguard.core.policy.ExtraType
import com.shezguard.core.policy.Unknown
import com.shezguard.core.policy.intentPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.shadows.ShadowLog

/**
 * Author condition 3 (step 9 follow-up): a failure while building the Sanitize copy is caught by
 * ShezGuard's outer catch (not the evaluator's), becomes EVALUATION_FAILED, emits exactly one
 * event, and leaks nothing, even with the canary in the exception message, the URI and the
 * extras. The failure is injected after the copy is built. Robolectric, SDK 34.
 */
@RunWith(RobolectricTestRunner::class)
class SanitizeCopyFailureTest {

    private val canary = "zqxcanary"

    @Test
    fun sanitizeCopyFailureLeaksNothing() {
        ShadowLog.clear()
        val events = mutableListOf<AuditEvent>()
        val logcat = LogcatAuditSink(Outcome.ALLOW, maxLinesPerMinute = 100)
        val policy = intentPolicy {
            auditSink { events += it; logcat.onDecision(it) }
            entryPoint("drop") {
                allowSchemes("https")
                allowHosts("example.com")
                anyPath()
                param("q") { string(CharClass.TEXT) }
                unknownParams(Unknown.Drop)
                extras { allow("title", ExtraType.STRING) }
            }
        }
        val intent = viewIntent("https://example.com/p?q=$canary&$canary=1").putExtra("title", canary).putExtra(canary, canary)

        // Without the failure it is a Sanitize whose copy holds the canary: the path is real.
        val ok = ShezGuard.evaluate(intent, policy, "drop")
        assertTrue(ok is Decision.Sanitize)
        assertTrue((ok as Decision.Sanitize).sanitizedIntent.dataString!!.contains(canary))
        events.clear()
        ShadowLog.clear()

        var hookRan = false
        val d = ShezGuard.evaluateWith(
            intent,
            policy,
            "drop",
            { CallerSource.NONE },
            afterSanitizeCopy = {
                hookRan = true
                throw IllegalStateException("copy failed: $canary ${it.dataString}")
            },
            domain = DomainVerifier.NONE,
        )
        assertTrue("the injected failure did not run", hookRan)
        assertTrue(d is Decision.Block)
        assertEquals(listOf(ViolationCode.EVALUATION_FAILED), d.violations.map { it.code })
        assertNull(d.score.threshold)

        assertEquals(1, events.size)
        assertEquals(listOf(ViolationCode.EVALUATION_FAILED), events.single().violations.map { it.code })
        assertFalse(events.single().toString(), events.single().toString().contains(canary))
        assertFalse(renderedOutput(d), renderedOutput(d).contains(canary))
        val logs = ShadowLog.getLogs()
        assertEquals(1, logs.size)
        logs.forEach {
            assertFalse(it.msg, it.msg.contains(canary))
            assertNull(it.throwable)
        }
    }
}
