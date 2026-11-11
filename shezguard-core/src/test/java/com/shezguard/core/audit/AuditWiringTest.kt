package com.shezguard.core.audit

import android.app.Activity
import android.content.Intent
import com.shezguard.core.Decision
import com.shezguard.core.Delivery
import com.shezguard.core.Outcome
import com.shezguard.core.ShezGuard
import com.shezguard.core.ViolationCode
import com.shezguard.core.eval.CallerInfo
import com.shezguard.core.eval.CallerSource
import com.shezguard.core.eval.DomainVerifier
import com.shezguard.core.eval.EvalFixtures.summary
import com.shezguard.core.eval.EvalFixtures.viewIntent
import com.shezguard.core.policy.CharClass
import com.shezguard.core.policy.EntryPointBuilder
import com.shezguard.core.policy.ExtraType
import com.shezguard.core.policy.IntentPolicy
import com.shezguard.core.policy.Unknown
import com.shezguard.core.policy.intentPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.shadows.ShadowLog

/** Step 9 proposals (c) and (e): when and how the sink is called. Robolectric, SDK 34. */
@RunWith(RobolectricTestRunner::class)
class AuditWiringTest {

    private class Recording : AuditSink {
        val events = mutableListOf<AuditEvent>()
        override fun onDecision(event: AuditEvent) {
            events += event
        }
    }

    private fun EntryPointBuilder.search(drop: Boolean) {
        allowSchemes("https")
        allowHosts("example.com")
        path { exact("/search") }
        param("q") { string(CharClass.TEXT) }
        unknownParams(if (drop) Unknown.Drop else Unknown.Block)
    }

    private fun policy(sink: AuditSink): IntentPolicy = intentPolicy {
        auditSink(sink)
        entryPoint("drop") { search(drop = true); extras { allow("title", ExtraType.STRING) } }
        entryPoint("strict") { search(drop = false) }
        entryPoint("scored") { search(drop = true); scoreWeight(ViolationCode.URI_NON_CANONICAL, 100) }
        entryPoint("partner") { allowedPackages { pkg("com.partner.app", "ab".repeat(32)) } }
    }

    /** Each case: entry point, intent, expected outcome, expected leading code. */
    private val cases = listOf(
        Triple("drop", viewIntent("https://example.com/search?q=x"), Outcome.ALLOW),
        Triple("drop", viewIntent("https://example.com/search?q=x&utm=1"), Outcome.SANITIZE),
        Triple("drop", viewIntent("https://example.com/search?q=x").putExtra("evil", "y"), Outcome.SANITIZE),
        Triple("strict", viewIntent("https://example.com/search?q=x&utm=1"), Outcome.BLOCK),
        Triple("scored", viewIntent("https://example.com//search?q=x"), Outcome.BLOCK),
        Triple("missing", viewIntent("https://example.com/search?q=x"), Outcome.BLOCK),
    )

    @Test
    fun everyOutcomePathEmitsExactlyOneMatchingEvent() {
        val sink = Recording()
        val p = policy(sink)
        for ((ep, intent, expected) in cases) {
            val before = sink.events.size
            val d = ShezGuard.evaluate(intent, p, ep)
            assertEquals("$ep", expected, d.outcome)
            assertEquals("$ep emitted ${sink.events.size - before} events", before + 1, sink.events.size)
            val e = sink.events.last()
            assertEquals(d.outcome, e.outcome)
            assertEquals(d.entryPoint, e.entryPoint)
            assertEquals(d.violations.map { it.code }, e.violations.map { it.code })
            assertEquals(d.violations.map { it.field.toString() }, e.violations.map { it.field })
            assertEquals(d.score.total, e.scoreTotal)
            assertEquals(d.score.threshold, e.threshold)
            assertEquals(d.callerIdentitySource, e.callerIdentitySource)
        }
        assertEquals(listOf(ViolationCode.ENTRY_POINT_UNKNOWN), sink.events.last().violations.map { it.code })
        assertEquals(null, sink.events.last().threshold)
    }

    @Test
    fun evaluationFailedEmitsExactlyOneEvent() {
        val sink = Recording()
        val throwing = object : CallerSource {
            override fun read(): CallerInfo = throw IllegalStateException("broken source")
            override fun currentSignerDigests(packageName: String): Set<String>? = null
        }
        val d = ShezGuard.evaluateWith(Intent(), policy(sink), "partner", { throwing }, domain = DomainVerifier.NONE)
        assertEquals(listOf(ViolationCode.EVALUATION_FAILED), d.violations.map { it.code })
        assertEquals(1, sink.events.size)
        assertEquals(listOf(ViolationCode.EVALUATION_FAILED), sink.events.single().violations.map { it.code })
    }

    @Test
    fun activityOverloadAlsoEmitsExactlyOneEvent() {
        val sink = Recording()
        val intent = Intent()
        val a = Robolectric.buildActivity(Activity::class.java, intent).create().get()
        for (delivery in Delivery.entries) ShezGuard.evaluate(a, intent, delivery, policy(sink), "partner")
        assertEquals(2, sink.events.size)
        assertTrue(sink.events.all { ViolationCode.CALLER_UNIDENTIFIED in it.violations.map { v -> v.code } })
    }

    @Test
    fun throwingSinkDoesNotChangeTheDecision() {
        ShadowLog.clear()
        val throwing = AuditSink { throw IllegalStateException("sink failed") }
        for ((ep, intent, _) in cases) {
            val expected = summary(ShezGuard.evaluate(intent, policy(AuditSink.NONE), ep))
            assertEquals(ep, expected, summary(ShezGuard.evaluate(intent, policy(throwing), ep)))
        }
        assertEquals("the exception is swallowed silently", emptyList<Any>(), ShadowLog.getLogs())
    }

    @Test
    fun errorsFromTheSinkPropagate() {
        val p = policy(AuditSink { throw AssertionError("an Error, not caught") })
        assertThrows(AssertionError::class.java) { ShezGuard.evaluate(viewIntent("https://example.com/search?q=x"), p, "drop") }
    }

    @Test
    fun sinkCannotMutateTheDecision() {
        // The sink only ever receives the AuditEvent; its lists are unmodifiable.
        val vandal = AuditSink { e ->
            @Suppress("UNCHECKED_CAST")
            (e.violations as MutableList<AuditViolation>).clear()
        }
        for ((ep, intent, _) in cases) {
            val clean = ShezGuard.evaluate(intent, policy(AuditSink.NONE), ep)
            val d = ShezGuard.evaluate(intent, policy(vandal), ep)
            assertEquals(summary(clean), summary(d))
            if (d is Decision.Sanitize) assertEquals(
                (clean as Decision.Sanitize).sanitizedIntent.toUri(0),
                d.sanitizedIntent.toUri(0),
            )
        }
    }

    @Test
    fun defaultPolicyUsesTheNoOpSink() {
        val p = intentPolicy { entryPoint("x") { } }
        assertSame(AuditSink.NONE, p.auditSink)
        assertEquals(Outcome.ALLOW, ShezGuard.evaluate(Intent(), p, "x").outcome)
    }
}
