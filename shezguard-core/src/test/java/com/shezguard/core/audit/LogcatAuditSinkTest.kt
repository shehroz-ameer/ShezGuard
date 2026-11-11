package com.shezguard.core.audit

import android.util.Log
import com.shezguard.core.Field
import com.shezguard.core.IdentitySource
import com.shezguard.core.Outcome
import com.shezguard.core.RiskScore
import com.shezguard.core.ScoreContribution
import com.shezguard.core.UriComponent
import com.shezguard.core.Violation
import com.shezguard.core.ViolationCode
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.shadows.ShadowLog
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Step 9 proposal (d): the debug logcat sink. Robolectric (ShadowLog), SDK 34. */
@RunWith(RobolectricTestRunner::class)
class LogcatAuditSinkTest {

    @Before
    fun clear() = ShadowLog.clear()

    private fun lines() = ShadowLog.getLogsForTag("ShezGuard").map { it.type to it.msg }

    private val block = AuditEvent.from(
        "product",
        Outcome.BLOCK,
        listOf(Violation(ViolationCode.URI_PATH_TRAVERSAL, "product", Field.UriPart(UriComponent.PATH))) +
            List(7) { Violation(ViolationCode.PARAM_UNKNOWN, "product", Field.Param("n$it", declared = false)) },
        RiskScore.of(emptyList(), threshold = 70),
        null,
    )

    private val allow = AuditEvent.from(
        "browse",
        Outcome.ALLOW,
        listOf(Violation(ViolationCode.PARAM_UNKNOWN_IGNORED, "browse", Field.Param("u", declared = false))),
        RiskScore.of(
            listOf(ScoreContribution(Violation(ViolationCode.PARAM_UNKNOWN_IGNORED, "browse", Field.Param("u", false)), 5)),
            threshold = 70,
        ),
        IdentitySource.REFERRER_EXTRA,
    )

    @Test
    fun blockLineHasTheExactFormatAndWarnLevel() {
        LogcatAuditSink().onDecision(block)
        assertEquals(
            listOf(
                Log.WARN to "outcome=BLOCK ep=product score=0/70 caller=- " +
                    "violations=[URI_PATH_TRAVERSAL@uri.path, PARAM_UNKNOWN@param:<undeclared>x7]",
            ),
            lines(),
        )
    }

    @Test
    fun onlyBlocksAreLoggedByDefault() {
        LogcatAuditSink().onDecision(allow)
        assertEquals(emptyList<Any>(), lines())
    }

    @Test
    fun lowerOutcomesAreLoggedAtInfoWhenEnabled() {
        LogcatAuditSink(minOutcome = Outcome.ALLOW).onDecision(allow)
        assertEquals(
            listOf(Log.INFO to "outcome=ALLOW ep=browse score=5/70 caller=REFERRER_EXTRA violations=[PARAM_UNKNOWN_IGNORED@param:<undeclared>]"),
            lines(),
        )
    }

    @Test
    fun noThresholdIsShownAsDash() {
        val e = AuditEvent.from("x", Outcome.BLOCK, listOf(Violation(ViolationCode.ENTRY_POINT_UNKNOWN, "x", Field.EntryPoint)), RiskScore.ZERO, null)
        LogcatAuditSink().onDecision(e)
        assertEquals("outcome=BLOCK ep=x score=0/- caller=- violations=[ENTRY_POINT_UNKNOWN@entryPoint]", lines().single().second)
    }

    @Test
    fun floodIsCappedPerMinuteWithOneSuppressedLine() {
        var now = 1_000L
        val sink = LogcatAuditSink(Outcome.BLOCK, maxLinesPerMinute = 3) { now }
        repeat(10) { sink.onDecision(block) }
        assertEquals(3, lines().size)
        now += 59_999
        sink.onDecision(block)
        assertEquals("still in the same window", 3, lines().size)
        now += 1
        sink.onDecision(block)
        val l = lines()
        assertEquals(5, l.size)
        assertEquals(Log.WARN to "suppressed=8 (more than 3 lines per minute)", l[3])
        assertEquals("outcome=BLOCK", l[4].second.substringBefore(' '))
    }

    @Test
    fun capHoldsUnderConcurrentCalls() {
        val sink = LogcatAuditSink(Outcome.BLOCK, maxLinesPerMinute = 30) { 0L }
        val pool = Executors.newFixedThreadPool(8)
        val start = CountDownLatch(1)
        repeat(8) { pool.execute { start.await(); repeat(100) { sink.onDecision(block) } } }
        start.countDown()
        pool.shutdown()
        pool.awaitTermination(30, TimeUnit.SECONDS)
        assertEquals(30, lines().size)
    }
}
