package com.shezguard.core.audit

import android.app.Activity
import android.content.ComponentName
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Parcelable
import androidx.core.content.IntentSanitizer
import com.shezguard.core.ActivityGuard
import com.shezguard.core.Decision
import com.shezguard.core.Delivery
import com.shezguard.core.Outcome
import com.shezguard.core.ShezGuard
import com.shezguard.core.activity.GuardHarness
import com.shezguard.core.activity.HarnessActivity
import com.shezguard.core.activity.PartnerActivity
import com.shezguard.core.activity.PlainActivity
import com.shezguard.core.activity.ProductActivity
import com.shezguard.core.activity.UnannotatedActivity
import com.shezguard.core.activity.UnregisteredActivity
import com.shezguard.core.android.NestedIntentSanitizer
import com.shezguard.core.eval.CallerInfo
import com.shezguard.core.eval.CallerSource
import com.shezguard.core.eval.DomainVerifier
import com.shezguard.core.eval.ExtrasFixtures
import com.shezguard.core.policy.CharClass
import com.shezguard.core.policy.EntryPointBuilder
import com.shezguard.core.policy.ExtraType
import com.shezguard.core.policy.Nested
import com.shezguard.core.policy.Unknown
import com.shezguard.core.policy.intentPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.shadows.ShadowLog
import kotlin.random.Random

/**
 * Step 9 canary test: attacker-controlled text never reaches an AuditEvent or logcat.
 * Robolectric, SDK 34. [CANARY] is placed in every attacker-controlled position; author
 * condition 3 adds exception messages and the Sanitize path.
 */
@RunWith(RobolectricTestRunner::class)
class AuditCanaryTest {

    private companion object {
        const val CANARY = "zqxcanary"
        const val SEED = 0xA0D17
    }

    private val events = mutableListOf<AuditEvent>()
    private val recording = AuditSink { events += it }
    private val logcat = LogcatAuditSink(Outcome.ALLOW, maxLinesPerMinute = Int.MAX_VALUE)
    private val fanOut = AuditSink { recording.onDecision(it); logcat.onDecision(it) }
    private val throwingSink = AuditSink { throw IllegalStateException("sink $CANARY") }

    @Before
    fun clear() = ShadowLog.clear()

    private fun EntryPointBuilder.web(unknown: Unknown) {
        allowSchemes("https")
        allowHosts("example.com")
        anyPath()
        param("q") { string(CharClass.TEXT) }
        unknownParams(unknown)
        allowFragment()
        extras { allow("title", ExtraType.STRING) }
    }

    private val nestedSanitizer = NestedIntentSanitizer(
        IntentSanitizer.Builder().allowAnyComponent().allowAction(Intent.ACTION_VIEW).allowExtra("note", String::class.java).build(),
    )

    private fun policy(sink: AuditSink) = intentPolicy {
        auditSink(sink)
        entryPoint("drop") { web(Unknown.Drop) }
        entryPoint("ignore") { web(Unknown.Ignore) }
        entryPoint("strict") { web(Unknown.Block) }
        entryPoint("nested") { nestedIntents(Nested.AllowSanitized(setOf("next"), nestedSanitizer)) }
        entryPoint("partner") { allowedPackages { pkg("com.partner.app", "ab".repeat(32)) } }
        entryPoint("verified") {
            allowSchemes("https")
            allowHosts("example.com")
            anyPath()
            requireVerifiedDomain()
        }
    }

    private val uris = listOf(
        "https://example.com/search?q=$CANARY",                          // Allow, canary in a declared value
        "https://example.com/search?q=a&$CANARY=1",                      // Sanitize (drop) / Block / Allow (ignore)
        "https://example.com/search?q=$CANARY&u=$CANARY#$CANARY",        // Sanitize, canary kept in the rebuilt URI
        "https://example.com/$CANARY/x?q=%7Aqxcanary",                   // canary in path; encoded canary in value
        "https://$CANARY.example.com/?q=x",                              // host
        "https://example.com.$CANARY/?q=x",                              // host
        "$CANARY://example.com/?q=x",                                    // scheme
        "https://example.com/?$CANARY",                                  // name without value
        "https://example.com/?q=x&zqx%20canary=1",                       // invalid name
        "https://example.com/a/../$CANARY?q=x",                          // hard canonicalisation failure
        "https://example.com/?q=x#$CANARY",                              // fragment
        "https://user$CANARY@example.com/?q=x",                          // userinfo
    )

    private fun randomExtras(r: Random, i: Intent): Intent {
        val b = Bundle()
        if (r.nextBoolean()) b.putString("title", CANARY)                 // kept on Sanitize
        if (r.nextBoolean()) b.putString(CANARY, CANARY)                  // unknown key and value
        if (r.nextInt(3) == 0) b.putString(Intent.EXTRA_REFERRER_NAME, "android-app://com.$CANARY.app")
        if (r.nextInt(3) == 0) b.putParcelable(Intent.EXTRA_REFERRER, Uri.parse("android-app://com.$CANARY.app"))
        if (r.nextInt(3) == 0) b.putParcelable(
            "next",
            Intent(Intent.ACTION_VIEW, Uri.parse("https://$CANARY.example/")).setComponent(ComponentName("com.$CANARY", "com.$CANARY.A"))
                .putExtra("note", CANARY).putExtra(CANARY, CANARY),
        )
        if (r.nextInt(4) == 0) b.putParcelableArray(CANARY, arrayOf<Parcelable>(Intent("$CANARY.ACTION")))
        if (r.nextInt(4) == 0) b.putBundle("deep", ExtrasFixtures.nestedBundles(6) { putString(CANARY, CANARY) })
        i.putExtras(b)
        return if (r.nextBoolean()) ExtrasFixtures.received(i) else i
    }

    private val entryPoints = listOf("drop", "ignore", "strict", "nested", "partner", "verified", "missing", "$CANARY!")

    @Test
    fun canaryNeverReachesAnAuditEventOrLogcat() {
        val r = Random(SEED)
        val decisions = mutableListOf<Decision>()
        val p = policy(fanOut)
        val throwingCaller = object : CallerSource {
            override fun read(): CallerInfo = throw IllegalStateException("caller $CANARY")
            override fun currentSignerDigests(packageName: String): Set<String>? = throw IllegalStateException(CANARY)
        }
        repeat(600) { n ->
            val base = if (r.nextInt(5) == 0) Intent() else Intent(Intent.ACTION_VIEW, Uri.parse(uris[r.nextInt(uris.size)]))
            val intent = if (r.nextBoolean()) randomExtras(r, base) else base
            val ep = entryPoints[r.nextInt(entryPoints.size)]
            decisions += when (n % 4) {
                0 -> ShezGuard.evaluate(intent, p, ep)
                1 -> {
                    val a = Robolectric.buildActivity(Activity::class.java, intent).create().get()
                    shadowOf(a).setCallingPackage("com.$CANARY.app")
                    ShezGuard.evaluate(a, intent, Delivery.entries[r.nextInt(2)], p, ep)
                }
                2 -> ShezGuard.evaluateWith(intent, p, ep, { throwingCaller }, domain = DomainVerifier.NONE)
                else -> ShezGuard.evaluate(intent, policy(throwingSink), ep)
            }
        }

        // Not vacuous: the canary did reach the decisions, every outcome occurred, logcat was written.
        assertEquals(Outcome.entries.toSet(), decisions.map { it.outcome }.toSet())
        assertTrue("canary never survived into a sanitized intent", decisions.any {
            it is Decision.Sanitize && (it.sanitizedIntent.dataString.orEmpty().contains(CANARY) || it.sanitizedIntent.getStringExtra("title") == CANARY)
        })
        assertTrue("canary never reached GuardedUri", decisions.any { it is Decision.Allow && it.data?.param("q") == CANARY })
        assertTrue(decisions.any { d -> d.violations.any { v -> v.code.id == "EVALUATION_FAILED" } })
        assertTrue(events.size > 400)
        val logs = ShadowLog.getLogs()
        assertTrue(logs.size > 400)

        // The property.
        for (e in events) {
            val text = listOf(e.toString(), e.entryPoint) + e.violations.map { it.field + it } + e.contributions.map { it.toString() }
            text.forEach { assertTrue("canary in event: $it", !it.contains(CANARY, ignoreCase = true)) }
        }
        for (l in logs) {
            assertTrue("canary in logcat: ${l.tag} ${l.msg}", !l.msg.contains(CANARY, ignoreCase = true) && !l.tag.contains(CANARY))
            assertTrue("a throwable was logged", l.throwable == null)
        }
    }

    /**
     * Step 10: the same property through `ActivityGuard`, for launches and `onNewIntent` deliveries,
     * including the unannotated and unregistered paths. Robolectric, SDK 34.
     */
    @Test
    fun canaryNeverReachesAnAuditEventOrLogcatThroughTheActivityGuard() {
        val r = Random(SEED + 10)
        GuardHarness.guard = ActivityGuard(
            intentPolicy {
                auditSink(fanOut)
                entryPoint("product") { web(Unknown.Drop) }
                entryPoint("plain") { extras { allow("title", ExtraType.STRING) } }
                entryPoint("partner") { allowedPackages { pkg("com.partner.app", "ab".repeat(32)) } }
            },
        )
        val classes = listOf(
            ProductActivity::class.java, PlainActivity::class.java, PartnerActivity::class.java,
            UnannotatedActivity::class.java, UnregisteredActivity::class.java,
        )
        fun randomIntent(): Intent {
            val base = if (r.nextInt(4) == 0) Intent() else Intent(Intent.ACTION_VIEW, Uri.parse(uris[r.nextInt(uris.size)]))
            return if (r.nextBoolean()) randomExtras(r, base) else base
        }
        var canaryReachedCheckedData = false
        repeat(300) {
            @Suppress("UNCHECKED_CAST")
            val cls = classes[r.nextInt(classes.size)] as Class<HarnessActivity>
            val c = Robolectric.buildActivity(cls, randomIntent())
            if (r.nextBoolean()) shadowOf(c.get()).setCallingPackage("com.$CANARY.app")
            c.create()
            if (!c.get().isFinishing) repeat(r.nextInt(3)) { c.newIntent(randomIntent()) }
            if (c.get().checked?.data?.param("q") == CANARY) canaryReachedCheckedData = true
            c.destroy() // keep no activity alive: 300 live activities exhaust the default test heap
        }

        // Not vacuous: every outcome occurred through the guard, and the canary reached the app's checked data.
        assertEquals(Outcome.entries.toSet(), events.map { it.outcome }.toSet())
        assertTrue(events.any { e -> e.violations.any { it.code.id == "ENTRY_POINT_NOT_ANNOTATED" } })
        assertTrue("canary never reached checked data", canaryReachedCheckedData)
        assertTrue(events.size >= 300)

        for (e in events) {
            val text = listOf(e.toString(), e.entryPoint) + e.violations.map { it.field + it } + e.contributions.map { it.toString() }
            text.forEach { assertTrue("canary in event: $it", !it.contains(CANARY, ignoreCase = true)) }
        }
        for (l in ShadowLog.getLogs()) {
            assertTrue("canary in logcat: ${l.tag} ${l.msg}", !l.msg.contains(CANARY, ignoreCase = true) && !l.tag.contains(CANARY))
            assertTrue("a throwable was logged", l.throwable == null)
        }
    }
}
