package com.shezguard.core.hardening

import android.content.ClipData
import android.content.ComponentName
import android.content.Intent
import android.net.Uri
import android.os.Parcel
import android.os.Parcelable
import androidx.core.content.IntentSanitizer
import com.shezguard.core.CheckedIntent
import com.shezguard.core.Decision
import com.shezguard.core.Field
import com.shezguard.core.Outcome
import com.shezguard.core.ShezGuard
import com.shezguard.core.android.NestedIntentSanitizer
import com.shezguard.core.audit.AuditEvent
import com.shezguard.core.audit.AuditSink
import com.shezguard.core.audit.LogcatAuditSink
import com.shezguard.core.hardening.Hardening.roundTrip
import com.shezguard.core.policy.CharClass
import com.shezguard.core.policy.ExtraType
import com.shezguard.core.policy.Nested
import com.shezguard.core.policy.Unknown
import com.shezguard.core.policy.intentPolicy
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowLog

/** A Parcelable whose CREATOR throws with attacker bytes in the message, and whose toString is attacker-ish. */
class CanaryParcelable(private val s: String) : Parcelable {
    override fun describeContents(): Int = 0
    override fun writeToParcel(dest: Parcel, flags: Int) = dest.writeString(s)
    override fun toString(): String = "CanaryParcelable($s)"

    companion object {
        @JvmField
        val CREATOR: Parcelable.Creator<CanaryParcelable> = object : Parcelable.Creator<CanaryParcelable> {
            override fun createFromParcel(p: Parcel): CanaryParcelable = throw IllegalStateException("bad value " + p.readString())
            override fun newArray(size: Int): Array<CanaryParcelable?> = arrayOfNulls(size)
        }
    }
}

/**
 * Step 15, area 6: attacker-controlled strings must not reach an audit event, logcat, a `toString()` of any
 * public output, or an exception message. Extends `AuditCanaryTest` with positions it does not cover: the
 * incoming intent's action, type, categories, package, component, selector, ClipData; a CREATOR exception
 * message; `CheckedIntent`/`GuardedUri`/`RiskScore` `toString()`; and any Throwable escaping `evaluate`.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class AuditLeakHardeningTest {

    private val c = "zqxcanary"
    private val events = mutableListOf<AuditEvent>()
    private val logcat = LogcatAuditSink(Outcome.ALLOW, maxLinesPerMinute = Int.MAX_VALUE)

    private val policy = intentPolicy {
        auditSink(AuditSink { events += it; logcat.onDecision(it) })
        entryPoint("any") {
            allowSchemes("https")
            allowHosts("example.com")
            anyPath()
            allowFragment()
            param("q") { string(CharClass.TEXT) }
            unknownParams(Unknown.Ignore)
            extras { allow("k", ExtraType.STRING) }
        }
        entryPoint("drop") {
            allowSchemes("https")
            allowHosts("example.com")
            anyPath()
            param("q") { string(CharClass.TEXT) }
            unknownParams(Unknown.Drop)
        }
        entryPoint("fwd") {
            nestedIntents(
                Nested.AllowSanitized(
                    setOf("next"),
                    NestedIntentSanitizer(IntentSanitizer.Builder().allowComponent(ComponentName("test.app", "test.app.Next")).allowAction("zqxcanary.A").allowData { true }.build()),
                ),
            )
        }
    }

    private fun inputs(): List<Pair<String, Intent>> {
        val base = { Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com/p?q=ok")) }
        return listOf(
            "action" to base().setAction("$c.ACTION"),
            "type" to base().also { it.setDataAndType(it.data, "text/$c") },
            "category" to base().addCategory("$c.CAT"),
            "package" to base().setPackage("com.$c"),
            "component" to base().setComponent(ComponentName("com.$c", "com.$c.A")),
            "selector" to base().also { it.selector = Intent(Intent.ACTION_VIEW, Uri.parse("https://$c.example/$c")) },
            "clipData" to base().also { it.clipData = ClipData.newPlainText(c, c) },
            "creator message" to base().putExtra("x", CanaryParcelable(c)),
            "allowed extra value" to base().putExtra("k", c),
            "undeclared param name+value" to Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com/$c?q=$c&$c=$c#$c")),
            "dropped param" to Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com/p?q=1&$c=$c")),
            "nested intent" to Intent().putExtra("next", Intent("$c.A").setComponent(ComponentName("test.app", "test.app.Next")).setData(Uri.parse("$c://$c")).putExtra(c, c)),
            "nested intent under unknown key $c" to Intent().putExtra(c, Intent(c)),
            "host" to Intent(Intent.ACTION_VIEW, Uri.parse("https://$c.example/")),
            "fragment only" to Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com/#$c")),
        )
    }

    @Test
    fun noCanaryInAnyOutputToStringLogOrExceptionMessage() {
        ShadowLog.clear()
        val leaks = mutableListOf<String>()
        fun check(where: String, text: String?) {
            if (text != null && c in text) leaks += "$where: $text"
        }
        for ((name, intent) in inputs()) {
            for (ep in listOf("any", "drop", "fwd")) {
                val where = "$name/$ep"
                val d = try {
                    ShezGuard.evaluate(roundTrip(intent), policy, ep)
                } catch (t: Throwable) {
                    var e: Throwable? = t
                    while (e != null) { check("$where throwable", "${e.javaClass.name}: ${e.message}"); e = e.cause }
                    continue
                }
                check("$where Decision.toString", d.toString())
                check("$where RiskScore.toString", d.score.toString())
                d.score.contributions.forEach { check("$where contribution", it.toString()) }
                d.violations.forEach { v ->
                    check("$where Violation.toString", v.toString())
                    check("$where Field.toString", v.field.toString())
                    check("$where entryPoint", v.entryPoint)
                    when (val f = v.field) {
                        is Field.Param -> check("$where Param.declaredName", f.declaredName)
                        is Field.Extra -> check("$where Extra.declaredName", f.declaredName)
                        else -> Unit
                    }
                }
                val data = when (d) {
                    is Decision.Allow -> d.data
                    is Decision.Sanitize -> d.data
                    is Decision.Block -> null
                }
                check("$where GuardedUri.toString", data?.toString())
                data?.paramNames?.forEach { check("$where GuardedUri.paramNames", it) }
                if (d !is Decision.Block) {
                    val ci = CheckedIntent(if (d is Decision.Sanitize) d.sanitizedIntent else (d as Decision.Allow).intent, data, d)
                    check("$where CheckedIntent.toString", ci.toString())
                }
            }
        }
        events.forEach { e ->
            check("AuditEvent.toString", e.toString())
            check("AuditEvent.entryPoint", e.entryPoint)
            e.violations.forEach { check("AuditViolation.field", it.field) }
        }
        ShadowLog.getLogs().forEach { check("logcat ${it.tag}", "${it.msg} ${it.throwable?.message ?: ""}") }
        println("[audit] ${inputs().size * 3} evaluations, ${events.size} events, ${ShadowLog.getLogs().size} log lines, ${leaks.size} leaks")
        assertEquals(emptyList<String>(), leaks)
    }
}
