package com.shezguard.core.hardening

import android.app.Notification
import android.app.PendingIntent
import android.content.ClipData
import android.content.ComponentName
import android.content.Intent
import android.content.pm.LabeledIntent
import android.os.Bundle
import android.os.Parcelable
import android.util.SparseArray
import androidx.core.content.IntentSanitizer
import com.shezguard.core.Decision
import com.shezguard.core.Outcome
import com.shezguard.core.ShezGuard
import com.shezguard.core.ViolationCode
import com.shezguard.core.ViolationCode.EXTRAS_TOO_DEEP
import com.shezguard.core.ViolationCode.NESTED_INTENT_DENIED
import com.shezguard.core.android.NestedIntentSanitizer
import com.shezguard.core.hardening.Hardening.roundTrip
import com.shezguard.core.policy.ExtraType
import com.shezguard.core.policy.Nested
import com.shezguard.core.policy.intentPolicy
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Step 15, area 3: nested intents in extras (Robolectric, SDK 29 and 34, after a Parcel round trip). */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [29, 34])
class NestedIntentHardeningTest {

    private val sanitizer = NestedIntentSanitizer(
        IntentSanitizer.Builder()
            .allowComponent(ComponentName("test.app", "test.app.Next"))
            .allowAction(Intent.ACTION_VIEW)
            .build(),
    )

    private val policy = intentPolicy {
        entryPoint("deny") { extras { allow("note", ExtraType.STRING); allow("names", ExtraType.STRING_ARRAY) } }
        entryPoint("fwd") { nestedIntents(Nested.AllowSanitized(setOf("next"), sanitizer)) }
    }

    private fun evil(): Intent = Intent("evil.ACTION").setComponent(ComponentName("com.victim", "com.victim.PrivateActivity"))

    private fun eval(extras: Bundle, ep: String = "deny", ipc: Boolean = true): Decision {
        val i = Intent("test.OPEN").putExtras(extras)
        return ShezGuard.evaluate(if (ipc) roundTrip(i) else i, policy, ep)
    }

    private fun bundleOf(vararg kv: Pair<String, Any?>): Bundle = Bundle().apply {
        kv.forEach { (k, v) ->
            when (v) {
                is Bundle -> putBundle(k, v)
                is Intent -> putParcelable(k, v)
                is Parcelable -> putParcelable(k, v)
                is ArrayList<*> -> @Suppress("UNCHECKED_CAST") putParcelableArrayList(k, v as ArrayList<Parcelable>)
                is Array<*> -> @Suppress("UNCHECKED_CAST") putParcelableArray(k, v as Array<Parcelable>)
                is SparseArray<*> -> @Suppress("UNCHECKED_CAST") putSparseParcelableArray(k, v as SparseArray<Parcelable>)
                is java.io.Serializable -> putSerializable(k, v)
                else -> error("unsupported $v")
            }
        }
    }

    private fun nested(depth: Int, leaf: Any): Bundle {
        var v: Any = leaf
        repeat(depth) { v = bundleOf("b" to v) }
        return v as Bundle
    }

    // ---- finding -----------------------------------------------------------------------------------------

    /**
     * H5, documented (docs/LIMITATIONS.md L26, step 16): an Intent or PendingIntent inside a framework Parcelable
     * (ClipData items, Notification actions) is opaque, so under `Nested.Deny` the extra is removed as
     * `EXTRA_NOT_ALLOWED` (Sanitize), not reported as a nested intent. The sanitized copy no longer carries it.
     */
    @Test
    fun observesIntentInsideFrameworkParcelableIsRemovedNotReportedAsNested() {
        val clip = eval(bundleOf("clip" to ClipData.newIntent("x", evil())))
        val ctx = RuntimeEnvironment.getApplication()
        val pi = PendingIntent.getActivity(ctx, 0, evil(), PendingIntent.FLAG_IMMUTABLE)
        @Suppress("DEPRECATION")
        val notification = Notification.Builder(ctx).setContentIntent(pi).build()
        val notif = eval(bundleOf("n" to notification), ipc = false) // PendingIntent: in-process, as in L28
        for ((key, d) in listOf("clip" to clip, "n" to notif)) {
            assertEquals(Outcome.SANITIZE, d.outcome)
            assertEquals(setOf<ViolationCode>(ViolationCode.EXTRA_NOT_ALLOWED), Hardening.codes(d))
            assertEquals(false, (d as Decision.Sanitize).sanitizedIntent.hasExtra(key))
        }
    }

    // ---- negative results ----------------------------------------------------------------------------------

    @Test
    fun holdsEveryContainerShapeAtTheDepthLimit() {
        val shapes: Map<String, Bundle> = mapOf(
            "Parcelable[]" to bundleOf("x" to arrayOf<Parcelable>(evil())),
            "Intent[] under allowed STRING_ARRAY key" to bundleOf("names" to arrayOf<Parcelable>(evil())),
            "ArrayList<Bundle{Intent}>" to bundleOf("x" to arrayListOf<Parcelable>(bundleOf("i" to evil()))),
            "SparseArray<Intent>" to bundleOf("x" to SparseArray<Parcelable>().apply { put(3, evil()) }),
            "HashMap key" to bundleOf("x" to hashMapOf<Any, Any>(evil() to "v")),
            "HashMap value" to bundleOf("x" to hashMapOf<Any, Any>("k" to evil())),
            "LabeledIntent" to bundleOf("x" to LabeledIntent(evil(), "p", 0, 0)),
            "3 Bundles" to bundleOf("x" to nested(3, evil())),
            "4 containers exactly (Bundle>List>Bundle>SparseArray>Intent)" to bundleOf(
                "x" to bundleOf("l" to arrayListOf<Parcelable>(bundleOf("s" to SparseArray<Parcelable>().apply { put(0, evil()) }))),
            ),
            "4 Bundles exactly" to bundleOf("x" to nested(4, evil())),
            "Intent wrapped in a Bundle under the AllowSanitized key" to bundleOf("next" to bundleOf("i" to evil())),
            "null key" to Bundle().apply { putParcelable(null, evil()) },
        )
        val notBlocked = shapes.mapNotNull { (name, b) ->
            val d = eval(b, if (name.contains("AllowSanitized")) "fwd" else "deny")
            if (d.outcome == Outcome.BLOCK && NESTED_INTENT_DENIED in Hardening.codes(d)) null else "$name: ${d.outcome} ${Hardening.codes(d)}"
        }
        assertEquals(emptyList<String>(), notBlocked)
    }

    @Test
    fun holdsJustBeyondTheDepthLimitBlocksUnread() {
        val d = eval(bundleOf("x" to nested(5, evil())))
        assertEquals(Outcome.BLOCK, d.outcome)
        assertEquals(setOf<ViolationCode>(EXTRAS_TOO_DEEP, ViolationCode.EXTRA_NOT_ALLOWED), Hardening.codes(d))
    }

    /** In-process only (a Parcel cannot carry a cycle): self-containing Bundle and List terminate. */
    @Test
    fun holdsCyclesTerminate() {
        val b = Bundle()
        b.putBundle("self", b)
        val l = ArrayList<Any>()
        l.add(l)
        val ex = Executors.newSingleThreadExecutor()
        try {
            val r1 = ex.submit<Decision> { ShezGuard.evaluate(Intent().putExtra("x", b), policy, "deny") }.get(10, TimeUnit.SECONDS)
            val r2 = ex.submit<Decision> { ShezGuard.evaluate(Intent().putExtra("x", l), policy, "deny") }.get(10, TimeUnit.SECONDS)
            assertEquals(Outcome.BLOCK, r1.outcome)
            assertEquals(Outcome.BLOCK, r2.outcome)
            assertEquals(true, EXTRAS_TOO_DEEP in Hardening.codes(r1) && EXTRAS_TOO_DEEP in Hardening.codes(r2))
        } finally {
            ex.shutdownNow()
        }
    }

    /** A clean nested intent is forwarded only as IntentSanitizer's output; its selector is not kept. */
    @Test
    fun holdsNestedSelectorIsDroppedBySanitizer() {
        val next = Intent(Intent.ACTION_VIEW).setComponent(ComponentName("test.app", "test.app.Next"))
        next.selector = evil()
        val d = eval(bundleOf("next" to next), "fwd")
        if (d is Decision.Sanitize) {
            @Suppress("DEPRECATION")
            val out = d.sanitizedIntent.getParcelableExtra<Intent>("next")!!
            assertEquals(null, out.selector)
        } else {
            assertEquals(Outcome.BLOCK, d.outcome)
        }
    }
}
