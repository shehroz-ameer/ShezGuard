package com.shezguard.core.device

import android.app.Activity
import android.content.ComponentName
import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.core.content.IntentSanitizer
import androidx.test.platform.app.InstrumentationRegistry
import com.shezguard.core.Decision
import com.shezguard.core.GuardedEntryPoint
import com.shezguard.core.android.NestedIntentSanitizer
import com.shezguard.core.eval.ExtrasFixtures
import com.shezguard.core.policy.CharClass
import com.shezguard.core.policy.IntentPolicy
import com.shezguard.core.policy.Nested
import com.shezguard.core.policy.intentPolicy
import org.junit.Assert.fail

/** Guarded entry point for the onNewIntent path; constructed directly, never launched (no manifest entry needed). */
@GuardedEntryPoint("any")
class DeepGuardedActivity : Activity()

/**
 * Step 16, H1 (`docs/HARDENING.md`), shared by the three `DeepNesting*DeviceTest` classes. Device-only: **overflow tests
 * never run under Robolectric** (standing rule; Robolectric doubles `Parcel` frames, poisoned class initialisation, and
 * its non-daemon main thread kept test JVMs from exiting after an overflow).
 *
 * Each class has exactly one test, so each can run in its own cold `am instrument` process: the overflow case is the
 * first evaluation in the process, then a benign intent must be allowed, then the overflow case must block again.
 * A `LinkageError` (for example `NoClassDefFoundError`) anywhere fails the test with its class name.
 */
internal object DeepNesting {
    const val DEPTH = 60_000 // about 0.5 MB on API 24, 0.7 MB on API 34; overflowed both main threads in step 15
    const val NEXT = "com.shezguard.core.test.Next"

    val sdk: Int = Build.VERSION.SDK_INT

    fun policy(): IntentPolicy = intentPolicy {
        entryPoint("any") {
            allowSchemes("https")
            allowHosts("example.com")
            anyPath()
            param("q") { string(CharClass.TEXT) }
        }
        entryPoint("fwd") {
            nestedIntents(
                Nested.AllowSanitized(
                    setOf("next"),
                    NestedIntentSanitizer(
                        IntentSanitizer.Builder()
                            .allowComponent(ComponentName("com.shezguard.core.test", NEXT))
                            .allowAction(Intent.ACTION_VIEW)
                            .allowExtra("deep", Any::class.java) // makes IntentSanitizer read the value
                            .build(),
                    ),
                ),
            )
        }
    }

    /** Builds and round-trips on a large-stack thread: writing nested Lists recurses too (attacker side). */
    fun received(build: () -> Intent): Intent {
        var out: Intent? = null
        val t = Thread(null, { out = ExtrasFixtures.received(build()) }, "attacker", 512L shl 20)
        t.start(); t.join()
        return out!!
    }

    fun deepList(depth: Int): java.io.Serializable {
        var v: Any = arrayListOf<Any>("leaf")
        repeat(depth) { v = arrayListOf(v) }
        return v as java.io.Serializable
    }

    fun deepView(): Intent = received {
        Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com/x")).putExtra("deep", deepList(DEPTH))
    }

    fun benignView(): Intent = received { Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com/x?q=ok")) }

    fun deepNested(): Intent = received {
        Intent().putExtra(
            "next",
            Intent(Intent.ACTION_VIEW).setComponent(ComponentName("com.shezguard.core.test", NEXT)).putExtra("deep", deepList(DEPTH)),
        )
    }

    /** Runs [block] on the real main thread; a LinkageError fails the test with its class name. */
    fun <T> onMain(step: String, block: () -> T): T? {
        var r: T? = null
        var thrown: Throwable? = null
        InstrumentationRegistry.getInstrumentation().runOnMainSync { try { r = block() } catch (e: Throwable) { thrown = e } }
        thrown?.let {
            println("[H1] sdk=$sdk $step: THREW ${it.javaClass.name}: ${it.message}")
            if (it is LinkageError) fail("$step: LinkageError ${it.javaClass.name}: ${it.message}")
            fail("$step: threw ${it.javaClass.name}")
        }
        return r
    }

    fun describe(d: Decision?): String = "${d?.outcome} ${d?.violations?.map { it.code }}"
}
