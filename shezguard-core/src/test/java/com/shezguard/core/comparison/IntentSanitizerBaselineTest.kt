package com.shezguard.core.comparison

import android.content.ComponentName
import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.core.content.IntentSanitizer
import androidx.core.util.Predicate
import com.shezguard.core.eval.ExtrasFixtures.received
import com.shezguard.core.eval.GadgetPayload
import com.shezguard.core.eval.KnownPayloadA
import com.shezguard.core.eval.SerialFixtures.withUnknownClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * SPEC section 10.3 baseline: what `androidx.core.content.IntentSanitizer` ALONE does against each attack
 * of the demo app (step 12, docs/ATTACK_MATRIX.md, "Comparison baselines"). ShezGuard is not called.
 *
 * For each entry point the test uses the tightest allow-list IntentSanitizer can express for the feature
 * (author condition 5), and every allow-list is also checked against the benign control, so it is not
 * tighter than the feature allows. The boundary of "what IntentSanitizer can express":
 * - Data: `allowData` with a predicate on the URI's scheme, host and path. A predicate that parses query
 *   parameters is hand-written parameter validation, which is the manual baseline, not IntentSanitizer.
 * - Extras: `allowExtra` with a type and, where the feature has one, a size or value bound, mirroring the
 *   ShezGuard extras rule. Value predicates ARE expressible, so `copies` is shown both ways.
 * - Nested intents: the outer intent is sanitized, then the nested one is sanitized again before use, as
 *   the androidx documentation advises.
 *
 * Results are what the sanitizer returns from `sanitize(intent, penalty)`; the attack is "prevented" if
 * its payload is not in the output (or the output targets no real component), "not prevented" if the
 * payload passes unchanged. Robolectric-only (SDK 29 and 34), not run on a device.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [29, 34])
class IntentSanitizerBaselineTest {

    private fun component(activity: String) = ComponentName(PKG, "$PKG.demo.$activity")

    /** Tightest data allow-list for a deep link entry point: component, VIEW, BROWSABLE, https + host + exact path. */
    private fun deepLink(activity: String, path: String): IntentSanitizer = IntentSanitizer.Builder()
        .allowComponent(component(activity))
        .allowAction(Intent.ACTION_VIEW)
        .allowCategory(Intent.CATEGORY_BROWSABLE)
        .allowData(Predicate<Uri> { it.scheme == "https" && it.host == HOST && it.path == path })
        .build()

    private fun link(activity: String, uri: String) =
        Intent(Intent.ACTION_VIEW, Uri.parse(uri)).addCategory(Intent.CATEGORY_BROWSABLE).setComponent(component(activity))

    private class Result(val output: Intent?, val thrown: Throwable?, val penalties: Int)

    private fun apply(sanitizer: IntentSanitizer, intent: Intent): Result {
        var penalties = 0
        return try {
            Result(sanitizer.sanitize(intent) { penalties++ }, null, penalties)
        } catch (e: RuntimeException) {
            Result(null, e, penalties)
        }
    }

    private fun record(case: String, verdict: String) =
        println("[baseline] sdk=${Build.VERSION.SDK_INT} $case: $verdict")

    @Before
    fun reset() {
        GadgetPayload.readObjectCalls = 0
    }

    // ---- URI parameter attacks (t2a, t2b, t2c, t3, t6): the payload is in the query, which the data predicate does not parse.

    private fun assertDataPasses(case: String, activity: String, path: String, uri: String) {
        val r = apply(deepLink(activity, path), link(activity, uri))
        assertEquals("$case: data passes unchanged", Uri.parse(uri), r.output!!.data)
        assertEquals("$case: component kept", component(activity), r.output.component)
        assertEquals(0, r.penalties)
        record(case, if (case.startsWith("benign")) "passes (data unchanged)" else "NOT PREVENTED (data passes unchanged, 0 penalties)")
    }

    @Test
    fun sqlInjectionInQueryParameterPasses() {
        assertDataPasses("benign b2a", "SearchActivity", "/search", "https://$HOST/search?q=blue%20mug")
        assertDataPasses("t2a", "SearchActivity", "/search", "https://$HOST/search?q=x%27%20OR%20hidden%3D1%20--")
    }

    @Test
    fun webViewUrlParameterPasses() {
        assertDataPasses("benign b2b", "PreviewActivity", "/preview", "https://$HOST/preview?url=https%3A%2F%2F$HOST%2Fhelp")
        assertDataPasses(
            "t2b file", "PreviewActivity", "/preview",
            "https://$HOST/preview?url=file%3A%2F%2F%2Fdata%2Fuser%2F0%2F$PKG%2Ffiles%2Fsecret.txt",
        )
        assertDataPasses(
            "t2b data", "PreviewActivity", "/preview",
            "https://$HOST/preview?url=data%3Atext%2Fhtml%2C%3Cscript%3Econsole.log(%27CANARY-JS-%27%2B(6*7))%3C%2Fscript%3E",
        )
    }

    @Test
    fun pathTraversalParameterPasses() {
        assertDataPasses("benign b2c", "FileViewerActivity", "/file", "https://$HOST/file?name=readme.txt")
        assertDataPasses("t2c", "FileViewerActivity", "/file", "https://$HOST/file?name=../secret.txt")
    }

    @Test
    fun openRedirectParameterPasses() {
        assertDataPasses("benign b3", "RedirectActivity", "/redirect", "https://$HOST/redirect?next=https%3A%2F%2F$HOST%2Fhelp")
        assertDataPasses("t3", "RedirectActivity", "/redirect", "https://$HOST/redirect?next=https%3A%2F%2Fattacker.invalid%2Flogin")
    }

    @Test
    fun encodedTraversalParametersPass() {
        assertDataPasses("benign b6", "ManualCheckActivity", "/manual", "https://$HOST/manual?name=readme.txt")
        for (p in listOf("../secret.txt", "%2e%2e%2fsecret.txt", "%252e%252e%252fsecret.txt")) {
            assertDataPasses("t6 $p", "ManualCheckActivity", "/manual", "https://$HOST/manual?name=$p")
        }
    }

    // ---- t1: nested intent. Outer allow-list, then the nested intent sanitized again (as DemoPolicy's forward rule).

    private val forwardOuter get() = IntentSanitizer.Builder()
        .allowComponent(component("ForwardActivity"))
        .allowExtra("next", Intent::class.java)
        .build()

    private val forwardTargets get() = IntentSanitizer.Builder()
        .allowComponent(component("SearchActivity"))
        .allowAction(Intent.ACTION_VIEW)
        .allowCategory(Intent.CATEGORY_BROWSABLE)
        .allowDataWithAuthority(HOST)
        .build()

    private fun forwarded(next: Intent): Result {
        val outer = apply(forwardOuter, received(Intent().setComponent(component("ForwardActivity")).putExtra("next", next)))
        @Suppress("DEPRECATION")
        val nested = outer.output!!.getParcelableExtra<Intent>("next")!!
        return apply(forwardTargets, nested)
    }

    @Test
    fun nestedIntentToNonExportedComponentIsPreventedWhenTheNestedIntentIsSanitizedToo() {
        val benign = forwarded(Intent(Intent.ACTION_VIEW, Uri.parse("https://$HOST/search?q=mug")).setComponent(component("SearchActivity")))
        assertEquals(component("SearchActivity"), benign.output!!.component)
        assertEquals(0, benign.penalties)
        record("benign b1", "passes (component SearchActivity kept)")

        val attack = forwarded(Intent().setComponent(component("InternalAdminActivity")))
        assertNotEquals(component("InternalAdminActivity"), attack.output!!.component)
        assertTrue(attack.penalties > 0)
        record("t1", "PREVENTED (component rewritten to ${attack.output.component?.flattenToShortString()}, ${attack.penalties} penalties)")
    }

    // ---- t2d: extras size. The ShezGuard rule is STRING note <= 2000, INT copies; mirrored with predicates.

    private fun note(copiesRule: Predicate<Any>) = IntentSanitizer.Builder()
        .allowComponent(component("NoteActivity"))
        .allowExtra("note", Predicate<Any> { it is String && it.length <= 2000 })
        .allowExtra("copies", copiesRule)
        .build()

    private val anyInt = Predicate<Any> { it is Int }
    private val boundedInt = Predicate<Any> { it is Int && it in 1..100 }

    private fun noteIntent(note: String, copies: Int) =
        received(Intent().setComponent(component("NoteActivity")).putExtra("note", note).putExtra("copies", copies))

    @Test
    fun oversizedNoteIsRemovedByALengthPredicate() {
        val benign = apply(note(anyInt), noteIntent("Buy milk", 2)).output!!
        assertEquals("Buy milk", benign.getStringExtra("note"))
        record("benign b2d", "passes")

        val attack = apply(note(anyInt), noteIntent("A".repeat(64_000), 20_000))
        assertNull("the oversized note is removed", attack.output!!.getStringExtra("note"))
        record("t2d", "PREVENTED (note removed, ${attack.penalties} penalties)")
    }

    @Test
    fun hugeCopiesPassesATypeRuleAndIsRemovedOnlyByAValuePredicate() {
        val typeOnly = apply(note(anyInt), noteIntent("A".repeat(1000), 2_000_000)).output!!
        assertEquals(2_000_000, typeOnly.getIntExtra("copies", -1))
        record("t2d copies (type rule)", "NOT PREVENTED (copies=2000000 kept)")

        assertEquals(2, apply(note(boundedInt), noteIntent("Buy milk", 2)).output!!.getIntExtra("copies", -1))
        val bounded = apply(note(boundedInt), noteIntent("A".repeat(1000), 2_000_000)).output!!
        assertFalse(bounded.hasExtra("copies"))
        record("t2d copies (value predicate 1..100)", "PREVENTED (copies removed)")
    }

    // ---- t5 and 5b: Serializable extras. Tightest allow-list: the component, and no extras at all.

    private val profileNoExtras get() = IntentSanitizer.Builder().allowComponent(component("ProfileActivity")).build()

    @Test
    fun unknownSerializableClassMakesTheSanitizerThrow() {
        val intent = withUnknownClass(Intent().setComponent(component("ProfileActivity")).putExtra("profile", KnownPayloadA("x")))
        val r = apply(profileNoExtras, intent)
        assertNull("no output: sanitize threw", r.output)
        assertTrue(r.thrown.toString(), r.thrown != null)
        record("t5", "NOT PREVENTED (sanitize threw ${r.thrown!!.javaClass.simpleName}; uncaught, the app crashes)")
    }

    @Test
    fun gadgetReadObjectRunsInsideTheSanitizer() {
        val r = apply(profileNoExtras, received(Intent().setComponent(component("ProfileActivity")).putExtra("profile", GadgetPayload("attacker"))))
        assertEquals("readObject ran inside sanitize", 1, GadgetPayload.readObjectCalls)
        assertFalse("the extra itself is removed", r.output!!.hasExtra("profile"))
        record("5b", "NOT PREVENTED (readObject ran inside sanitize; the extra was then removed)")
    }

    private companion object {
        const val PKG = "com.shezguard.router"
        const val HOST = "shezguard.example"
    }
}
