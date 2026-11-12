package com.shezguard.core.activity

import android.app.Activity
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.Signature
import android.content.pm.SigningInfo
import android.net.Uri
import android.os.Build
import android.os.Bundle
import com.shezguard.core.ActivityGuard
import com.shezguard.core.Decision
import com.shezguard.core.IdentitySource
import com.shezguard.core.Outcome
import com.shezguard.core.ViolationCode
import com.shezguard.core.ViolationCode.CALLER_IDENTITY_REQUIRED
import com.shezguard.core.ViolationCode.DATA_MISSING
import com.shezguard.core.ViolationCode.ENTRY_POINT_NOT_ANNOTATED
import com.shezguard.core.ViolationCode.ENTRY_POINT_UNKNOWN
import com.shezguard.core.ViolationCode.PARAM_UNKNOWN_DROPPED
import com.shezguard.core.ViolationCode.URI_PATH_TRAVERSAL
import com.shezguard.core.audit.AuditEvent
import com.shezguard.core.audit.AuditSink
import com.shezguard.core.policy.IntentPolicy
import com.shezguard.core.policy.Unknown
import com.shezguard.core.policy.intentPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import org.robolectric.shadow.api.Shadow
import org.robolectric.shadows.ShadowSigningInfo
import java.security.MessageDigest

/**
 * Step 10: the Activity helper. Robolectric-only, device check pending (step 14).
 *
 * Robolectric's `ActivityController` does not model two platform details, so tests simulate them
 * explicitly (`docs/PAPER_NOTES.md` N14):
 * - **Rotation** (relaunch in the same process) keeps the activity's current `mIntent`
 *   (`ActivityThread.handleRelaunchActivityInner`). Robolectric's `recreate()` re-attaches the
 *   controller's original intent instead, which is what happens after **process death**. [rotate]
 *   builds the new instance with the old instance's `getIntent()`; `recreate()` is used for
 *   process death.
 * - The platform skips `onStart` and `onRestoreInstanceState` for an activity finished in
 *   `onCreate`; Robolectric's controller calls them unconditionally, so that is source-read only.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [24, 29, 31, 34])
class ActivityGuardTest {

    private val partner = "com.partner.app"
    private val cert = "partner-cert".toByteArray()
    private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    private val events = mutableListOf<AuditEvent>()

    private fun policy(strictProduct: Boolean = false): IntentPolicy = intentPolicy {
        auditSink { events += it }
        entryPoint("product") {
            allowSchemes("https")
            allowHosts("example.com")
            path { prefix("/product/") }
            param("id") { digitsOnly(maxLength = 10); required() }
            unknownParams(if (strictProduct) Unknown.Block else Unknown.Drop)
        }
        entryPoint("plain") { }
        entryPoint("partner") { allowedPackages { pkg(partner, sha256(cert)) } }
        entryPoint("strict") { allowedPackages(requireReliableIdentity = true) { pkg(partner, sha256(cert)) } }
    }

    @Before
    fun setUp() {
        GuardHarness.guard = ActivityGuard(policy())
        RecordingFragment.created = 0
        RecordingFragment.restoredFromState = 0
    }

    private fun view(uri: String) = Intent(Intent.ACTION_VIEW, Uri.parse(uri))

    private val clean = "https://example.com/product/42?id=42"
    private val withTracker = "https://example.com/product/42?id=42&utm_source=x"
    private val traversal = "https://example.com/product/../admin?id=42"

    private fun <T : Activity> launch(cls: Class<T>, intent: Intent?, callingPackage: String? = null, saved: Bundle? = null): ActivityController<T> {
        val c = Robolectric.buildActivity(cls, intent)
        if (callingPackage != null) shadowOf(c.get()).setCallingPackage(callingPackage)
        return c.create(saved)
    }

    /** Simulates an in-process relaunch: the new instance gets the old instance's current intent. */
    private fun <T : Activity> rotate(old: ActivityController<T>, cls: Class<T>, callingPackage: String? = null): ActivityController<T> {
        val saved = Bundle()
        old.saveInstanceState(saved)
        return launch(cls, old.get().intent, callingPackage, saved)
    }

    private fun installPartner() {
        val signatures = arrayOf(Signature(cert))
        val info = PackageInfo().apply {
            packageName = partner
            applicationInfo = ApplicationInfo().apply { packageName = partner }
            @Suppress("DEPRECATION")
            this.signatures = signatures
        }
        if (Build.VERSION.SDK_INT >= 28) {
            info.signingInfo = SigningInfo().also { Shadow.extract<ShadowSigningInfo>(it).setSignatures(signatures) }
        }
        shadowOf(RuntimeEnvironment.getApplication().packageManager).installPackage(info)
    }

    private fun HarnessActivity.decision(): Decision = checkNotNull(checked).decision

    private fun assertBlockedLaunch(a: HarnessActivity, original: Intent?) {
        assertTrue("activity must be finishing", a.isFinishing)
        assertEquals(Activity.RESULT_CANCELED, shadowOf(a).resultCode)
        assertNull(shadowOf(a).resultIntent)
        assertFalse("app code after a Block must not run", a.appCodeRanInOnCreate)
        assertNull(a.checked)
        assertNull("saved state must not reach super.onCreate", a.stateGivenToSuper)
        val now = a.intent
        assertNotSame("the blocked intent must not remain the activity's intent", original, now)
        assertNull(now.data)
        assertNull(now.extras)
        assertNull(now.action)
    }

    // ---- onCreate --------------------------------------------------------------------------

    @Test
    fun blocksPathTraversalLaunchFinishesWithResultCanceled() {
        val raw = view(traversal)
        val a = launch(ProductActivity::class.java, raw).get()
        assertBlockedLaunch(a, raw)
        assertEquals(Outcome.BLOCK, events.single().outcome)
        assertTrue(events.single().violations.any { it.code == URI_PATH_TRAVERSAL })
    }

    @Test
    fun blockResetsAResultSetBeforeTheGuardToCanceledWithoutData() {
        // Control: the initializer's result survives an allowed launch, so the test below is not vacuous.
        val allowed = launch(PresetResultActivity::class.java, view(clean)).get()
        assertTrue(allowed.appCodeRanInOnCreate)
        assertEquals(Activity.RESULT_OK, shadowOf(allowed).resultCode)
        assertNotNull(shadowOf(allowed).resultIntent)

        val blocked = launch(PresetResultActivity::class.java, view(traversal)).get()
        assertTrue(blocked.isFinishing)
        assertEquals(Activity.RESULT_CANCELED, shadowOf(blocked).resultCode)
        assertNull(shadowOf(blocked).resultIntent)
    }

    @Test
    fun appCodeAfterBlockDoesNotRunWhenResultIsUsed() {
        val a = launch(ProductActivity::class.java, view(traversal)).get()
        assertFalse(a.appCodeRanInOnCreate)
        assertNull(a.checked)
    }

    @Test
    fun allowKeepsTheOriginalIntentUnchanged() {
        val raw = view(clean)
        val a = launch(ProductActivity::class.java, raw).get()
        assertTrue(a.appCodeRanInOnCreate)
        assertFalse(a.isFinishing)
        assertSame(raw, a.intent)
        assertEquals(clean, a.intent.dataString)
        val checked = checkNotNull(a.checked)
        assertSame(raw, checked.intent)
        assertTrue(checked.decision is Decision.Allow)
        assertEquals("42", checked.data?.param("id"))
    }

    @Test
    fun sanitizeReplacesTheActivityIntentWithTheSanitizedCopy() {
        val raw = view(withTracker)
        val a = launch(ProductActivity::class.java, raw).get()
        val d = a.decision() as Decision.Sanitize
        assertTrue(d.violations.any { it.code == PARAM_UNKNOWN_DROPPED })
        assertSame(d.sanitizedIntent, a.intent)
        assertSame(d.sanitizedIntent, a.checked?.intent)
        assertEquals(clean, a.intent.dataString)
        assertEquals(withTracker, raw.dataString) // the caller's intent is not modified
        assertTrue(a.appCodeRanInOnCreate)
    }

    @Test
    fun finishSetResultAndSetIntentBeforeSuperOnCreateDoNotThrow() {
        // The Block path calls setResult, setIntent and finish before super.onCreate.
        val c = launch(ProductActivity::class.java, view(traversal))
        assertTrue(c.get().isFinishing)
        c.destroy() // and the finished activity can be torn down normally
    }

    // ---- Entry point name ------------------------------------------------------------------

    @Test
    fun missingAnnotationIsDenied() {
        val raw = view(clean)
        val a = launch(UnannotatedActivity::class.java, raw).get()
        assertBlockedLaunch(a, raw)
        val e = events.single()
        assertEquals(listOf(ENTRY_POINT_NOT_ANNOTATED), e.violations.map { it.code })
        assertEquals(ActivityGuard.UNANNOTATED, e.entryPoint)
    }

    @Test
    fun exemptEmptyAndContradictoryAnnotationsAreDenied() {
        for (cls in listOf(ExemptActivity::class.java, EmptyNameActivity::class.java, NamedButExemptActivity::class.java)) {
            events.clear()
            val raw = view(clean)
            val a = launch(cls, raw).get()
            assertBlockedLaunch(a, raw)
            assertEquals(cls.simpleName, listOf(ENTRY_POINT_NOT_ANNOTATED), events.single().violations.map { it.code })
        }
    }

    @Test
    fun annotationIsNotInheritedBySubclasses() {
        val raw = view(clean)
        val a = launch(ProductSubclassActivity::class.java, raw).get()
        assertBlockedLaunch(a, raw)
        assertEquals(listOf(ENTRY_POINT_NOT_ANNOTATED), events.single().violations.map { it.code })
    }

    @Test
    fun annotatedNameMissingFromPolicyIsDenied() {
        val a = launch(UnregisteredActivity::class.java, view(clean)).get()
        assertTrue(a.isFinishing)
        assertEquals(listOf(ENTRY_POINT_UNKNOWN), events.single().violations.map { it.code })
    }

    // ---- Null and data-less intents ---------------------------------------------------------

    @Test
    fun nullIntentDoesNotCrash() {
        val c = Robolectric.buildActivity(PlainActivity::class.java, Intent())
        c.get().intent = null
        c.create()
        assertTrue("an empty intent on a data-forbidden entry point is allowed", c.get().appCodeRanInOnCreate)
        assertEquals(Outcome.ALLOW, events.single().outcome)

        events.clear()
        val p = Robolectric.buildActivity(ProductActivity::class.java, Intent())
        p.get().intent = null
        p.create()
        assertTrue(p.get().isFinishing)
        assertEquals(listOf(DATA_MISSING), events.single().violations.map { it.code })
    }

    @Test
    fun dataLessIntentDoesNotCrash() {
        val a = launch(ProductActivity::class.java, Intent(Intent.ACTION_VIEW)).get()
        assertTrue(a.isFinishing)
        assertEquals(listOf(DATA_MISSING), events.single().violations.map { it.code })

        val plain = launch(PlainActivity::class.java, Intent(Intent.ACTION_MAIN))
        assertTrue(plain.get().appCodeRanInOnCreate)
        assertNull(plain.get().checked?.data)
        plain.newIntent(Intent(Intent.ACTION_MAIN))
        assertEquals(1, plain.get().newIntentBodyRuns)
    }

    // ---- onNewIntent -----------------------------------------------------------------------

    @Test
    fun newIntentAllowReplacesTheActivityIntentWithTheCheckedIntent() {
        val c = launch(ProductActivity::class.java, view(clean))
        val next = view("https://example.com/product/7?id=7")
        c.newIntent(next)
        val a = c.get()
        assertSame(next, a.intent)
        assertSame(next, a.checked?.intent)
        assertEquals("7", a.checked?.data?.param("id"))
        assertEquals(1, a.newIntentBodyRuns)
        assertFalse(a.isFinishing)
    }

    @Test
    fun newIntentSanitizeReplacesTheActivityIntentWithTheSanitizedCopy() {
        val c = launch(ProductActivity::class.java, view(clean))
        val next = view("https://example.com/product/7?id=7&utm_source=x")
        c.newIntent(next)
        val a = c.get()
        val d = a.decision() as Decision.Sanitize
        assertSame(d.sanitizedIntent, a.intent)
        assertEquals("https://example.com/product/7?id=7", a.intent.dataString)
        assertEquals(1, a.newIntentBodyRuns)
    }

    @Test
    fun newIntentBlockIsIgnoredAndTheSessionKeepsItsCheckedState() {
        val first = view(clean)
        val c = launch(ProductActivity::class.java, first)
        val before = c.get().checked
        events.clear()
        c.newIntent(view(traversal)) // super.onNewIntent is skipped; must not throw
        val a = c.get()
        assertFalse("a blocked onNewIntent must not finish a running session", a.isFinishing)
        assertSame(first, a.intent)
        assertSame(before, a.checked)
        assertEquals(0, a.newIntentBodyRuns)
        assertEquals(Outcome.BLOCK, events.single().outcome)
    }

    @Test
    fun skippingSuperOnNewIntentDoesNotThrowAndActivityStaysUsable() {
        val c = Robolectric.buildActivity(ProductActivity::class.java, view(clean)).setup()
        repeat(3) { c.newIntent(view(traversal)) }
        c.pause().resume() // still a normal, running activity
        assertFalse(c.get().isFinishing)
        assertEquals(0, c.get().newIntentBodyRuns)
    }

    @Test
    fun newIntentOnUnannotatedActivityIsDeniedWithoutFinishing() {
        // Not reachable through onCreate (it blocks), so call the guard directly on a live instance.
        val c = launch(PlainActivity::class.java, Intent(Intent.ACTION_MAIN))
        val a = c.get()
        val stranger = Robolectric.buildActivity(UnannotatedActivity::class.java, Intent()).get()
        events.clear()
        assertNull(GuardHarness.guard.onNewIntent(stranger, view(clean)))
        assertFalse(stranger.isFinishing)
        assertEquals(listOf(ENTRY_POINT_NOT_ANNOTATED), events.single().violations.map { it.code })
        assertFalse(a.isFinishing)
    }

    @Test
    fun newIntentEvaluatesTheDeliveredIntentNotGetIntent() {
        val c = launch(ProductActivity::class.java, view(clean))
        val a = c.get()
        a.intent = view(traversal) // what getIntent() would return if the guard read it
        c.newIntent(view("https://example.com/product/9?id=9"))
        assertEquals(Outcome.ALLOW, events.last().outcome)
        assertEquals("9", a.checked?.data?.param("id"))

        a.intent = view(clean)
        c.newIntent(view(traversal))
        assertEquals(Outcome.BLOCK, events.last().outcome)
    }

    // ---- Caller identity per delivery -------------------------------------------------------

    @Test
    fun launchUsesReliableIdentityAndNewIntentDoesNot() {
        installPartner()
        val c = launch(PartnerActivity::class.java, Intent(), callingPackage = partner)
        assertEquals(IdentitySource.CALLING_PACKAGE, c.get().decision().callerIdentitySource)
        c.newIntent(Intent())
        assertEquals(IdentitySource.NONE, c.get().decision().callerIdentitySource)
        assertTrue(c.get().decision().violations.any { it.code == ViolationCode.CALLER_UNIDENTIFIED })
    }

    @Test
    fun requireReliableIdentityIgnoresEveryNewIntent() {
        installPartner()
        val c = launch(StrictPartnerActivity::class.java, Intent(), callingPackage = partner)
        assertTrue(c.get().appCodeRanInOnCreate)
        repeat(2) {
            events.clear()
            c.newIntent(Intent())
            assertEquals(listOf(CALLER_IDENTITY_REQUIRED), events.single().violations.map { it.code })
        }
        assertEquals(0, c.get().newIntentBodyRuns)
        assertFalse(c.get().isFinishing)
    }

    // ---- Recreation -------------------------------------------------------------------------

    @Test
    fun rotationReevaluatesSanitizedIntentAsAllowWithIdenticalCanonicalData() {
        val first = launch(ProductActivity::class.java, view(withTracker))
        val firstDecision = first.get().decision() as Decision.Sanitize
        events.clear()
        val again = rotate(first, ProductActivity::class.java).get()
        val d = again.decision()
        assertTrue("re-evaluating a sanitized intent must give Allow, got $d", d is Decision.Allow)
        assertEquals(firstDecision.data, (d as Decision.Allow).data)
        assertEquals(firstDecision.data?.param("id"), d.data?.param("id"))
        assertEquals(firstDecision.data?.paramNames, d.data?.paramNames)
        assertSame(firstDecision.sanitizedIntent, again.intent)
        assertTrue(again.appCodeRanInOnCreate)
        assertEquals(1, events.size)
    }

    @Test
    fun processDeathRedeliversTheRawIntentAndItIsSanitizedAgain() {
        val raw = view(withTracker)
        val c = launch(ProductActivity::class.java, raw).start().resume()
        events.clear()
        c.recreate() // Robolectric re-attaches the original (raw) intent, as the OS does after process death
        val a = c.get()
        assertEquals(Outcome.SANITIZE, events.first().outcome)
        assertEquals(clean, a.intent.dataString)
        assertTrue(a.appCodeRanInOnCreate)
    }

    @Test
    fun recreationIsEvaluatedUnderTheCurrentPolicyNotACachedDecision() {
        val c = launch(ProductActivity::class.java, view(withTracker))
        assertTrue(c.get().appCodeRanInOnCreate)
        GuardHarness.guard = ActivityGuard(policy(strictProduct = true)) // e.g. app update between process death and restore
        events.clear()
        val a = launch(ProductActivity::class.java, view(withTracker), saved = Bundle().also { c.saveInstanceState(it) }).get()
        assertBlockedLaunch(a, null)
    }

    @Test
    fun recreationWithoutReliableIdentityIsBlockedUnderEnforcingPolicy() {
        // Simulates a task restored after reboot: launchedFrom* survive, resultTo does not (N14).
        installPartner()
        val c = launch(StrictPartnerActivity::class.java, Intent(), callingPackage = partner)
        assertTrue(c.get().appCodeRanInOnCreate)
        events.clear()
        val restored = rotate(c, StrictPartnerActivity::class.java, callingPackage = null).get()
        assertTrue(restored.isFinishing)
        assertEquals(listOf(CALLER_IDENTITY_REQUIRED), events.single().violations.map { it.code })
    }

    @Test
    fun rotationAfterNewIntentAttributesLauncherIdentityToTheLatestIntent() {
        // The OS keeps the launch identity on the record (N12); after rotation the latest checked
        // intent is re-evaluated as LAUNCH, so that identity is attributed to it (N14).
        installPartner()
        val c = launch(PartnerActivity::class.java, Intent(), callingPackage = partner)
        val latest = Intent() // a second delivery, from an unidentified sender
        c.newIntent(latest)
        assertEquals(IdentitySource.NONE, c.get().decision().callerIdentitySource)
        assertSame(latest, c.get().intent)
        val rotated = rotate(c, PartnerActivity::class.java, callingPackage = partner).get()
        assertSame(latest, rotated.intent)
        assertEquals(IdentitySource.CALLING_PACKAGE, rotated.decision().callerIdentitySource)
        assertTrue(rotated.decision().violations.isEmpty())
    }

    @Test
    fun blockedRecreationDoesNotRestoreFrameworkFragments() {
        @Suppress("DEPRECATION")
        fun addFragment(a: Activity) = a.fragmentManager.beginTransaction().add(RecordingFragment(), "rec").commitNow()

        val first = launch(ProductActivity::class.java, view(clean))
        addFragment(first.get())
        val saved = Bundle().also { first.saveInstanceState(it) }

        // Control: an allowed recreation does restore the fragment, so the check below is not vacuous.
        val allowed = launch(ProductActivity::class.java, view(clean), saved = saved).get()
        @Suppress("DEPRECATION")
        assertNotNull(allowed.fragmentManager.findFragmentByTag("rec"))
        assertEquals(1, RecordingFragment.restoredFromState)

        val createdBefore = RecordingFragment.created
        val blocked = launch(ProductActivity::class.java, view(traversal), saved = saved).get()
        assertTrue(blocked.isFinishing)
        @Suppress("DEPRECATION")
        assertNull(blocked.fragmentManager.findFragmentByTag("rec"))
        assertEquals(createdBefore, RecordingFragment.created)
        assertEquals(1, RecordingFragment.restoredFromState)
    }

    // ---- Audit ----------------------------------------------------------------------------

    @Test
    fun everyGuardCallEmitsExactlyOneAuditEvent() {
        val c = launch(ProductActivity::class.java, view(clean))
        assertEquals(1, events.size)
        c.newIntent(view(traversal))
        assertEquals(2, events.size)
        c.newIntent(view(withTracker))
        assertEquals(3, events.size)
        launch(UnannotatedActivity::class.java, view(clean))
        assertEquals(4, events.size)
        assertEquals(listOf(Outcome.ALLOW, Outcome.BLOCK, Outcome.SANITIZE, Outcome.BLOCK), events.map { it.outcome })
    }
}
