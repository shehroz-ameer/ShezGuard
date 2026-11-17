package com.shezguard.core.device

import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.shezguard.core.Decision
import com.shezguard.core.Delivery
import com.shezguard.core.IdentitySource
import com.shezguard.core.ViolationCode.CALLER_IDENTITY_REQUIRED
import com.shezguard.core.ViolationCode.CALLER_NOT_ALLOWED
import com.shezguard.core.ViolationCode.CALLER_NOT_ALLOWED_RELIABLE
import com.shezguard.core.ViolationCode.CALLER_UNIDENTIFIED
import com.shezguard.core.device.probe.DeviceShell
import com.shezguard.core.device.probe.DeviceShell.attacker
import com.shezguard.core.device.probe.Probe
import com.shezguard.core.device.probe.ProbeActivity
import com.shezguard.core.device.probe.ProbeLog
import com.shezguard.core.device.probe.ProbeRecord
import com.shezguard.core.device.probe.ProbeSingleTopActivity
import com.shezguard.core.device.probe.RequesterActivity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Caller identity, package visibility and the referrer with a real second app (step 14 phase 2,
 * emulator only; `docs/PAPER_NOTES.md` N11-N13, `docs/LIMITATIONS.md` L30). `:attacker`'s
 * `IdentityActivity` launches the probe activities of this test APK; the probes record what the
 * platform reports and what ShezGuard decides (`Probe.record`).
 *
 * Before every test `:attacker` is uninstalled and reinstalled, so no visibility grant from an earlier
 * test remains. The test APK declares no `<queries>`, targets SDK 35, and never resolves the attacker
 * itself (the shell starts it). Lines tagged `[N11d]`, `[N12d]`, `[N13d]` are recorded for the docs.
 *
 * Policy (`Probe.policy`): "partner" allows the attacker with its real certificate digest (advisory
 * mode), "strict" the same with `requireReliableIdentity`, "wrongKey" the attacker with a wrong digest,
 * "self" this test APK, "router" the demo app.
 */
@RunWith(AndroidJUnit4::class)
class CallerIdentityDeviceTest {

    private val sdk = Build.VERSION.SDK_INT
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    fun freshAttacker() {
        DeviceShell.freshAttacker()
        ProbeLog.records.clear()
    }

    private fun record(tag: String, test: String, r: ProbeRecord) = println("[$tag] sdk=$sdk $test ${r.line()}")

    private fun awaitProbe(what: String): ProbeRecord {
        val r = ProbeLog.await()
        assertNotNull("no probe record: $what", r)
        return r!!
    }

    private fun callerCodes(d: Decision) = d.violations.map { it.code }.filter { it.name.startsWith("CALLER_") }

    private fun attackerVisibleToThisApp(): Boolean = try {
        context.packageManager.getPackageInfo(Probe.ATTACKER, 0); true
    } catch (e: PackageManager.NameNotFoundException) {
        false
    }

    // ---- Package visibility (N13) ---------------------------------------------------------------

    /** API 30+: no `<queries>`, no interaction, so the freshly installed attacker is hidden. Visible on 24-29. */
    @Test
    fun freshlyInstalledAttackerIsHiddenWithoutInteraction() {
        val visible = attackerVisibleToThisApp()
        println("[N13d] sdk=$sdk freshlyInstalledAttackerIsHiddenWithoutInteraction attackerVisible=$visible")
        assertEquals(sdk < 30, visible)
    }

    // ---- Reliable sources -----------------------------------------------------------------------

    /** Plain startActivity: no reliable source; the referrer (if any) is advisory. No visibility grant. */
    @Test
    fun plainLaunchHasNoReliableIdentity() {
        attacker("plain", ProbeActivity::class.java)
        val r = awaitProbe("plain")
        record("N13d", "plainLaunchHasNoReliableIdentity", r)
        assertNull(r.callingPackage)
        assertNull(r.launchedFromPackage)
        val partner = r.decisions.getValue("partner")
        assertEquals(listOf(CALLER_UNIDENTIFIED), callerCodes(partner))
        assertTrue(partner.callerIdentitySource in setOf(IdentitySource.REFERRER_SYSTEM, IdentitySource.NONE))
        assertEquals(listOf(CALLER_IDENTITY_REQUIRED), callerCodes(r.decisions.getValue("strict")))
        assertEquals("plain launch grants no visibility", sdk < 30, r.attackerVisible)
    }

    /**
     * startActivityForResult: `getCallingPackage()` names the attacker; the OS makes it visible to this
     * app (implicit grant, API 30+), so its certificate can be read without `<queries>` (N13).
     */
    @Test
    fun forResultLaunchIsReliableAndGrantsVisibility() {
        attacker("for_result", ProbeActivity::class.java)
        val r = awaitProbe("for_result")
        record("N13d", "forResultLaunchIsReliableAndGrantsVisibility", r)
        assertEquals(Probe.ATTACKER, r.callingPackage)
        assertNull("not shared, different uid", r.launchedFromPackage)
        assertTrue("visible after a for-result launch", r.attackerVisible)
        val partner = r.decisions.getValue("partner")
        assertTrue(r.summary("partner"), partner is Decision.Allow)
        assertEquals(IdentitySource.CALLING_PACKAGE, partner.callerIdentitySource)
        assertTrue(r.decisions.getValue("strict") is Decision.Allow)
        assertEquals(listOf(CALLER_NOT_ALLOWED_RELIABLE), callerCodes(r.decisions.getValue("wrongKey")))
        assertEquals(listOf(CALLER_NOT_ALLOWED_RELIABLE), callerCodes(r.decisions.getValue("self")))
    }

    /** API 34+: `setShareIdentityEnabled(true)` makes `getLaunchedFromPackage()` name the attacker and grants visibility. */
    @Test
    fun sharedIdentityIsReliableOnApi34() {
        assumeTrue("ActivityOptions.setShareIdentityEnabled is API 34+", sdk >= 34)
        attacker("share_identity", ProbeActivity::class.java)
        val r = awaitProbe("share_identity")
        record("N13d", "sharedIdentityIsReliableOnApi34", r)
        assertNull(r.callingPackage)
        assertEquals(Probe.ATTACKER, r.launchedFromPackage)
        assertTrue("visible after a shared-identity launch", r.attackerVisible)
        val partner = r.decisions.getValue("partner")
        assertTrue(r.summary("partner"), partner is Decision.Allow)
        assertEquals(IdentitySource.LAUNCHED_FROM_PACKAGE, partner.callerIdentitySource)
        assertEquals(listOf(CALLER_NOT_ALLOWED_RELIABLE), callerCodes(r.decisions.getValue("wrongKey")))
    }

    /**
     * L30 forward-result caveat: the attacker starts this app's ForwarderActivity for result, which
     * starts the probe with FLAG_ACTIVITY_FORWARD_RESULT. The immediate launcher is the forwarder (this
     * app), but `getCallingPackage()` names the attacker, the app that receives the result.
     * On API 34+ the forwarder shares the probe's uid, so `getLaunchedFromPackage()` names it (same-uid
     * rule) and ShezGuard then requires both to be allowed.
     */
    @Test
    fun forwardedResultNamesTheResultRecipientNotTheLauncher() {
        attacker("forward_result", ProbeActivity::class.java)
        val r = awaitProbe("forward_result")
        record("N13d", "forwardedResultNamesTheResultRecipientNotTheLauncher", r)
        assertEquals(Probe.ATTACKER, r.callingPackage)
        val partner = r.decisions.getValue("partner")
        if (r.launchedFromPackage == null) {
            assertTrue(r.summary("partner"), partner is Decision.Allow)
            assertEquals(IdentitySource.CALLING_PACKAGE, partner.callerIdentitySource)
        } else {
            assertEquals(Probe.SELF, r.launchedFromPackage)
            assertEquals(listOf(CALLER_NOT_ALLOWED_RELIABLE), callerCodes(partner))
        }
    }

    // ---- The referrer (N11) ---------------------------------------------------------------------

    /** A spoofed EXTRA_REFERRER naming the demo app: advisory only; ShezGuard leaves the extras parcelled. */
    @Test
    fun spoofedReferrerExtraIsAdvisory() {
        attacker("referrer_extra", ProbeActivity::class.java)
        val r = awaitProbe("referrer_extra")
        record("N11d", "spoofedReferrerExtraIsAdvisory", r)
        assertEquals("getReferrer() returns the caller's value", "android-app://${Probe.ROUTER}", r.referrer)
        assertEquals(IdentitySource.REFERRER_EXTRA, r.decisions.getValue("router").callerIdentitySource)
        assertEquals("spoofing an allowed package gains nothing", listOf(CALLER_UNIDENTIFIED), callerCodes(r.decisions.getValue("router")))
        assertEquals(listOf(CALLER_NOT_ALLOWED), callerCodes(r.decisions.getValue("partner")))
        assertExtrasStayParcelledUntilGetReferrer(r)
    }

    @Test
    fun spoofedReferrerNameExtraIsAdvisory() {
        attacker("referrer_name", ProbeActivity::class.java)
        val r = awaitProbe("referrer_name")
        record("N11d", "spoofedReferrerNameExtraIsAdvisory", r)
        assertEquals("android-app://${Probe.ROUTER}", r.referrer)
        assertEquals(IdentitySource.REFERRER_EXTRA, r.decisions.getValue("router").callerIdentitySource)
        assertEquals(listOf(CALLER_UNIDENTIFIED), callerCodes(r.decisions.getValue("router")))
        assertExtrasStayParcelledUntilGetReferrer(r)
    }

    /** N11: with extras and no referrer keys, ShezGuard does not read the system referrer; getReferrer() itself unparcels. */
    @Test
    fun systemReferrerIsNotReadWhenTheIntentHasExtras() {
        attacker("extras_only", ProbeActivity::class.java)
        val r = awaitProbe("extras_only")
        record("N11d", "systemReferrerIsNotReadWhenTheIntentHasExtras", r)
        assertEquals(IdentitySource.NONE, r.decisions.getValue("partner").callerIdentitySource)
        assertEquals(listOf(CALLER_UNIDENTIFIED), callerCodes(r.decisions.getValue("partner")))
        assertExtrasStayParcelledUntilGetReferrer(r)
    }

    /**
     * ShezGuard's caller stage leaves the activity's Bundle parcelled; `Activity.getReferrer()` then
     * unparcels it (N11). Requires the reflection allowed by `hidden_api_policy` (set by the run script).
     * Asserted on API 24-34, the levels the docs claim (N5); recorded only above.
     */
    private fun assertExtrasStayParcelledUntilGetReferrer(r: ProbeRecord) {
        assertNotNull("reflection blocked: is hidden_api_policy set?", r.extrasParcelledBefore)
        assertEquals("precondition: delivered extras are parcelled", true, r.extrasParcelledBefore)
        if (sdk <= 34) {
            assertEquals("ShezGuard unparcelled the delivered intent", true, r.extrasParcelledAfterGuard)
            assertEquals("ShezGuard unparcelled activity.intent", true, r.activityIntentParcelledAfterGuard)
        }
        assertEquals("getReferrer() unparcels activity.intent (N11)", false, r.activityIntentParcelledAfterGetReferrer)
    }

    // ---- onNewIntent (N12) ----------------------------------------------------------------------

    /** Launch: this app's RequesterActivity starts the singleTop probe for result (reliable: this app). */
    private fun launchSingleTopFromThisApp(test: String): ProbeRecord {
        InstrumentationRegistry.getInstrumentation().startActivitySync(
            // CLEAR_TASK: a task left over by an earlier test is replaced, not just brought to front.
            Intent(context, RequesterActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK),
        )
        val launch = awaitProbe("singleTop launch")
        record("N12d", "$test(launch)", launch)
        assertEquals(Delivery.LAUNCH, launch.delivery)
        assertEquals(Probe.SELF, launch.callingPackage)
        // API 34+: the requester shares the probe's uid, so getLaunchedFromPackage() also names this app and is preferred.
        assertEquals(reliableSourceForThisApp(), launch.decisions.getValue("self").callerIdentitySource)
        assertTrue(launch.decisions.getValue("self") is Decision.Allow)
        return launch
    }

    private fun reliableSourceForThisApp() =
        if (sdk >= 34) IdentitySource.LAUNCHED_FROM_PACKAGE else IdentitySource.CALLING_PACKAGE

    private fun assertNewIntentHasNoReliableIdentity(r: ProbeRecord) {
        assertEquals(Delivery.NEW_INTENT, r.delivery)
        assertEquals("getCallingPackage() still names the launch's caller", Probe.SELF, r.callingPackage)
        if (sdk >= 34) assertEquals("getLaunchedFromPackage() still names the launch's caller", Probe.SELF, r.launchedFromPackage)
        val self = r.decisions.getValue("self")
        assertEquals(listOf(CALLER_UNIDENTIFIED), callerCodes(self))
        assertEquals(IdentitySource.NONE, self.callerIdentitySource)
        assertEquals(listOf(CALLER_IDENTITY_REQUIRED), callerCodes(r.decisions.getValue("strict")))
        // Misuse for contrast: evaluated as LAUNCH, the stale identity would allow it.
        val misuse = r.decisions.getValue("self(asLaunch)")
        assertTrue(r.summary("self(asLaunch)"), misuse is Decision.Allow)
        assertEquals(reliableSourceForThisApp(), misuse.callerIdentitySource)
    }

    /** N12: a second intent from the shell to the singleTop probe; the OS keeps the launch's caller. */
    @Test
    fun newIntentFromTheShellKeepsTheLaunchIdentity() {
        launchSingleTopFromThisApp("newIntentFromTheShellKeepsTheLaunchIdentity")
        // FLAG_ACTIVITY_NEW_TASK | FLAG_ACTIVITY_SINGLE_TOP
        DeviceShell.run("am start -n ${Probe.SELF}/${ProbeSingleTopActivity::class.java.name} -f 0x30000000")
        val r = awaitProbe("shell new intent")
        record("N12d", "newIntentFromTheShellKeepsTheLaunchIdentity", r)
        assertNewIntentHasNoReliableIdentity(r)
    }

    /**
     * N12 with an app as the second sender. Where the platform does not deliver the attacker's intent to
     * `onNewIntent` (e.g. it starts a new instance instead), that is recorded and the test is skipped.
     */
    @Test
    fun newIntentFromAnotherAppKeepsTheLaunchIdentity() {
        launchSingleTopFromThisApp("newIntentFromAnotherAppKeepsTheLaunchIdentity")
        attacker("new_intent", ProbeSingleTopActivity::class.java)
        val r = ProbeLog.await()
        if (r == null || r.delivery != Delivery.NEW_INTENT) {
            println("[N12d] sdk=$sdk newIntentFromAnotherAppKeepsTheLaunchIdentity not delivered to onNewIntent: ${r?.line()}")
            assumeTrue("the attacker's intent was not delivered to onNewIntent", false)
        }
        record("N12d", "newIntentFromAnotherAppKeepsTheLaunchIdentity", r!!)
        assertNewIntentHasNoReliableIdentity(r)
    }
}
