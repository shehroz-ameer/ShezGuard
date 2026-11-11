package com.shezguard.core.eval

import android.app.Activity
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.Signature
import android.content.pm.SigningInfo
import android.net.Uri
import android.os.Build
import com.shezguard.core.Decision
import com.shezguard.core.Delivery
import com.shezguard.core.IdentitySource
import com.shezguard.core.ShezGuard
import com.shezguard.core.ViolationCode
import com.shezguard.core.ViolationCode.CALLER_IDENTITY_REQUIRED
import com.shezguard.core.ViolationCode.CALLER_NOT_ALLOWED
import com.shezguard.core.ViolationCode.CALLER_NOT_ALLOWED_RELIABLE
import com.shezguard.core.ViolationCode.CALLER_UNIDENTIFIED
import com.shezguard.core.ViolationCode.DOMAIN_NOT_VERIFIED
import com.shezguard.core.ViolationCode.DOMAIN_VERIFICATION_UNAVAILABLE
import com.shezguard.core.eval.EvalFixtures.renderedOutput
import com.shezguard.core.eval.ExtrasFixtures.extrasParcelled
import com.shezguard.core.eval.ExtrasFixtures.received
import com.shezguard.core.policy.intentPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadow.api.Shadow
import org.robolectric.shadows.ShadowSigningInfo
import java.security.MessageDigest

/**
 * Caller signals with real Activities, PackageManager and Parcels (step 8).
 * Robolectric-only, device check pending (step 14): Robolectric fakes `getCallingPackage()`
 * through `ShadowActivity`, does not enforce package visibility, has no shadow for
 * `getLaunchedFromPackage()` or `DomainVerificationManager`.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [24, 29, 31, 34])
class CallerAndroidTest {

    private val partner = "com.partner.app"
    private val certA = "certificate-A".toByteArray()
    private val certB = "certificate-B".toByteArray()
    private val certOld = "certificate-old".toByteArray()

    private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    private val policy = intentPolicy {
        entryPoint("partner") { allowedPackages { pkg(partner, sha256(certA)) } }
        entryPoint("multi") { allowedPackages { pkg(partner, sha256(certA), sha256(certB)) } }
        entryPoint("oldKey") { allowedPackages { pkg(partner, sha256(certOld)) } }
        entryPoint("strict") { allowedPackages(requireReliableIdentity = true) { pkg(partner, sha256(certA)) } }
        entryPoint("verified") {
            allowSchemes("https")
            allowHosts("example.com")
            anyPath()
            requireVerifiedDomain()
        }
    }

    private fun activity(intent: Intent): Activity = Robolectric.buildActivity(Activity::class.java, intent).create().get()

    private fun install(pkg: String, current: List<ByteArray>, past: List<ByteArray> = emptyList()) {
        val signatures = current.map(::Signature).toTypedArray()
        val info = PackageInfo().apply {
            packageName = pkg
            applicationInfo = ApplicationInfo().apply { packageName = pkg }
            @Suppress("DEPRECATION")
            this.signatures = signatures
        }
        if (Build.VERSION.SDK_INT >= 28) {
            info.signingInfo = SigningInfo().also {
                val s = Shadow.extract<ShadowSigningInfo>(it)
                s.setSignatures(signatures)
                if (past.isNotEmpty()) s.setPastSigningCertificates(past.map(::Signature).toTypedArray())
            }
        }
        shadowOf(RuntimeEnvironmentApp.pm()).installPackage(info)
    }

    private object RuntimeEnvironmentApp {
        fun pm() = org.robolectric.RuntimeEnvironment.getApplication().packageManager
    }

    private fun setSystemReferrer(a: Activity, pkg: String?) {
        Activity::class.java.getDeclaredField("mReferrer").apply { isAccessible = true }.set(a, pkg)
    }

    private fun launch(ep: String, intent: Intent = Intent(), callingPackage: String? = null, delivery: Delivery = Delivery.LAUNCH): Decision {
        val a = activity(intent)
        if (callingPackage != null) shadowOf(a).setCallingPackage(callingPackage)
        return ShezGuard.evaluate(a, intent, delivery, policy, ep)
    }

    private fun callerCodes(d: Decision) = d.violations.map { it.code }.filter { it.name.startsWith("CALLER_") || it.name.startsWith("DOMAIN_") }

    // ---- Reliable source: getCallingPackage (startActivityForResult) -----------------

    @Test
    fun allowsReliableCallerWithListedCertificate() {
        install(partner, listOf(certA))
        val d = launch("partner", callingPackage = partner)
        assertTrue(d.toString(), d is Decision.Allow)
        assertEquals(IdentitySource.CALLING_PACKAGE, d.callerIdentitySource)
    }

    @Test
    fun blocksPackageSquatterSignedWithAnotherKey() {
        install(partner, listOf(certB))
        val d = launch("partner", callingPackage = partner)
        assertTrue(d is Decision.Block)
        assertEquals(listOf(CALLER_NOT_ALLOWED_RELIABLE), callerCodes(d))
    }

    @Test
    fun blocksReliableCallerNotInAllowList() {
        install("com.evil.app", listOf(certA))
        assertEquals(listOf(CALLER_NOT_ALLOWED_RELIABLE), callerCodes(launch("partner", callingPackage = "com.evil.app")))
    }

    @Test
    fun blocksReliableCallerWhosePackageCannotBeRead() {
        assertEquals(listOf(CALLER_NOT_ALLOWED_RELIABLE), callerCodes(launch("partner", callingPackage = partner)))
    }

    /** Author condition 3. */
    @Test
    fun multiSignerCallerNeedsEverySignerListed() {
        install(partner, listOf(certA, certB))
        assertEquals(listOf(CALLER_NOT_ALLOWED_RELIABLE), callerCodes(launch("partner", callingPackage = partner)))
        assertTrue(launch("multi", callingPackage = partner) is Decision.Allow)
    }

    @Test
    fun rotatedOutSigningKeyIsNotAccepted() {
        assumeTrue("signing lineage exists from API 28", Build.VERSION.SDK_INT >= 28)
        install(partner, current = listOf(certA), past = listOf(certOld, certA))
        assertEquals(listOf(CALLER_NOT_ALLOWED_RELIABLE), callerCodes(launch("oldKey", callingPackage = partner)))
        assertTrue(launch("partner", callingPackage = partner) is Decision.Allow)
    }

    // ---- Advisory source: the referrer -----------------------------------------------

    @Test
    fun spoofedReferrerExtraNamingAllowedPackageIsStillUnidentified() {
        val d = launch("partner", Intent().putExtra(Intent.EXTRA_REFERRER, Uri.parse("android-app://$partner")))
        assertEquals(listOf(CALLER_UNIDENTIFIED), callerCodes(d))
        assertEquals(IdentitySource.REFERRER_EXTRA, d.callerIdentitySource)
    }

    @Test
    fun referrerNameExtraNamingUnlistedPackageScores() {
        val d = launch("partner", Intent().putExtra(Intent.EXTRA_REFERRER_NAME, "android-app://com.evil.app"))
        assertEquals(listOf(CALLER_NOT_ALLOWED), callerCodes(d))
        assertEquals(IdentitySource.REFERRER_EXTRA, d.callerIdentitySource)
    }

    @Test
    fun webReferrerNamesNoPackage() {
        val d = launch("partner", Intent().putExtra(Intent.EXTRA_REFERRER, Uri.parse("https://evil.example/")))
        assertEquals(listOf(CALLER_UNIDENTIFIED), callerCodes(d))
    }

    @Test
    fun systemReferrerIsReadOnlyWhenTheIntentHasNoExtras() {
        val bare = Intent()
        val a = activity(bare)
        setSystemReferrer(a, "com.evil.app")
        val d = ShezGuard.evaluate(a, bare, Delivery.LAUNCH, policy, "partner")
        assertEquals(listOf(CALLER_NOT_ALLOWED), callerCodes(d))
        assertEquals(IdentitySource.REFERRER_SYSTEM, d.callerIdentitySource)

        // With extras, getReferrer() would unparcel the caller's Bundle (N11): not read.
        val withExtras = Intent().putExtra("k", "v")
        val b = activity(withExtras)
        setSystemReferrer(b, "com.evil.app")
        val e = ShezGuard.evaluate(b, withExtras, Delivery.LAUNCH, policy, "partner")
        assertEquals(listOf(CALLER_UNIDENTIFIED), callerCodes(e))
        assertEquals(IdentitySource.NONE, e.callerIdentitySource)
    }

    @Test
    fun callerStageNeverUnparcelsTheCallersExtras() {
        val intent = received(Intent().putExtra("k", "v").putExtra(Intent.EXTRA_REFERRER_NAME, "android-app://$partner"))
        val a = activity(intent)
        setSystemReferrer(a, "com.evil.app")
        assertTrue("precondition", extrasParcelled(intent))
        val d = ShezGuard.evaluate(a, intent, Delivery.LAUNCH, policy, "partner")
        assertEquals(IdentitySource.REFERRER_EXTRA, d.callerIdentitySource)
        assertTrue("the caller's Bundle was unparcelled", extrasParcelled(intent))
        assertTrue("the activity's Bundle was unparcelled", extrasParcelled(a.intent))
    }

    /** N11: with extras but no referrer keys, getReferrer() would unparcel the activity's Bundle to look for them. */
    @Test
    fun systemReferrerIsNotReadWhenItWouldUnparcelTheCallersExtras() {
        val intent = received(Intent().putExtra("k", "v"))
        val a = activity(intent)
        setSystemReferrer(a, "com.evil.app")
        assertTrue("precondition", extrasParcelled(intent) && extrasParcelled(a.intent))
        val d = ShezGuard.evaluate(a, intent, Delivery.LAUNCH, policy, "partner")
        assertEquals(IdentitySource.NONE, d.callerIdentitySource)
        assertTrue("the caller's Bundle was unparcelled", extrasParcelled(intent))
        assertTrue("the activity's Bundle was unparcelled", extrasParcelled(a.intent))
    }

    // ---- onNewIntent delivery (author condition 2) ------------------------------------

    @Test
    fun newIntentDeliveryHasNoReliableIdentity() {
        install(partner, listOf(certA))
        assertTrue(launch("partner", callingPackage = partner, delivery = Delivery.LAUNCH) is Decision.Allow)
        val d = launch("partner", callingPackage = partner, delivery = Delivery.NEW_INTENT)
        assertEquals(listOf(CALLER_UNIDENTIFIED), callerCodes(d))
        assertEquals(IdentitySource.NONE, d.callerIdentitySource)
        assertEquals(listOf(CALLER_IDENTITY_REQUIRED), callerCodes(launch("strict", callingPackage = partner, delivery = Delivery.NEW_INTENT)))
    }

    @Test
    fun newIntentDeliveryIgnoresTheSystemReferrer() {
        val bare = Intent()
        val a = activity(bare)
        setSystemReferrer(a, "com.evil.app")
        val d = ShezGuard.evaluate(a, bare, Delivery.NEW_INTENT, policy, "partner")
        assertEquals(listOf(CALLER_UNIDENTIFIED), callerCodes(d))
    }

    @Test
    fun newIntentDeliveryStillReadsReferrerExtrasOfTheNewIntent() {
        val fresh = Intent().putExtra(Intent.EXTRA_REFERRER_NAME, "android-app://com.evil.app")
        val d = launch("partner", Intent().putExtra(Intent.EXTRA_REFERRER_NAME, "android-app://$partner"))
        assertEquals(listOf(CALLER_UNIDENTIFIED), callerCodes(d))
        val a = activity(Intent().putExtra(Intent.EXTRA_REFERRER_NAME, "android-app://$partner"))
        val e = ShezGuard.evaluate(a, fresh, Delivery.NEW_INTENT, policy, "partner")
        assertEquals("the passed intent is read, not activity.intent", listOf(CALLER_NOT_ALLOWED), callerCodes(e))
    }

    // ---- Enforcing mode --------------------------------------------------------------

    @Test
    fun enforcingAllowListBlocksAnOrdinaryLaunch() {
        val d = launch("strict", EvalFixtures.viewIntent("https://example.com/x"))
        assertTrue(d is Decision.Block)
        assertTrue(CALLER_IDENTITY_REQUIRED in d.violations.map { it.code })
    }

    @Test
    fun launchedFromPackageIsSafelyAbsentUnderRobolectric() {
        // API 34 path is exercised with fakes only (CallerValidatorTest); here it must not crash.
        assertEquals(listOf(CALLER_UNIDENTIFIED), callerCodes(launch("partner")))
    }

    // ---- Domain verification ---------------------------------------------------------

    @Test
    fun domainVerificationIsUnavailableWithoutTheService() {
        // Below API 31 the API does not exist; from 31 Robolectric has no DomainVerificationManager shadow.
        val d = launch("verified", EvalFixtures.viewIntent("https://example.com/p"))
        assertEquals(listOf(DOMAIN_VERIFICATION_UNAVAILABLE), callerCodes(d))
        assertTrue(d is Decision.Allow)
    }

    @Test
    fun domainStatesEndToEndWithAFakeVerifier() {
        val intent = EvalFixtures.viewIntent("https://example.com/p")
        val verified = ShezGuard.evaluateWith(intent, policy, "verified", { CallerSource.NONE }) { DomainState.VERIFIED }
        assertEquals(emptyList<ViolationCode>(), callerCodes(verified))
        val not = ShezGuard.evaluateWith(intent, policy, "verified", { CallerSource.NONE }) { DomainState.NOT_VERIFIED }
        assertEquals(listOf(DOMAIN_NOT_VERIFIED), callerCodes(not))
        assertEquals(50, not.score.total)
        assertTrue(not is Decision.Allow)
    }

    @Test
    fun intentOnlyOverloadHasNoCallerSourceOrContext() {
        assertEquals(listOf(CALLER_UNIDENTIFIED), callerCodes(ShezGuard.evaluate(Intent(), policy, "partner")))
        assertEquals(listOf(CALLER_IDENTITY_REQUIRED), callerCodes(ShezGuard.evaluate(Intent(), policy, "strict")))
        val d = ShezGuard.evaluate(EvalFixtures.viewIntent("https://example.com/p"), policy, "verified")
        assertEquals(listOf(DOMAIN_VERIFICATION_UNAVAILABLE), callerCodes(d))
    }

    // ---- Redaction and exclusivity ---------------------------------------------------

    @Test
    fun noDecisionOutputContainsPackageNamesOrDigests() {
        val evil = "com.zqxevil.app"
        install(evil, listOf(certA))
        val outputs = listOf(
            launch("partner", callingPackage = evil),
            launch("partner", Intent().putExtra(Intent.EXTRA_REFERRER_NAME, "android-app://com.zqxspoof.app")),
            launch("partner", callingPackage = partner),
        ).map { renderedOutput(it) + it.callerIdentitySource }
        for (out in outputs) {
            assertFalse(out, out.contains("zqx"))
            assertFalse(out, out.contains(partner))
            assertFalse(out, out.contains(sha256(certA)))
        }
    }

    @Test
    fun neverEmitsBothSignalsOfAnExclusivePairEndToEnd() {
        install(partner, listOf(certA))
        val intents = listOf(
            Intent(),
            Intent().putExtra(Intent.EXTRA_REFERRER_NAME, "android-app://$partner"),
            Intent().putExtra(Intent.EXTRA_REFERRER_NAME, "android-app://com.evil.app"),
            EvalFixtures.viewIntent("https://example.com/p"),
        )
        for (ep in listOf("partner", "multi", "oldKey", "strict", "verified")) {
            for (intent in intents) for (calling in listOf(null, partner, "com.evil.app")) for (delivery in Delivery.entries) {
                val c = callerCodes(launch(ep, intent, calling, delivery))
                assertFalse("$ep $c", CALLER_UNIDENTIFIED in c && CALLER_NOT_ALLOWED in c)
                assertFalse("$ep $c", DOMAIN_NOT_VERIFIED in c && DOMAIN_VERIFICATION_UNAVAILABLE in c)
                assertTrue("$ep $c", c.size <= 1)
            }
        }
    }
}
