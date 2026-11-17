package com.shezguard.core.device

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.shezguard.core.Decision
import com.shezguard.core.Delivery
import com.shezguard.core.ShezGuard
import com.shezguard.core.ViolationCode
import com.shezguard.core.ViolationCode.DOMAIN_NOT_VERIFIED
import com.shezguard.core.ViolationCode.DOMAIN_VERIFICATION_UNAVAILABLE
import com.shezguard.core.device.probe.DeviceShell
import com.shezguard.core.device.probe.HostActivity
import com.shezguard.core.device.probe.Probe
import com.shezguard.core.policy.intentPolicy
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * `requireVerifiedDomain` against the real `DomainVerificationManager` (step 14 phase 2, emulator only;
 * `docs/PAPER_NOTES.md` N13, `docs/LIMITATIONS.md` L30, L32). The test APK declares `autoVerify` filters
 * for three hosts under `.invalid` (`src/androidTest/AndroidManifest.xml`). **States are set with
 * `pm set-app-links` and `pm set-app-links-user-selection`, not by real Digital Asset Links
 * verification**; what is checked is how ShezGuard maps the state the platform reports. Lines tagged
 * `[N13d]`, including the `pm get-app-links` output, are recorded for the docs.
 */
@RunWith(AndroidJUnit4::class)
class DomainVerificationDeviceTest {

    private val sdk = Build.VERSION.SDK_INT
    private val verified = "dv-verified.invalid"
    private val selected = "dv-selected.invalid"
    private val unverified = "dv-unverified.invalid"
    private val undeclared = "dv-undeclared.invalid"

    private val policy = intentPolicy {
        entryPoint("dv") {
            allowSchemes("https")
            allowHosts(verified, selected, unverified, undeclared)
            anyPath()
            requireVerifiedDomain()
        }
    }

    private lateinit var host: Activity

    @Before
    fun setUp() {
        host = InstrumentationRegistry.getInstrumentation().startActivitySync(
            Intent(InstrumentationRegistry.getInstrumentation().targetContext, HostActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        )
    }

    @After
    fun tearDown() {
        host.finish()
        if (sdk >= 31) {
            DeviceShell.run("pm set-app-links --package ${Probe.SELF} 0 all")
            DeviceShell.run("pm set-app-links-user-selection --user 0 --package ${Probe.SELF} false all")
            DeviceShell.run("pm set-app-links-allowed --user 0 --package ${Probe.SELF} true")
        }
    }

    private fun domainCodes(h: String): List<ViolationCode> {
        val d: Decision = ShezGuard.evaluate(host, Intent(Intent.ACTION_VIEW, Uri.parse("https://$h/p")), Delivery.LAUNCH, policy, "dv")
        return d.violations.map { it.code }.filter { it.name.startsWith("DOMAIN_") }
    }

    private fun appLinks(label: String) {
        // The "Signatures:" line (the signing certificate's fingerprint) is dropped: not needed, not recorded.
        val out = DeviceShell.run("pm get-app-links --user 0 ${Probe.SELF}").lines().map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("Signatures") }
        println("[N13d] sdk=$sdk pm get-app-links ($label): ${out.joinToString(" | ")}")
    }

    /** API 24-30: the API does not exist, so every host is unavailable. */
    @Test
    fun domainVerificationIsUnavailableBelowApi31() {
        assumeTrue(sdk < 31)
        val codes = listOf(verified, selected, unverified, undeclared).associateWith { domainCodes(it) }
        println("[N13d] sdk=$sdk domainVerificationIsUnavailableBelowApi31 $codes")
        for (c in codes.values) assertEquals(listOf(DOMAIN_VERIFICATION_UNAVAILABLE), c)
    }

    /**
     * API 31+: verified (state set to approved via pm) passes; user-selected, unverified and undeclared
     * hosts are not verified (L32: DOMAIN_STATE_SELECTED counts as not verified).
     */
    @Test
    fun mapsThePlatformDomainStates() {
        assumeTrue(sdk >= 31)
        appLinks("after install")
        DeviceShell.run("pm set-app-links --package ${Probe.SELF} 0 all")
        DeviceShell.run("pm set-app-links --package ${Probe.SELF} 2 $verified")
        DeviceShell.run("pm set-app-links-user-selection --user 0 --package ${Probe.SELF} true $selected")
        appLinks("states set")
        val codes = listOf(verified, selected, unverified, undeclared).associateWith { domainCodes(it) }
        println("[N13d] sdk=$sdk mapsThePlatformDomainStates $codes")
        assertEquals(emptyList<ViolationCode>(), codes[verified])
        assertEquals(listOf(DOMAIN_NOT_VERIFIED), codes[selected])
        assertEquals(listOf(DOMAIN_NOT_VERIFIED), codes[unverified])
        assertEquals(listOf(DOMAIN_NOT_VERIFIED), codes[undeclared])
    }

    /** API 31+: with link handling disallowed for the app, even the verified host is not verified. */
    @Test
    fun linkHandlingDisallowedMeansNotVerified() {
        assumeTrue(sdk >= 31)
        DeviceShell.run("pm set-app-links --package ${Probe.SELF} 2 $verified")
        DeviceShell.run("pm set-app-links-allowed --user 0 --package ${Probe.SELF} false")
        appLinks("verified, link handling disallowed")
        val codes = domainCodes(verified)
        println("[N13d] sdk=$sdk linkHandlingDisallowedMeansNotVerified $verified=$codes")
        assertEquals(listOf(DOMAIN_NOT_VERIFIED), codes)
    }
}
