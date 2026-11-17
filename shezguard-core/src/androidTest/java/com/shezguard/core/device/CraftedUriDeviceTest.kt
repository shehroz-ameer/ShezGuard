package com.shezguard.core.device

import android.net.Uri
import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.shezguard.core.Decision
import com.shezguard.core.Field
import com.shezguard.core.UriComponent
import com.shezguard.core.ViolationCode.URI_PARSER_MISMATCH
import com.shezguard.core.device.probe.DeviceShell
import com.shezguard.core.device.probe.DeviceShell.attacker
import com.shezguard.core.device.probe.ProbeActivity
import com.shezguard.core.device.probe.ProbeLog
import com.shezguard.core.eval.CraftedUri
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

/**
 * `docs/PAPER_NOTES.md` N4 on emulators (step 14 phase 2): a `Uri` built from a hand-written parcel
 * whose encoded and decoded paths disagree (representation `BOTH`).
 *
 * - In process, at this level: does `Uri.CREATOR` accept the bytes, and do the forms disagree?
 * - Cross process (N4 said "not tested"): `:attacker` builds the same object with its own
 *   `Uri.CREATOR` and sends it as `ACTION_VIEW` data through `system_server` to `ProbeActivity`. Does
 *   the disagreement survive delivery, and does ShezGuard block it?
 *
 * Lines tagged `[N4d]` are recorded for the docs.
 */
@RunWith(AndroidJUnit4::class)
class CraftedUriDeviceTest {

    private val sdk = Build.VERSION.SDK_INT

    @Before
    fun setUp() {
        ProbeLog.records.clear()
    }

    private fun disagrees(u: Uri) = u.path != Uri.decode(u.encodedPath)

    /** Docs claim (N4): API 24-29 accept `BOTH` with no check; from 30 these bytes cannot produce the mismatch. */
    @Test
    fun characterisesTheBothRepresentationAtThisLevel() {
        val result = try {
            val u = CraftedUri.craft(encodedPath = "/product/1", decodedPath = "/admin/../../secret")
            ("accepted ${u.javaClass.simpleName} toString=<$u> scheme=<${u.scheme}> authority=<${u.authority}> " +
                "getPath=<${u.path}> getEncodedPath=<${u.encodedPath}> disagrees=${disagrees(u)}").also {
                if (sdk <= 29) assertTrue("N4: the forms disagree up to API 29", disagrees(u))
                else assertTrue("N4: from API 30 these bytes cannot produce the mismatch", !disagrees(u))
            }
        } catch (e: RuntimeException) {
            if (sdk <= 29) throw e
            "rejected ${e.javaClass.name}: ${e.message}"
        }
        println("[N4d] sdk=$sdk characterisesTheBothRepresentationAtThisLevel $result")
    }

    /**
     * Cross process. Up to API 29: if the disagreement reaches the probe, ShezGuard must block it with
     * URI_PARSER_MISMATCH on the path; whether it survives is recorded. From API 30 (N4: these bytes cannot
     * produce the mismatch): the attacker's own `Uri.CREATOR` either rejects the bytes (nothing is sent) or
     * builds some other `Uri`; whatever reaches the probe must not have disagreeing forms. The attacker's log
     * line, matched by nonce, is recorded.
     */
    @Test
    fun craftedUriSentByAnotherApp() {
        DeviceShell.freshAttacker()
        val nonce = UUID.randomUUID().toString().take(8)
        attacker("uri_mismatch", ProbeActivity::class.java, "nonce" to nonce)
        val r = ProbeLog.await(if (sdk <= 29) 20_000 else 8_000)
        val attackerLog = DeviceShell.run("logcat -d -s ShezAttacker:I").lines().firstOrNull { it.contains("nonce=$nonce") }?.substringAfter("nonce=$nonce")?.trim()
        println("[N4d] sdk=$sdk craftedUriSentByAnotherApp attacker: $attackerLog")
        if (sdk <= 29) {
            assertNotNull("probe not reached", r)
            val survived = r!!.path != Uri.decode(r.encodedPath)
            val product = r.decisions.getValue("product")
            println(
                "[N4d] sdk=$sdk craftedUriSentByAnotherApp received dataString=<${r.dataString}> getPath=<${r.path}> " +
                    "getEncodedPath=<${r.encodedPath}> getPathSegments=${r.pathSegments} survived=$survived product=${r.summary("product")}",
            )
            if (survived) {
                assertTrue(r.summary("product"), product is Decision.Block)
                assertTrue(
                    product.violations.toString(),
                    product.violations.any { it.code == URI_PARSER_MISMATCH && it.field == Field.UriPart(UriComponent.PATH) },
                )
            }
        } else {
            println(
                "[N4d] sdk=$sdk craftedUriSentByAnotherApp received " +
                    (r?.let { "dataString=<${it.dataString}> getPath=<${it.path}> getEncodedPath=<${it.encodedPath}> product=${it.summary("product")}" } ?: "nothing"),
            )
            assertNotNull("attacker log line for nonce $nonce", attackerLog)
            if (r == null) {
                assertTrue(attackerLog, attackerLog!!.startsWith("craft failed"))
            } else {
                assertTrue("forms disagree on API $sdk", r.path == Uri.decode(r.encodedPath))
                assertTrue(r.summary("product"), r.decisions.getValue("product") !is Decision.Allow || r.path?.contains("..") != true)
            }
        }
    }

}
