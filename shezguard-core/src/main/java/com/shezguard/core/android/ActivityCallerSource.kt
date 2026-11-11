package com.shezguard.core.android

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.net.Uri
import android.os.Build
import androidx.annotation.RequiresApi
import com.shezguard.core.Delivery
import com.shezguard.core.IdentitySource
import com.shezguard.core.eval.Advisory
import com.shezguard.core.eval.CallerInfo
import com.shezguard.core.eval.CallerSource
import com.shezguard.core.eval.Identified
import com.shezguard.core.policy.PACKAGE_NAME
import java.security.MessageDigest

/**
 * Reads caller information for one delivery to an Activity (SPEC section 8, step 8).
 *
 * Every signal is advisory unless its source is reliable:
 * - **Reliable, [Delivery.LAUNCH] only:** `getLaunchedFromPackage()` (API 34+, only if the
 *   launcher shared its identity) and `getCallingPackage()` (only for `startActivityForResult`;
 *   names the app that receives the result, see [IdentitySource.CALLING_PACKAGE]). For
 *   [Delivery.NEW_INTENT] both describe the launch that created the activity, so neither is used
 *   (`docs/PAPER_NOTES.md` N12).
 * - **Advisory:** `EXTRA_REFERRER` / `EXTRA_REFERRER_NAME`, read from ShezGuard's own copy of the
 *   extras ([extras]); and, only for [Delivery.LAUNCH] when neither the delivered intent nor
 *   `activity.intent` has extras (`getExtras() == null`, which never unparcels), the system
 *   referrer via `Activity.getReferrer()`. With extras present, `getReferrer()` would unparcel
 *   the caller's Bundle (N11), so it is not called.
 *
 * Signing certificates are read with `GET_SIGNING_CERTIFICATES` (API 28+, current signers via
 * `SigningInfo.getApkContentsSigners()`) or `GET_SIGNATURES` (API 24–27). The reliable sources
 * come with the OS's implicit package-visibility grant on API 30+, so no `<queries>` entry is
 * needed for them (source read only; unconfirmed on device).
 *
 * Every platform call is guarded; this class never throws.
 */
internal class ActivityCallerSource(
    private val activity: Activity,
    private val intent: Intent,
    private val delivery: Delivery,
    private val extras: AndroidExtras,
) : CallerSource {

    override fun read(): CallerInfo {
        val reliable = if (delivery == Delivery.LAUNCH) {
            listOfNotNull(
                guarded { if (Build.VERSION.SDK_INT >= 34) Api34.launchedFromPackage(activity) else null }
                    ?.let { Identified(it, IdentitySource.LAUNCHED_FROM_PACKAGE) },
                guarded { activity.callingPackage }?.let { Identified(it, IdentitySource.CALLING_PACKAGE) },
            ).distinctBy { it.packageName to it.source }
        } else {
            emptyList()
        }
        return CallerInfo(reliable, advisory())
    }

    private fun advisory(): Advisory? {
        extras.referrerExtra()?.let { return Advisory(packageOf(it), IdentitySource.REFERRER_EXTRA) }
        if (delivery != Delivery.LAUNCH) return null
        val noExtras = guarded { intent.extras == null && activity.intent?.extras == null } ?: false
        if (!noExtras) return null
        val system = guarded { activity.referrer?.toString() } ?: return null
        return Advisory(packageOf(system), IdentitySource.REFERRER_SYSTEM)
    }

    /** `android-app://<package>` names a package; anything else (e.g. a web referrer) names none. */
    private fun packageOf(referrer: String): String? = guarded {
        val uri = Uri.parse(referrer)
        if (uri.scheme == "android-app") uri.authority?.takeIf { PACKAGE_NAME.matches(it) } else null
    }

    @Suppress("DEPRECATION")
    override fun currentSignerDigests(packageName: String): Set<String>? = try {
        val pm = activity.packageManager
        val signers: Array<Signature>? = if (Build.VERSION.SDK_INT >= 28) {
            pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo?.apkContentsSigners
        } else {
            pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES).signatures
        }
        signers?.takeIf { it.isNotEmpty() }?.mapTo(HashSet()) { sha256Hex(it.toByteArray()) }
    } catch (e: PackageManager.NameNotFoundException) {
        null
    } catch (e: RuntimeException) {
        null
    }

    private inline fun <T> guarded(block: () -> T?): T? = try {
        block()
    } catch (e: RuntimeException) {
        null
    }

    @RequiresApi(34)
    private object Api34 {
        fun launchedFromPackage(a: Activity): String? = a.launchedFromPackage
    }

    private companion object {
        fun sha256Hex(bytes: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    }
}
