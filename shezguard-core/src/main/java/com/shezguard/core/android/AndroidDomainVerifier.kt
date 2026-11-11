package com.shezguard.core.android

import android.content.Context
import android.content.pm.verify.domain.DomainVerificationManager
import android.content.pm.verify.domain.DomainVerificationUserState
import android.os.Build
import androidx.annotation.RequiresApi
import com.shezguard.core.eval.DomainState
import com.shezguard.core.eval.DomainVerifier

/**
 * Reads this app's own App Links verification state for a host (SPEC section 8, step 8).
 *
 * API 31+: `DomainVerificationManager.getDomainVerificationUserState(context.packageName)`.
 * The host is [DomainState.VERIFIED] only if its entry in `getHostToStateMap()` is
 * `DOMAIN_STATE_VERIFIED` **and** `isLinkHandlingAllowed()` is true. The host is looked up exactly;
 * wildcard keys (`*.example.com`) are not expanded. `DOMAIN_STATE_SELECTED` (chosen by the user)
 * counts as not verified.
 *
 * [DomainState.UNAVAILABLE] below API 31, without the service, when the state is `null` (the app
 * declares no web domains), or if any call throws. This class never throws.
 *
 * This is a fact about the app's domain, not proof that an intent came through a verified link.
 */
internal class AndroidDomainVerifier(private val context: Context) : DomainVerifier {

    override fun state(host: String): DomainState =
        if (Build.VERSION.SDK_INT >= 31) Api31.state(context, host) else DomainState.UNAVAILABLE

    @RequiresApi(31)
    private object Api31 {
        fun state(context: Context, host: String): DomainState = try {
            val manager = context.getSystemService(DomainVerificationManager::class.java)
            val userState = manager?.getDomainVerificationUserState(context.packageName)
            when {
                userState == null -> DomainState.UNAVAILABLE
                !userState.isLinkHandlingAllowed -> DomainState.NOT_VERIFIED
                userState.hostToStateMap[host] == DomainVerificationUserState.DOMAIN_STATE_VERIFIED -> DomainState.VERIFIED
                else -> DomainState.NOT_VERIFIED
            }
        } catch (e: Exception) {
            // Includes PackageManager.NameNotFoundException, which is a checked exception.
            DomainState.UNAVAILABLE
        }
    }
}
