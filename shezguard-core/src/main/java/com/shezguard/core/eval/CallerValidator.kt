package com.shezguard.core.eval

import com.shezguard.core.Field
import com.shezguard.core.IdentitySource
import com.shezguard.core.Violation
import com.shezguard.core.ViolationCode
import com.shezguard.core.ViolationCode.CALLER_IDENTITY_REQUIRED
import com.shezguard.core.ViolationCode.CALLER_NOT_ALLOWED
import com.shezguard.core.ViolationCode.CALLER_NOT_ALLOWED_RELIABLE
import com.shezguard.core.ViolationCode.CALLER_UNIDENTIFIED
import com.shezguard.core.ViolationCode.DOMAIN_NOT_VERIFIED
import com.shezguard.core.ViolationCode.DOMAIN_VERIFICATION_UNAVAILABLE
import com.shezguard.core.policy.Caller
import com.shezguard.core.policy.EntryPointPolicy

/** A caller package named by a reliable, OS-set source. Never exposed outside ShezGuard. */
internal class Identified(val packageName: String, val source: IdentitySource)

/** What an advisory (caller-settable) source says. [packageName] is `null` when it names no package. */
internal class Advisory(val packageName: String?, val source: IdentitySource)

/**
 * Everything ShezGuard knows about the caller of one delivery.
 *
 * @property reliable every reliable source that named a package, preferred first
 * (`LAUNCHED_FROM_PACKAGE`, then `CALLING_PACKAGE`). Empty when none is available.
 * @property advisory the advisory source, if any.
 */
internal class CallerInfo(val reliable: List<Identified>, val advisory: Advisory?)

/** The Android side of the caller stage. Implementations must not throw. */
internal interface CallerSource {
    fun read(): CallerInfo

    /**
     * SHA-256 digests (64 lowercase hex characters) of the **current** signing certificates of
     * [packageName], or `null` if they cannot be read.
     */
    fun currentSignerDigests(packageName: String): Set<String>?

    companion object {
        /** No caller information: used by the intent-only `ShezGuard.evaluate` overload. */
        val NONE: CallerSource = object : CallerSource {
            override fun read(): CallerInfo = CallerInfo(emptyList(), null)
            override fun currentSignerDigests(packageName: String): Set<String>? = null
        }
    }
}

internal enum class DomainState { VERIFIED, NOT_VERIFIED, UNAVAILABLE }

/** Reads the app's own App Links verification state for a host. Implementations must not throw. */
internal fun interface DomainVerifier {
    fun state(host: String): DomainState

    companion object {
        /** No `Context`: verification state cannot be read. */
        val NONE: DomainVerifier = DomainVerifier { DomainState.UNAVAILABLE }
    }
}

/**
 * @property identitySource the source the decision used, or `null` when the caller rule is
 * `Caller.Any` or `RequireVerifiedDomain` (no identity is looked at).
 */
internal class CallerOutcome(val violations: List<Violation>, val identitySource: IdentitySource?)

/**
 * The caller stage (SPEC section 8). Emits at most one caller code and at most one domain
 * code, from single `when` expressions, so the exclusive pairs the risk score relies on
 * (`CALLER_UNIDENTIFIED` / `CALLER_NOT_ALLOWED`, `DOMAIN_NOT_VERIFIED` /
 * `DOMAIN_VERIFICATION_UNAVAILABLE`) can never occur together. The caller rule is single-valued,
 * so caller and domain codes never occur together either.
 */
internal object CallerValidator {

    /** @param host the canonical host of the data URI, or `null` if there is none. */
    fun validate(ep: EntryPointPolicy, host: String?, caller: CallerSource, domain: DomainVerifier): CallerOutcome =
        when (val rule = ep.caller) {
            Caller.Any -> CallerOutcome(emptyList(), null)
            Caller.RequireVerifiedDomain -> {
                val code = if (host == null) {
                    null
                } else {
                    when (domain.state(host)) {
                        DomainState.VERIFIED -> null
                        DomainState.NOT_VERIFIED -> DOMAIN_NOT_VERIFIED
                        DomainState.UNAVAILABLE -> DOMAIN_VERIFICATION_UNAVAILABLE
                    }
                }
                CallerOutcome(listOfNotNull(code?.let { violation(it, ep) }), null)
            }
            is Caller.AllowedPackages -> allowedPackages(rule, ep, caller)
        }

    private fun allowedPackages(rule: Caller.AllowedPackages, ep: EntryPointPolicy, caller: CallerSource): CallerOutcome {
        val info = caller.read()
        val advisory = info.advisory
        val (code: ViolationCode?, source: IdentitySource) = when {
            info.reliable.isNotEmpty() ->
                (if (info.reliable.all { permitted(it.packageName, rule, caller) }) null else CALLER_NOT_ALLOWED_RELIABLE) to
                    info.reliable.first().source
            rule.requireReliableIdentity -> CALLER_IDENTITY_REQUIRED to (advisory?.source ?: IdentitySource.NONE)
            advisory?.packageName != null && advisory.packageName !in rule.packages -> CALLER_NOT_ALLOWED to advisory.source
            else -> CALLER_UNIDENTIFIED to (advisory?.source ?: IdentitySource.NONE)
        }
        return CallerOutcome(listOfNotNull(code?.let { violation(it, ep) }), source)
    }

    /** Listed, and every current signer is listed for it (author condition 3). Fails closed. */
    private fun permitted(pkg: String, rule: Caller.AllowedPackages, caller: CallerSource): Boolean {
        val allowed = rule.packages[pkg] ?: return false
        val current = caller.currentSignerDigests(pkg)
        if (current.isNullOrEmpty()) return false
        return allowed.mapTo(HashSet()) { it.sha256Hex }.containsAll(current)
    }

    private fun violation(code: ViolationCode, ep: EntryPointPolicy) = Violation(code, ep.name, Field.CallerSignal)
}
