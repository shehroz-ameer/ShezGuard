package com.shezguard.core.policy

/**
 * Who may send intents to an entry point (SPEC sections 4 and 8).
 *
 * Caller identity on Android is mostly unreliable for Activities. Every rule here is an
 * advisory signal unless the identity comes from a reliable source, such as the OS-set
 * calling package or a signature-level permission on the component. See
 * `docs/LIMITATIONS.md`, L3.
 */
public sealed class Caller {

    /** No caller restriction. */
    public data object Any : Caller()

    /**
     * The app's own domain should be verified for App Links (API 31+).
     *
     * This checks the domain, not the intent: it cannot prove that a given intent came
     * through a verified link, because any app can send an explicit intent with `https`
     * data. It produces soft signals only. The canonical host is looked up exactly; the policy
     * must accept only `http`/`https` data and may not use `subdomainsOf(...)`.
     */
    public data object RequireVerifiedDomain : Caller()

    /**
     * Only the listed packages, signed with one of the listed certificates, should call.
     *
     * Every package needs at least one certificate digest. A package name alone is not
     * enough, because another app can be installed under that name if the real one is
     * absent.
     *
     * **Advisory by default.** Without [requireReliableIdentity], an allow-list only adds to the
     * risk score when the caller cannot be identified reliably, and most launches cannot: the OS
     * reveals the caller only for `startActivityForResult`, or on API 34+ when the caller opts in
     * with `ActivityOptions.setShareIdentityEnabled(true)`. A reliable caller that is not allowed
     * always blocks.
     *
     * Certificates are compared with the caller's **current** signers only: every current signer
     * must be listed. Keys from the caller's signing lineage are not accepted, so after the caller
     * rotates its signing key the new key must be added here.
     *
     * @property packages package name to the SHA-256 digests of its accepted signing certificates.
     * @property requireReliableIdentity when true, a caller without a reliable identity is blocked
     * (`CALLER_IDENTITY_REQUIRED`). This blocks ordinary browser deep links and plain
     * `startActivity` calls; use it only for app-to-app integrations whose callers you control.
     */
    public data class AllowedPackages(
        public val packages: Map<String, Set<CertificateDigest>>,
        public val requireReliableIdentity: Boolean = false,
    ) : Caller() {
        init {
            require(packages.isNotEmpty()) { "AllowedPackages needs at least one package" }
            packages.forEach { (pkg, digests) ->
                require(PACKAGE_NAME.matches(pkg)) { "invalid package name: $pkg" }
                require(digests.isNotEmpty()) { "package $pkg needs at least one certificate digest" }
            }
        }
    }
}

/**
 * The SHA-256 digest of a signing certificate.
 *
 * @property sha256Hex 64 lowercase hex characters, without separators.
 */
@JvmInline
public value class CertificateDigest(public val sha256Hex: String) {
    init {
        require(SHA256_HEX.matches(sha256Hex)) { "expected 64 lowercase hex characters" }
    }

    private companion object {
        val SHA256_HEX = Regex("^[0-9a-f]{64}$")
    }
}
