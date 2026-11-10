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
     * data. It produces soft signals only.
     */
    public data object RequireVerifiedDomain : Caller()

    /**
     * Only the listed packages, signed with one of the listed certificates, should call.
     *
     * Every package needs at least one certificate digest. A package name alone is not
     * enough, because another app can be installed under that name if the real one is
     * absent.
     *
     * @property packages package name to the SHA-256 digests of its accepted signing certificates.
     */
    public data class AllowedPackages(
        public val packages: Map<String, Set<CertificateDigest>>,
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
