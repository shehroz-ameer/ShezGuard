package com.shezguard.core.eval

import com.shezguard.core.Field
import com.shezguard.core.IdentitySource
import com.shezguard.core.IdentitySource.CALLING_PACKAGE
import com.shezguard.core.IdentitySource.LAUNCHED_FROM_PACKAGE
import com.shezguard.core.IdentitySource.NONE
import com.shezguard.core.IdentitySource.REFERRER_EXTRA
import com.shezguard.core.IdentitySource.REFERRER_SYSTEM
import com.shezguard.core.ViolationCode
import com.shezguard.core.ViolationCode.CALLER_IDENTITY_REQUIRED
import com.shezguard.core.ViolationCode.CALLER_NOT_ALLOWED
import com.shezguard.core.ViolationCode.CALLER_NOT_ALLOWED_RELIABLE
import com.shezguard.core.ViolationCode.CALLER_UNIDENTIFIED
import com.shezguard.core.ViolationCode.DOMAIN_NOT_VERIFIED
import com.shezguard.core.ViolationCode.DOMAIN_VERIFICATION_UNAVAILABLE
import com.shezguard.core.policy.Caller
import com.shezguard.core.policy.CertificateDigest
import com.shezguard.core.policy.Data
import com.shezguard.core.policy.EntryPointPolicy
import com.shezguard.core.policy.HostPattern
import com.shezguard.core.policy.PathPattern
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.random.Random

/** SPEC 8 caller and domain rules (step 8), with fakes. Pure JVM. */
class CallerValidatorTest {

    private val keyA = "a".repeat(64)
    private val keyB = "b".repeat(64)
    private val keyOld = "c".repeat(64)
    private val partner = "com.partner.app"

    private fun allowed(enforce: Boolean = false, digests: Set<String> = setOf(keyA)) = EntryPointPolicy(
        "ep",
        caller = Caller.AllowedPackages(mapOf(partner to digests.map(::CertificateDigest).toSet()), enforce),
    )

    private val domainEp = EntryPointPolicy(
        "ep", data = Data.Required, schemes = setOf("https"), hosts = setOf(HostPattern.Exact("example.com")),
        paths = listOf(PathPattern.AnyPath), caller = Caller.RequireVerifiedDomain,
    )

    /** A fake caller source; [signers] maps package to its current signer digests (missing = lookup fails). */
    private class Fake(
        val info: CallerInfo,
        val signers: Map<String, Set<String>> = emptyMap(),
    ) : CallerSource {
        var lookups = 0
        override fun read(): CallerInfo = info
        override fun currentSignerDigests(packageName: String): Set<String>? = signers[packageName].also { lookups++ }
    }

    private fun reliable(pkg: String, source: IdentitySource = CALLING_PACKAGE) = Identified(pkg, source)

    private fun run(
        ep: EntryPointPolicy,
        info: CallerInfo = CallerInfo(emptyList(), null),
        signers: Map<String, Set<String>> = emptyMap(),
        host: String? = null,
        domain: DomainState = DomainState.UNAVAILABLE,
    ) = CallerValidator.validate(ep, host, Fake(info, signers), { domain })

    private fun codes(o: CallerOutcome) = o.violations.map { it.code }

    // ---- Reliable sources ------------------------------------------------------------

    @Test
    fun allowsReliableCallerWithListedCurrentSigner() {
        val o = run(allowed(), CallerInfo(listOf(reliable(partner)), null), mapOf(partner to setOf(keyA)))
        assertEquals(emptyList<ViolationCode>(), codes(o))
        assertEquals(CALLING_PACKAGE, o.identitySource)
    }

    @Test
    fun blocksReliableCallerNotInAllowList() {
        val f = Fake(CallerInfo(listOf(reliable("com.evil.app")), null), mapOf("com.evil.app" to setOf(keyA)))
        val o = CallerValidator.validate(allowed(), null, f, { DomainState.UNAVAILABLE })
        assertEquals(listOf(CALLER_NOT_ALLOWED_RELIABLE), codes(o))
        assertEquals("an unlisted package is not looked up", 0, f.lookups)
    }

    @Test
    fun blocksPackageSquatterWithWrongCertificate() {
        val o = run(allowed(), CallerInfo(listOf(reliable(partner)), null), mapOf(partner to setOf(keyB)))
        assertEquals(listOf(CALLER_NOT_ALLOWED_RELIABLE), codes(o))
    }

    @Test
    fun blocksReliableCallerWhoseCertificatesCannotBeRead() {
        assertEquals(listOf(CALLER_NOT_ALLOWED_RELIABLE), codes(run(allowed(), CallerInfo(listOf(reliable(partner)), null))))
        assertEquals(
            listOf(CALLER_NOT_ALLOWED_RELIABLE),
            codes(run(allowed(), CallerInfo(listOf(reliable(partner)), null), mapOf(partner to emptySet()))),
        )
    }

    /** Author condition 3: every signer of the caller must be listed. */
    @Test
    fun multiSignerCallerNeedsEverySignerListed() {
        val two = mapOf(partner to setOf(keyA, keyB))
        assertEquals(emptyList<ViolationCode>(), codes(run(allowed(digests = setOf(keyA, keyB)), CallerInfo(listOf(reliable(partner)), null), two)))
        assertEquals(listOf(CALLER_NOT_ALLOWED_RELIABLE), codes(run(allowed(digests = setOf(keyA)), CallerInfo(listOf(reliable(partner)), null), two)))
    }

    @Test
    fun rotatedOutKeyIsNotAccepted() {
        // The allow-list names only the old key; the caller's current signer is the new one.
        val o = run(allowed(digests = setOf(keyOld)), CallerInfo(listOf(reliable(partner)), null), mapOf(partner to setOf(keyA)))
        assertEquals(listOf(CALLER_NOT_ALLOWED_RELIABLE), codes(o))
    }

    @Test
    fun everyReliableSourceMustPass() {
        // launchedFrom (the launcher) is fine, but the forwarded result goes to an unlisted app.
        val info = CallerInfo(listOf(reliable(partner, LAUNCHED_FROM_PACKAGE), reliable("com.other.app")), null)
        val o = run(allowed(), info, mapOf(partner to setOf(keyA), "com.other.app" to setOf(keyA)))
        assertEquals(listOf(CALLER_NOT_ALLOWED_RELIABLE), codes(o))
        assertEquals(LAUNCHED_FROM_PACKAGE, o.identitySource)
    }

    @Test
    fun reliableSourceWinsOverAdvisory() {
        val info = CallerInfo(listOf(reliable(partner)), Advisory("com.evil.app", REFERRER_EXTRA))
        val o = run(allowed(), info, mapOf(partner to setOf(keyA)))
        assertEquals(emptyList<ViolationCode>(), codes(o))
        assertEquals(CALLING_PACKAGE, o.identitySource)
    }

    // ---- Advisory sources and enforcing mode -----------------------------------------

    @Test
    fun scoresAdvisoryReferrerNamingUnlistedPackage() {
        val o = run(allowed(), CallerInfo(emptyList(), Advisory("com.evil.app", REFERRER_SYSTEM)))
        assertEquals(listOf(CALLER_NOT_ALLOWED), codes(o))
        assertEquals(REFERRER_SYSTEM, o.identitySource)
    }

    @Test
    fun spoofedReferrerNamingAllowedPackageIsStillUnidentified() {
        val o = run(allowed(), CallerInfo(emptyList(), Advisory(partner, REFERRER_EXTRA)))
        assertEquals(listOf(CALLER_UNIDENTIFIED), codes(o))
        assertEquals(REFERRER_EXTRA, o.identitySource)
    }

    @Test
    fun referrerWithoutPackageAndNoSourceAreUnidentified() {
        assertEquals(listOf(CALLER_UNIDENTIFIED), codes(run(allowed(), CallerInfo(emptyList(), Advisory(null, REFERRER_EXTRA)))))
        val none = run(allowed(), CallerInfo(emptyList(), null))
        assertEquals(listOf(CALLER_UNIDENTIFIED), codes(none))
        assertEquals(NONE, none.identitySource)
    }

    @Test
    fun enforcingAllowListRequiresReliableIdentity() {
        for (adv in listOf(null, Advisory(partner, REFERRER_EXTRA), Advisory("com.evil.app", REFERRER_SYSTEM))) {
            assertEquals(listOf(CALLER_IDENTITY_REQUIRED), codes(run(allowed(enforce = true), CallerInfo(emptyList(), adv))))
        }
        val ok = run(allowed(enforce = true), CallerInfo(listOf(reliable(partner)), null), mapOf(partner to setOf(keyA)))
        assertEquals(emptyList<ViolationCode>(), codes(ok))
    }

    @Test
    fun anyCallerRuleEmitsNoCallerSignal() {
        val o = run(EntryPointPolicy("ep"), CallerInfo(listOf(reliable("com.evil.app")), Advisory("com.evil.app", REFERRER_EXTRA)))
        assertEquals(emptyList<ViolationCode>(), codes(o))
        assertNull(o.identitySource)
    }

    @Test
    fun callerViolationsUseTheFixedCallerField() {
        val o = run(allowed(), CallerInfo(emptyList(), Advisory("com.evil.app", REFERRER_EXTRA)))
        assertEquals(listOf<Field>(Field.CallerSignal), o.violations.map { it.field })
    }

    // ---- Domain verification ---------------------------------------------------------

    @Test
    fun domainStatesMapToCodes() {
        assertEquals(emptyList<ViolationCode>(), codes(run(domainEp, host = "example.com", domain = DomainState.VERIFIED)))
        assertEquals(listOf(DOMAIN_NOT_VERIFIED), codes(run(domainEp, host = "example.com", domain = DomainState.NOT_VERIFIED)))
        assertEquals(listOf(DOMAIN_VERIFICATION_UNAVAILABLE), codes(run(domainEp, host = "example.com", domain = DomainState.UNAVAILABLE)))
    }

    @Test
    fun noCanonicalHostMeansNoDomainSignal() {
        assertEquals(emptyList<ViolationCode>(), codes(run(domainEp, host = null, domain = DomainState.NOT_VERIFIED)))
    }

    @Test
    fun domainVerifierIsAskedForTheCanonicalHost() {
        var asked: String? = null
        CallerValidator.validate(domainEp, "example.com", CallerSource.NONE, { asked = it; DomainState.VERIFIED })
        assertEquals("example.com", asked)
    }

    // ---- Exclusive pairs (step 7 depends on these) -----------------------------------

    private val callerCodes = setOf(CALLER_UNIDENTIFIED, CALLER_NOT_ALLOWED, CALLER_NOT_ALLOWED_RELIABLE, CALLER_IDENTITY_REQUIRED)
    private val domainCodes = setOf(DOMAIN_NOT_VERIFIED, DOMAIN_VERIFICATION_UNAVAILABLE)

    @Test
    fun neverEmitsBothSignalsOfAnExclusivePair() {
        val r = Random(0xCA_11E2)
        val pkgs = listOf(partner, "com.evil.app", "com.other.app")
        val sources = IdentitySource.entries
        repeat(20_000) {
            val ep = when (r.nextInt(4)) {
                0 -> EntryPointPolicy("ep")
                1 -> allowed(enforce = false, digests = setOf(keyA, keyB).filter { r.nextBoolean() }.toSet().ifEmpty { setOf(keyA) })
                2 -> allowed(enforce = true)
                else -> domainEp
            }
            val info = CallerInfo(
                List(r.nextInt(0, 3)) { Identified(pkgs[r.nextInt(pkgs.size)], listOf(CALLING_PACKAGE, LAUNCHED_FROM_PACKAGE)[r.nextInt(2)]) },
                if (r.nextBoolean()) Advisory(if (r.nextBoolean()) pkgs[r.nextInt(pkgs.size)] else null, sources[r.nextInt(sources.size)]) else null,
            )
            val signers = pkgs.filter { r.nextBoolean() }.associateWith { setOf(keyA, keyB, keyOld).filter { r.nextBoolean() }.toSet() }
            val o = run(ep, info, signers, host = listOf(null, "example.com")[r.nextInt(2)], domain = DomainState.entries[r.nextInt(3)])
            val c = codes(o)
            assertTrue("$c", !(CALLER_UNIDENTIFIED in c && CALLER_NOT_ALLOWED in c))
            assertTrue("$c", !(DOMAIN_NOT_VERIFIED in c && DOMAIN_VERIFICATION_UNAVAILABLE in c))
            assertTrue("at most one caller code: $c", c.count { it in callerCodes } <= 1)
            assertTrue("at most one domain code: $c", c.count { it in domainCodes } <= 1)
            assertTrue("caller and domain rules are exclusive: $c", c.none { it in callerCodes } || c.none { it in domainCodes })
        }
    }
}
