package com.shezguard.core.policy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Step 8 DSL: enforcing allow-lists and the requireVerifiedDomain() build-time checks. Pure JVM. */
class CallerDslTest {

    private val digest = "ab".repeat(32)

    private fun problems(block: EntryPointBuilder.() -> Unit): List<String> = try {
        intentPolicy { entryPoint("p", block) }
        throw AssertionError("expected PolicyDefinitionException")
    } catch (e: PolicyDefinitionException) {
        e.problems
    }

    private fun EntryPointBuilder.https() {
        allowSchemes("https")
        allowHosts("example.com")
        anyPath()
    }

    @Test
    fun allowListIsAdvisoryByDefault() {
        val c = intentPolicy { entryPoint("p") { allowedPackages { pkg("com.partner.app", digest) } } }["p"]!!.caller
        assertFalse((c as Caller.AllowedPackages).requireReliableIdentity)
    }

    @Test
    fun buildsEnforcingAllowList() {
        val c = intentPolicy {
            entryPoint("p") { allowedPackages(requireReliableIdentity = true) { pkg("com.partner.app", digest) } }
        }["p"]!!.caller as Caller.AllowedPackages
        assertTrue(c.requireReliableIdentity)
        assertEquals(setOf("com.partner.app"), c.packages.keys)
    }

    @Test
    fun requireVerifiedDomainWithHttpsDataBuilds() {
        val ep = intentPolicy { entryPoint("p") { https(); requireVerifiedDomain() } }["p"]!!
        assertEquals(Caller.RequireVerifiedDomain, ep.caller)
    }

    @Test
    fun rejectsRequireVerifiedDomainWithoutData() {
        assertEquals(
            listOf(
                "entryPoint(\"p\"): requireVerifiedDomain() needs an entry point that accepts an http or https data URI, " +
                    "but data is Forbidden. Add allowSchemes(\"https\") and allowHosts(...), or remove requireVerifiedDomain().",
            ),
            problems { requireVerifiedDomain() },
        )
    }

    @Test
    fun rejectsRequireVerifiedDomainWithCustomScheme() {
        val p = problems {
            allowSchemes("https", "myapp")
            allowHosts("example.com")
            anyPath()
            requireVerifiedDomain()
        }
        assertEquals(
            listOf(
                "entryPoint(\"p\"): requireVerifiedDomain() with allowSchemes(\"myapp\"): only http and https links can be " +
                    "verified as App Links. Remove the other schemes or remove requireVerifiedDomain().",
            ),
            p,
        )
    }

    /** Author condition 4. */
    @Test
    fun rejectsRequireVerifiedDomainWithSubdomainsOf() {
        val p = problems {
            allowSchemes("https")
            subdomainsOf("example.com")
            anyPath()
            requireVerifiedDomain()
        }
        assertEquals(
            listOf(
                "entryPoint(\"p\"): requireVerifiedDomain() cannot be combined with subdomainsOf(\"example.com\"): ShezGuard " +
                    "looks up each host exactly and does not expand wildcard hosts (*.example.com) in the verification state, " +
                    "so every subdomain would be reported as not verified. List the verified hosts with allowHosts(...) instead.",
            ),
            p,
        )
    }
}
