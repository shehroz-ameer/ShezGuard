package com.shezguard.core.eval

import android.content.Intent
import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.shezguard.core.Decision
import com.shezguard.core.Field
import com.shezguard.core.Outcome
import com.shezguard.core.ShezGuard
import com.shezguard.core.UriComponent
import com.shezguard.core.Violation
import com.shezguard.core.ViolationCode.URI_PARSER_MISMATCH
import com.shezguard.core.policy.CharClass
import com.shezguard.core.policy.intentPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Step 16, H2 (`docs/HARDENING.md`): attack category "open redirect through a network-path reference". `Uri.getPath()`
 * keeps duplicate slashes that ShezGuard's canonical path collapses; `//evil.example/landing` resolved against the
 * app's origin is `https://evil.example/landing`. The parser-mismatch check now compares `getPath()` exactly, so every
 * such URI is blocked, and every allowed URI's `getPath()` equals the checked path. Shared with the instrumented tests.
 */
@RunWith(AndroidJUnit4::class)
class PathAccessorAgreementTest {

    private val policy = intentPolicy {
        entryPoint("any") {
            allowSchemes("https")
            allowHosts("example.com")
            anyPath()
            param("q") { string(CharClass.TEXT) }
        }
        entryPoint("product") {
            allowSchemes("https")
            allowHosts("example.com")
            path { prefix("/product/") }
        }
    }

    private fun eval(uri: String, ep: String = "any"): Decision =
        ShezGuard.evaluate(ExtrasFixtures.received(Intent(Intent.ACTION_VIEW, Uri.parse(uri))), policy, ep)

    @Test
    fun blocksNetworkPathReferenceThatOnlyGetPathSees() {
        val cases = listOf(
            "https://example.com//evil.example/landing" to "any",
            "https://example.com///evil.example" to "any",
            "https://example.com//" to "any",
            "https://example.com/a//b" to "any",
            "https://example.com/a/b//" to "any",
            "https://example.com//product/x" to "product", // resolves to host "product"
        )
        for ((s, ep) in cases) {
            val d = eval(s, ep)
            assertEquals(s, Outcome.BLOCK, d.outcome)
            assertTrue("$s ${d.violations}", Violation(URI_PARSER_MISMATCH, ep, Field.UriPart(UriComponent.PATH)) in d.violations)
        }
    }

    @Test
    fun allowedUriGetPathEqualsTheCheckedPath() {
        for (s in listOf("https://example.com", "https://example.com/", "https://example.com/a/b", "https://example.com/a/b/", "https://example.com/a/%62?q=x")) {
            val d = eval(s)
            assertEquals(s, Outcome.ALLOW, d.outcome)
            val path = (d as Decision.Allow).intent.data!!.path
            val checked = d.data!!.path
            assertTrue("$s getPath=$path checked=$checked", path == checked || (d.data!!.pathSegments.isEmpty() && (path == "" || path == null)))
        }
    }
}
