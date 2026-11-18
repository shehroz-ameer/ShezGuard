package com.shezguard.core.policy

import android.content.ComponentName
import androidx.core.content.IntentSanitizer
import com.shezguard.core.ViolationCode
import com.shezguard.core.android.NestedIntentSanitizer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Step 16, H6 (`docs/HARDENING.md`): attack category "policy changed after it was built". A built policy's collections
 * are unmodifiable copies: a cast cannot change them, and later changes to a collection passed to `IntentPolicy`,
 * `EntryPointPolicy`, `Nested.AllowSanitized` or `ScoreWeights` do not reach the policy. (Data classes keep the
 * caller's collection when constructed directly: `docs/LIMITATIONS.md` L45.)
 */
@RunWith(RobolectricTestRunner::class)
class PolicyImmutabilityTest {

    private val sanitizer = NestedIntentSanitizer(IntentSanitizer.Builder().allowComponent(ComponentName("a.b", "a.b.C")).build())

    private fun built(): IntentPolicy = intentPolicy {
        entryPoint("product") {
            allowSchemes("https")
            allowHosts("example.com")
            allowPorts(8443)
            path { prefix("/product/") }
            param("id") { digitsOnly() }
            param("k") { oneOf("a", "b") }
            param("next") { url { allowSchemes("https"); allowHosts("example.com") } }
            extras { allow("x", ExtraType.STRING) }
            nestedIntents(Nested.AllowSanitized(setOf("next"), sanitizer))
            allowedPackages { pkg("com.partner.app", "a".repeat(64)) }
            scoreWeight(ViolationCode.URI_NON_CANONICAL, 10)
        }
    }

    private fun rejectsMutation(name: String, mutate: () -> Unit): String? = try {
        mutate(); "$name was mutable"
    } catch (e: UnsupportedOperationException) {
        null
    } catch (e: ClassCastException) {
        null
    }

    @Suppress("UNCHECKED_CAST")
    @Test
    fun builtPolicyCollectionsRejectMutationThroughACast() {
        val p = built()
        val ep = p["product"]!!
        val type = { n: String -> ep.param(n)!!.type }
        val failures = listOfNotNull(
            rejectsMutation("entryPoints") { (p.entryPoints as MutableMap<String, EntryPointPolicy>)["admin"] = ep },
            rejectsMutation("schemes") { (ep.schemes as MutableSet<String>).add("http") },
            rejectsMutation("hosts") { (ep.hosts as MutableSet<HostPattern>).add(HostPattern.Exact("evil.example")) },
            rejectsMutation("ports") { (ep.ports as MutableSet<Int>).add(1) },
            rejectsMutation("paths") { (ep.paths as MutableList<PathPattern>).add(PathPattern.AnyPath) },
            rejectsMutation("params") { (ep.params as MutableList<ParamRule>).clear() },
            rejectsMutation("oneOf") { ((type("k") as ParamType.OneOf).values as MutableSet<String>).add("evil") },
            rejectsMutation("url schemes") { ((type("next") as ParamType.Url).schemes as MutableSet<String>).add("javascript") },
            rejectsMutation("url hosts") { ((type("next") as ParamType.Url).hosts as MutableSet<HostPattern>).add(HostPattern.Exact("evil.example")) },
            rejectsMutation("extras") { (ep.extras.allowed as MutableMap<String, ExtraType>)["evil"] = ExtraType.STRING },
            rejectsMutation("nested keys") { ((ep.nestedIntents as Nested.AllowSanitized).keys as MutableSet<String>).add("evil") },
            rejectsMutation("packages") { ((ep.caller as Caller.AllowedPackages).packages as MutableMap<String, Set<CertificateDigest>>).clear() },
            rejectsMutation("package digests") {
                ((ep.caller as Caller.AllowedPackages).packages.getValue("com.partner.app") as MutableSet<CertificateDigest>).add(CertificateDigest("b".repeat(64)))
            },
            rejectsMutation("score weights") { (ep.scoreWeights.overrides as MutableMap<ViolationCode, Int>).clear() },
        )
        assertEquals(emptyList<String>(), failures)
    }

    @Test
    fun laterChangesToTheCallersCollectionsDoNotReachThePolicy() {
        val hosts = mutableSetOf<HostPattern>(HostPattern.Exact("example.com"))
        val schemes = mutableSetOf("https")
        val paths = mutableListOf<PathPattern>(PathPattern.Exact("/a"))
        val keys = mutableSetOf("next")
        val weights = mutableMapOf(ViolationCode.URI_NON_CANONICAL to 10)
        val ep = EntryPointPolicy(
            "ctor", data = Data.Required, schemes = schemes, hosts = hosts, paths = paths,
            nestedIntents = Nested.AllowSanitized(keys, sanitizer), scoreWeights = ScoreWeights(weights),
        )
        val list = mutableListOf(ep)
        val p = IntentPolicy(list)
        hosts += HostPattern.Exact("evil.example"); schemes += "HTTP"; paths += PathPattern.AnyPath
        keys += ""; weights[ViolationCode.URI_NON_CANONICAL] = 100; list.clear()
        assertEquals(setOf(HostPattern.Exact("example.com")), ep.hosts)
        assertEquals(setOf("https"), ep.schemes)
        assertEquals(listOf<PathPattern>(PathPattern.Exact("/a")), ep.paths)
        assertEquals(setOf("next"), (ep.nestedIntents as Nested.AllowSanitized).keys)
        assertEquals(10, ep.scoreWeights.overrides[ViolationCode.URI_NON_CANONICAL])
        assertTrue(p["ctor"] === ep)
    }
}
