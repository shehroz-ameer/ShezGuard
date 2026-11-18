package com.shezguard.core.hardening

import com.shezguard.core.Decision
import com.shezguard.core.Outcome
import com.shezguard.core.ShezGuard
import com.shezguard.core.hardening.Hardening.view
import com.shezguard.core.policy.Data
import com.shezguard.core.policy.EntryPointPolicy
import com.shezguard.core.policy.ExtraType
import com.shezguard.core.policy.ExtrasRule
import com.shezguard.core.policy.HostPattern
import com.shezguard.core.policy.IntentPolicy
import com.shezguard.core.policy.PathPattern
import com.shezguard.core.policy.PolicyDefinitionException
import com.shezguard.core.policy.intentPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.random.Random

/** Step 15, area 4: policy model and DSL (Robolectric SDK 34). */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class PolicyHardeningTest {

    private fun productPolicy(): IntentPolicy = intentPolicy {
        entryPoint("product") {
            allowSchemes("https")
            allowHosts("example.com")
            path { prefix("/product/") }
            param("id") { digitsOnly() }
        }
    }

    private fun outcome(p: IntentPolicy, uri: String, ep: String = "product") = ShezGuard.evaluate(view(uri), p, ep).outcome

    /**
     * Finding (hardening). A built policy is presented as read-only (`Set`, `List`, `Map`), but the DSL stores
     * `LinkedHashSet`/`LinkedHashMap` instances that any code holding the policy can cast and change after
     * `intentPolicy {}` returned, bypassing every build-time check. The public `EntryPointPolicy` and
     * `ExtrasRule` constructors keep the caller's own collections, so later changes to them change the policy.
     */
    @Test
    fun builtPolicyCannotBeChangedAfterBuild() {
        val changed = mutableListOf<String>()

        val p1 = productPolicy()
        if (runCatching { @Suppress("UNCHECKED_CAST") (p1["product"]!!.hosts as MutableSet<HostPattern>).add(HostPattern.Exact("evil.example")) }.getOrDefault(false) &&
            outcome(p1, "https://evil.example/product/1") == Outcome.ALLOW
        ) changed += "DSL hosts set: evil.example allowed after build"

        val p2 = productPolicy()
        if (runCatching { @Suppress("UNCHECKED_CAST") (p2.entryPoints as MutableMap<String, EntryPointPolicy>)["admin"] = p2["product"]!! }.isSuccess &&
            p2["admin"] != null
        ) changed += "entryPoints map: an entry point added under a name that is not its own"

        val hosts = mutableSetOf<HostPattern>(HostPattern.Exact("example.com"))
        val ep = EntryPointPolicy("ctor", data = Data.Required, schemes = setOf("https"), hosts = hosts, paths = listOf(PathPattern.AnyPath))
        val p3 = IntentPolicy(listOf(ep))
        hosts += HostPattern.Exact("evil.example")
        if (outcome(p3, "https://evil.example/x", "ctor") == Outcome.ALLOW) changed += "constructor aliasing: caller's hosts set changed the policy"

        val allowed = mutableMapOf("k" to ExtraType.STRING)
        val rule = ExtrasRule(allowed)
        allowed[""] = ExtraType.STRING // bypasses ExtrasRule's own init check
        if (rule.allowed.containsKey("")) changed += "ExtrasRule aliasing: an empty key added after its init check"

        assertEquals(emptyList<String>(), changed)
    }

    /** Shared policy, 8 threads: every decision equals the single-threaded one. */
    @Test
    fun holdsConcurrentEvaluationOfASharedPolicy() {
        val p = productPolicy()
        val rnd = Random(15)
        val corpus = List(400) {
            val id = rnd.nextInt(0, 100000)
            when (it % 4) {
                0 -> "https://example.com/product/$id?id=$id"
                1 -> "https://example.com/product/../$id?id=$id"
                2 -> "https://example.com/product/$id?id=$id&x=1"
                else -> "https://EXAMPLE.com:443/product/$id?id=${id}a"
            }
        }
        fun summary(d: Decision) = "${d.outcome} ${d.violations}"
        val expected = corpus.map { summary(ShezGuard.evaluate(view(it), p, "product")) }
        val pool = Executors.newFixedThreadPool(8)
        try {
            val futures = (0 until 8).map { t ->
                pool.submit(Callable { (0 until 20).flatMap { corpus.indices.map { i -> (i + t) % corpus.size } }.map { i -> i to summary(ShezGuard.evaluate(view(corpus[i]), p, "product")) } })
            }
            val wrong = futures.flatMap { it.get(120, TimeUnit.SECONDS) }.count { (i, s) -> s != expected[i] }
            assertEquals(0, wrong)
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun holdsUnsafeDefaultsAndEmptyAllowListsAreFailClosed() {
        // An entry point with nothing configured accepts no data, no extras and no nested intent.
        val p = intentPolicy { entryPoint("bare") { } }
        assertEquals(Outcome.BLOCK, outcome(p, "https://example.com/", "bare"))
        assertEquals(Outcome.SANITIZE, ShezGuard.evaluate(android.content.Intent().putExtra("x", "y"), p, "bare").outcome) // removed, not kept
        // Model-level policy with empty allow-lists blocks everything that carries data.
        val m = IntentPolicy(listOf(EntryPointPolicy("m", data = Data.Optional)))
        assertEquals(Outcome.BLOCK, outcome(m, "https://example.com/", "m"))
        // The DSL rejects the empty or incomplete forms.
        val rejected = listOf<Pair<String, () -> Unit>>(
            "allowSchemes() with nothing" to { intentPolicy { entryPoint("a") { allowSchemes(); allowHosts("example.com"); anyPath() } } },
            "no path" to { intentPolicy { entryPoint("a") { allowSchemes("https"); allowHosts("example.com") } } },
            "duplicate name" to { intentPolicy { entryPoint("a") { }; entryPoint("a") { } } },
            "name with space" to { intentPolicy { entryPoint("a b") { } } },
            "uppercase host" to { intentPolicy { entryPoint("a") { allowSchemes("https"); allowHosts("Example.com"); anyPath() } } },
            "host with trailing dot" to { intentPolicy { entryPoint("a") { allowSchemes("https"); allowHosts("example.com."); anyPath() } } },
            "subdomainsOf(com)" to { intentPolicy { entryPoint("a") { allowSchemes("https"); subdomainsOf("com"); anyPath() } } },
            "prefix without slash" to { intentPolicy { entryPoint("a") { allowSchemes("https"); allowHosts("example.com"); path { prefix("/p") } } } },
            "pattern with .." to { intentPolicy { entryPoint("a") { allowSchemes("https"); allowHosts("example.com"); path { prefix("/p/../") } } } },
            "empty oneOf" to { intentPolicy { entryPoint("a") { allowSchemes("https"); allowHosts("example.com"); anyPath(); param("x") { oneOf() } } } },
            "empty allowedPackages" to { intentPolicy { entryPoint("a") { allowedPackages { } } } },
        )
        val accepted = rejected.mapNotNull { (name, build) ->
            try {
                build(); name
            } catch (e: PolicyDefinitionException) {
                null
            }
        }
        assertEquals(emptyList<String>(), accepted)
    }

    /** Names are exact and case-sensitive everywhere; a confusable name never falls back to another policy. */
    @Test
    fun holdsEntryPointNamesAreExact() {
        val p = intentPolicy {
            entryPoint("product") { allowSchemes("https"); allowHosts("example.com"); anyPath() }
            entryPoint("Product") { }
        }
        assertEquals(Outcome.ALLOW, outcome(p, "https://example.com/x", "product"))
        assertEquals(Outcome.BLOCK, outcome(p, "https://example.com/x", "Product"))
        for (n in listOf("product ", " product", "PRODUCT", "prоduct" /* Cyrillic о */, "")) {
            val d = ShezGuard.evaluate(view("https://example.com/x"), p, n)
            assertTrue("<$n> ${d.violations}", d.outcome == Outcome.BLOCK)
        }
        try {
            intentPolicy { entryPoint("prоduct") { } }
            fail("non-ASCII entry point name accepted")
        } catch (e: PolicyDefinitionException) {
            // expected
        }
    }
}
