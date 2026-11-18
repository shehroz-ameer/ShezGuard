package com.shezguard.benchmark

import android.content.ComponentName
import android.content.Intent
import android.net.Uri
import android.os.Parcel
import androidx.core.content.IntentSanitizer
import com.shezguard.core.Decision
import com.shezguard.core.ShezGuard
import com.shezguard.core.android.NestedIntentSanitizer
import com.shezguard.core.policy.ExtraType
import com.shezguard.core.policy.IntentPolicy
import com.shezguard.core.policy.Nested
import com.shezguard.core.policy.Unknown
import com.shezguard.core.policy.intentPolicy

/**
 * The benchmark scenarios (docs/BENCHMARK.md), shared by the per-call timed loop and the
 * androidx.benchmark microbenchmark. Every call works on a freshly delivered intent: the template is
 * written to a Parcel and read back, with the app's class loader set for its extras, as
 * `ActivityThread` delivers it (extras still parcelled). That preparation is never timed.
 *
 * ShezGuard is called through the intent-only overload `ShezGuard.evaluate(intent, policy, name)`:
 * no caller lookup (PackageManager) and no domain verification are timed. The policy has no audit sink.
 */
internal object Scenarios {

    private val target = ComponentName("com.shezguard.benchmark.test", "com.shezguard.benchmark.Target")

    /** Accepts a nested VIEW intent for [target] carrying only "note" (String) and "next" (Intent). */
    private fun sanitizer(): IntentSanitizer = IntentSanitizer.Builder()
        .allowComponent(target)
        .allowAction(Intent.ACTION_VIEW)
        .allowExtra("note", String::class.java)
        .allowExtra("next", Intent::class.java)
        .build()

    private val manyNames = (1..10).map { "p%02d".format(it) }
    private val maxNames = (1..7).map { "v$it" }
    private val bundleKeys = (1..60).map { "s%02d".format(it) }
    private val arrayKeys = (1..4).map { "a$it" }

    val policy: IntentPolicy = intentPolicy {
        entryPoint("link") {
            allowSchemes("https")
            allowHosts("example.com")
            path { prefix("/product/") }
            param("id") { digitsOnly(maxLength = 10); required() }
            param("ref") { string() }
        }
        entryPoint("many") {
            allowSchemes("https")
            allowHosts("example.com")
            path { exact("/search") }
            for (n in manyNames) param(n) { string() }
            unknownParams(Unknown.Drop)
        }
        entryPoint("maxlen") {
            allowSchemes("https")
            allowHosts("example.com")
            path { exact("/max") }
            for (n in maxNames) param(n) { string() } // default maximum length: 256
        }
        entryPoint("nested") {
            nestedIntents(Nested.AllowSanitized(setOf("next"), NestedIntentSanitizer(sanitizer())))
        }
        entryPoint("cap") { // step 16, H8: the maxUriLength bound
            allowSchemes("https")
            allowHosts("example.com")
            anyPath()
            unknownParams(Unknown.Ignore)
            limits(maxUriLength = 8192)
        }
        entryPoint("cap256") { // step 16, H8: the highest parameter cap an app can configure
            allowSchemes("https")
            allowHosts("example.com")
            anyPath()
            unknownParams(Unknown.Ignore)
            limits(maxUriLength = 8192, maxParameters = 256)
        }
        entryPoint("dflt") { // step 16, H8: default limits
            allowSchemes("https")
            allowHosts("example.com")
            anyPath()
            unknownParams(Unknown.Ignore)
        }
        entryPoint("bundle") {
            extras {
                maxKeys(64)
                for (k in bundleKeys) allow(k, ExtraType.STRING)
                for (k in arrayKeys) allow(k, ExtraType.STRING_ARRAY)
            }
        }
    }

    /** One benchmarked operation on a delivered intent. */
    class Scenario(
        val name: String,
        val description: String,
        val template: () -> Intent,
        val run: (Intent) -> Any?,
    )

    private fun guard(entryPoint: String): (Intent) -> Any? = { ShezGuard.evaluate(it, policy, entryPoint) }

    private fun view(uri: String) = Intent(Intent.ACTION_VIEW, Uri.parse(uri))

    private fun chars(n: Int, seed: Int): String {
        val alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return String(CharArray(n) { alphabet[(it * 7 + seed) % alphabet.length] })
    }

    private fun nestedChain(depth: Int): Intent {
        var inner = Intent(Intent.ACTION_VIEW).setComponent(target).putExtra("note", "hello")
        repeat(depth - 1) { inner = Intent(Intent.ACTION_VIEW).setComponent(target).putExtra("note", "hello").putExtra("next", inner) }
        return Intent().putExtra("next", inner)
    }

    /** Step 16, H8: the most distinct value-less parameter names (1- and 2-char) that fit in [maxLength] chars, or [count]. */
    private fun denseUri(maxLength: Int, count: Int = Int.MAX_VALUE): String {
        val alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
        val names = alphabet.map { "$it" } + alphabet.flatMap { a -> alphabet.map { b -> "$a$b" } }
        val sb = StringBuilder("https://example.com/x?")
        var n = 0
        for (name in names) {
            val piece = (if (n == 0) "" else "&") + name
            if (sb.length + piece.length > maxLength || n >= count) break
            sb.append(piece); n++
        }
        return sb.toString()
    }

    val capUri: String = denseUri(8192)
    private val defaultWorstUri: String = denseUri(2048)
    private val cap64Uri: String = denseUri(8192, count = 64)
    private val cap256Uri: String = denseUri(8192, count = 256)

    private val simpleUri = "https://example.com/product/123?id=123&ref=home"

    private val bundleTemplate: () -> Intent = {
        Intent().apply {
            bundleKeys.forEachIndexed { i, k -> putExtra(k, chars(256, i)) }
            arrayKeys.forEachIndexed { i, k -> putExtra(k, Array(64) { j -> chars(32, i + j) }) }
        }
    }

    val all: List<Scenario> = listOf(
        Scenario("simple_link", "https deep link, path prefix, 2 declared params (Allow)", { view(simpleUri) }, guard("link")),
        Scenario(
            "many_params",
            "10 declared + 40 undeclared params under Unknown.Drop (Sanitize)",
            { view("https://example.com/search?" + (manyNames.map { "$it=v$it" } + (1..40).map { "u$it=x$it" }).joinToString("&")) },
            guard("many"),
        ),
        Scenario(
            "max_length",
            "7 params of 256 chars each (maximum param length; URI about 1 850 chars) (Allow)",
            { view("https://example.com/max?" + maxNames.mapIndexed { i, n -> "$n=${chars(256, i)}" }.joinToString("&")) },
            guard("maxlen"),
        ),
        Scenario("nested_depth1", "one nested intent under Nested.AllowSanitized", { nestedChain(1) }, guard("nested")),
        Scenario("nested_depth4", "nested intents 4 deep under Nested.AllowSanitized", { nestedChain(4) }, guard("nested")),
        Scenario("large_bundle", "64 extras: 60 Strings of 256 chars, 4 String arrays of 64 x 32 chars (Allow)", bundleTemplate, guard("bundle")),
        Scenario("early_block_unregistered", "entry point not in the policy: Block before reading the intent", { view(simpleUri) }, guard("notRegistered")),
        Scenario("early_block_scheme", "http instead of https on the deep-link entry point (Block; all violations still collected)", { view("http://example.com/product/123?id=123&ref=home") }, guard("link")),
        Scenario("h8_cap_worst", "step 16 H8: 8 192-char URI, most distinct value-less params that fit (2 745)", { view(capUri) }, guard("cap")),
        Scenario("h8_default_worst", "step 16 H8: 2 048-char URI, most distinct value-less params that fit (697), default limits", { view(defaultWorstUri) }, guard("dflt")),
        Scenario("h8_cap256", "step 16 H8: 256 distinct value-less params (maxParameters = 256, the maximum)", { view(cap256Uri) }, guard("cap256")),
        Scenario("h8_cap64", "step 16 H8: 64 distinct value-less params (the default parameter cap)", { view(cap64Uri) }, guard("cap")),
        // Baselines: no ShezGuard.
        Scenario("baseline_app_reads_link", "no guard: the app reads id and ref from the delivered simple link", { view(simpleUri) }) {
            it.data?.getQueryParameter("id"); it.data?.getQueryParameter("ref")
        },
        Scenario("baseline_app_reads_bundle", "no guard: the app reads all 64 extras of the large Bundle", bundleTemplate) { i ->
            bundleKeys.forEach { i.getStringExtra(it) }; arrayKeys.forEach { i.getStringArrayExtra(it) }
        },
        Scenario("baseline_sanitizer_nested1", "no guard: IntentSanitizer alone on the depth-1 nested intent (as an app would use it)", { nestedChain(1) }) { i ->
            @Suppress("DEPRECATION")
            val nested: Intent? = i.getParcelableExtra("next")
            nested?.let { sanitizer().sanitizeByFiltering(it) }
        },
    )

    /** The intent as an Activity receives it (extras still parcelled, app class loader set). */
    fun delivered(template: Intent): Intent {
        val p = Parcel.obtain()
        try {
            template.writeToParcel(p, 0)
            p.setDataPosition(0)
            return Intent.CREATOR.createFromParcel(p).apply { setExtrasClassLoader(Scenarios::class.java.classLoader) }
        } finally {
            p.recycle()
        }
    }

    /** Outcome label for a result: the Decision type, or "-" for a baseline. */
    fun outcome(result: Any?): String = when (result) {
        is Decision -> result.javaClass.simpleName.uppercase() + result.violations.map { it.code }.toSortedSet()
        else -> "-"
    }
}
