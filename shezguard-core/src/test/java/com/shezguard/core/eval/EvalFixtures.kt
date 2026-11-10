package com.shezguard.core.eval

import android.content.Intent
import android.net.Uri
import com.shezguard.core.Decision
import com.shezguard.core.ViolationCode
import com.shezguard.core.policy.CharClass
import com.shezguard.core.policy.Data
import com.shezguard.core.policy.IntentPolicy
import com.shezguard.core.policy.Unknown
import com.shezguard.core.policy.intentPolicy

/** Shared policies and helpers for the step 5b evaluator tests. */
internal object EvalFixtures {

    val policy: IntentPolicy = intentPolicy {
        entryPoint("product") {
            allowSchemes("https")
            allowHosts("example.com")
            path { prefix("/product/") }
            param("id") { digitsOnly(maxLength = 10); required() }
            param("ref") { string() }
            param("next") { url { allowSchemes("https"); allowHosts("example.com") } }
        }
        entryPoint("search") {
            allowSchemes("https")
            allowHosts("example.com")
            path { exact("/search") }
            param("q") { string(CharClass.TEXT) }
            unknownParams(Unknown.Drop)
            allowFragment()
        }
        entryPoint("browse") {
            allowSchemes("https")
            allowHosts("example.com")
            anyPath()
            param("q") { string(CharClass.TEXT) }
            unknownParams(Unknown.Ignore)
        }
        entryPoint("optional") {
            data(Data.Optional)
            allowSchemes("https")
            allowHosts("example.com")
            anyPath()
        }
        entryPoint("nodata") { }
    }

    val entryPointNames: List<String> = listOf("product", "search", "browse", "optional", "nodata", "notRegistered")

    fun viewIntent(uri: String): Intent = Intent(Intent.ACTION_VIEW, Uri.parse(uri))

    fun codes(d: Decision): Set<ViolationCode> = d.violations.map { it.code }.toSet()

    /** Everything a Decision exposes as text: what could end up in a log. */
    fun renderedOutput(d: Decision): String = buildString {
        append(d.toString()).append('\n')
        d.violations.forEach { append(it.toString()).append(' ').append(it.field.toString()).append('\n') }
        append(d.score.toString()).append('\n')
        when (d) {
            is Decision.Allow -> append(d.data.toString())
            is Decision.Sanitize -> append(d.data.toString())
            is Decision.Block -> Unit
        }
    }

    /** A comparable summary of a Decision, used for determinism checks. */
    fun summary(d: Decision): List<Any?> = listOf(
        d.outcome,
        d.entryPoint,
        d.violations,
        d.score,
        when (d) {
            is Decision.Allow -> d.data
            is Decision.Sanitize -> listOf(d.data, d.sanitizedIntent.dataString)
            is Decision.Block -> null
        },
    )
}
