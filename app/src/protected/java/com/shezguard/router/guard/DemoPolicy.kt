package com.shezguard.router.guard

import android.content.ComponentName
import android.content.Intent
import androidx.core.content.IntentSanitizer
import com.shezguard.core.Outcome
import com.shezguard.core.android.NestedIntentSanitizer
import com.shezguard.core.audit.LogcatAuditSink
import com.shezguard.core.policy.Caller
import com.shezguard.core.policy.CharClass
import com.shezguard.core.policy.ExtraType
import com.shezguard.core.policy.IntentPolicy
import com.shezguard.core.policy.Nested
import com.shezguard.core.policy.Unknown
import com.shezguard.core.policy.intentPolicy
import com.shezguard.router.BuildConfig

/**
 * The demo app's ShezGuard policy (step 12, protected flavor only). Held at app level in this object and
 * built on first use; nothing is injected. It is the policy a developer would write for each feature, not
 * one tuned to the attack scripts (author instruction for step 12): see docs/ATTACK_MATRIX.md, "Policy the
 * predictions assume", for the reasoning per entry point and for what it deliberately does NOT prevent.
 *
 * Defaults used everywhere unless stated: library limits (URI 2048, parameter 256), no fragment, no
 * non-default port, exact host, no extras allowed, `Nested.Deny`, `Caller.Any` (a browser link or a plain
 * startActivity has no reliable caller identity, so an advisory caller rule could never block alone; L3).
 */
object DemoPolicy {
    private const val HOST = "shezguard.example"
    private const val PKG = BuildConfig.APPLICATION_ID

    /**
     * The only screen "forward" sends users to is search (the benign forward is a search link).
     * FileViewerActivity is NOT allowed: no feature of the demo forwards to it, so allowing it would be
     * speculative (author condition 1).
     */
    private val forwardTargets = IntentSanitizer.Builder()
        .allowComponent(ComponentName(PKG, "$PKG.demo.SearchActivity"))
        .allowAction(Intent.ACTION_VIEW)
        .allowCategory(Intent.CATEGORY_BROWSABLE)
        .allowDataWithAuthority(HOST)
        .build()

    val policy: IntentPolicy by lazy {
        intentPolicy {
            // Debug and the test-only "minified" build type log one redacted line per decision (tag ShezGuard),
            // including Allow and Sanitize, so the attack scripts show the violation codes. Off in release.
            if (BuildConfig.AUDIT_LOGCAT) auditSink(LogcatAuditSink(minOutcome = Outcome.ALLOW))

            // Threat 1: forwards a nested Intent in "next". The feature needs it, so AllowSanitized, not Deny.
            entryPoint("forward") {
                nestedIntents(Nested.AllowSanitized(setOf("next"), NestedIntentSanitizer(forwardTargets)))
                caller(Caller.Any)
            }

            // Threat 2: search box. Users type spaces and apostrophes ("men's mug"), so PRINTABLE_ASCII.
            // This does not make the value safe for SQL (CharClass KDoc); the SQL sink stays injectable.
            entryPoint("search") {
                allowSchemes("https")
                allowHosts(HOST)
                path { exact("/search") }
                param("q") { string(CharClass.PRINTABLE_ASCII, maxLength = 64) }
                unknownParams(Unknown.Drop) // marketing / tracking parameters on a public link
                caller(Caller.Any)
            }

            // Threat 2: page preview in a WebView; only the app's own site may be previewed.
            entryPoint("preview") {
                allowSchemes("https")
                allowHosts(HOST)
                path { exact("/preview") }
                param("url") {
                    url { allowSchemes("https"); allowHosts(HOST) }
                    required()
                }
                unknownParams(Unknown.Block)
                caller(Caller.Any)
            }

            // Threat 2: public help file viewer. SLUG rejects the "." of "readme.txt" and no class admits
            // "." but rejects "..", so a developer ends up with PRINTABLE_ASCII (author decision 1, L37).
            entryPoint("file") {
                allowSchemes("https")
                allowHosts(HOST)
                path { exact("/file") }
                param("name") {
                    string(CharClass.PRINTABLE_ASCII, maxLength = 64)
                    required()
                }
                unknownParams(Unknown.Drop)
                caller(Caller.Any)
            }

            // Threat 2: a note shown "copies" times. INT values cannot be range-limited (L38).
            entryPoint("note") {
                extras {
                    allow("note", ExtraType.STRING)
                    allow("copies", ExtraType.INT)
                    maxStringLength(2000)
                }
                caller(Caller.Any)
            }

            // Threat 3: "continue to the next page" stays on the app's own site.
            entryPoint("redirect") {
                allowSchemes("https")
                allowHosts(HOST)
                path { exact("/redirect") }
                param("next") {
                    url { allowSchemes("https"); allowHosts(HOST) }
                    required()
                }
                unknownParams(Unknown.Block)
                caller(Caller.Any)
            }

            // Threat 4: login link on https://shezguard.example/login and shezdemo://login. anyPath() because
            // the custom-scheme link has an empty path. Hosts and schemes are a cross-product (L39).
            // requireVerifiedDomain() is not allowed together with a custom scheme (DSL rule 15).
            entryPoint("login") {
                allowSchemes("https", "shezdemo")
                allowHosts(HOST, "login")
                anyPath()
                param("token") {
                    string(CharClass.SLUG, maxLength = 64)
                    required()
                }
                unknownParams(Unknown.Block)
                caller(Caller.Any)
            }

            // Threat 5: the profile is a Serializable extra, which cannot be allow-listed (L6). No extras.
            entryPoint("profile") {
                caller(Caller.Any)
            }

            // Threat 6: same file feature as "file", behind the hand-written check; same rule.
            entryPoint("manual") {
                allowSchemes("https")
                allowHosts(HOST)
                path { exact("/manual") }
                param("name") {
                    string(CharClass.PRINTABLE_ASCII, maxLength = 64)
                    required()
                }
                unknownParams(Unknown.Drop)
                caller(Caller.Any)
            }
        }
    }
}
