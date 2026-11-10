package com.shezguard.core.eval

import com.shezguard.core.Field
import com.shezguard.core.UriComponent
import com.shezguard.core.Violation
import com.shezguard.core.ViolationCode.URI_PARSER_MISMATCH
import com.shezguard.core.canon.CanonicalUri
import com.shezguard.core.canon.UriCanonicalizer
import com.shezguard.core.policy.EntryPointPolicy

/**
 * Detects `URI_PARSER_MISMATCH` (SPEC section 6; step 5b proposal (c)).
 *
 * The app may later read the URI through `android.net.Uri`, so ShezGuard's canonical view
 * and the platform's view must agree; on any difference the intent is blocked. Two checks:
 *
 * 1. **Canonicaliser vs `android.net.Uri`.** `isHierarchical` must be true. Scheme and
 *    host are compared after ASCII-only lowercasing (no Unicode case folding: U+212A KELVIN
 *    SIGN must not turn into `k`). The port is compared after mapping `-1` and the scheme's
 *    default port to "none". `getUserInfo` must be `null`. `getPathSegments` must equal the
 *    canonical segments, and the trailing slash (from `getPath`) must agree.
 *    `getFragment` must equal the canonical fragment. `getQueryParameterNames` must be the
 *    same set as the canonical names; inside the allowed name set all accessors agree
 *    (`docs/PAPER_NOTES.md` N3). Each value is read with `getQueryParameter` (singular,
 *    `docs/LIMITATIONS.md` L11, N1) and must equal the first canonical value of that name.
 * 2. **`android.net.Uri` vs itself.** A parcelled `HierarchicalUri` could carry a decoded
 *    form of a part that disagrees with its encoded form (possible up to API 29, see
 *    `docs/PAPER_NOTES.md` N4). `toString()` (what the canonicaliser parsed) uses the
 *    encoded form; `getAuthority`, `getPath`, `getQuery` and `getFragment` return the
 *    decoded one. Each must equal `Uri.decode` of its encoded counterpart.
 *
 * Every disagreeing component is reported once. A parameter value mismatch is reported on
 * the parameter's field (redacted in `toString()` when undeclared); an authority mismatch
 * is reported on [UriComponent.HOST].
 */
internal object ParserMismatch {

    fun check(c: CanonicalUri, u: UriView, policy: EntryPointPolicy): List<Violation> {
        val out = LinkedHashSet<Violation>()
        fun add(component: UriComponent) {
            out.add(Violation(URI_PARSER_MISMATCH, policy.name, Field.UriPart(component)))
        }

        // The other accessors are meaningless (or throw) on an opaque URI.
        if (!u.isHierarchical()) {
            add(UriComponent.WHOLE)
            return out.toList()
        }

        // ---- 1. canonicaliser vs android.net.Uri ----
        if (u.scheme()?.asciiLowercase() != c.scheme) add(UriComponent.SCHEME)
        if (u.host()?.asciiLowercase() != c.host) add(UriComponent.HOST)
        val androidPort = u.port().let { if (it == -1 || it == UriCanonicalizer.defaultPort(c.scheme)) null else it }
        if (androidPort != c.port) add(UriComponent.PORT)
        if (u.userInfo() != null) add(UriComponent.USERINFO)

        val segments = u.pathSegments()
        if (segments != c.pathSegments) add(UriComponent.PATH)
        val trailingSlash = segments.isNotEmpty() && u.path()?.endsWith("/") == true
        if (trailingSlash != c.hasTrailingSlash) add(UriComponent.PATH)

        if (u.fragment() != c.fragment) add(UriComponent.FRAGMENT)

        val names = LinkedHashSet<String>()
        c.query.forEach { names.add(it.first) }
        if (u.queryParameterNames() != names) add(UriComponent.QUERY)
        for (name in names) {
            val first = c.query.first { it.first == name }.second
            if (u.queryParameter(name) != first) {
                out.add(Violation(URI_PARSER_MISMATCH, policy.name, Field.Param(name, declared = policy.param(name) != null)))
            }
        }

        // ---- 2. android.net.Uri decoded parts vs its own encoded parts ----
        fun consistent(decoded: String?, encoded: String?, component: UriComponent) {
            val expected = encoded?.let(u::decode)
            if (decoded != expected) add(component)
        }
        consistent(u.authority(), u.encodedAuthority(), UriComponent.HOST)
        consistent(u.path(), u.encodedPath(), UriComponent.PATH)
        consistent(u.query(), u.encodedQuery(), UriComponent.QUERY)
        consistent(u.fragment(), u.encodedFragment(), UriComponent.FRAGMENT)

        return out.toList()
    }

    /** Lowercases `A-Z` only. Kotlin's `lowercase()` would also fold non-ASCII lookalikes. */
    private fun String.asciiLowercase(): String =
        String(CharArray(length) { i -> this[i].let { if (it in 'A'..'Z') it + 32 else it } })
}
