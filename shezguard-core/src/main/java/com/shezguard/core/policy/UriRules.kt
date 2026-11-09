package com.shezguard.core.policy

/**
 * An allowed host. There is deliberately no free-form regex (SPEC section 4).
 *
 * Hosts must be lowercase ASCII without a trailing dot. Lookalike hosts (Cyrillic,
 * fullwidth, punycode) cannot be expressed here and never match an ASCII entry.
 */
public sealed class HostPattern {

    /**
     * Matches exactly one host. Single-label hosts are allowed because custom-scheme
     * deep links use them (`myapp://product/1` has host `product`).
     *
     * @property host the lowercase ASCII host.
     */
    public data class Exact(public val host: String) : HostPattern() {
        init {
            require(isValidHost(host)) { "invalid host (must be lowercase ASCII, no trailing dot)" }
        }
    }

    /**
     * Matches any host strictly below [domain], e.g. `subdomainsOf("example.com")`
     * matches `shop.example.com` but not `example.com` itself (list that separately).
     *
     * The domain needs at least two labels, so `subdomainsOf("com")` is rejected. Public
     * suffixes such as `co.uk` cannot be detected without a suffix list; see
     * `docs/LIMITATIONS.md`.
     *
     * @property domain the lowercase ASCII parent domain.
     */
    public data class SubdomainsOf(public val domain: String) : HostPattern() {
        init {
            require(isValidHost(domain)) { "invalid domain (must be lowercase ASCII, no trailing dot)" }
            require('.' in domain) { "subdomainsOf needs at least two labels" }
        }
    }
}

/**
 * An allowed path. Paths are matched after canonicalisation and percent-decoding.
 *
 * Patterns must start with `/` and may not contain `//`, `.` or `..` segments, `%`,
 * `\`, `?`, `#`, or non-printable characters, so a pattern can never itself express
 * the tricks canonicalisation removes.
 */
public sealed class PathPattern {

    /**
     * Matches any path that survives canonicalisation. Must be declared explicitly
     * (`anyPath()` in the DSL); an entry point with no path patterns matches no path.
     */
    public data object AnyPath : PathPattern()

    /**
     * Matches exactly one path.
     *
     * @property path the canonical path, e.g. `/settings`.
     */
    public data class Exact(public val path: String) : PathPattern() {
        init {
            require(isValidPathPattern(path)) { "invalid path pattern" }
        }
    }

    /**
     * Matches any path that starts with [prefix].
     *
     * The prefix must end with `/` so matching stops at a segment boundary:
     * `/product/` matches `/product/42` but never `/product-admin`.
     *
     * @property prefix the canonical prefix, e.g. `/product/`.
     */
    public data class Prefix(public val prefix: String) : PathPattern() {
        init {
            require(isValidPathPattern(prefix)) { "invalid path pattern" }
            require(prefix.endsWith("/")) { "prefix must end with '/' to keep a segment boundary" }
        }
    }
}

private val HOST_LABEL = "[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?"
private val HOST = Regex("^$HOST_LABEL(?:\\.$HOST_LABEL)*$")

internal fun isValidHost(host: String): Boolean = host.length <= 253 && HOST.matches(host)

internal fun isValidPathPattern(path: String): Boolean {
    if (!path.startsWith("/")) return false
    if (path.any { it.code < 0x21 || it.code > 0x7E || it in "%\\?#" }) return false
    if ("//" in path) return false
    val segments = path.split('/')
    return segments.none { it == "." || it == ".." }
}
