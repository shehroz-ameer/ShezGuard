package com.shezguard.core

/**
 * The validated, canonical form of an intent's data URI. Apps read deep link data from
 * here, never from `getIntent().getData()`.
 *
 * Every value is decoded exactly once by ShezGuard's canonicaliser and has passed the
 * entry point policy. Query values follow `Uri.getQueryParameter`: `+` is a space and `%2B`
 * is a literal `+` (`docs/LIMITATIONS.md` L11).
 *
 * Only parameters the policy **declares** can be read. Undeclared parameters kept under
 * `Unknown.Ignore` are not readable here, although they remain in the original intent:
 * the app must not read them from the intent either. Parameters removed under
 * `Unknown.Drop` are absent from both this object and the sanitized intent.
 *
 * `toString()` is safe to log. It shows the scheme and the names of the declared
 * parameters present, and redacts everything else, including the host: a host matched
 * through `subdomainsOf` is partly chosen by the sender.
 *
 * @property scheme the lowercase scheme, one of the policy's allowed schemes.
 * @property host the lowercase host, matched against the policy's host patterns.
 * @property port the explicit non-default port, or `null` for the scheme's default.
 * @property pathSegments the decoded, non-empty path segments.
 * @property hasTrailingSlash whether the path ends with `/` after at least one segment.
 * @property fragment the decoded fragment, or `null` if there is none. Only present when
 * the policy allows fragments.
 */
public class GuardedUri internal constructor(
    public val scheme: String,
    public val host: String,
    public val port: Int?,
    public val pathSegments: List<String>,
    public val hasTrailingSlash: Boolean,
    public val fragment: String?,
    private val declaredParams: Map<String, List<String>>,
) {
    /** The decoded path: `/` for an empty path, else `/` + segments joined by `/` (+ `/` if [hasTrailingSlash]). */
    public val path: String
        get() = if (pathSegments.isEmpty()) "/" else
            pathSegments.joinToString("/", prefix = "/", postfix = if (hasTrailingSlash) "/" else "")

    /** Names of the declared parameters present in the URI. */
    public val paramNames: Set<String> get() = declaredParams.keys

    /**
     * The value of declared parameter [name], or `null` if it is absent or not declared.
     * If the policy allows repeated parameters, this is the first value, as with
     * `Uri.getQueryParameter`.
     */
    public fun param(name: String): String? = declaredParams[name]?.firstOrNull()

    /** All values of declared parameter [name] in URI order; empty if absent or not declared. */
    public fun params(name: String): List<String> = declaredParams[name].orEmpty()

    override fun equals(other: Any?): Boolean =
        other is GuardedUri && scheme == other.scheme && host == other.host && port == other.port &&
            pathSegments == other.pathSegments && hasTrailingSlash == other.hasTrailingSlash &&
            fragment == other.fragment && declaredParams == other.declaredParams

    override fun hashCode(): Int =
        listOf(scheme, host, port, pathSegments, hasTrailingSlash, fragment, declaredParams).hashCode()

    override fun toString(): String =
        "GuardedUri(scheme=$scheme, host=$REDACTED, path=$REDACTED, params=${paramNames.toList()}, " +
            "fragment=${if (fragment == null) "none" else REDACTED})"

    private companion object {
        const val REDACTED = "<redacted>"
    }
}
