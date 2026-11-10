package com.shezguard.core.canon

import com.shezguard.core.UriComponent
import com.shezguard.core.ViolationCode

/**
 * One problem found while canonicalising a URI.
 *
 * Deliberately holds only a code and a component, never any part of the URI, so a
 * finding is always safe to log or put in a [com.shezguard.core.Violation].
 */
internal data class Finding(val code: ViolationCode, val component: UriComponent)

/**
 * A hierarchical URI after canonicalisation. Every text field is decoded exactly once.
 *
 * @property scheme lowercase ASCII scheme.
 * @property host lowercase ASCII host. No IDN conversion is done.
 * @property port explicit non-default port, or `null` when absent or the scheme default.
 * @property pathSegments decoded, non-empty segments. Duplicate slashes are collapsed.
 * @property hasTrailingSlash whether the path ended with `/` after at least one segment.
 * @property query decoded parameters in their original order, duplicates kept.
 * @property fragment decoded fragment, or `null` if the URI had no `#`.
 */
internal data class CanonicalUri(
    val scheme: String,
    val host: String,
    val port: Int?,
    val pathSegments: List<String>,
    val hasTrailingSlash: Boolean,
    val query: List<Pair<String, String>>,
    val fragment: String?,
)

/** The outcome of [UriCanonicalizer.canonicalize]. */
internal sealed class CanonResult {
    /** Every finding, in the order found, without duplicates. */
    abstract val findings: List<Finding>

    /** No hard finding. [findings] can hold only soft ones (`URI_NON_CANONICAL`). */
    data class Ok(val uri: CanonicalUri, override val findings: List<Finding>) : CanonResult()

    /** At least one hard finding. [findings] holds all of them, not just the first. */
    data class Rejected(override val findings: List<Finding>) : CanonResult()
}
