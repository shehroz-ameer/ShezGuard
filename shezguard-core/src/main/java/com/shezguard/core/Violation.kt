package com.shezguard.core

/**
 * One reason behind a [Decision].
 *
 * ShezGuard collects every violation it finds for an intent, not just the first.
 * A violation never contains raw intent data: no URI, parameter value or extra value.
 * The only attacker-influenced text it can hold is the name of an undeclared parameter
 * or extra, and [Field.toString] redacts that.
 *
 * @property code the stable reason code.
 * @property entryPoint the name of the entry point policy that was evaluated.
 * @property field which part of the intent the violation is about.
 * @property severity how serious it is; defaults to the code's default severity.
 */
public data class Violation(
    public val code: ViolationCode,
    public val entryPoint: String,
    public val field: Field,
    public val severity: Severity = code.defaultSeverity,
) {
    /** How this violation affects the decision. Fixed by [code]. */
    public val tier: Tier get() = code.tier
}

/**
 * The part of an intent a [Violation] refers to.
 *
 * `toString()` is safe to log: names that come from the policy are shown, names that
 * come only from the incoming intent are replaced with `<undeclared>`. The raw name
 * is still available through the property for debugging, so do not log it by default.
 */
public sealed class Field {

    /** A component of the data URI. */
    public data class UriPart(public val component: UriComponent) : Field() {
        override fun toString(): String = "uri.${component.name.lowercase()}"
    }

    /**
     * A query parameter.
     *
     * @property name the parameter name. Attacker-controlled when [declared] is false.
     * @property declared whether the policy declares this parameter.
     */
    public data class Param(public val name: String, public val declared: Boolean) : Field() {
        override fun toString(): String = if (declared) "param:$name" else "param:$UNDECLARED"
    }

    /**
     * An intent extra.
     *
     * @property key the extra key. Attacker-controlled when [declared] is false.
     * @property declared whether the policy declares this key.
     */
    public data class Extra(public val key: String, public val declared: Boolean) : Field() {
        override fun toString(): String = if (declared) "extra:$key" else "extra:$UNDECLARED"
    }

    /** The extras Bundle as a whole (e.g. unparcelling failure, too many keys). */
    public data object Extras : Field() {
        override fun toString(): String = "extras"
    }

    /** The caller identity or domain verification signals. */
    public data object CallerSignal : Field() {
        override fun toString(): String = "caller"
    }

    /** The entry point itself (e.g. no policy registered). */
    public data object EntryPoint : Field() {
        override fun toString(): String = "entryPoint"
    }

    private companion object {
        const val UNDECLARED = "<undeclared>"
    }
}

/** A component of a hierarchical URI. */
public enum class UriComponent {
    /** The URI as a whole (length, parsing, parser mismatch). */
    WHOLE,

    /** The scheme, e.g. `https`. */
    SCHEME,

    /** The userinfo part of the authority, e.g. `user:pass`. */
    USERINFO,

    /** The host. */
    HOST,

    /** The port. */
    PORT,

    /** The path. */
    PATH,

    /** The query string as a whole. Individual parameters use [Field.Param]. */
    QUERY,

    /** The fragment. */
    FRAGMENT,
}
