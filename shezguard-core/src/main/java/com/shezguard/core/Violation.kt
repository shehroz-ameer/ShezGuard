package com.shezguard.core

/**
 * One reason behind a [Decision].
 *
 * ShezGuard collects every violation it finds for an intent, not just the first.
 * A violation never exposes raw intent data: no URI, parameter value or extra value, and no
 * undeclared parameter or extra name through any public member (see [Field]).
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
 * come only from the incoming intent are replaced with `<undeclared>`.
 *
 * **No public member returns an undeclared name** (step 9 follow-up). For [Param] and [Extra] the
 * name is public only as [Param.declaredName] / [Extra.declaredName], which is non-null only when
 * the name comes from the policy. The raw name is kept internally for equality. It is also
 * `@JvmSynthetic`, because Kotlin `internal` members compile to public JVM methods. This keeps
 * attacker-chosen text (an extra key can be any string) out of app logs; it is not a security
 * boundary against code that uses reflection.
 */
public sealed class Field {

    /** A component of the data URI. */
    public data class UriPart(public val component: UriComponent) : Field() {
        override fun toString(): String = "uri.${component.name.lowercase()}"
    }

    /**
     * A query parameter.
     *
     * @property declared whether the policy declares this parameter.
     */
    public class Param internal constructor(
        @get:JvmSynthetic internal val name: String,
        public val declared: Boolean,
    ) : Field() {
        /** The parameter name if the policy declares it, otherwise `null` (the name is attacker-chosen). */
        public val declaredName: String? get() = if (declared) name else null

        override fun equals(other: Any?): Boolean = other is Param && other.name == name && other.declared == declared
        override fun hashCode(): Int = 31 * name.hashCode() + declared.hashCode()
        override fun toString(): String = if (declared) "param:$name" else "param:$UNDECLARED"
    }

    /**
     * An intent extra.
     *
     * @property declared whether the policy declares this key (as an allowed extra or a nested-intent key).
     */
    public class Extra internal constructor(
        @get:JvmSynthetic internal val key: String,
        public val declared: Boolean,
    ) : Field() {
        /** The extra key if the policy declares it, otherwise `null` (the key is attacker-chosen). */
        public val declaredName: String? get() = if (declared) key else null

        override fun equals(other: Any?): Boolean = other is Extra && other.key == key && other.declared == declared
        override fun hashCode(): Int = 31 * key.hashCode() + declared.hashCode() + 1
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
