package com.shezguard.core.policy

/**
 * The complete set of entry point policies for an app (SPEC section 4).
 *
 * Lookup is by entry point name. A name with no policy returns `null`, and the evaluator
 * blocks such intents with `ENTRY_POINT_UNKNOWN` (deny by default).
 *
 * This class only checks that names are unique. Checks across fields, such as an
 * `https` entry point with no allowed hosts, belong to the policy DSL.
 *
 * @param entryPoints the entry point policies. Names must be unique.
 */
public class IntentPolicy(entryPoints: Collection<EntryPointPolicy>) {

    /** The entry point policies, keyed by name. */
    public val entryPoints: Map<String, EntryPointPolicy>

    init {
        val duplicates = entryPoints.groupBy { it.name }.filterValues { it.size > 1 }.keys
        require(duplicates.isEmpty()) { "duplicate entry point names: $duplicates" }
        this.entryPoints = entryPoints.associateBy { it.name }
    }

    /** Returns the policy for [name], or `null` if none is registered. */
    public operator fun get(name: String): EntryPointPolicy? = entryPoints[name]
}

/**
 * The policy for one named entry point (SPEC section 4).
 *
 * Every default is the most restrictive meaningful choice: no data URI accepted, no
 * extras, nested intents denied, unknown and repeated parameters blocked, no fragment,
 * only default ports.
 *
 * @property name the entry point name, matched against `@GuardedEntryPoint` and the
 * name passed to the evaluator. 1 to 64 characters from `A-Z a-z 0-9 _ . -`.
 * @property data whether the intent must, must not, or may carry a data URI. Defaults to
 * [Data.Forbidden] here; the policy DSL switches it to [Data.Required] when `allowSchemes`
 * is called, unless `data(...)` is set explicitly.
 * @property schemes allowed URI schemes, lowercase.
 * @property hosts allowed hosts. Matching is exact unless [HostPattern.SubdomainsOf] is used.
 * @property ports allowed non-default ports. Empty means only the scheme's default port.
 * @property paths allowed path patterns. Empty matches no path, so an entry point that
 * accepts URI data must declare at least one pattern, or [PathPattern.AnyPath] to accept
 * any canonical path explicitly. The DSL rejects a data-accepting policy without one.
 * @property allowFragment whether a URI fragment is accepted.
 * @property params declared query parameters. Names must be unique.
 * @property unknownParams what happens to undeclared query parameters.
 * @property allowRepeatedParams whether a parameter may appear more than once.
 * @property nestedIntents how Intents nested inside extras are handled.
 * @property extras which extras are allowed, with size limits.
 * @property caller the caller rule. Advisory unless a reliable identity source exists (SPEC section 8).
 * @property threshold the soft-signal score at which the intent is blocked.
 * @property limits length limits applied during canonicalisation.
 * @property scoreWeights per-code weight overrides for SOFT signals (SPEC 5.2). Defaults to none.
 */
public class EntryPointPolicy(
    public val name: String,
    public val data: Data = Data.Forbidden,
    public val schemes: Set<String> = emptySet(),
    public val hosts: Set<HostPattern> = emptySet(),
    public val ports: Set<Int> = emptySet(),
    public val paths: List<PathPattern> = emptyList(),
    public val allowFragment: Boolean = false,
    public val params: List<ParamRule> = emptyList(),
    public val unknownParams: Unknown = Unknown.Block,
    public val allowRepeatedParams: Boolean = false,
    public val nestedIntents: Nested = Nested.Deny,
    public val extras: ExtrasRule = ExtrasRule.NONE,
    public val caller: Caller = Caller.Any,
    public val threshold: Threshold = Threshold.DEFAULT,
    public val limits: Limits = Limits.DEFAULT,
    public val scoreWeights: ScoreWeights = ScoreWeights.DEFAULT,
) {
    init {
        require(ENTRY_POINT_NAME.matches(name)) { "invalid entry point name" }
        schemes.forEach { require(SCHEME.matches(it)) { "invalid or non-lowercase scheme: $it" } }
        ports.forEach { require(it in 1..65535) { "port out of range: $it" } }
        val dupParams = params.groupBy { it.name }.filterValues { it.size > 1 }.keys
        require(dupParams.isEmpty()) { "duplicate parameter rules: $dupParams" }
    }

    /** Returns the rule for parameter [name], or `null` if it is not declared. */
    public fun param(name: String): ParamRule? = params.firstOrNull { it.name == name }

    override fun toString(): String = "EntryPointPolicy($name)"
}

/**
 * Whether an entry point accepts a data URI.
 *
 * In the policy DSL, calling `allowSchemes(...)` switches the entry point to [Required]
 * unless `data(...)` was set explicitly, because allowing schemes only makes sense when
 * a URI is expected. Use `data(Data.Optional)` for entry points that accept both.
 */
public enum class Data {
    /** A data URI must be present; its absence is `DATA_MISSING`. */
    Required,

    /** A data URI must not be present; its presence is `DATA_FORBIDDEN`. */
    Forbidden,

    /** A data URI may be present. If present, it is checked in full. */
    Optional,
}

/** What happens to query parameters the policy does not declare. */
public enum class Unknown {
    /** Undeclared parameters block the intent (`PARAM_UNKNOWN`). The default. */
    Block,

    /** Undeclared parameters are removed, producing Sanitize (`PARAM_UNKNOWN_DROPPED`). */
    Drop,

    /** Undeclared parameters stay in the intent and add a soft signal (`PARAM_UNKNOWN_IGNORED`). */
    Ignore,
}

/**
 * The soft-signal score at which an intent is blocked (SPEC section 5.2).
 *
 * There is deliberately no sanitize threshold: Sanitize can only remove parts, and soft
 * signals (caller hints, domain verification) have nothing to remove. The outcome rule is:
 * any HARD violation gives Block; otherwise `score >= block` gives Block; otherwise any
 * REMOVABLE violation gives Sanitize; otherwise Allow, with soft signals listed.
 *
 * @property block the lowest soft-signal score that blocks. In `1..100`.
 */
public data class Threshold(public val block: Int) {
    init {
        require(block in 1..100) { "block threshold must be in 1..100" }
    }

    /** Defaults. */
    public companion object {
        /** `block = 70`, the value from the SPEC's API sketch. */
        public val DEFAULT: Threshold = Threshold(block = 70)
    }
}

/**
 * Length limits applied during canonicalisation (SPEC section 4.2).
 *
 * @property maxUriLength the maximum raw URI length, in characters.
 * @property maxParamLength the maximum decoded length of any parameter value. A [ParamRule]
 * may set a lower limit for its own value. Parameter names have a fixed limit of 64
 * characters, the same as [ParamRule.name], which this setting does not change.
 */
public data class Limits(
    public val maxUriLength: Int = DEFAULT_MAX_URI_LENGTH,
    public val maxParamLength: Int = DEFAULT_MAX_PARAM_LENGTH,
) {
    init {
        require(maxUriLength > 0) { "maxUriLength must be positive" }
        require(maxParamLength > 0) { "maxParamLength must be positive" }
    }

    /** Defaults. */
    public companion object {
        /** Default maximum raw URI length: 2048 characters. */
        public const val DEFAULT_MAX_URI_LENGTH: Int = 2048

        /** Default maximum decoded parameter length: 256 characters. */
        public const val DEFAULT_MAX_PARAM_LENGTH: Int = 256

        /** The default limits. */
        public val DEFAULT: Limits = Limits()
    }
}
