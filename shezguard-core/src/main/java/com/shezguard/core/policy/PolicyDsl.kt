package com.shezguard.core.policy

/**
 * Marks the ShezGuard policy DSL builders.
 *
 * With this marker, Kotlin rejects at compile time any *implicit* call to an outer builder
 * from inside an inner block, so a rule cannot silently land in the wrong scope. For
 * example, each of these fails to compile:
 *
 * ```kotlin
 * entryPoint("a") { param("id") { allowHosts("x") } }     // allowHosts belongs to the entry point
 * entryPoint("a") { entryPoint("b") { } }                  // entry points do not nest
 * entryPoint("a") { path { anyPath() } }                   // anyPath() is an entry point call
 * ```
 *
 * An explicit receiver (`this@entryPoint.allowHosts(...)`) is still possible, and it is
 * deliberate when written.
 */
@DslMarker
@Target(AnnotationTarget.CLASS)
public annotation class ShezGuardDsl

/**
 * Thrown by [intentPolicy] when the policy definition is invalid.
 *
 * It is thrown when the policy is **built**, which is usually at app start, not when an
 * intent arrives. This is deliberate: a misconfigured policy is a developer error and
 * should stop the app in development, rather than fail open or block everything silently
 * in production. Build the policy in a unit test so that problems show up in CI first:
 *
 * ```kotlin
 * @Test fun policyIsValid() { AppPolicy.build() }   // throws PolicyDefinitionException if not
 * ```
 *
 * Every problem in every entry point is collected, not just the first. Each message names
 * where the problem is, what is wrong and how to fix it. Messages contain only names from
 * the policy itself, never intent data.
 *
 * @property problems one message per problem, e.g. `entryPoint("product"): accepts a data URI
 * but declares no path pattern. Add path { exact(...) / prefix(...) } or anyPath().`
 */
public class PolicyDefinitionException internal constructor(public val problems: List<String>) :
    IllegalArgumentException(
        "Invalid ShezGuard policy (${problems.size} problem${if (problems.size == 1) "" else "s"}):\n" +
            problems.joinToString("\n") { " - $it" },
    )

/**
 * Builds an [IntentPolicy] from the ShezGuard DSL (SPEC section 7).
 *
 * ```kotlin
 * val policy = intentPolicy {
 *     entryPoint("product") {
 *         allowSchemes("https")          // also switches data to Data.Required
 *         allowHosts("example.com")
 *         path { prefix("/product/") }   // or anyPath(); one of them is mandatory
 *         param("id") { digitsOnly(maxLength = 10); required() }
 *     }
 * }
 * ```
 *
 * Every option not set keeps its fail-closed default: no data URI, no hosts or paths,
 * unknown and repeated parameters blocked, no fragment, no extras, nested intents denied,
 * no caller restriction, block threshold 70, default limits.
 *
 * The policy is checked as a whole when this function returns. Setting a single-valued
 * option twice (`data`, `threshold`, `unknownParams`, `nestedIntents`, `limits`, `extras`,
 * the caller rule) is an error by design, not an override, so that the last call never
 * silently wins.
 *
 * @throws PolicyDefinitionException listing every problem, if the policy is invalid.
 */
public fun intentPolicy(block: IntentPolicyBuilder.() -> Unit): IntentPolicy =
    IntentPolicyBuilder().apply(block).build()

/** The top level of the DSL: a set of named entry points. */
@ShezGuardDsl
public class IntentPolicyBuilder internal constructor() {
    private val entryPoints = mutableListOf<EntryPointBuilder>()

    /**
     * Declares the policy for one entry point.
     *
     * @param name matched against `@GuardedEntryPoint` and the evaluator's argument.
     * 1 to 64 characters from `A-Z a-z 0-9 _ . -`, unique within the policy.
     */
    public fun entryPoint(name: String, block: EntryPointBuilder.() -> Unit) {
        entryPoints += EntryPointBuilder(name).apply(block)
    }

    internal fun build(): IntentPolicy {
        val problems = mutableListOf<String>()
        if (entryPoints.isEmpty()) problems += "intentPolicy: declares no entry points. Add entryPoint(\"name\") { ... }."
        entryPoints.groupBy { it.name }.filterValues { it.size > 1 }.keys.forEach {
            problems += "entryPoint(\"$it\"): declared more than once. Entry point names must be unique."
        }
        val built = entryPoints.mapNotNull { it.build(problems) }
        if (problems.isNotEmpty()) throw PolicyDefinitionException(problems.toList())
        return IntentPolicy(built)
    }
}

/** The rules for one entry point. Every call adds to, or sets, one part of [EntryPointPolicy]. */
@ShezGuardDsl
public class EntryPointBuilder internal constructor(internal val name: String) {
    private val where = "entryPoint(\"$name\")"
    private val setTwice = LinkedHashSet<String>()

    private var data: Data? = null
    private val schemes = mutableListOf<String>()
    private val hosts = mutableListOf<Pending<HostPattern>>()
    private val ports = mutableListOf<Int>()
    private var pathCalled = false
    private val paths = mutableListOf<Pending<PathPattern>>()
    private var anyPath = false
    private var fragment = false
    private val params = mutableListOf<ParamBuilder>()
    private var unknown: Unknown? = null
    private var repeated = false
    private var nested: Nested? = null
    private var extras: ExtrasBuilder? = null
    private val callerCalls = mutableListOf<Pair<String, () -> Caller?>>()
    private var threshold: Int? = null
    private var limits: Pair<Int, Int>? = null

    private fun <T : Any> once(label: String, current: T?, value: T): T {
        if (current != null) setTwice += label
        return current ?: value
    }

    /**
     * Sets whether a data URI is required, forbidden or optional. Without this call the
     * rule is [Data.Forbidden], or [Data.Required] once [allowSchemes] is called. An
     * explicit call wins over that switch, in either order.
     */
    public fun data(rule: Data) {
        data = once("data(...)", data, rule)
    }

    /** Allows these lowercase schemes, e.g. `"https"`, `"myapp"`. Switches data to Required (see [data]). */
    public fun allowSchemes(vararg schemes: String) {
        this.schemes += schemes
    }

    /** Allows these hosts exactly (lowercase ASCII, no trailing dot). No subdomains. */
    public fun allowHosts(vararg hosts: String) {
        hosts.forEach { h -> this.hosts += Pending("allowHosts(\"$h\")") { HostPattern.Exact(h) } }
    }

    /**
     * Allows every host strictly below [domain], e.g. `shop.example.com` for `"example.com"`.
     * Not [domain] itself. Public suffixes cannot be detected (`docs/LIMITATIONS.md` L5).
     */
    public fun subdomainsOf(domain: String) {
        hosts += Pending("subdomainsOf(\"$domain\")") { HostPattern.SubdomainsOf(domain) }
    }

    /** Allows these explicit non-default ports (`1..65535`). Default ports are always allowed. */
    public fun allowPorts(vararg ports: Int) {
        this.ports += ports.toList()
    }

    /** Declares exact and prefix path patterns. Use either this or [anyPath], not both. */
    public fun path(block: PathBuilder.() -> Unit) {
        pathCalled = true
        paths += PathBuilder().apply(block).patterns
    }

    /** Accepts any canonical path, explicitly. Use either this or [path], not both. */
    public fun anyPath() {
        anyPath = true
    }

    /** Accepts a URI fragment (`#...`). Rejected by default. */
    public fun allowFragment() {
        fragment = true
    }

    /**
     * Declares a query parameter and its type.
     *
     * @param name 1 to 64 characters from `A-Z a-z 0-9 _ . -` (`docs/LIMITATIONS.md` L16).
     */
    public fun param(name: String, block: ParamBuilder.() -> Unit) {
        params += ParamBuilder(name).apply(block)
    }

    /** Sets what happens to undeclared parameters: [Unknown.Block] (default), Drop or Ignore. */
    public fun unknownParams(mode: Unknown) {
        unknown = once("unknownParams(...)", unknown, mode)
    }

    /** Allows a parameter to appear more than once. Blocked by default (parameter pollution). */
    public fun allowRepeatedParams() {
        repeated = true
    }

    /** Sets the nested-intent rule: [Nested.Deny] (default) or [Nested.AllowSanitized]. */
    public fun nestedIntents(rule: Nested) {
        nested = once("nestedIntents(...)", nested, rule)
    }

    /** Declares the allowed extras and their size limits. No extras are allowed by default. */
    public fun extras(block: ExtrasBuilder.() -> Unit) {
        extras = once("extras { }", extras, ExtrasBuilder().apply(block))
    }

    /** Sets the caller rule directly. Use only one of this, [requireVerifiedDomain] and [allowedPackages]. */
    public fun caller(rule: Caller) {
        callerCalls += "caller(...)" to { rule }
    }

    /** Shorthand for `caller(Caller.RequireVerifiedDomain)`: an advisory signal (SPEC section 8). */
    public fun requireVerifiedDomain() {
        callerCalls += "requireVerifiedDomain()" to { Caller.RequireVerifiedDomain }
    }

    /**
     * Shorthand for `caller(Caller.AllowedPackages(...))`. Each package needs at least one
     * SHA-256 certificate digest. Soft unless the identity source is reliable (SPEC section 8).
     */
    public fun allowedPackages(block: AllowedPackagesBuilder.() -> Unit) {
        val b = AllowedPackagesBuilder().apply(block)
        callerCalls += "allowedPackages { }" to { null }
        allowedPackagesBuilder = b
    }

    private var allowedPackagesBuilder: AllowedPackagesBuilder? = null

    /** Sets the soft-signal score at which the intent is blocked, in `1..100` (default 70). */
    public fun threshold(block: Int) {
        threshold = once("threshold(...)", threshold, block)
    }

    /**
     * Overrides the length limits for this entry point. A parameter without its own
     * `maxLength` uses [maxParamLength]; an explicit `maxLength` may not exceed it.
     */
    public fun limits(
        maxUriLength: Int = Limits.DEFAULT_MAX_URI_LENGTH,
        maxParamLength: Int = Limits.DEFAULT_MAX_PARAM_LENGTH,
    ) {
        limits = once("limits(...)", limits, maxUriLength to maxParamLength)
    }

    internal fun build(problems: MutableList<String>): EntryPointPolicy? {
        val before = problems.size
        fun problem(msg: String) {
            problems += "$where: $msg"
        }
        fun <T> attempt(p: Pending<T>): T? = try {
            p.make()
        } catch (e: IllegalArgumentException) {
            problem("${p.call}: ${e.message}.")
            null
        }

        if (!ENTRY_POINT_NAME.matches(name)) problem("invalid name. Use 1 to 64 characters from A-Z a-z 0-9 _ . -.")
        setTwice.forEach { problem("$it is set more than once. Set it once; a second call is an error, not an override.") }

        // Limits and threshold.
        val (maxUri, maxParam) = limits ?: (Limits.DEFAULT_MAX_URI_LENGTH to Limits.DEFAULT_MAX_PARAM_LENGTH)
        val builtLimits = attempt(Pending("limits(maxUriLength = $maxUri, maxParamLength = $maxParam)") { Limits(maxUri, maxParam) })
        val effectiveMaxParam = builtLimits?.maxParamLength ?: Limits.DEFAULT_MAX_PARAM_LENGTH
        val builtThreshold = threshold?.let {
            if (it in 1..100) Threshold(it) else null.also { _ -> problem("threshold(block = $it): the block threshold must be in 1..100.") }
        }

        // URI rules.
        schemes.filterNot { SCHEME.matches(it) }.forEach {
            problem("allowSchemes(\"$it\"): invalid scheme. Use a lowercase scheme such as \"https\" or \"myapp\".")
        }
        val builtHosts = hosts.mapNotNull { attempt(it) }
        ports.filterNot { it in 1..65535 }.forEach { problem("allowPorts($it): port out of range 1..65535.") }
        val builtPaths = paths.mapNotNull { attempt(it) }

        val effectiveData = data ?: if (schemes.isNotEmpty()) Data.Required else Data.Forbidden
        if (effectiveData == Data.Forbidden) {
            val declared = buildList {
                if (schemes.isNotEmpty()) add("allowSchemes(...)")
                if (hosts.any { it.call.startsWith("allowHosts") }) add("allowHosts(...)")
                if (hosts.any { it.call.startsWith("subdomainsOf") }) add("subdomainsOf(...)")
                if (ports.isNotEmpty()) add("allowPorts(...)")
                if (pathCalled) add("path { }")
                if (anyPath) add("anyPath()")
                if (fragment) add("allowFragment()")
                if (params.isNotEmpty()) add("param(...)")
                if (unknown != null) add("unknownParams(...)")
                if (repeated) add("allowRepeatedParams()")
            }
            if (declared.isNotEmpty()) {
                val why = if (data == Data.Forbidden) "set by data(Data.Forbidden)" else "the default, because allowSchemes(...) is not called"
                problem(
                    "declares URI rules (${declared.joinToString()}) but data is Forbidden ($why), so they " +
                        "could never apply. Add allowSchemes(...) or data(...).",
                )
            }
        } else {
            if (schemes.isEmpty()) problem("accepts a data URI (data is $effectiveData) but allows no scheme. Add allowSchemes(...).")
            if (hosts.isEmpty()) problem("accepts a data URI but allows no host. Add allowHosts(...) or subdomainsOf(...).")
            if (!anyPath && paths.isEmpty()) {
                problem("accepts a data URI but declares no path pattern. Add path { exact(...) / prefix(...) } or anyPath().")
            }
        }
        if (anyPath && paths.isNotEmpty()) {
            problem("anyPath() is combined with path { } patterns, which would then have no effect. Use either anyPath() or path { ... }.")
        }

        // Parameters.
        params.groupBy { it.name }.filterValues { it.size > 1 }.keys.forEach {
            problem("param(\"$it\") is declared more than once. Declare each parameter once.")
        }
        val builtParams = params.mapNotNull { it.build(where, effectiveMaxParam, problems) }

        // Extras and nested intents.
        val builtExtras = extras?.build(where, problems)
        val nestedRule = nested
        if (nestedRule is Nested.AllowSanitized && builtExtras != null) {
            nestedRule.keys.intersect(builtExtras.allowed.keys).forEach {
                problem(
                    "extra \"$it\" is listed in both extras { allow(...) } and nestedIntents(Nested.AllowSanitized(...)). " +
                        "Nested-intent keys belong only to the nested rule; remove it from extras.",
                )
            }
        }

        // Caller.
        if (callerCalls.size > 1) {
            problem(
                "the caller rule is set more than once (${callerCalls.joinToString { it.first }}). " +
                    "Choose one of caller(...), requireVerifiedDomain() or allowedPackages { }.",
            )
        }
        val builtCaller = when {
            callerCalls.isEmpty() -> Caller.Any
            else -> callerCalls.first().second() ?: allowedPackagesBuilder?.build(where, problems)
        }

        if (problems.size > before) return null
        return attempt(
            Pending("entryPoint") {
                EntryPointPolicy(
                    name = name,
                    data = effectiveData,
                    schemes = schemes.toSet(),
                    hosts = builtHosts.toSet(),
                    ports = ports.toSet(),
                    paths = if (anyPath) listOf(PathPattern.AnyPath) else builtPaths,
                    allowFragment = fragment,
                    params = builtParams,
                    unknownParams = unknown ?: Unknown.Block,
                    allowRepeatedParams = repeated,
                    nestedIntents = nested ?: Nested.Deny,
                    extras = builtExtras ?: ExtrasRule.NONE,
                    caller = builtCaller ?: Caller.Any,
                    threshold = builtThreshold ?: Threshold.DEFAULT,
                    limits = builtLimits ?: Limits.DEFAULT,
                )
            },
        )
    }
}

/** A model object whose constructor may reject its input, with the DSL call that made it. */
internal class Pending<T>(val call: String, val make: () -> T)

/** Exact and prefix path patterns. Matched against the decoded, canonical path. */
@ShezGuardDsl
public class PathBuilder internal constructor() {
    internal val patterns = mutableListOf<Pending<PathPattern>>()

    /** Matches exactly this path, e.g. `"/settings"`. */
    public fun exact(path: String) {
        patterns += Pending("path { exact(\"$path\") }") { PathPattern.Exact(path) }
    }

    /** Matches paths starting with [prefix], which must end with `/`, e.g. `"/product/"`. */
    public fun prefix(prefix: String) {
        patterns += Pending("path { prefix(\"$prefix\") }") { PathPattern.Prefix(prefix) }
    }
}

/**
 * The type of one query parameter. Call exactly one type function, plus [required] if the
 * parameter must be present. Every `maxLength` left `null` becomes the entry point's
 * `maxParamLength`; an explicit one may not exceed it.
 */
@ShezGuardDsl
public class ParamBuilder internal constructor(internal val name: String) {
    private val types = mutableListOf<TypeSpec>()
    private var required = false

    /** ASCII digits only ([ParamType.Digits]). */
    public fun digitsOnly(maxLength: Int? = null) {
        types += TypeSpec("digitsOnly()", maxLength) { _, _ -> ParamType.Digits }
    }

    /** One of these exact, case-sensitive values ([ParamType.OneOf]). */
    public fun oneOf(vararg values: String, maxLength: Int? = null) {
        val list = values.toList()
        types += TypeSpec("oneOf(...)", maxLength) { max, problem ->
            when {
                list.isEmpty() -> null.also { problem("oneOf(): no values. List at least one allowed value.") }
                list.any { it.isEmpty() } -> null.also {
                    problem("oneOf(...): contains an empty value, which can never match (empty values are rejected). Remove it.")
                }
                else -> {
                    val tooLong = list.filter { it.length > max }
                    tooLong.forEach {
                        problem("oneOf(...): value \"$it\" is longer than maxLength $max and can never match. Raise maxLength or remove it.")
                    }
                    if (tooLong.isEmpty()) ParamType.OneOf(list.toSet()) else null
                }
            }
        }
    }

    /** A UUID in 8-4-4-4-12 hex form, either case ([ParamType.Uuid]). */
    public fun uuid() {
        types += TypeSpec("uuid()", null) { _, _ -> ParamType.Uuid }
    }

    /**
     * A non-empty string from [chars] ([ParamType.BoundedString]). Defaults to
     * [CharClass.SLUG]; widen it deliberately.
     */
    public fun string(chars: CharClass = CharClass.SLUG, maxLength: Int? = null) {
        types += TypeSpec("string(...)", maxLength) { _, _ -> ParamType.BoundedString(chars) }
    }

    /** A URL with an allowed scheme and host ([ParamType.Url]), declared in [block]. */
    public fun url(maxLength: Int? = null, block: UrlBuilder.() -> Unit) {
        val b = UrlBuilder().apply(block)
        types += TypeSpec("url { }", maxLength) { _, problem -> b.build(problem) }
    }

    /** The parameter must be present (`PARAM_MISSING` otherwise). */
    public fun required() {
        required = true
    }

    internal fun build(entryPoint: String, maxParamLength: Int, problems: MutableList<String>): ParamRule? {
        val before = problems.size
        val problem = { msg: String -> problems += "$entryPoint: param(\"$name\"): $msg" }
        if (!PARAM_NAME.matches(name)) {
            problem("invalid name. Names must be 1 to 64 characters from A-Z a-z 0-9 _ . - (docs/LIMITATIONS.md L16).")
        }
        when (types.size) {
            0 -> problem("declares no type. Add one of digitsOnly(), oneOf(...), uuid(), string(...) or url { }.")
            1 -> Unit
            else -> problem("declares ${types.size} types (${types.joinToString { it.label }}); keep one.")
        }
        val spec = types.firstOrNull() ?: return null
        val explicit = spec.maxLength
        if (explicit != null && explicit <= 0) {
            problem("maxLength must be positive.")
        } else if (explicit != null && explicit > maxParamLength) {
            problem(
                "maxLength $explicit exceeds maxParamLength $maxParamLength, which the canonicaliser enforces first. " +
                    "Lower maxLength or raise limits(maxParamLength = ...).",
            )
        }
        val maxLength = explicit ?: maxParamLength
        val type = spec.make(maxLength, problem)
        if (problems.size > before || type == null) return null
        return ParamRule(name, type, maxLength, required)
    }

    private class TypeSpec(
        val label: String,
        val maxLength: Int?,
        val make: (maxLength: Int, problem: (String) -> Unit) -> ParamType?,
    )
}

/** The allowed schemes and hosts of a URL-typed parameter. Same rules as the entry point's. */
@ShezGuardDsl
public class UrlBuilder internal constructor() {
    private val schemes = mutableListOf<String>()
    private val hosts = mutableListOf<Pending<HostPattern>>()

    /** Allows these lowercase schemes, e.g. `"https"`. */
    public fun allowSchemes(vararg schemes: String) {
        this.schemes += schemes
    }

    /** Allows these hosts exactly. */
    public fun allowHosts(vararg hosts: String) {
        hosts.forEach { h -> this.hosts += Pending("allowHosts(\"$h\")") { HostPattern.Exact(h) } }
    }

    /** Allows every host strictly below [domain]. */
    public fun subdomainsOf(domain: String) {
        hosts += Pending("subdomainsOf(\"$domain\")") { HostPattern.SubdomainsOf(domain) }
    }

    internal fun build(problem: (String) -> Unit): ParamType.Url? {
        var ok = true
        if (schemes.isEmpty()) { problem("url { } allows no scheme. Add allowSchemes(...) inside url { }."); ok = false }
        if (hosts.isEmpty()) { problem("url { } allows no host. Add allowHosts(...) or subdomainsOf(...) inside url { }."); ok = false }
        schemes.filterNot { SCHEME.matches(it) }.forEach {
            problem("url { allowSchemes(\"$it\") }: invalid scheme. Use a lowercase scheme such as \"https\".")
            ok = false
        }
        val built = hosts.mapNotNull {
            try {
                it.make()
            } catch (e: IllegalArgumentException) {
                problem("url { ${it.call} }: ${e.message}.")
                ok = false
                null
            }
        }
        return if (ok) ParamType.Url(schemes.toSet(), built.toSet()) else null
    }
}

/** Allowed extras and their size limits ([ExtrasRule]). */
@ShezGuardDsl
public class ExtrasBuilder internal constructor() {
    private val allowed = mutableListOf<Pair<String, ExtraType>>()
    private val setTwice = LinkedHashSet<String>()
    private var maxKeys: Int? = null
    private var maxStringLength: Int? = null
    private var maxArrayLength: Int? = null

    /** Allows the extra [key] with exactly this [type]. */
    public fun allow(key: String, type: ExtraType) {
        allowed += key to type
    }

    /** The maximum number of extras (default 16). */
    public fun maxKeys(n: Int) {
        if (maxKeys != null) setTwice += "maxKeys(...)"
        maxKeys = n
    }

    /** The maximum length of a String extra or String array element (default 256). */
    public fun maxStringLength(n: Int) {
        if (maxStringLength != null) setTwice += "maxStringLength(...)"
        maxStringLength = n
    }

    /** The maximum number of elements in an array extra (default 64). */
    public fun maxArrayLength(n: Int) {
        if (maxArrayLength != null) setTwice += "maxArrayLength(...)"
        maxArrayLength = n
    }

    internal fun build(entryPoint: String, problems: MutableList<String>): ExtrasRule? {
        val before = problems.size
        val at = "$entryPoint: extras { }"
        setTwice.forEach { problems += "$at: $it is set more than once. Set it once; a second call is an error, not an override." }
        allowed.groupBy { it.first }.filterValues { it.size > 1 }.keys.forEach {
            problems += "$at: extra \"$it\" is allowed more than once. Allow each key once, with one type."
        }
        val rule = try {
            ExtrasRule(
                allowed = allowed.toMap(),
                maxKeys = maxKeys ?: ExtrasRule.DEFAULT_MAX_KEYS,
                maxStringLength = maxStringLength ?: ExtrasRule.DEFAULT_MAX_STRING_LENGTH,
                maxArrayLength = maxArrayLength ?: ExtrasRule.DEFAULT_MAX_ARRAY_LENGTH,
            )
        } catch (e: IllegalArgumentException) {
            problems += "$at: ${e.message}."
            null
        }
        return if (problems.size > before) null else rule
    }
}

/**
 * Packages allowed to call, each with the SHA-256 digests of its accepted signing
 * certificates ([Caller.AllowedPackages]).
 */
@ShezGuardDsl
public class AllowedPackagesBuilder internal constructor() {
    private val packages = mutableListOf<Pair<String, List<String>>>()

    /**
     * Allows package [name] when signed with one of [sha256Digests].
     *
     * A digest may be written as 64 hex characters in either case, or as 32 colon-separated
     * pairs as printed by `keytool -list -v` or Android Studio (`AB:CD:...`). It is
     * normalised to 64 lowercase hex characters. Anything else, such as a SHA-1
     * fingerprint, is rejected.
     */
    public fun pkg(name: String, vararg sha256Digests: String) {
        packages += name to sha256Digests.toList()
    }

    internal fun build(entryPoint: String, problems: MutableList<String>): Caller? {
        val before = problems.size
        val at = "$entryPoint: allowedPackages { }"
        if (packages.isEmpty()) {
            problems += "$at lists no package. Add pkg(\"com.example.app\", \"<SHA-256 certificate digest>\")."
            return null
        }
        packages.groupBy { it.first }.filterValues { it.size > 1 }.keys.forEach {
            problems += "$at: package \"$it\" is listed more than once. List each package once, with all its digests."
        }
        val map = LinkedHashMap<String, Set<CertificateDigest>>()
        for ((pkg, digests) in packages) {
            if (!PACKAGE_NAME.matches(pkg)) {
                problems += "$at: \"$pkg\" is not a valid package name. Use a name such as com.example.app."
            }
            if (digests.isEmpty()) {
                problems += "$at: package \"$pkg\" has no certificate digest. Add at least one: " +
                    "pkg(\"$pkg\", \"<SHA-256 certificate digest>\")."
            }
            val normalised = digests.mapNotNull { d ->
                normaliseDigest(d).also {
                    if (it == null) {
                        problems += "$at: certificate digest for \"$pkg\" is not a SHA-256 fingerprint. Use 64 hex " +
                            "characters, optionally as 32 colon-separated pairs as printed by keytool or Android Studio " +
                            "(AB:CD:...)."
                    }
                }
            }
            map[pkg] = normalised.map { CertificateDigest(it) }.toSet()
        }
        return if (problems.size > before) null else Caller.AllowedPackages(map)
    }

    private fun normaliseDigest(d: String): String? = when {
        HEX_64.matches(d) -> d.lowercase()
        COLON_PAIRS.matches(d) -> d.replace(":", "").lowercase()
        else -> null
    }

    private companion object {
        val HEX_64 = Regex("^[0-9A-Fa-f]{64}$")
        val COLON_PAIRS = Regex("^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){31}$")
    }
}
