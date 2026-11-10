package com.shezguard.core.validate

import com.shezguard.core.Field
import com.shezguard.core.UriComponent
import com.shezguard.core.Violation
import com.shezguard.core.ViolationCode
import com.shezguard.core.ViolationCode.FRAGMENT_NOT_ALLOWED
import com.shezguard.core.ViolationCode.HOST_NOT_ALLOWED
import com.shezguard.core.ViolationCode.PARAM_INVALID_FORMAT
import com.shezguard.core.ViolationCode.PARAM_MISSING
import com.shezguard.core.ViolationCode.PARAM_REPEATED
import com.shezguard.core.ViolationCode.PARAM_TOO_LONG
import com.shezguard.core.ViolationCode.PARAM_UNKNOWN
import com.shezguard.core.ViolationCode.PARAM_UNKNOWN_DROPPED
import com.shezguard.core.ViolationCode.PARAM_UNKNOWN_IGNORED
import com.shezguard.core.ViolationCode.PARAM_URL_NOT_ALLOWED
import com.shezguard.core.ViolationCode.PATH_NOT_ALLOWED
import com.shezguard.core.ViolationCode.PORT_NOT_ALLOWED
import com.shezguard.core.ViolationCode.SCHEME_NOT_ALLOWED
import com.shezguard.core.canon.CanonResult
import com.shezguard.core.canon.CanonicalUri
import com.shezguard.core.canon.UriCanonicalizer
import com.shezguard.core.policy.CharClass
import com.shezguard.core.policy.EntryPointPolicy
import com.shezguard.core.policy.HostPattern
import com.shezguard.core.policy.Limits
import com.shezguard.core.policy.ParamRule
import com.shezguard.core.policy.ParamType
import com.shezguard.core.policy.PathPattern
import com.shezguard.core.policy.Unknown

/**
 * The result of checking a canonical URI against an entry point policy.
 *
 * @property violations every violation found, in a stable order, without duplicates.
 * @property retainedQuery the query with parameters removed under `Unknown.Drop`. Order and
 * duplicates of the remaining parameters are kept. This is what a Sanitize decision exposes.
 */
internal data class UriValidation(
    val violations: List<Violation>,
    val retainedQuery: List<Pair<String, String>>,
)

/**
 * SPEC section 5, steps 2 and 3 for the data URI: scheme, host, port, path and fragment
 * allow-lists, then query parameters. Pure Kotlin, no Android types.
 *
 * Runs only on a URI that canonicalised without hard findings. Whether the intent carries a
 * URI at all (the `Data` rule) is the evaluator's job (step 4b).
 */
internal object UriPolicyValidator {

    private val UUID = Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

    fun validate(uri: CanonicalUri, policy: EntryPointPolicy): UriValidation {
        val out = LinkedHashSet<Violation>()
        fun add(code: ViolationCode, field: Field) {
            out.add(Violation(code, policy.name, field))
        }

        if (uri.scheme !in policy.schemes) add(SCHEME_NOT_ALLOWED, Field.UriPart(UriComponent.SCHEME))
        if (policy.hosts.none { it.matches(uri.host) }) add(HOST_NOT_ALLOWED, Field.UriPart(UriComponent.HOST))
        if (uri.port != null && uri.port !in policy.ports) add(PORT_NOT_ALLOWED, Field.UriPart(UriComponent.PORT))
        if (policy.paths.none { it.matches(uri.path) }) add(PATH_NOT_ALLOWED, Field.UriPart(UriComponent.PATH))
        if (uri.fragment != null && !policy.allowFragment) add(FRAGMENT_NOT_ALLOWED, Field.UriPart(UriComponent.FRAGMENT))

        val retained = checkParams(uri.query, policy, ::add)
        return UriValidation(out.toList(), retained)
    }

    private fun checkParams(
        query: List<Pair<String, String>>,
        policy: EntryPointPolicy,
        add: (ViolationCode, Field) -> Unit,
    ): List<Pair<String, String>> {
        val byName: Map<String, List<String>> = query.groupBy({ it.first }, { it.second })

        for (rule in policy.params) {
            if (rule.required && rule.name !in byName) add(PARAM_MISSING, Field.Param(rule.name, declared = true))
        }

        val dropped = HashSet<String>()
        for ((name, values) in byName) {
            val rule = policy.param(name)
            val field = Field.Param(name, declared = rule != null)
            if (rule == null) {
                when (policy.unknownParams) {
                    Unknown.Block -> add(PARAM_UNKNOWN, field)
                    Unknown.Ignore -> add(PARAM_UNKNOWN_IGNORED, field)
                    Unknown.Drop -> {
                        // Removed entirely, so nothing else about it matters.
                        add(PARAM_UNKNOWN_DROPPED, field)
                        dropped.add(name)
                        continue
                    }
                }
            }
            if (values.size > 1 && !policy.allowRepeatedParams) add(PARAM_REPEATED, field)
            if (rule != null) values.forEach { checkValue(it, rule, policy.limits, field, add) }
        }
        return query.filter { it.first !in dropped }
    }

    /** Every type rejects an empty value: a present but empty parameter has no valid typed value. */
    private fun checkValue(value: String, rule: ParamRule, limits: Limits, field: Field, add: (ViolationCode, Field) -> Unit) {
        if (value.length > rule.maxLength) add(PARAM_TOO_LONG, field)
        val ok = when (val type = rule.type) {
            ParamType.Digits -> value.isNotEmpty() && value.all { it in '0'..'9' }
            is ParamType.OneOf -> value in type.values
            ParamType.Uuid -> UUID.matches(value)
            is ParamType.BoundedString -> value.isNotEmpty() && type.chars.accepts(value)
            is ParamType.Url -> {
                if (!urlAllowed(value, type, limits)) add(PARAM_URL_NOT_ALLOWED, field)
                true
            }
        }
        if (!ok) add(PARAM_INVALID_FORMAT, field)
    }

    /**
     * The value is canonicalised with the same rules as the intent's URI. It must have no hard
     * finding (so no opaque `javascript:`/`data:`/`https:host` forms, no `//host`, no userinfo),
     * an allowed scheme, a matching host, and no explicit non-default port.
     */
    private fun urlAllowed(value: String, type: ParamType.Url, limits: Limits): Boolean {
        val r = UriCanonicalizer.canonicalize(value, limits)
        if (r !is CanonResult.Ok) return false
        val u = r.uri
        return u.scheme in type.schemes && type.hosts.any { it.matches(u.host) } && u.port == null
    }
}

/** Exact match, or a strict subdomain at a label boundary for [HostPattern.SubdomainsOf]. */
internal fun HostPattern.matches(host: String): Boolean = when (this) {
    is HostPattern.Exact -> host == this.host
    is HostPattern.SubdomainsOf -> host.length > domain.length + 1 && host.endsWith(".$domain")
}

/** Matches a canonical path as built by [CanonicalUri.path]. */
internal fun PathPattern.matches(path: String): Boolean = when (this) {
    PathPattern.AnyPath -> true
    is PathPattern.Exact -> path == this.path
    is PathPattern.Prefix -> path.startsWith(prefix)
}

/** Whether every character of [value] belongs to this class. The empty string always does. */
internal fun CharClass.accepts(value: String): Boolean = when (this) {
    CharClass.ALPHANUMERIC -> value.all { it.isAsciiAlnum() }
    CharClass.SLUG -> value.all { it.isAsciiAlnum() || it == '_' || it == '-' }
    CharClass.PRINTABLE_ASCII -> value.all { it.code in 0x20..0x7E }
    CharClass.TEXT -> {
        var i = 0
        var ok = true
        while (ok && i < value.length) {
            val cp = value.codePointAt(i) // a lone surrogate comes back as itself: category Cs
            ok = Character.getType(cp) in TEXT_CATEGORIES
            i += Character.charCount(cp)
        }
        ok
    }
}

private fun Char.isAsciiAlnum(): Boolean = this in 'a'..'z' || this in 'A'..'Z' || this in '0'..'9'

/** Letters, marks, numbers, punctuation, symbols and space separators (L, M, N, P, S, Zs). */
private val TEXT_CATEGORIES: Set<Int> = setOf(
    Character.UPPERCASE_LETTER, Character.LOWERCASE_LETTER, Character.TITLECASE_LETTER,
    Character.MODIFIER_LETTER, Character.OTHER_LETTER,
    Character.NON_SPACING_MARK, Character.ENCLOSING_MARK, Character.COMBINING_SPACING_MARK,
    Character.DECIMAL_DIGIT_NUMBER, Character.LETTER_NUMBER, Character.OTHER_NUMBER,
    Character.CONNECTOR_PUNCTUATION, Character.DASH_PUNCTUATION, Character.START_PUNCTUATION,
    Character.END_PUNCTUATION, Character.INITIAL_QUOTE_PUNCTUATION, Character.FINAL_QUOTE_PUNCTUATION,
    Character.OTHER_PUNCTUATION,
    Character.MATH_SYMBOL, Character.CURRENCY_SYMBOL, Character.MODIFIER_SYMBOL, Character.OTHER_SYMBOL,
    Character.SPACE_SEPARATOR,
).map { it.toInt() }.toSet()
