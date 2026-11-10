package com.shezguard.core.policy

/**
 * A declared query parameter (SPEC section 4).
 *
 * @property name the parameter name: 1 to 64 characters from `A-Z a-z 0-9 _ . -`, compared
 * case-sensitively. This is the only set of names the canonicaliser accepts in a URI, so a
 * declared name can always match. Not configurable in v1 (`docs/LIMITATIONS.md` L16).
 * @property type what a valid value looks like.
 * @property maxLength the maximum decoded value length. Must be positive.
 * @property required whether the parameter must be present.
 */
public data class ParamRule(
    public val name: String,
    public val type: ParamType,
    public val maxLength: Int = Limits.DEFAULT_MAX_PARAM_LENGTH,
    public val required: Boolean = false,
) {
    init {
        require(PARAM_NAME.matches(name)) { "invalid parameter name" }
        require(maxLength > 0) { "maxLength must be positive" }
    }

    private companion object {
        val PARAM_NAME = Regex("^[A-Za-z0-9_.-]{1,64}$")
    }
}

/**
 * The type of a query parameter value. Checked after decoding.
 *
 * Every type rejects an empty value (`?x=` or `?x`) with `PARAM_INVALID_FORMAT`
 * (`PARAM_URL_NOT_ALLOWED` for [Url]): a parameter that is present but empty has no valid
 * typed value. Optional parameters may still be absent.
 *
 * These types limit what reaches the app. They do not make a value safe for every sink:
 * a [BoundedString] with [CharClass.PRINTABLE_ASCII] still accepts `'` and `../`, so
 * queries and file paths must still be built safely.
 */
public sealed class ParamType {

    /** ASCII digits `0-9` only. */
    public data object Digits : ParamType()

    /**
     * One of a fixed set of values, compared case-sensitively.
     *
     * @property values the allowed values. Must not be empty or contain an empty string.
     */
    public data class OneOf(public val values: Set<String>) : ParamType() {
        init {
            require(values.isNotEmpty()) { "OneOf needs at least one value" }
            require(values.none { it.isEmpty() }) { "OneOf values must not be empty" }
        }
    }

    /**
     * A UUID in 8-4-4-4-12 hex form, e.g. `123e4567-e89b-12d3-a456-426614174000`. Upper- and
     * lowercase hex are both accepted, and the value is passed on unchanged (not lowercased).
     * Braces, missing hyphens and other lengths are rejected.
     */
    public data object Uuid : ParamType()

    /**
     * A non-empty string limited to a character class. The length limit comes from
     * [ParamRule.maxLength].
     *
     * @property chars the allowed characters. Defaults to [CharClass.SLUG], which is
     * ASCII-only and has no `.`, `/`, `\`, quotes, `<`, space or `%`. Choose a wider class
     * deliberately.
     */
    public data class BoundedString(public val chars: CharClass = CharClass.SLUG) : ParamType()

    /**
     * A URL whose scheme and host must be allow-listed (open-redirect and WebView defence).
     *
     * The decoded value is canonicalised with the same rules as the intent's own URI and
     * must have no hard finding. That rejects `javascript:`, `data:` and other opaque forms,
     * `https:host`, protocol-relative `//host`, relative paths and userinfo. Then the scheme
     * must be in [schemes], the host must match one of [hosts] (exactly, or as a subdomain
     * only through [HostPattern.SubdomainsOf]), and the URL must not name an explicit
     * non-default port. The URL cannot contain percent-escapes of its own
     * (`docs/LIMITATIONS.md` L17).
     *
     * @property schemes allowed lowercase schemes. Must not be empty.
     * @property hosts allowed hosts. Must not be empty.
     */
    public data class Url(public val schemes: Set<String>, public val hosts: Set<HostPattern>) : ParamType() {
        init {
            require(schemes.isNotEmpty()) { "Url needs at least one scheme" }
            require(hosts.isNotEmpty()) { "Url needs at least one host" }
        }
    }
}

/**
 * Character classes for [ParamType.BoundedString], checked on the decoded value.
 *
 * Only [TEXT] accepts non-ASCII characters, so it is the only class that admits Unicode
 * lookalikes of `/`, `.` and `\` (`docs/LIMITATIONS.md` L14). The default is [SLUG].
 */
public enum class CharClass {
    /**
     * ASCII letters and digits: `A-Z a-z 0-9`.
     *
     * Accepts `abc123`, `XYZ`. Rejects `a-b`, `a_b`, `a b`, `a.b`, and non-ASCII digits
     * such as `١` (U+0661).
     */
    ALPHANUMERIC,

    /**
     * ASCII letters, digits, `_` and `-`. The default class.
     *
     * Accepts `summer-sale_2026`, `ABC`. Rejects `.` (so `..` cannot be formed), `/`, `\`,
     * `'`, `"`, `<`, space and `%`, so it rejects `../etc`, `<script>`, `a' OR '1'='1` and
     * re-encoded text such as `%2e`. It also rejects every non-ASCII character, including
     * lookalikes such as `∕` (U+2215).
     */
    SLUG,

    /**
     * Printable ASCII `0x20..0x7E`, including space.
     *
     * Accepts `Hello, world!`, `it's`, and also `../x` and `<b>`: this class limits the
     * alphabet but does not make a value safe for a path, SQL or HTML sink. Rejects tabs,
     * other control characters and every non-ASCII character (`café`, U+2215).
     */
    PRINTABLE_ASCII,

    /**
     * Unicode text: letters, marks, numbers, punctuation, symbols and space separators
     * (general categories L, M, N, P, S and Zs).
     *
     * Accepts `café`, `日本`, `€5`, emoji, and also lookalikes such as `a∕b` (U+2215).
     * Rejects control characters, format characters (bidi, zero-width), line and paragraph
     * separators, private-use and unassigned code points, and unpaired surrogates. Use it
     * only for display text that never reaches a file system or another path-sensitive sink.
     */
    TEXT,
}
