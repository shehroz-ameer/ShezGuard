package com.shezguard.core.policy

/**
 * A declared query parameter (SPEC section 4).
 *
 * @property name the decoded parameter name. 1 to 64 printable ASCII characters,
 * excluding `=`, `&`, `#`, `%` and whitespace.
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
        val PARAM_NAME = Regex("^[\\x21-\\x7E&&[^=&#%]]{1,64}$")
    }
}

/**
 * The type of a query parameter value. Checked after decoding.
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

    /** A UUID in canonical 8-4-4-4-12 hex form. */
    public data object Uuid : ParamType()

    /**
     * A string limited to a character class. The length limit comes from [ParamRule.maxLength].
     *
     * @property chars the allowed characters.
     */
    public data class BoundedString(public val chars: CharClass) : ParamType()

    /**
     * A URL whose scheme and host must be allow-listed (open-redirect and WebView defence).
     * The value is canonicalised with the same rules as the intent's own URI.
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

/** Character classes for [ParamType.BoundedString]. */
public enum class CharClass {
    /** `A-Z a-z 0-9`. */
    ALPHANUMERIC,

    /** `A-Z a-z 0-9 _ -`. No `.`, so `..` cannot be formed. */
    SLUG,

    /** Printable ASCII `0x20..0x7E`, including space. Accepts `'`, `<`, `/` and `.`. */
    PRINTABLE_ASCII,

    /**
     * Unicode letters, marks, digits, punctuation, symbols and spaces. Never control,
     * format (bidi, zero-width), private-use or unpaired surrogate characters.
     */
    TEXT,
}
