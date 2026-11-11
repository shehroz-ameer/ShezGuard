package com.shezguard.core.policy

import com.shezguard.core.android.NestedIntentSanitizer

/**
 * Which extras an entry point accepts (SPEC section 4).
 *
 * Size limits are an approximation (key count, string and array lengths), not a
 * measured Parcel size. Extra keys used for nested intents under
 * [Nested.AllowSanitized] are governed by that rule, not by [allowed].
 *
 * @property allowed allowed extra keys and the type each must have.
 * @property maxKeys the maximum number of extras, counted before any value is read.
 * @property maxStringLength the maximum length of a String extra, or of each element of a String array.
 * @property maxArrayLength the maximum number of elements in an array extra.
 */
public data class ExtrasRule(
    public val allowed: Map<String, ExtraType> = emptyMap(),
    public val maxKeys: Int = DEFAULT_MAX_KEYS,
    public val maxStringLength: Int = DEFAULT_MAX_STRING_LENGTH,
    public val maxArrayLength: Int = DEFAULT_MAX_ARRAY_LENGTH,
) {
    init {
        require(allowed.keys.none { it.isEmpty() }) { "extra keys must not be empty" }
        require(maxKeys > 0) { "maxKeys must be positive" }
        require(maxStringLength > 0) { "maxStringLength must be positive" }
        require(maxArrayLength > 0) { "maxArrayLength must be positive" }
    }

    /** Defaults. */
    public companion object {
        /** Default maximum number of extras: 16. */
        public const val DEFAULT_MAX_KEYS: Int = 16

        /** Default maximum String length: 256, matching the parameter default. */
        public const val DEFAULT_MAX_STRING_LENGTH: Int = 256

        /** Default maximum array length: 64. */
        public const val DEFAULT_MAX_ARRAY_LENGTH: Int = 64

        /**
         * How many containers (Bundle, array, List, Map, SparseArray) may be nested inside one
         * extra before ShezGuard stops reading and reports `EXTRAS_TOO_DEEP`. Fixed in v1.
         * A top-level Bundle extra holding three more nested Bundles is at the limit.
         */
        public const val MAX_NESTING_DEPTH: Int = 4

        /** No extras allowed. The default for every entry point. */
        public val NONE: ExtrasRule = ExtrasRule()
    }
}

/**
 * Extra value types a policy can allow.
 *
 * `Parcelable`, `Serializable` and `Bundle` are deliberately absent: reading them runs
 * attacker-chosen deserialisation code (see `docs/LIMITATIONS.md`, L1). Nested
 * `Intent` extras are handled by [Nested].
 */
public enum class ExtraType {
    /** `String`. */
    STRING,

    /** `Boolean`. */
    BOOLEAN,

    /** `Int`. */
    INT,

    /** `Long`. */
    LONG,

    /** `Float`. */
    FLOAT,

    /** `Double`. */
    DOUBLE,

    /** `Array<String>`. */
    STRING_ARRAY,

    /** `IntArray`. */
    INT_ARRAY,

    /** `LongArray`. */
    LONG_ARRAY,
}

/** How Intents nested inside extras are handled (threat 1, intent redirection). */
public sealed class Nested {

    /** Any nested Intent blocks (`NESTED_INTENT_DENIED`). The default. */
    public data object Deny : Nested()

    /**
     * Nested Intents are allowed only under [keys], and only after `IntentSanitizer`
     * has reduced them. A nested Intent under any other key is denied.
     *
     * @property keys extra keys that may carry a nested Intent. Must not be empty.
     * @property sanitizer the wrapped `androidx.core.content.IntentSanitizer` to apply.
     */
    public class AllowSanitized(
        public val keys: Set<String>,
        public val sanitizer: NestedIntentSanitizer,
    ) : Nested() {
        init {
            require(keys.isNotEmpty()) { "AllowSanitized needs at least one key" }
            require(keys.none { it.isEmpty() }) { "nested intent keys must not be empty" }
        }

        override fun toString(): String = "Nested.AllowSanitized(keys=$keys)"
    }
}
