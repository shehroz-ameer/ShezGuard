package com.shezguard.core

/**
 * Stable identifiers for every reason ShezGuard can give for a decision.
 *
 * The [id] string is part of the public contract: tests assert on it, the attack matrix
 * and the paper cite it, and it must never change once released. It is spelled out
 * explicitly, not derived from the enum name, so renaming or obfuscating the Kotlin
 * entry cannot change it.
 *
 * Each code has a fixed [tier]. Where the same situation can be hard, removable or soft
 * depending on the policy (for example unknown query parameters), there is one code per
 * tier, so a code alone tells the reader what effect it had.
 *
 * @property id the stable string identifier.
 * @property tier how this violation affects the decision.
 * @property defaultSeverity the severity reported unless a policy overrides it.
 */
public enum class ViolationCode(
    public val id: String,
    public val tier: Tier,
    public val defaultSeverity: Severity,
) {
    // ---- Entry point -------------------------------------------------------------

    /** No policy is registered under the requested entry point name (deny by default). */
    ENTRY_POINT_UNKNOWN("ENTRY_POINT_UNKNOWN", Tier.HARD, Severity.CRITICAL),

    /**
     * Evaluation could not be completed because a `RuntimeException` was thrown, for
     * example by an `android.net.Uri` accessor on a malformed or crafted object. Fails
     * closed instead of crashing. The violation carries no exception message, and no other
     * violations, because a partial evaluation cannot be trusted. `Error`s are not caught.
     */
    EVALUATION_FAILED("EVALUATION_FAILED", Tier.HARD, Severity.CRITICAL),

    // ---- Canonicalisation (SPEC section 6) ---------------------------------------

    /** The URI string is empty. */
    URI_EMPTY("URI_EMPTY", Tier.HARD, Severity.HIGH),

    /** The raw URI is longer than the entry point's maximum URI length. */
    URI_TOO_LONG("URI_TOO_LONG", Tier.HARD, Severity.HIGH),

    /** The URI could not be parsed into components. */
    URI_MALFORMED("URI_MALFORMED", Tier.HARD, Severity.HIGH),

    /** The URI is opaque (e.g. `mailto:x`, `intent:#Intent;end`) instead of hierarchical. */
    URI_OPAQUE("URI_OPAQUE", Tier.HARD, Severity.HIGH),

    /** The scheme is not syntactically valid. */
    URI_SCHEME_INVALID("URI_SCHEME_INVALID", Tier.HARD, Severity.HIGH),

    /** The authority has no host (e.g. `https:///path`). */
    URI_HOST_EMPTY("URI_HOST_EMPTY", Tier.HARD, Severity.HIGH),

    /** The host contains non-ASCII characters (e.g. a Cyrillic or fullwidth lookalike). */
    URI_HOST_NON_ASCII("URI_HOST_NON_ASCII", Tier.HARD, Severity.HIGH),

    /** The host contains characters or labels that are not valid in a host name. */
    URI_HOST_INVALID("URI_HOST_INVALID", Tier.HARD, Severity.HIGH),

    /** The host contains percent-encoding (e.g. `example.com%40evil.com`). */
    URI_HOST_PERCENT_ENCODED("URI_HOST_PERCENT_ENCODED", Tier.HARD, Severity.HIGH),

    /** The host ends with a dot (`example.com.`), an equivalent spelling that evades exact matching. */
    URI_HOST_TRAILING_DOT("URI_HOST_TRAILING_DOT", Tier.HARD, Severity.MEDIUM),

    /** The authority contains userinfo (`user:pass@host`, `example.com@evil.com`). */
    URI_USERINFO("URI_USERINFO", Tier.HARD, Severity.HIGH),

    /** The port is not a number in `1..65535`. */
    URI_PORT_INVALID("URI_PORT_INVALID", Tier.HARD, Severity.HIGH),

    /** A `%` is not followed by two hex digits (e.g. `%G1`, `%u002e`). */
    URI_PERCENT_MALFORMED("URI_PERCENT_MALFORMED", Tier.HARD, Severity.HIGH),

    /** After decoding once, the value still contains `%XX` (double or deeper encoding). */
    URI_DOUBLE_ENCODING("URI_DOUBLE_ENCODING", Tier.HARD, Severity.HIGH),

    /**
     * Decoded bytes are not valid UTF-8, including overlong encodings such as `%C0%AE` and
     * encoded surrogates such as `%ED%A0%80`. Also covers invalid UTF-16 in the input
     * string itself: a raw unpaired surrogate has no UTF-8 form, so it gets the same code.
     */
    URI_INVALID_UTF8("URI_INVALID_UTF8", Tier.HARD, Severity.HIGH),

    /** A null byte, raw or encoded as `%00`. */
    URI_NULL_BYTE("URI_NULL_BYTE", Tier.HARD, Severity.CRITICAL),

    /** A control character (C0, DEL or C1), raw or encoded, e.g. CR/LF injection. */
    URI_CONTROL_CHAR("URI_CONTROL_CHAR", Tier.HARD, Severity.HIGH),

    /**
     * A Unicode format character (category Cf) anywhere after decoding, e.g. a bidi
     * override (U+202E) or zero-width space (U+200B).
     */
    URI_FORMAT_CHAR("URI_FORMAT_CHAR", Tier.HARD, Severity.HIGH),

    /**
     * Whitespace in the URI: an unencoded U+0020 anywhere, or any other Unicode whitespace
     * (categories Zs, Zl, Zp, e.g. U+00A0, U+3000, U+2028), raw or encoded. An encoded
     * U+0020 (`%20`, or `+` in a query) is allowed.
     */
    URI_WHITESPACE("URI_WHITESPACE", Tier.HARD, Severity.MEDIUM),

    /** A backslash in the scheme separator, authority or path, raw or encoded. */
    URI_BACKSLASH("URI_BACKSLASH", Tier.HARD, Severity.HIGH),

    /** A `..` path segment, raw or encoded. */
    URI_PATH_TRAVERSAL("URI_PATH_TRAVERSAL", Tier.HARD, Severity.CRITICAL),

    /** A `.` path segment, raw or encoded. */
    URI_PATH_DOT_SEGMENT("URI_PATH_DOT_SEGMENT", Tier.HARD, Severity.MEDIUM),

    /** An encoded `/` inside a path segment (`%2F`). */
    URI_PATH_ENCODED_SEPARATOR("URI_PATH_ENCODED_SEPARATOR", Tier.HARD, Severity.HIGH),

    /** A Unicode lookalike of `/` or `.` in the path (e.g. U+2215, U+FF0F, U+FF0E). */
    URI_PATH_UNICODE_SEPARATOR("URI_PATH_UNICODE_SEPARATOR", Tier.HARD, Severity.HIGH),

    /** ShezGuard's parser and `android.net.Uri` disagree about the URI's components. */
    URI_PARSER_MISMATCH("URI_PARSER_MISMATCH", Tier.HARD, Severity.HIGH),

    /**
     * The URI was normalised (e.g. duplicate slashes collapsed, needless encoding,
     * explicit default port). Letter case in scheme and host alone does not count.
     */
    URI_NON_CANONICAL("URI_NON_CANONICAL", Tier.SOFT, Severity.LOW),

    // ---- Structure (SPEC section 5, step 2) --------------------------------------

    /** The entry point requires a data URI and the intent has none. */
    DATA_MISSING("DATA_MISSING", Tier.HARD, Severity.HIGH),

    /** The entry point forbids a data URI and the intent has one. */
    DATA_FORBIDDEN("DATA_FORBIDDEN", Tier.HARD, Severity.HIGH),

    /** The scheme is not in the entry point's allow-list. */
    SCHEME_NOT_ALLOWED("SCHEME_NOT_ALLOWED", Tier.HARD, Severity.HIGH),

    /** The host does not match the entry point's allow-list. */
    HOST_NOT_ALLOWED("HOST_NOT_ALLOWED", Tier.HARD, Severity.HIGH),

    /** A non-default port that the entry point does not allow. */
    PORT_NOT_ALLOWED("PORT_NOT_ALLOWED", Tier.HARD, Severity.HIGH),

    /** The path matches none of the entry point's path patterns. */
    PATH_NOT_ALLOWED("PATH_NOT_ALLOWED", Tier.HARD, Severity.HIGH),

    /** The URI has a fragment and the entry point does not allow one. */
    FRAGMENT_NOT_ALLOWED("FRAGMENT_NOT_ALLOWED", Tier.HARD, Severity.MEDIUM),

    // ---- Query parameters (SPEC section 5, step 3) -------------------------------

    /** A parameter marked required is absent. */
    PARAM_MISSING("PARAM_MISSING", Tier.HARD, Severity.MEDIUM),

    /** A parameter name is longer than 64 characters, or a value is longer than its limit. */
    PARAM_TOO_LONG("PARAM_TOO_LONG", Tier.HARD, Severity.HIGH),

    /**
     * A parameter name is empty or contains a character outside `A-Z a-z 0-9 _ . -` in the
     * raw URI, including `+` and `%` (e.g. `?=x`, `?a+b=1`, `?%69d=5`, `?ids[]=1`).
     */
    PARAM_NAME_INVALID("PARAM_NAME_INVALID", Tier.HARD, Severity.MEDIUM),

    /** A parameter value does not match its declared type (digits, enum, UUID, character class). */
    PARAM_INVALID_FORMAT("PARAM_INVALID_FORMAT", Tier.HARD, Severity.HIGH),

    /** A URL-typed parameter points outside its scheme or host allow-list (open redirect). */
    PARAM_URL_NOT_ALLOWED("PARAM_URL_NOT_ALLOWED", Tier.HARD, Severity.HIGH),

    /** The same parameter appears more than once (parameter pollution). */
    PARAM_REPEATED("PARAM_REPEATED", Tier.HARD, Severity.HIGH),

    /** An undeclared parameter, under `Unknown.Block`. */
    PARAM_UNKNOWN("PARAM_UNKNOWN", Tier.HARD, Severity.MEDIUM),

    /** An undeclared parameter, removed under `Unknown.Drop`. */
    PARAM_UNKNOWN_DROPPED("PARAM_UNKNOWN_DROPPED", Tier.REMOVABLE, Severity.LOW),

    /** An undeclared parameter, left in place under `Unknown.Ignore` and scored. */
    PARAM_UNKNOWN_IGNORED("PARAM_UNKNOWN_IGNORED", Tier.SOFT, Severity.LOW),

    // ---- Extras and nested intents (SPEC section 5, step 4) ----------------------

    /** Reading the extras threw (malformed or hostile Bundle). The intent cannot be inspected safely. */
    EXTRAS_UNPARCEL_FAILED("EXTRAS_UNPARCEL_FAILED", Tier.HARD, Severity.CRITICAL),

    /** The intent carries more extras than the entry point allows. */
    EXTRAS_TOO_MANY("EXTRAS_TOO_MANY", Tier.HARD, Severity.MEDIUM),

    /** An extra whose key the policy does not allow; removed by Sanitize. */
    EXTRA_NOT_ALLOWED("EXTRA_NOT_ALLOWED", Tier.REMOVABLE, Severity.LOW),

    /**
     * An allowed extra has the wrong type. Hard, because the app expects this key and
     * removing it would change behaviour instead of fixing the violation.
     */
    EXTRA_WRONG_TYPE("EXTRA_WRONG_TYPE", Tier.HARD, Severity.HIGH),

    /** An allowed string or array extra exceeds its size limit. */
    EXTRA_TOO_LARGE("EXTRA_TOO_LARGE", Tier.HARD, Severity.HIGH),

    /** A nested Intent was found and the policy denies nested intents. */
    NESTED_INTENT_DENIED("NESTED_INTENT_DENIED", Tier.HARD, Severity.CRITICAL),

    /** A nested Intent was reduced by `IntentSanitizer` under `Nested.AllowSanitized`. */
    NESTED_INTENT_SANITIZED("NESTED_INTENT_SANITIZED", Tier.REMOVABLE, Severity.MEDIUM),

    // ---- Caller signals (SPEC section 8, advisory unless noted) ------------------

    /** No caller identity was available from any source. */
    CALLER_UNIDENTIFIED("CALLER_UNIDENTIFIED", Tier.SOFT, Severity.LOW),

    /** An advisory caller source (e.g. `getReferrer()`) names a package or signature outside the allow-list. */
    CALLER_NOT_ALLOWED("CALLER_NOT_ALLOWED", Tier.SOFT, Severity.HIGH),

    /**
     * A reliable caller source names a package or signature outside the allow-list.
     * Hard, because the identity comes from the OS rather than from the caller.
     */
    CALLER_NOT_ALLOWED_RELIABLE("CALLER_NOT_ALLOWED_RELIABLE", Tier.HARD, Severity.CRITICAL),

    /** The app's own domain is not verified for App Links (API 31+). A fact about the domain, not the intent. */
    DOMAIN_NOT_VERIFIED("DOMAIN_NOT_VERIFIED", Tier.SOFT, Severity.HIGH),

    /** Domain verification state could not be read (below API 31, or the call failed). */
    DOMAIN_VERIFICATION_UNAVAILABLE("DOMAIN_VERIFICATION_UNAVAILABLE", Tier.SOFT, Severity.LOW),
    ;

    /** Lookup helpers. */
    public companion object {
        /** Returns the code whose [ViolationCode.id] equals [id], or `null` if there is none. */
        public fun fromId(id: String): ViolationCode? = entries.firstOrNull { it.id == id }
    }
}
