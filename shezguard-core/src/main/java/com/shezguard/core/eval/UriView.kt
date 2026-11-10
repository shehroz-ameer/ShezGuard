package com.shezguard.core.eval

/**
 * What the platform's URI parser (`android.net.Uri`) reports for the intent's data URI.
 *
 * This interface keeps the pipeline free of Android types: the Android adapter
 * (`com.shezguard.core.android.AndroidUriView`) implements it over a real `Uri`, and JVM
 * tests use fakes. Every accessor is a function so that an accessor that throws is called
 * inside the evaluator's fail-closed boundary (`EVALUATION_FAILED`).
 *
 * The names match the `android.net.Uri` getters they wrap. `queryParameter` is
 * `getQueryParameter` (singular), the only query accessor whose `+` handling ShezGuard
 * matches (`docs/LIMITATIONS.md` L11).
 */
internal interface UriView {
    fun isHierarchical(): Boolean
    fun scheme(): String?
    fun host(): String?

    /** `-1` when the URI has no explicit port. */
    fun port(): Int
    fun userInfo(): String?
    fun pathSegments(): List<String>
    fun path(): String?
    fun encodedPath(): String?
    fun authority(): String?
    fun encodedAuthority(): String?
    fun query(): String?
    fun encodedQuery(): String?
    fun fragment(): String?
    fun encodedFragment(): String?
    fun queryParameterNames(): Set<String>
    fun queryParameter(name: String): String?

    /** The platform's own decoder (`Uri.decode`: `%XX` only, `+` stays literal). */
    fun decode(encoded: String): String
}

/**
 * The intent's data URI as given to the evaluator.
 *
 * @property dataString `intent.getDataString()`, the string the canonicaliser parses
 * (`docs/CANONICALISER_TESTS.md`, "Input contract").
 * @property view the platform parser's view of the same `Uri` object.
 */
internal class UriInput(val dataString: String, val view: UriView)
