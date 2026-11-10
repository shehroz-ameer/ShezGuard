package com.shezguard.core.eval

import com.shezguard.core.Field
import com.shezguard.core.Outcome
import com.shezguard.core.UriComponent
import com.shezguard.core.Violation
import com.shezguard.core.ViolationCode.EVALUATION_FAILED
import com.shezguard.core.ViolationCode.URI_PARSER_MISMATCH
import com.shezguard.core.canon.CanonResult
import com.shezguard.core.canon.CanonicalUri
import com.shezguard.core.canon.UriCanonicalizer
import com.shezguard.core.policy.Limits
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.net.URLDecoder

/**
 * Proposal (c): every row of the mismatch table, each with a fake `UriView` that disagrees
 * with the canonical result on exactly that one component. Pure JVM, no Robolectric.
 */
class ParserMismatchTest {

    private val raw = "https://example.com/product/42/?id=42&ref=abc#top"
    private val ep = EvalFixtures.policy["product"]!!
    private val canonical: CanonicalUri =
        (UriCanonicalizer.canonicalize(raw, Limits.DEFAULT) as CanonResult.Ok).uri

    /** Agrees with [raw] on every accessor; each test changes one value. */
    private val agreeing = FakeUriView(
        isHierarchical = true,
        scheme = "https",
        host = "example.com",
        port = -1,
        userInfo = null,
        pathSegments = listOf("product", "42"),
        path = "/product/42/",
        encodedPath = "/product/42/",
        authority = "example.com",
        encodedAuthority = "example.com",
        query = "id=42&ref=abc",
        encodedQuery = "id=42&ref=abc",
        fragment = "top",
        encodedFragment = "top",
        queryParameterNames = setOf("id", "ref"),
        params = mapOf("id" to "42", "ref" to "abc"),
    )

    private fun mismatches(view: UriView) = ParserMismatch.check(canonical, view, ep)

    private fun mismatch(component: UriComponent) =
        listOf(Violation(URI_PARSER_MISMATCH, "product", Field.UriPart(component)))

    @Test
    fun agreeingViewHasNoMismatch() {
        assertEquals(emptyList<Violation>(), mismatches(agreeing))
    }

    // ---- (c)1: canonicaliser vs android.net.Uri, one row each ---------------------

    @Test
    fun blocksWhenAndroidSeesOpaqueUri() {
        assertEquals(mismatch(UriComponent.WHOLE), mismatches(agreeing.copy(isHierarchical = false)))
    }

    @Test
    fun blocksSchemeMismatch() {
        assertEquals(mismatch(UriComponent.SCHEME), mismatches(agreeing.copy(scheme = "http")))
    }

    @Test
    fun blocksHostMismatch() {
        assertEquals(mismatch(UriComponent.HOST), mismatches(agreeing.copy(host = "evil.com")))
    }

    @Test
    fun hostAndSchemeCompareIgnoringAsciiCaseOnly() {
        assertEquals(emptyList<Violation>(), mismatches(agreeing.copy(host = "EXAMPLE.com", scheme = "HTTPS")))
    }

    /** U+212A KELVIN SIGN lowercases to `k` under Unicode rules; the comparison must not fold it. */
    @Test
    fun hostComparisonDoesNotUseUnicodeCaseFolding() {
        val canon = (UriCanonicalizer.canonicalize("https://k.example/", Limits.DEFAULT) as CanonResult.Ok).uri
        val view = agreeing.copy(
            host = "K.example", authority = "k.example", encodedAuthority = "k.example",
            pathSegments = emptyList(), path = "/", encodedPath = "/", query = null, encodedQuery = null,
            fragment = null, encodedFragment = null, queryParameterNames = emptySet(), params = emptyMap(),
        )
        assertEquals(
            listOf(Violation(URI_PARSER_MISMATCH, "browse", Field.UriPart(UriComponent.HOST))),
            ParserMismatch.check(canon, view, EvalFixtures.policy["browse"]!!),
        )
    }

    @Test
    fun blocksPortMismatch() {
        assertEquals(mismatch(UriComponent.PORT), mismatches(agreeing.copy(port = 8443)))
    }

    @Test
    fun explicitDefaultPortOnAndroidSideIsNotAMismatch() {
        assertEquals(emptyList<Violation>(), mismatches(agreeing.copy(port = 443)))
    }

    @Test
    fun blocksUserInfoSeenOnlyByAndroid() {
        assertEquals(mismatch(UriComponent.USERINFO), mismatches(agreeing.copy(userInfo = "user")))
    }

    @Test
    fun blocksPathSegmentMismatch() {
        assertEquals(mismatch(UriComponent.PATH), mismatches(agreeing.copy(pathSegments = listOf("admin", "42"))))
    }

    @Test
    fun blocksTrailingSlashMismatch() {
        assertEquals(
            mismatch(UriComponent.PATH),
            mismatches(agreeing.copy(path = "/product/42", encodedPath = "/product/42")),
        )
    }

    @Test
    fun blocksFragmentMismatch() {
        assertEquals(mismatch(UriComponent.FRAGMENT), mismatches(agreeing.copy(fragment = "other", encodedFragment = "other")))
    }

    @Test
    fun blocksFragmentSeenOnlyByOneSide() {
        assertEquals(mismatch(UriComponent.FRAGMENT), mismatches(agreeing.copy(fragment = null, encodedFragment = null)))
    }

    @Test
    fun blocksParamNameSetMismatch() {
        assertEquals(
            mismatch(UriComponent.QUERY),
            mismatches(agreeing.copy(queryParameterNames = setOf("id", "ref", "admin"))),
        )
    }

    @Test
    fun blocksParamValueMismatchThroughGetQueryParameter() {
        assertEquals(
            listOf(Violation(URI_PARSER_MISMATCH, "product", Field.Param("id", declared = true))),
            mismatches(agreeing.copy(params = mapOf("id" to "43", "ref" to "abc"))),
        )
    }

    @Test
    fun undeclaredParamValueMismatchHasRedactedField() {
        val canon = (UriCanonicalizer.canonicalize("https://example.com/product/42/?id=42&zz=1#top", Limits.DEFAULT) as CanonResult.Ok).uri
        val view = agreeing.copy(
            query = "id=42&zz=1", encodedQuery = "id=42&zz=1",
            queryParameterNames = setOf("id", "zz"), params = mapOf("id" to "42", "zz" to "2"),
        )
        assertEquals(
            listOf(Violation(URI_PARSER_MISMATCH, "product", Field.Param("zz", declared = false))),
            ParserMismatch.check(canon, view, ep),
        )
    }

    // ---- (c)2: android.net.Uri's decoded parts vs Uri.decode(encoded parts) ---------

    @Test
    fun blocksAuthorityWhoseDecodedFormDisagreesWithEncoded() {
        assertEquals(mismatch(UriComponent.HOST), mismatches(agreeing.copy(authority = "evil.com")))
    }

    @Test
    fun blocksPathWhoseDecodedFormDisagreesWithEncoded() {
        assertEquals(mismatch(UriComponent.PATH), mismatches(agreeing.copy(path = "/admin/secret/")))
    }

    @Test
    fun blocksQueryWhoseDecodedFormDisagreesWithEncoded() {
        assertEquals(mismatch(UriComponent.QUERY), mismatches(agreeing.copy(query = "id=43&ref=abc")))
    }

    @Test
    fun blocksFragmentWhoseDecodedFormDisagreesWithEncoded() {
        assertEquals(mismatch(UriComponent.FRAGMENT), mismatches(agreeing.copy(encodedFragment = "evil")))
    }

    @Test
    fun reportsEveryDisagreeingComponent() {
        val v = agreeing.copy(scheme = "http", host = "evil.com", port = 1, path = "/x/")
        assertEquals(
            setOf(UriComponent.SCHEME, UriComponent.HOST, UriComponent.PORT, UriComponent.PATH),
            mismatches(v).map { (it.field as Field.UriPart).component }.toSet(),
        )
    }

    // ---- EVALUATION_FAILED (approved decision 1) ----------------------------------

    @Test
    fun throwingUriViewGivesEvaluationFailed() {
        val throwing = agreeing.copy(throwOn = "host")
        val result = Evaluator.evaluate(EvalFixtures.policy, "product") { UriInput(raw, throwing) }
        assertEquals(Outcome.BLOCK, result.outcome)
        assertEquals(listOf(Violation(EVALUATION_FAILED, "product", Field.EntryPoint)), result.violations)
    }

    @Test
    fun throwingInputProviderGivesEvaluationFailed() {
        val result = Evaluator.evaluate(EvalFixtures.policy, "product") { throw IllegalStateException("boom") }
        assertEquals(listOf(Violation(EVALUATION_FAILED, "product", Field.EntryPoint)), result.violations)
    }

    @Test
    fun errorsAreNotCaught() {
        assertThrows(StackOverflowError::class.java) {
            Evaluator.evaluate(EvalFixtures.policy, "product") { throw StackOverflowError() }
        }
    }

    @Test
    fun unknownEntryPointDoesNotTouchTheInput() {
        val result = Evaluator.evaluate(EvalFixtures.policy, "nope") { throw AssertionError("input read") }
        assertEquals(Outcome.BLOCK, result.outcome)
    }
}

/** A `UriView` with fixed answers. [throwOn] names an accessor that throws instead. */
internal data class FakeUriView(
    private val isHierarchical: Boolean,
    private val scheme: String?,
    private val host: String?,
    private val port: Int,
    private val userInfo: String?,
    private val pathSegments: List<String>,
    private val path: String?,
    private val encodedPath: String?,
    private val authority: String?,
    private val encodedAuthority: String?,
    private val query: String?,
    private val encodedQuery: String?,
    private val fragment: String?,
    private val encodedFragment: String?,
    private val queryParameterNames: Set<String>,
    private val params: Map<String, String>,
    private val throwOn: String? = null,
) : UriView {
    private fun <T> v(name: String, value: T): T {
        if (name == throwOn) throw UnsupportedOperationException("fake failure in $name")
        return value
    }

    override fun isHierarchical(): Boolean = v("isHierarchical", isHierarchical)
    override fun scheme(): String? = v("scheme", scheme)
    override fun host(): String? = v("host", host)
    override fun port(): Int = v("port", port)
    override fun userInfo(): String? = v("userInfo", userInfo)
    override fun pathSegments(): List<String> = v("pathSegments", pathSegments)
    override fun path(): String? = v("path", path)
    override fun encodedPath(): String? = v("encodedPath", encodedPath)
    override fun authority(): String? = v("authority", authority)
    override fun encodedAuthority(): String? = v("encodedAuthority", encodedAuthority)
    override fun query(): String? = v("query", query)
    override fun encodedQuery(): String? = v("encodedQuery", encodedQuery)
    override fun fragment(): String? = v("fragment", fragment)
    override fun encodedFragment(): String? = v("encodedFragment", encodedFragment)
    override fun queryParameterNames(): Set<String> = v("queryParameterNames", queryParameterNames)
    override fun queryParameter(name: String): String? = v("queryParameter", params[name])

    /** Like `Uri.decode`: `%XX` only, `+` stays literal. */
    override fun decode(encoded: String): String = URLDecoder.decode(encoded.replace("+", "%2B"), "UTF-8")
}
