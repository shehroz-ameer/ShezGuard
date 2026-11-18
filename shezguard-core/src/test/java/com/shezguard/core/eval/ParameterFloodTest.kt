package com.shezguard.core.eval

import com.shezguard.core.Outcome
import com.shezguard.core.ViolationCode.EVALUATION_FAILED
import com.shezguard.core.ViolationCode.PARAM_TOO_MANY
import com.shezguard.core.ViolationCode.URI_PARSER_MISMATCH
import com.shezguard.core.policy.CharClass
import com.shezguard.core.policy.Unknown
import com.shezguard.core.policy.intentPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Step 16, H8 (`docs/HARDENING.md`): attack category "parameter flood (denial of service through the parser-mismatch
 * check)". `Uri.getQueryParameter` costs about the cube of the number of value-less parameters (about 5.2 s per call
 * for 2 745 of them on an API 34 emulator). The count is capped (`Limits.maxParameters`, default 64) on the raw query
 * **before** any `android.net.Uri` accessor runs. JVM only; asserts decisions and codes, never wall-clock time.
 */
class ParameterFloodTest {

    private val policy = intentPolicy {
        entryPoint("any") {
            allowSchemes("https")
            allowHosts("example.com")
            anyPath()
            param("q") { string(CharClass.TEXT) }
            unknownParams(Unknown.Ignore)
            limits(maxUriLength = 8192)
        }
    }

    /** A platform view whose every accessor fails the evaluation if called. */
    private val untouchable = object : UriView {
        private fun touched(): Nothing = throw IllegalStateException("an android.net.Uri accessor was called")
        override fun isHierarchical(): Boolean = touched()
        override fun scheme(): String? = touched()
        override fun host(): String? = touched()
        override fun port(): Int = touched()
        override fun userInfo(): String? = touched()
        override fun pathSegments(): List<String> = touched()
        override fun path(): String? = touched()
        override fun encodedPath(): String? = touched()
        override fun authority(): String? = touched()
        override fun encodedAuthority(): String? = touched()
        override fun query(): String? = touched()
        override fun encodedQuery(): String? = touched()
        override fun fragment(): String? = touched()
        override fun encodedFragment(): String? = touched()
        override fun queryParameterNames(): Set<String> = touched()
        override fun queryParameter(name: String): String? = touched()
        override fun decode(encoded: String): String = touched()
    }

    /** The densest flood: 1- and 2-char value-less names, as long as fits in [maxLength]. */
    private fun flood(maxLength: Int): String {
        val alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
        val names = (alphabet.map { "$it" } + alphabet.flatMap { a -> alphabet.map { b -> "$a$b" } }).filter { it != "q" }
        val sb = StringBuilder("https://example.com/x?")
        var n = 0
        for (name in names) {
            val piece = (if (n == 0) "" else "&") + name
            if (sb.length + piece.length > maxLength) break
            sb.append(piece); n++
        }
        return sb.toString()
    }

    @Test
    fun blocksParameterFloodBeforeAnyPlatformAccessorRuns() {
        for (maxLength in listOf(2048, 8192)) {
            val e = Evaluator.evaluate(policy, "any") { UriInput(flood(maxLength), untouchable) }
            val codes = e.violations.map { it.code }
            assertEquals("$maxLength: $codes", Outcome.BLOCK, e.outcome)
            assertTrue("$maxLength: $codes", PARAM_TOO_MANY in codes)
            assertFalse("an accessor ran ($maxLength)", EVALUATION_FAILED in codes)
            assertFalse(URI_PARSER_MISMATCH in codes)
        }
    }

    @Test
    fun sixtyFourParametersAreStillCheckedAgainstThePlatform() {
        val uri = "https://example.com/x?" + (0 until 64).joinToString("&") { "p$it" }
        val e = Evaluator.evaluate(policy, "any") { UriInput(uri, untouchable) }
        // Under the cap the parser-mismatch check runs, so the untouchable view is reached (fails closed).
        assertEquals(listOf(EVALUATION_FAILED), e.violations.map { it.code })
    }
}
