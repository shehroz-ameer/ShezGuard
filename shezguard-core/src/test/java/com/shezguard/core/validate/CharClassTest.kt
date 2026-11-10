package com.shezguard.core.validate

import com.shezguard.core.policy.CharClass
import com.shezguard.core.policy.ParamType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The character classes for `ParamType.BoundedString`, one example set per class. */
class CharClassTest {

    private fun ch(code: Int): String = code.toChar().toString()

    private fun assertAccepts(c: CharClass, vararg values: String) {
        for (v in values) assertTrue("$c should accept <$v>", c.accepts(v))
    }

    private fun assertRejects(c: CharClass, vararg values: String) {
        for (v in values) assertFalse("$c should reject <$v>", c.accepts(v))
    }

    @Test
    fun defaultCharClassIsSlug() {
        assertEquals(CharClass.SLUG, ParamType.BoundedString().chars)
    }

    @Test
    fun defaultSlugRejectsTraversalInjectionAndEncodingCharacters() {
        // '.', '/', '\', both quotes, '<', space and '%': the characters behind path traversal,
        // SQL/JS string breaking, HTML injection and re-encoding tricks.
        for (bad in listOf(".", "/", "\\", "'", "\"", "<", " ", "%")) {
            assertRejects(CharClass.SLUG, "a${bad}b", bad)
        }
        assertRejects(CharClass.SLUG, "..", "../etc", "<script>", "a' OR '1'='1", "%2e")
    }

    @Test
    fun slugAcceptsAsciiLettersDigitsUnderscoreAndHyphen() {
        assertAccepts(CharClass.SLUG, "summer-sale_2026", "ABC", "a", "0")
    }

    @Test
    fun slugRejectsUnicodeLookalikes() {
        // docs/LIMITATIONS.md L14: the ASCII default keeps lookalikes of '/', '.' and '\' out.
        for (cp in listOf(0x2215, 0x2044, 0xFF0F, 0xFF0E, 0x2024, 0xFE52, 0x29F8, 0xFF3C, 0x2216)) {
            assertRejects(CharClass.SLUG, "a${ch(cp)}b")
        }
        assertRejects(CharClass.SLUG, "caf${ch(0xE9)}", "${ch(0x0430)}dmin") // é, Cyrillic а
    }

    @Test
    fun alphanumericAcceptsOnlyAsciiLettersAndDigits() {
        assertAccepts(CharClass.ALPHANUMERIC, "abc123", "XYZ")
        assertRejects(CharClass.ALPHANUMERIC, "a-b", "a_b", "a b", "a.b", "${ch(0x0661)}") // Arabic-Indic one
    }

    @Test
    fun printableAsciiAcceptsSpaceAndPunctuationButNotControlOrNonAscii() {
        assertAccepts(CharClass.PRINTABLE_ASCII, "Hello, world!", "a b", "../x", "<b>", "it's")
        assertRejects(CharClass.PRINTABLE_ASCII, "a\tb", "a\u007Fb", "caf${ch(0xE9)}", "a${ch(0x2215)}b")
    }

    @Test
    fun textAcceptsUnicodeLettersMarksDigitsPunctuationSymbolsAndSpaces() {
        assertAccepts(
            CharClass.TEXT,
            "caf${ch(0xE9)}", "e${ch(0x0301)}", "${ch(0x65E5)}${ch(0x672C)}", "Hello, world!",
            "${ch(0x20AC)}5", "a${ch(0x2215)}b", "😀",
        )
    }

    @Test
    fun textRejectsControlFormatPrivateUseUnassignedAndUnpairedSurrogates() {
        assertRejects(
            CharClass.TEXT,
            "a\u0000b", "a\nb", "a${ch(0x202E)}b", "a${ch(0x200B)}b", "a${ch(0xE000)}b",
            "a${ch(0x0378)}b", "a${ch(0xD800)}b", "a${ch(0xDC00)}b", "a${ch(0x2028)}b",
        )
    }

    @Test
    fun everyClassAcceptsTheEmptyString() {
        // Emptiness is a parameter-level rule (UriPolicyValidator), not a character rule.
        for (c in CharClass.entries) assertTrue(c.accepts(""))
    }
}
