package com.shezguard.core.eval

import org.junit.Assert.assertEquals
import org.junit.Test

/** Proposal (d)2: removal is purely by raw piece, nothing is re-encoded. Pure JVM. */
class QueryRemovalTest {

    private fun rm(raw: String, vararg names: String) = QueryRemoval.remove(raw, names.toSet())

    @Test
    fun keepsRetainedPiecesByteForByte() =
        assertEquals("https://h/p?q=a+b%2B%41&k=%E2%82%AC", rm("https://h/p?u=1&q=a+b%2B%41&k=%E2%82%AC", "u"))

    @Test
    fun questionMarkAndAmpersandInsideFragmentAreNotQuery() =
        assertEquals("https://h/p#x?u=1&y", rm("https://h/p?u=1#x?u=1&y", "u"))

    @Test
    fun removesValuelessPiecesByName() = assertEquals("https://h/p?q=1", rm("https://h/p?flag&q=1&flag=", "flag"))

    @Test
    fun valueContainingEqualsDoesNotChangeTheName() =
        assertEquals("https://h/p?q=u=1", rm("https://h/p?q=u=1&u=q=1", "u"))

    @Test
    fun removesQuestionMarkWhenNothingRemains() {
        assertEquals("https://h/p", rm("https://h/p?u=1&v=2", "u", "v"))
        assertEquals("https://h/p#f", rm("https://h/p?u=1#f", "u"))
    }

    @Test
    fun noQueryOrNoNamesIsUnchanged() {
        assertEquals("https://h/p#u=1", rm("https://h/p#u=1", "u"))
        assertEquals("https://h/p?u=1", rm("https://h/p?u=1"))
    }

    @Test
    fun namesMatchExactlyAndCaseSensitively() =
        assertEquals("https://h/p?U=1&uu=2&u.x=3", rm("https://h/p?U=1&u=0&uu=2&u.x=3", "u"))
}
