package com.shezguard.core.eval

/**
 * Removes query parameters from a raw URI string without re-encoding anything
 * (SPEC 4.1; step 5b proposal (d)2).
 *
 * The method, in full:
 * 1. Split the raw `dataString` at the first `#`, then the part before it at the first
 *    `?`. This is exactly how the canonicaliser splits it: the scheme cannot contain `?`
 *    or `#`, and the authority ends at the first `/`, `?` or `#`, so the first `#` starts
 *    the fragment and the first `?` before it starts the query.
 * 2. Split the raw query on `&` into pieces. A piece's name is the text before its first
 *    `=`, or the whole piece if it has none.
 * 3. Drop every piece whose name is in the set of dropped names. Matching on the raw name
 *    is exact, because the step 4 name rule (`docs/LIMITATIONS.md` L16) only accepts raw
 *    names made of `A-Z a-z 0-9 _ . -`, so the raw name and the decoded name are identical.
 * 4. Rejoin the remaining pieces with `&`, byte for byte as they arrived. No piece is
 *    decoded, re-encoded or reordered.
 * 5. Everything before the `?` (scheme, authority, path) and everything from the `#` on
 *    (the fragment, including the `#`) is copied unchanged.
 * 6. If no piece remains, the `?` is removed as well (author decision 4).
 *
 * Only call this for a URI the canonicaliser accepted; the result is checked again by
 * [SanitizeCheck] before it is used.
 */
internal object QueryRemoval {

    fun remove(raw: String, droppedNames: Set<String>): String {
        if (droppedNames.isEmpty()) return raw
        val hash = raw.indexOf('#')
        val beforeHash = if (hash < 0) raw else raw.substring(0, hash)
        val fragmentPart = if (hash < 0) "" else raw.substring(hash) // includes '#'
        val question = beforeHash.indexOf('?')
        if (question < 0) return raw
        val head = beforeHash.substring(0, question)
        val kept = beforeHash.substring(question + 1).split('&').filter { piece ->
            val eq = piece.indexOf('=')
            val name = if (eq < 0) piece else piece.substring(0, eq)
            name !in droppedNames
        }
        val query = if (kept.isEmpty()) "" else kept.joinToString("&", prefix = "?")
        return head + query + fragmentPart
    }
}
