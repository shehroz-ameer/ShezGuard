package com.shezguard.core.canon

import com.shezguard.core.Tier
import com.shezguard.core.UriComponent
import com.shezguard.core.UriComponent.FRAGMENT
import com.shezguard.core.UriComponent.HOST
import com.shezguard.core.UriComponent.PATH
import com.shezguard.core.UriComponent.PORT
import com.shezguard.core.UriComponent.QUERY
import com.shezguard.core.UriComponent.SCHEME
import com.shezguard.core.UriComponent.USERINFO
import com.shezguard.core.UriComponent.WHOLE
import com.shezguard.core.ViolationCode
import com.shezguard.core.ViolationCode.PARAM_NAME_INVALID
import com.shezguard.core.ViolationCode.PARAM_TOO_LONG
import com.shezguard.core.ViolationCode.URI_BACKSLASH
import com.shezguard.core.ViolationCode.URI_CONTROL_CHAR
import com.shezguard.core.ViolationCode.URI_DOUBLE_ENCODING
import com.shezguard.core.ViolationCode.URI_EMPTY
import com.shezguard.core.ViolationCode.URI_FORMAT_CHAR
import com.shezguard.core.ViolationCode.URI_HOST_EMPTY
import com.shezguard.core.ViolationCode.URI_HOST_INVALID
import com.shezguard.core.ViolationCode.URI_HOST_NON_ASCII
import com.shezguard.core.ViolationCode.URI_HOST_PERCENT_ENCODED
import com.shezguard.core.ViolationCode.URI_HOST_TRAILING_DOT
import com.shezguard.core.ViolationCode.URI_INVALID_UTF8
import com.shezguard.core.ViolationCode.URI_MALFORMED
import com.shezguard.core.ViolationCode.URI_NON_CANONICAL
import com.shezguard.core.ViolationCode.URI_NULL_BYTE
import com.shezguard.core.ViolationCode.URI_OPAQUE
import com.shezguard.core.ViolationCode.URI_PATH_DOT_SEGMENT
import com.shezguard.core.ViolationCode.URI_PATH_ENCODED_SEPARATOR
import com.shezguard.core.ViolationCode.URI_PATH_TRAVERSAL
import com.shezguard.core.ViolationCode.URI_PATH_UNICODE_SEPARATOR
import com.shezguard.core.ViolationCode.URI_PERCENT_MALFORMED
import com.shezguard.core.ViolationCode.URI_PORT_INVALID
import com.shezguard.core.ViolationCode.URI_SCHEME_INVALID
import com.shezguard.core.ViolationCode.URI_TOO_LONG
import com.shezguard.core.ViolationCode.URI_USERINFO
import com.shezguard.core.ViolationCode.URI_WHITESPACE
import com.shezguard.core.policy.Limits
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException

/**
 * Splits a URI string into components, then decodes each component exactly once
 * (SPEC section 6). Pure Kotlin, no Android types.
 *
 * Only hierarchical URIs (`scheme://host[:port]/path?query#fragment`) are accepted.
 * Scheme, host, port and fragment allow-lists, repeated parameters and parameter value
 * rules are not checked here; that is the policy stage (step 4).
 *
 * Every problem found is reported, not just the first. Findings never carry URI text.
 */
internal object UriCanonicalizer {

    private val DEFAULT_PORTS = mapOf("http" to 80, "https" to 443)

    /** Lookalikes of `/` and `.`: U+2215, U+2044, U+FF0F, U+FF0E. */
    private val UNICODE_SEPARATORS = charArrayOf('∕', '⁄', '／', '．')

    /**
     * @param raw the URI string, normally `intent.getDataString()`.
     * @param limits the URI length and decoded parameter length limits.
     */
    fun canonicalize(raw: String, limits: Limits): CanonResult {
        if (raw.isEmpty()) return CanonResult.Rejected(listOf(Finding(URI_EMPTY, WHOLE)))
        val f = Findings()
        if (raw.length > limits.maxUriLength) f.add(URI_TOO_LONG, WHOLE)
        val uri = parse(raw, limits, f)
        val findings = f.toList()
        val hard = findings.any { it.code.tier == Tier.HARD }
        return if (uri == null || hard) CanonResult.Rejected(findings) else CanonResult.Ok(uri, findings)
    }

    // ---- structure -----------------------------------------------------------------

    private fun parse(raw: String, limits: Limits, f: Findings): CanonicalUri? {
        val colon = raw.indexOf(':')
        val firstDelimiter = raw.indexOfAny(charArrayOf('/', '?', '#'))
        if (colon < 0 || (firstDelimiter in 0 until colon)) {
            f.add(URI_MALFORMED, WHOLE)
            checkRaw(raw, WHOLE, f)
            return null
        }

        val rawScheme = raw.substring(0, colon)
        checkRaw(rawScheme, SCHEME, f)
        if (!isValidScheme(rawScheme)) f.add(URI_SCHEME_INVALID, SCHEME)
        val scheme = rawScheme.lowercase()

        val rest = raw.substring(colon + 1)
        if (!rest.startsWith("/")) {
            // Opaque: `mailto:x`, `https:evil.com`, `https:\\evil.com`.
            f.add(URI_OPAQUE, WHOLE)
            checkRaw(rest, WHOLE, f)
            if ('\\' in rest) f.add(URI_BACKSLASH, WHOLE)
            return null
        }

        var host: String? = null
        var port: Int? = null
        val afterAuthority: String
        if (rest.startsWith("//")) {
            val end = rest.indexOfAny(charArrayOf('/', '?', '#'), startIndex = 2).let { if (it < 0) rest.length else it }
            val authority = parseAuthority(rest.substring(2, end), scheme, f)
            host = authority.first
            port = authority.second
            afterAuthority = rest.substring(end)
        } else {
            // `https:/path`: hierarchical but without an authority.
            f.add(URI_HOST_EMPTY, HOST)
            afterAuthority = rest
        }

        val hash = afterAuthority.indexOf('#')
        val beforeHash = if (hash < 0) afterAuthority else afterAuthority.substring(0, hash)
        val rawFragment = if (hash < 0) null else afterAuthority.substring(hash + 1)
        val question = beforeHash.indexOf('?')
        val rawPath = if (question < 0) beforeHash else beforeHash.substring(0, question)
        val rawQuery = if (question < 0) null else beforeHash.substring(question + 1)

        val (segments, trailingSlash) = parsePath(rawPath, f)
        val query = if (rawQuery == null) emptyList() else parseQuery(rawQuery, limits, f)
        val fragment = rawFragment?.let { decodeAndCheck(it, FRAGMENT, f) }

        if (host == null) return null
        return CanonicalUri(scheme, host, port, segments, trailingSlash, query, fragment)
    }

    /** RFC 3986: `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`, ASCII only. */
    private fun isValidScheme(s: String): Boolean =
        s.isNotEmpty() && s[0].isAsciiLetter() &&
            s.all { it.isAsciiLetter() || it in '0'..'9' || it == '+' || it == '-' || it == '.' }

    /** Returns (host, port). The host is `null` when there is none to report. */
    private fun parseAuthority(authority: String, scheme: String, f: Findings): Pair<String?, Int?> {
        checkRaw(authority, HOST, f)
        if ('\\' in authority) f.add(URI_BACKSLASH, HOST)

        val at = authority.lastIndexOf('@')
        if (at >= 0) f.add(URI_USERINFO, USERINFO)
        val hostPort = authority.substring(at + 1)

        if (hostPort.startsWith("[")) {
            // IPv6 literal: unsupported (docs/LIMITATIONS.md L9).
            f.add(URI_HOST_INVALID, HOST)
            return null to null
        }

        val colon = hostPort.indexOf(':')
        val rawHost = if (colon < 0) hostPort else hostPort.substring(0, colon)
        val port = if (colon < 0) null else parsePort(hostPort.substring(colon + 1), scheme, f)

        if (rawHost.isEmpty()) {
            f.add(URI_HOST_EMPTY, HOST)
            return null to port
        }
        return checkHost(rawHost, f) to port
    }

    /** Hosts are never percent-decoded and never IDN-converted; anything unusual is hard. */
    private fun checkHost(rawHost: String, f: Findings): String {
        if ('%' in rawHost) f.add(URI_HOST_PERCENT_ENCODED, HOST)
        if (rawHost.any { it.code > 0x7F }) f.add(URI_HOST_NON_ASCII, HOST)

        val host = rawHost.lowercase()
        var labels = host
        if (host.endsWith('.')) {
            f.add(URI_HOST_TRAILING_DOT, HOST)
            labels = host.dropLast(1)
        }
        // Non-ASCII and '%' are reported above under their own codes.
        val badAscii = labels.any { it.code <= 0x7F && it != '%' && it != '.' && !it.isHostChar() }
        val emptyLabel = labels.split('.').any { it.isEmpty() }
        if (badAscii || emptyLabel) f.add(URI_HOST_INVALID, HOST)
        return host
    }

    /** `1..65535`, digits only, no leading zero. An explicit default port is dropped. */
    private fun parsePort(raw: String, scheme: String, f: Findings): Int? {
        val digitsOk = raw.length in 1..5 && raw.all { it in '0'..'9' } && raw[0] != '0'
        val n = if (digitsOk) raw.toInt() else 0
        if (n !in 1..65535) {
            f.add(URI_PORT_INVALID, PORT)
            return null
        }
        if (DEFAULT_PORTS[scheme] == n) {
            f.add(URI_NON_CANONICAL, PORT)
            return null
        }
        return n
    }

    /** Returns (decoded non-empty segments, trailing slash). Duplicate slashes collapse. */
    private fun parsePath(rawPath: String, f: Findings): Pair<List<String>, Boolean> {
        if (rawPath.isEmpty()) return emptyList<String>() to false
        // rawPath always starts with '/', so the first piece is the empty root.
        val pieces = rawPath.split('/').drop(1)
        val endsWithSlash = pieces.last().isEmpty()
        val interior = if (endsWithSlash) pieces.dropLast(1) else pieces
        if (interior.any { it.isEmpty() }) f.add(URI_NON_CANONICAL, PATH)

        val segments = interior.filter { it.isNotEmpty() }.map { checkSegment(it, f) }
        return segments to (endsWithSlash && segments.isNotEmpty())
    }

    private fun checkSegment(rawSegment: String, f: Findings): String {
        val d = decodeAndCheck(rawSegment, PATH, f, flagNeedlessEscapes = true)
        if ('/' in d) f.add(URI_PATH_ENCODED_SEPARATOR, PATH)
        if ('\\' in d) f.add(URI_BACKSLASH, PATH)
        // Check what each side of an encoded separator would become, e.g. `%2e%2e%2fetc`.
        for (piece in d.split('/', '\\')) {
            if (piece == "..") f.add(URI_PATH_TRAVERSAL, PATH)
            if (piece == ".") f.add(URI_PATH_DOT_SEGMENT, PATH)
        }
        if (d.indexOfAny(UNICODE_SEPARATORS) >= 0) f.add(URI_PATH_UNICODE_SEPARATOR, PATH)
        return d
    }

    /** Splits on `&` only (`;` is literal), then on the first `=`, then decodes. */
    private fun parseQuery(rawQuery: String, limits: Limits, f: Findings): List<Pair<String, String>> {
        if (rawQuery.isEmpty()) return emptyList()
        return rawQuery.split('&').map { piece ->
            val eq = piece.indexOf('=')
            val rawName = if (eq < 0) piece else piece.substring(0, eq)
            val rawValue = if (eq < 0) "" else piece.substring(eq + 1)
            val name = decodeAndCheck(rawName, QUERY, f, plusAsSpace = true)
            val value = decodeAndCheck(rawValue, QUERY, f, plusAsSpace = true)
            if (name.isEmpty()) f.add(PARAM_NAME_INVALID, QUERY)
            if (name.length > limits.maxParamLength || value.length > limits.maxParamLength) {
                f.add(PARAM_TOO_LONG, QUERY)
            }
            name to value
        }
    }

    // ---- character checks and decoding ---------------------------------------------

    private fun decodeAndCheck(
        raw: String,
        component: UriComponent,
        f: Findings,
        plusAsSpace: Boolean = false,
        flagNeedlessEscapes: Boolean = false,
    ): String {
        checkRaw(raw, component, f)
        val decoded = percentDecode(raw, component, f, plusAsSpace, flagNeedlessEscapes)
        checkCodePoints(decoded, component, f)
        if (containsPercentEscape(decoded)) f.add(URI_DOUBLE_ENCODING, component)
        return decoded
    }

    /** Checks on the text as received: raw spaces, plus everything [checkCodePoints] finds. */
    private fun checkRaw(s: String, component: UriComponent, f: Findings) {
        if (' ' in s) f.add(URI_WHITESPACE, component)
        checkCodePoints(s, component, f)
    }

    /**
     * Null bytes, C0/DEL/C1 controls, Unicode format characters (Cf), Unicode whitespace
     * other than U+0020 (Zs, Zl, Zp), and unpaired UTF-16 surrogates, which have no UTF-8
     * form and are reported as invalid UTF-8. Runs on raw and on decoded text, so both
     * a raw and an encoded U+00A0 are caught. U+0020 is handled only by [checkRaw],
     * because an encoded `%20` is legitimate.
     */
    private fun checkCodePoints(s: String, component: UriComponent, f: Findings) {
        var i = 0
        while (i < s.length) {
            val c = s[i]
            val cp: Int
            if (c.isHighSurrogate() && i + 1 < s.length && s[i + 1].isLowSurrogate()) {
                cp = Character.toCodePoint(c, s[i + 1])
                i += 2
            } else if (c.isSurrogate()) {
                f.add(URI_INVALID_UTF8, component)
                i += 1
                continue
            } else {
                cp = c.code
                i += 1
            }
            when {
                cp == 0 -> f.add(URI_NULL_BYTE, component)
                cp < 0x20 || cp == 0x7F || cp in 0x80..0x9F -> f.add(URI_CONTROL_CHAR, component)
                cp == 0x20 -> Unit
                else -> when (Character.getType(cp)) {
                    Character.FORMAT.toInt() -> f.add(URI_FORMAT_CHAR, component)
                    Character.SPACE_SEPARATOR.toInt(),
                    Character.LINE_SEPARATOR.toInt(),
                    Character.PARAGRAPH_SEPARATOR.toInt(),
                    -> f.add(URI_WHITESPACE, component)
                }
            }
        }
    }

    /**
     * Decodes `%XX` escapes once. Consecutive escapes are decoded together as strict UTF-8
     * (overlong forms and encoded surrogates are rejected). Raw characters are kept as is,
     * except `+`, which becomes a space when [plusAsSpace] is set (query names and values).
     */
    private fun percentDecode(
        s: String,
        component: UriComponent,
        f: Findings,
        plusAsSpace: Boolean,
        flagNeedlessEscapes: Boolean,
    ): String {
        val out = StringBuilder(s.length)
        val bytes = ByteArray(s.length / 3 + 1)
        var n = 0

        fun flush() {
            if (n == 0) return
            try {
                out.append(
                    Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes, 0, n)),
                )
            } catch (e: CharacterCodingException) {
                f.add(URI_INVALID_UTF8, component)
                out.append('�')
            }
            n = 0
        }

        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '%') {
                val hi = if (i + 1 < s.length) hexValue(s[i + 1]) else -1
                val lo = if (i + 2 < s.length) hexValue(s[i + 2]) else -1
                if (hi >= 0 && lo >= 0) {
                    val b = hi * 16 + lo
                    if (flagNeedlessEscapes && isUnreserved(b)) f.add(URI_NON_CANONICAL, component)
                    bytes[n++] = b.toByte()
                    i += 3
                    continue
                }
                f.add(URI_PERCENT_MALFORMED, component)
            }
            flush()
            out.append(if (plusAsSpace && c == '+') ' ' else c)
            i += 1
        }
        flush()
        return out.toString()
    }

    private fun containsPercentEscape(s: String): Boolean {
        var i = s.indexOf('%')
        while (i >= 0 && i + 2 < s.length) {
            if (hexValue(s[i + 1]) >= 0 && hexValue(s[i + 2]) >= 0) return true
            i = s.indexOf('%', i + 1)
        }
        return false
    }

    private fun hexValue(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> -1
    }

    /** RFC 3986 unreserved: ALPHA / DIGIT / "-" / "." / "_" / "~". */
    private fun isUnreserved(b: Int): Boolean {
        val c = b.toChar()
        return b < 0x80 && (c.isAsciiLetter() || c in '0'..'9' || c == '-' || c == '.' || c == '_' || c == '~')
    }

    private fun Char.isAsciiLetter(): Boolean = this in 'a'..'z' || this in 'A'..'Z'

    private fun Char.isHostChar(): Boolean = this in 'a'..'z' || this in '0'..'9' || this == '-'

    /** Insertion-ordered, duplicate-free collection of findings. */
    private class Findings {
        private val set = LinkedHashSet<Finding>()
        fun add(code: ViolationCode, component: UriComponent) {
            set.add(Finding(code, component))
        }
        fun toList(): List<Finding> = set.toList()
    }
}
