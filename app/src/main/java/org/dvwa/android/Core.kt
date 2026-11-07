package org.dvwa.android

import java.net.URLDecoder
import java.net.URLEncoder
import java.security.MessageDigest
import java.security.SecureRandom

object U {
    val rnd = SecureRandom()
    fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    fun md5(s: String) = hex(MessageDigest.getInstance("MD5").digest(s.toByteArray(Charsets.UTF_8)))
    fun sha1(s: String) = hex(MessageDigest.getInstance("SHA-1").digest(s.toByteArray(Charsets.UTF_8)))
    fun sha256(s: String) = hex(MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8)))
    fun randHex(n: Int): String { val b = ByteArray(n); rnd.nextBytes(b); return hex(b) }
    fun rand(lo: Int, hi: Int) = lo + rnd.nextInt(hi - lo + 1)

    /** PHP htmlspecialchars (ENT_QUOTES-ish as in PHP 8.1 default) */
    fun h(s: String?): String = (s ?: "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace("\"", "&quot;").replace("'", "&#039;")

    /** mysqli_real_escape_string */
    fun esc(s: String): String {
        val sb = StringBuilder()
        for (c in s) when (c) {
            '\\' -> sb.append("\\\\")
            '\'' -> sb.append("\\'")
            '"' -> sb.append("\\\"")
            '\n' -> sb.append("\\n")
            '\r' -> sb.append("\\r")
            '\u0000' -> sb.append("\\0")
            '\u001a' -> sb.append("\\Z")
            else -> sb.append(c)
        }
        return sb.toString()
    }
    fun addslashes(s: String): String {
        val sb = StringBuilder()
        for (c in s) when (c) {
            '\\', '\'', '"' -> sb.append('\\').append(c)
            '\u0000' -> sb.append("\\0")
            else -> sb.append(c)
        }
        return sb.toString()
    }
    fun stripslashes(s: String): String {
        val sb = StringBuilder(); var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '\\' && i + 1 < s.length) { val n = s[i + 1]; sb.append(if (n == '0') '\u0000' else n); i += 2 }
            else if (c == '\\') i++ else { sb.append(c); i++ }
        }
        return sb.toString()
    }
    fun stripTags(s: String): String = s.replace(Regex("<[^>]*>?", RegexOption.DOT_MATCHES_ALL), "").replace(Regex("<!--.*?-->"), "")
    fun isNumeric(s: String?): Boolean = s != null && Regex("^\\s*[+-]?(\\d+\\.?\\d*|\\.\\d+)([eE][+-]?\\d+)?\\s*$").matches(s)
    fun rot13(s: String) = s.map { c ->
        when (c) {
            in 'a'..'z' -> 'a' + (c - 'a' + 13) % 26
            in 'A'..'Z' -> 'A' + (c - 'A' + 13) % 26
            else -> c
        }
    }.joinToString("")

    fun urldecode(s: String): String = try { URLDecoder.decode(s, "UTF-8") } catch (e: Exception) {
        // tolerate malformed % sequences like PHP does
        val sb = StringBuilder(); var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '+') { sb.append(' '); i++ }
            else if (c == '%' && i + 2 < s.length + 0 && i + 2 <= s.length - 1 && s.substring(i + 1, i + 3).all { it.isLetterOrDigit() }) {
                try { sb.append(s.substring(i + 1, i + 3).toInt(16).toChar()); i += 3 } catch (x: Exception) { sb.append(c); i++ }
            } else { sb.append(c); i++ }
        }
        sb.toString()
    }
    fun parseQuery(q: String?): LinkedHashMap<String, String> {
        val m = LinkedHashMap<String, String>()
        if (q.isNullOrEmpty()) return m
        for (part in q.split('&')) {
            if (part.isEmpty()) continue
            val i = part.indexOf('=')
            val k = urldecode(if (i < 0) part else part.substring(0, i))
            val v = if (i < 0) "" else urldecode(part.substring(i + 1))
            m[k.removeSuffix("[]")] = v
        }
        return m
    }
    fun jsonStr(s: String?): String = org.json.JSONObject.quote(s ?: "")
    fun urlencode(s: String): String = URLEncoder.encode(s, "UTF-8")
    /** decode a few HTML entities like a browser would inside attributes */
    fun unentity(s: String): String {
        var r = Regex("&#[xX]([0-9a-fA-F]+);?").replace(s) { m -> m.groupValues[1].toIntOrNull(16)?.takeIf { it < 0xFFFF }?.toChar()?.toString() ?: m.value }
        r = Regex("&#(\\d+);?").replace(r) { m -> m.groupValues[1].toIntOrNull()?.takeIf { it < 0xFFFF }?.toChar()?.toString() ?: m.value }
        return r.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&#039;", "'").replace("&apos;", "'").replace("&amp;", "&")
    }
    fun phpUniqid(): String = java.lang.Long.toHexString(System.currentTimeMillis() / 1000) + String.format("%05x", (System.nanoTime() / 1000) % 0x100000)
}

