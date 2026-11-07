package org.dvwa.android

import java.net.URLDecoder
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
}

class Upload(val field: String, val filename: String, val type: String, val data: ByteArray)

class Req(
    val method: String, val path: String, val query: String, val get: Map<String, String>, val post: Map<String, String>,
    val cookies: Map<String, String>, val headers: Map<String, String>, val body: ByteArray, val upload: Upload?
) {
    val contentType: String get() = headers["content-type"] ?: ""
    fun req(k: String): String? = post[k] ?: get[k]
    fun has(k: String) = post.containsKey(k) || get.containsKey(k)
    val bodyText: String get() = String(body, Charsets.UTF_8)
}

class Out(var body: Any = "", var status: Int = 200, var mime: String = "text/html; charset=utf-8") {
    val headers = LinkedHashMap<String, String>()
    val cookies = ArrayList<String>()
    companion object {
        fun redirect(loc: String, code: Int = 302) = Out("", code).also { it.headers["Location"] = loc }
        fun text(s: String, code: Int = 200) = Out(s, code, "text/plain; charset=utf-8")
        fun json(s: String, code: Int = 200) = Out(s, code, "application/json; charset=UTF-8")
    }
}

class Sess(val id: String) {
    var user: String? = null
    var token: String = U.md5(U.randHex(16))
    val vars = HashMap<String, Any>()
    val messages = ArrayList<String>()
    fun newToken() { token = U.md5(U.randHex(16)) }
}

class TokenFail(val back: String) : Exception()
class Die(val out: Out) : Exception()
