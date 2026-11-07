package org.dvwa.android

import android.util.Base64

/**
 * There is no browser and no JavaScript engine in this app. Instead, the HTML a vulnerable
 * DVWA page WOULD have sent to the browser is analysed here: if it contains markup that a
 * browser would turn into script execution, we report what would have run and simulate the
 * visible effect (alert/prompt/confirm text, cookie theft, redirects) natively.
 */
object Xss {
    data class Hit(
        val vector: String,      // e.g. "<script>", "<img onerror>", "javascript: URL"
        val code: String,        // the JavaScript that would run
        val auto: Boolean,       // runs on page load (true) or needs a click/hover (false)
        val tag: String = "",
        val attrs: String = "",
        val src: String? = null, // external script URL for <script src>
    )

    private val scriptRe = Regex("(?is)<script\\b([^>]*)>(.*?)</script\\s*>")
    private val tagRe = Regex("(?is)<([a-z][a-z0-9-]*)((?:[\\s/]+[^>]*)?)>?")
    private val handlerRe = Regex("(?is)(?:^|[\\s/\"'])on([a-z]+)\\s*=\\s*(\"([^\"]*)\"|'([^']*)'|([^\\s>]+))")
    private val jsUrlRe = Regex("(?is)(?:^|[\\s/\"'])(href|src|action|formaction|data)\\s*=\\s*[\"']?\\s*(javascript:[^\"'>]*)")
    private val autoEvents = setOf("error", "load", "focus", "toggle", "animationstart", "animationend", "transitionend", "begin", "pageshow", "start", "focusin", "readystatechange")

    /** Analyse rendered HTML. */
    fun scan(html: String): List<Hit> {
        val hits = ArrayList<Hit>()
        for (m in scriptRe.findAll(html)) {
            val attrs = m.groupValues[1]
            val src = Regex("(?is)\\bsrc\\s*=\\s*(\"([^\"]*)\"|'([^']*)'|([^\\s>]+))").find(attrs)?.let { s ->
                s.groupValues[2].ifEmpty { s.groupValues[3].ifEmpty { s.groupValues[4] } }
            }
            hits += Hit(if (src != null) "<script src>" else "<script>", m.groupValues[2].trim(), true, "script", attrs, src)
        }
        val noScripts = scriptRe.replace(html, " ")
        for (t in tagRe.findAll(noScripts)) {
            val tag = t.groupValues[1].lowercase()
            val attrs = t.groupValues[2]
            for (h in handlerRe.findAll(attrs)) {
                val ev = h.groupValues[1].lowercase()
                val code = U.unentity(h.groupValues[3].ifEmpty { h.groupValues[4].ifEmpty { h.groupValues[5] } })
                val auto = ev in autoEvents && when (ev) {
                    "focus", "focusin" -> attrs.contains("autofocus", true)
                    "toggle" -> attrs.contains("open", true)
                    else -> true
                }
                hits += Hit("<$tag on$ev>", code, auto, tag, attrs)
            }
            for (j in jsUrlRe.findAll(attrs)) {
                val code = U.urldecode(U.unentity(j.groupValues[2])).removePrefix("javascript:").removePrefix("JAVASCRIPT:")
                val auto = tag == "iframe" || tag == "embed" || tag == "object"
                hits += Hit("<$tag ${j.groupValues[1]}=javascript:>", code, auto, tag, attrs)
            }
        }
        return hits
    }

    /** Simulate what the injected JavaScript would visibly do. Returns human-readable effects. */
    fun simulate(code: String, depth: Int = 0): List<String> {
        val out = ArrayList<String>()
        if (depth > 3) return out
        // eval(atob('...')) / eval(String.fromCharCode(...))
        Regex("(?is)eval\\s*\\(\\s*atob\\s*\\(\\s*['\"`]([A-Za-z0-9+/=]+)['\"`]\\s*\\)\\s*\\)").findAll(code).forEach {
            val dec = try { String(Base64.decode(it.groupValues[1], Base64.DEFAULT)) } catch (e: Exception) { "" }
            out += "eval(atob(…)) decoded to: $dec"
            out += simulate(dec, depth + 1)
        }
        Regex("(?is)\\b(alert|prompt|confirm|print)\\s*(?:\\(([^)]*)\\)|`([^`]*)`)").findAll(code).forEach {
            val fn = it.groupValues[1]
            val arg = if (it.groupValues[3].isNotEmpty() || it.value.contains('`')) it.groupValues[3] else evalArg(it.groupValues[2])
            out += "$fn dialog → \"$arg\""
        }
        Regex("(?is)(?:document|window)\\.location(?:\\.href)?\\s*=\\s*([^;]+)").findAll(code).forEach {
            out += "Victim browser navigated to: ${evalArg(it.groupValues[1])} (simulated, nothing leaves the device)"
        }
        Regex("(?is)(?:fetch|navigator\\.sendBeacon)\\s*\\(([^,)]*)").findAll(code).forEach {
            out += "HTTP request to ${evalArg(it.groupValues[1])} (simulated exfiltration, no network)"
        }
        Regex("(?is)\\.src\\s*=\\s*([^;]+)").findAll(code).forEach {
            out += "Image/script beacon to ${evalArg(it.groupValues[1])} (simulated exfiltration, no network)"
        }
        Regex("(?is)document\\.write(?:ln)?\\s*\\(([^)]*)\\)").findAll(code).forEach {
            out += "document.write → ${evalArg(it.groupValues[1])}"
        }
        Regex("(?is)console\\.log\\s*\\(([^)]*)\\)").findAll(code).forEach {
            out += "console.log → ${evalArg(it.groupValues[1])}"
        }
        if (out.isEmpty() && code.isNotBlank()) out += "Script executed: ${code.take(200)}"
        return out
    }

    /** Tiny expression evaluator for alert() arguments: literals, concatenation, cookie/domain. */
    fun evalArg(expr: String): String {
        val parts = ArrayList<String>()
        var cur = StringBuilder(); var q: Char? = null; var depth = 0
        for (c in expr.trim()) {
            if (q != null) { cur.append(c); if (c == q) q = null; continue }
            when (c) {
                '\'', '"', '`' -> { q = c; cur.append(c) }
                '(' -> { depth++; cur.append(c) }
                ')' -> { depth--; cur.append(c) }
                '+' -> if (depth == 0) { parts += cur.toString(); cur = StringBuilder() } else cur.append(c)
                else -> cur.append(c)
            }
        }
        parts += cur.toString()
        return parts.joinToString("") { p0 ->
            val p = p0.trim()
            val fcc = Regex("(?i)^String\\.fromCharCode\\s*\\(([^)]*)\\)$").find(p)
            when {
                p.isEmpty() -> ""
                p.length >= 2 && (p[0] == '\'' || p[0] == '"' || p[0] == '`') && p.last() == p[0] -> p.substring(1, p.length - 1)
                p.matches(Regex("-?\\d+(\\.\\d+)?")) -> p
                p.equals("document.cookie", true) -> Session.cookieHeader()
                p.equals("document.domain", true) || p.equals("window.origin", true) || p.equals("location.host", true) -> "127.0.0.1"
                p.equals("document.location", true) || p.equals("location.href", true) || p.equals("window.location", true) -> "http://127.0.0.1/"
                p.startsWith("encodeURIComponent(", true) || p.startsWith("escape(", true) || p.startsWith("btoa(", true) ->
                    evalArg(p.substringAfter('(').removeSuffix(")"))
                fcc != null -> fcc.groupValues[1].split(',').mapNotNull { it.trim().toIntOrNull()?.toChar() }.joinToString("")
                p.startsWith("/") && p.lastIndexOf('/') > 0 -> p.substring(1, p.lastIndexOf('/'))
                else -> p
            }
        }
    }

    /** One-line verdict + effects for display. */
    fun describe(h: Hit): String {
        val trig = if (h.auto) "runs automatically on page load" else "runs when the victim clicks/hovers"
        return "${h.vector} — $trig\n" + simulate(h.code).joinToString("\n") { "  • $it" }
    }

    /** First dialog text (for a native popup imitating the browser's alert box). */
    fun firstDialog(hits: List<Hit>): String? {
        for (h in hits) for (e in simulate(h.code)) {
            val m = Regex("^(alert|prompt|confirm|print) dialog → \"(.*)\"$", RegexOption.DOT_MATCHES_ALL).find(e)
            if (m != null) return m.groupValues[2]
        }
        return null
    }
}
