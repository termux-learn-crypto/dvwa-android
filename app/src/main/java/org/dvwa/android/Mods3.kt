package org.dvwa.android

import android.text.InputFilter
import android.widget.EditText

/*
 * The JavaScript-dependent modules. There is NO WebView: each module ports the PHP that builds
 * the page, then the resulting HTML is analysed by [Xss] to decide whether a browser would
 * have executed script, and the effect is simulated natively.
 */

private val SCRIPT_FILTER_HIGH = Regex("<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t", RegexOption.IGNORE_CASE)

private fun showRendered(res: OutBox, rawHtml: String) {
    res.text(tr("Raw HTML in the response:"))
    res.pre(rawHtml)
    res.text(tr("Rendered (as text, scripts never run):"))
    res.html(rawHtml.replace(Regex("(?is)<script\\b.*?</script>"), "").ifEmpty { " " })
}

// =====================================================================================
object XssRPage : Page() {
    override val id = "xss_r"; override val title = "Reflected Cross Site Scripting (XSS)"
    override val links = listOf("https://owasp.org/www-community/attacks/xss/", "https://owasp.org/www-community/xss-filter-evasion-cheatsheet",
        "https://en.wikipedia.org/wiki/Cross-site_scripting", "http://www.cgisecurity.com/xss-faq.html", "http://www.scriptalert1.com/")

    fun respond(lv: String, name0: String): String {
        if (name0.isEmpty()) return ""
        val name = when (lv) {
            "low" -> name0
            "medium" -> name0.replace("<script>", "")
            "high" -> SCRIPT_FILTER_HIGH.replace(name0, "")
            else -> U.h(name0)
        }
        return "<pre>Hello $name</pre>"
    }

    override fun build(ui: Ui, f: PageFragment) {
        val lv = level
        val c = ui.card()
        val name = c.field(tr("What's your name?"))
        val t = c.tamper(); val tok = Tok(t, lv == "impossible")
        if (!tok.enabled) t.p(tr("Parameter travels in the URL: ?name=…  (a victim can be sent this link)"))
        val res = c.result()
        c.button(tr("Submit")) {
            val v = name.str(); val tv = tok.value()
            res.clear()
            res.info("GET /vulnerabilities/xss_r/?name=${U.urlencode(v)}")
            if (!tok.valid(tv)) { res.err(TOKEN_FAIL); tok.refresh(); return@button }
            val html = respond(lv, v)
            showRendered(res, html)
            res.xss(html)
            tok.refresh()
        }
    }
}

// =====================================================================================
object XssDPage : Page() {
    override val id = "xss_d"; override val title = "DOM Based Cross Site Scripting (XSS)"
    override val links = listOf("https://owasp.org/www-community/attacks/xss/", "https://owasp.org/www-community/attacks/DOM_Based_XSS",
        "https://www.acunetix.com/blog/articles/dom-xss-explained/")
    private val langs = listOf("English", "French", "Spanish", "German")

    /** Browser-style percent-encoding of characters a browser escapes in location.href. */
    private fun browserEncode(s: String) = buildString { for (ch in s) when (ch) {
        ' ' -> append("%20"); '"' -> append("%22"); '<' -> append("%3C"); '>' -> append("%3E"); '`' -> append("%60"); '\'' -> append("%27")
        else -> if (ch.code > 126) append(U.urlencode(ch.toString())) else append(ch) } }

    /** JavaScript decodeURI(): decodes escapes except reserved characters. */
    private fun decodeURI(s: String): String {
        val reserved = ";/?:@&=+$,#"
        val bytes = java.io.ByteArrayOutputStream(); val sb = StringBuilder(); var i = 0
        fun flush() { if (bytes.size() > 0) { sb.append(String(bytes.toByteArray(), Charsets.UTF_8)); bytes.reset() } }
        while (i < s.length) {
            if (s[i] == '%' && i + 2 < s.length + 0 && i + 2 <= s.length - 1) {
                val v = s.substring(i + 1, i + 3).toIntOrNull(16)
                if (v != null && !(v < 128 && reserved.contains(v.toChar()))) { bytes.write(v); i += 3; continue }
            }
            flush(); sb.append(s[i]); i++
        }
        flush(); return sb.toString()
    }

    override fun build(ui: Ui, f: PageFragment) {
        val lv = level
        val c = ui.card()
        c.p(tr("Please choose a language:"))
        val sp = c.spinner(tr("Language"), langs)
        val url = c.field(tr("Address bar (full URL — edit freely)"), "http://127.0.0.1/vulnerabilities/xss_d/?default=English")
        val res = c.result()
        fun load(typed: String) {
            res.clear()
            // ---- server side (PHP) sees only the part before '#'
            var href = typed
            val q = typed.substringBefore('#').substringAfter('?', "")
            val def = U.parseQuery(q)["default"]
            if (def != null) {
                when (lv) {
                    "medium" -> if (def.contains("<script", true)) { href = "http://127.0.0.1/vulnerabilities/xss_d/?default=English"; res.info(tr("Server: 302 redirect → ?default=English (\"<script\" is blocked)")) }
                    "high" -> if (def !in listOf("French", "English", "German", "Spanish")) { href = "http://127.0.0.1/vulnerabilities/xss_d/?default=English"; res.info(tr("Server: 302 redirect → ?default=English (not on the whitelist)")) }
                }
            }
            res.info(tr("Server received: GET /vulnerabilities/xss_d/") + (if (q.isNotEmpty()) "?$q" else "") + (if (typed.contains('#')) tr("   (the #fragment is never sent to the server)") else ""))
            // ---- client side: the page's own JavaScript, ported
            val loc = browserEncode(href)
            val idx = loc.indexOf("default=")
            if (idx < 0) { res.text(tr("No default= parameter: the page only writes the static option list.")); res.xss(""); return }
            val lang = loc.substring(idx + 8)
            val written = if (lv == "impossible")
                "<option value='$lang'>$lang</option><option value='' disabled='disabled'>----</option>"
            else "<option value='$lang'>${decodeURI(lang)}</option><option value='' disabled='disabled'>----</option>"
            res.text(tr("document.write() inserted into <select name=\"default\">:"))
            res.pre(written)
            res.xss(written, if (lv == "impossible") tr("the input is written without decodeURI(), so it stays URL-encoded and is never parsed as HTML") else null)
        }
        c.button(tr("Select")) { url.setText("http://127.0.0.1/vulnerabilities/xss_d/?default=" + langs[sp.selectedItemPosition]); load(url.str()) }
        c.button(tr("Load URL"), outlined = true) { load(url.str()) }
    }
}

// =====================================================================================
object XssSPage : Page() {
    override val id = "xss_s"; override val title = "Stored Cross Site Scripting (XSS)"
    override val links = listOf("https://owasp.org/www-community/attacks/xss/", "https://owasp.org/www-community/xss-filter-evasion-cheatsheet",
        "https://en.wikipedia.org/wiki/Cross-site_scripting", "http://www.cgisecurity.com/xss-faq.html", "http://www.scriptalert1.com/")

    fun sign(lv: String, msg0: String, name0: String) {
        var message = msg0.trim(); var name = name0.trim()
        val db = DvwaApp.I.db
        when (lv) {
            "low" -> { message = U.esc(U.stripslashes(message)); name = U.esc(name) }
            "medium" -> { message = U.h(U.esc(U.stripTags(U.addslashes(message)))); name = U.esc(name.replace("<script>", "")) }
            "high" -> { message = U.h(U.esc(U.stripTags(U.addslashes(message)))); name = U.esc(SCRIPT_FILTER_HIGH.replace(name, "")) }
            else -> {
                message = U.h(U.esc(U.stripslashes(message))); name = U.h(U.esc(U.stripslashes(name)))
                db.preparedExec("INSERT INTO guestbook ( comment, name ) VALUES ( ?, ? );", message, name); return
            }
        }
        db.vulnExec("INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );")
    }

    /** dvwaGuestbook() */
    fun guestbook(lv: String): List<String> = DvwaApp.I.db.prepared("SELECT name, comment FROM guestbook").map {
        val n = it["#0"] ?: ""; val m = it["#1"] ?: ""
        if (lv == "impossible") "Name: ${U.h(n)}<br />Message: ${U.h(m)}<br />" else "Name: $n<br />Message: $m<br />"
    }

    override fun build(ui: Ui, f: PageFragment) {
        val lv = level
        val c = ui.card()
        val name = c.field(tr("Name *"), maxLen = 10)
        val msg = c.field(tr("Message *"), multiline = true, maxLen = 50)
        val t = c.tamper()
        val nolimit = t.check(tr("Remove client-side maxlength (DevTools / proxy)"))
        nolimit.setOnCheckedChangeListener { _, on ->
            name.filters = if (on) arrayOf<InputFilter>() else arrayOf<InputFilter>(InputFilter.LengthFilter(10))
            msg.filters = if (on) arrayOf<InputFilter>() else arrayOf<InputFilter>(InputFilter.LengthFilter(50))
        }
        val tok = Tok(t, lv == "impossible")
        val res = c.result()
        val book = ui.card(tr("Guestbook")).result()
        fun render(popup: Boolean) {
            book.clear()
            val entries = try { guestbook(lv) } catch (e: Exception) { listOf() }
            val all = StringBuilder()
            for (e in entries) { book.html(e); book.pre(e); all.append(e) }
            if (entries.isEmpty()) book.text("(empty)")
            book.text(tr("Every visitor's browser renders the entries above. Verdict:"))
            book.xss(all.toString(), null, popup)
        }
        c.button(tr("Sign Guestbook")) { b ->
            val n = name.str(); val m = msg.str(); val tv = tok.value()
            Bg.run(b) {
                res.clear()
                if (!tok.valid(tv)) { res.err(TOKEN_FAIL); tok.refresh(); return@run }
                try { sign(lv, m, n); res.ok(tr("Entry stored in the guestbook table (SQLite).")) } catch (e: Exception) { res.err(e.message ?: "error") }
                tok.refresh()
                res.custom { render(true) }
            }
        }
        c.button(tr("Clear Guestbook"), outlined = true) {
            app.db.preparedExec("DELETE FROM guestbook"); res.clear(); res.info(tr("Guestbook cleared.")); render(false)
        }
        render(true)
    }
}

// =====================================================================================
object CspPage : Page() {
    override val id = "csp"; override val title = "Content Security Policy (CSP) Bypass"
    override val links = listOf("https://content-security-policy.com/", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
        "https://blog.mozilla.org/security/2014/10/04/csp-for-the-web-we-have/", "https://portswigger.net/research/using-form-hijacking-to-bypass-csp")
    private const val NONCE = "TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA="
    private val lowHosts = listOf("pastebin.com" to "https", "hastebin.com" to "", "www.toptal.com" to "", "example.com" to "", "code.jquery.com" to "",
        "ssl.google-analytics.com" to "https", "unpkg.com" to "", "cdn.jsdelivr.net" to "", "digi.ninja" to "")

    fun policy(lv: String) = when (lv) {
        "low" -> "script-src 'self' https://pastebin.com hastebin.com www.toptal.com example.com code.jquery.com https://ssl.google-analytics.com unpkg.com cdn.jsdelivr.net digi.ninja ;"
        "medium" -> "script-src 'self' 'unsafe-inline' 'nonce-$NONCE';"
        else -> "script-src 'self';"
    }

    private fun isSelf(src: String) = !Regex("^[a-z][a-z0-9+.-]*:|^//", RegexOption.IGNORE_CASE).containsMatchIn(src) ||
        Regex("^(https?:)?//(127\\.0\\.0\\.1|localhost)(:80)?(/|$)", RegexOption.IGNORE_CASE).containsMatchIn(src)

    private fun allowedLow(src: String): Boolean {
        if (isSelf(src)) return true
        val m = Regex("^(https?)://([^/:?#]+)", RegexOption.IGNORE_CASE).find(src) ?: return false
        val scheme = m.groupValues[1].lowercase(); val host = m.groupValues[2].lowercase()
        return lowHosts.any { (h, s) -> h == host && (s.isEmpty() || s == scheme) }
    }

    /** Content of a same-origin script: JSONP endpoint or an uploaded file. */
    private fun selfContent(lv: String, src: String): String? {
        val path = src.replace(Regex("^(https?:)?//[^/]+"), "")
        if (path.contains("jsonp_impossible.php")) return "solveSum({\"answer\":\"15\"})"
        if (path.contains("jsonp.php")) {
            val cb = U.parseQuery(path.substringAfter('?', ""))["callback"] ?: return ""
            return if (lv == "impossible") "solveSum({\"answer\":\"15\"})" else cb + "({\"answer\":\"15\"})"
        }
        val up = path.substringAfter("/hackable/uploads/", "").substringBefore('?')
        if (up.isNotEmpty() && !up.contains("..")) { val fl = java.io.File(UploadPage.dir(), up); if (fl.isFile) return fl.readText() }
        return null
    }

    override fun build(ui: Ui, f: PageFragment) {
        val lv = level
        val c = ui.card()
        c.code("Content-Security-Policy: ${policy(lv)}")
        val res = c.result()
        when (lv) {
            "low" -> {
                c.p(tr("You can include scripts from external sources, examine the Content Security Policy and enter a URL to include here:"))
                val inc = c.field(tr("include (script URL)"), "https://cdn.jsdelivr.net/gh/digininja/csp_bypass/alert.js")
                val body = c.field(tr("Simulated content served by that URL (nothing is downloaded)"), "alert(document.cookie)", multiline = true)
                c.button(tr("Include")) {
                    val src = inc.str()
                    res.clear()
                    val html = "<script src='$src'></script>"
                    res.text(tr("Page body now contains:")); res.pre(html)
                    if (!allowedLow(src)) { res.warn(tr("🛡 Refused to load the script '{0}' because it violates the following Content Security Policy directive: \"{1}\"", src, policy(lv))); return@button }
                    val code = if (isSelf(src)) selfContent(lv, src) ?: body.str() else body.str()
                    res.err(tr("⚠ CSP allowed the script — it executes (simulated)\n") + Xss.simulate(code).joinToString("\n") { "  • $it" })
                    Xss.firstDialog(listOf(Xss.Hit("<script src>", code, true)))?.let { OutBox.alert(f.requireContext(), "127.0.0.1 says", it) }
                }
            }
            else -> {
                c.p(when (lv) {
                    "medium" -> tr("Whatever you enter here gets dropped directly into the page, see if you can get an alert box to pop up.")
                    "high" -> tr("The page makes a call to ../..//vulnerabilities/csp/source/jsonp.php to load some code. Modify that page to run your own code.")
                    else -> tr("Unlike the high level, this does a JSONP call but does not use a callback, instead it hardcodes the function to call. The CSP settings only allow external JavaScript on the local server and no inline code.")
                })
                val inc = c.field(tr("include (raw HTML dropped into the page)"), if (lv == "medium") "<script nonce=\"$NONCE\">alert(1)</script>" else "<script src=\"source/jsonp.php?callback=alert(document.cookie)//\"></script>", multiline = true)
                if (lv != "medium") c.button(tr("Solve the sum"), outlined = true) {
                    res.clear(); res.info("GET source/" + (if (lv == "high") "jsonp.php?callback=solveSum" else "jsonp_impossible.php") + tr(" → solveSum({\"answer\":\"15\"})")); res.ok("1+2+3+4+5=15")
                }
                val t = c.tamper()
                t.p(tr("High level: the include parameter is POSTed (field above). Same-origin sources include source/jsonp.php and /hackable/uploads/<file>."))
                c.button(tr("Include")) {
                    val html = inc.str()
                    res.clear(); res.text(tr("Page body now contains:")); res.pre(html)
                    val hits = Xss.scan(html)
                    if (hits.isEmpty()) { res.ok(tr("No executable markup.")); return@button }
                    val fired = ArrayList<Xss.Hit>()
                    for (h in hits) {
                        val why: String? = when {
                            h.src != null -> if (isSelf(h.src) || (lv == "medium" && h.attrs.contains(NONCE))) null else tr("host not allowed by script-src")
                            lv == "medium" && h.vector == "<script>" -> if (h.attrs.contains("nonce=\"$NONCE\"") || h.attrs.contains("nonce='$NONCE'") || h.attrs.contains("nonce=$NONCE")) null else tr("inline script without the right nonce ('unsafe-inline' is ignored when a nonce is present)")
                            else -> tr("inline script/event handler blocked (no 'unsafe-inline')")
                        }
                        if (why != null) { res.warn(tr("🛡 Blocked by CSP: {0} — {1}", h.vector, why)); continue }
                        val code = if (h.src != null) (selfContent(lv, h.src) ?: run { res.warn(tr("{0}: 404 Not Found (same-origin file does not exist)", h.src)); null }) else h.code
                        if (code == null) continue
                        if (h.src != null) res.info(tr("Loaded {0} → {1}", h.src, code))
                        val eff = Xss.simulate(code)
                        if (lv == "impossible" && code.startsWith("solveSum(")) { res.ok(tr("Script ran solveSum() only — callback is hard-coded, nothing injected.")); continue }
                        fired += Xss.Hit(h.vector, code, true)
                        res.err(tr("⚠ Script executed despite CSP (simulated)\n") + eff.joinToString("\n") { "  • $it" })
                    }
                    Xss.firstDialog(fired)?.let { OutBox.alert(f.requireContext(), "127.0.0.1 says", it) }
                }
            }
        }
    }
}

// =====================================================================================
object JsPage : Page() {
    override val id = "javascript"; override val title = "JavaScript Attacks"
    override val links = listOf("https://www.w3schools.com/js/", "https://www.youtube.com/watch?v=cs7EQdWO5o0&index=17&list=WL", "https://ponyfoo.com/articles/es6-proxies-in-depth")

    private fun check(lv: String, phrase: String?, token: String?): Pair<Boolean, String> {
        if (phrase == null || token == null) return false to tr("Missing phrase or token.")
        if (phrase != "success") return false to tr("You got the phrase wrong.")
        val expected = when (lv) {
            "low" -> U.md5(U.rot13("success"))
            "medium" -> "XXsuccessXX".reversed()
            "high" -> U.sha256(U.sha256("XX" + "success".reversed()) + "ZZ")
            else -> return false to tr("You can never trust anything that comes from the user or prevent them from messing with it and so there is no impossible level.")
        }
        return if (token == expected) true to tr("Well done!") else false to tr("Invalid token.")
    }

    override fun build(ui: Ui, f: PageFragment) {
        val lv = level
        val c = ui.card()
        c.p(tr("Submit the word \"success\" to win."))
        if (lv == "impossible") c.warn(tr("You can never trust anything that comes from the user or prevent them from messing with it and so there is no impossible level."))
        val phrase = c.field(tr("Phrase"), if (lv == "high") "" else "ChangeMe")
        val t = c.tamper(tr("🛠 Hidden token field & browser console (simulated JS)"))
        // page-load JavaScript, ported
        val initial = when (lv) {
            "low" -> U.md5(U.rot13("ChangeMe"))
            "medium" -> ("XX" + "ChangeMe" + "XX").reversed()
            "high" -> U.sha256("XX" + "")      // token_part_1("") then token_part_2("XX") after 300 ms
            else -> ""
        }
        val token: EditText = t.field(tr("token (hidden input)"), initial)
        when (lv) {
            "low" -> t.button("console> generate_token()", outlined = true) { token.setText(U.md5(U.rot13(phrase.str()))) }
            "medium" -> t.button("console> do_elsesomething(\"XX\")", outlined = true) { token.setText(("XX" + phrase.str() + "XX").reversed()) }
            "high" -> {
                t.button("console> token_part_1(\"ABCD\", 44)", outlined = true) { token.setText(phrase.str().reversed()) }
                t.button("console> token_part_2(\"XX\")", outlined = true) { token.setText(U.sha256("XX" + token.str())) }
                t.button("console> token_part_3(t, \"ZZ\")", outlined = true) { token.setText(U.sha256(token.str() + "ZZ")) }
                t.p(tr("Note: the Submit button's click handler runs token_part_3() before the form is sent."))
            }
        }
        val res = c.result()
        c.button(tr("Submit")) {
            if (lv == "high") token.setText(U.sha256(token.str() + "ZZ"))  // addEventListener("click", token_part_3)
            val (ok, msg) = check(lv, phrase.str(), token.str())
            res.clear(); res.info("POST phrase=${U.urlencode(phrase.str())}&token=${token.str()}&send=Submit")
            if (ok) res.err("🎯 $msg") else res.warn(msg)
        }
    }
}

private fun Ui.warn(s: String) { val r = result(); r.warn(s) }
