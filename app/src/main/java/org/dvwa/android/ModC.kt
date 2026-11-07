package org.dvwa.android

import android.database.sqlite.SQLiteException
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.GCMParameterSpec

object ModC {
    fun handle(id: String, sub: String, c: Ctx): Out? {
        return when (id) {
            "weak_id" -> handleWeakId(sub, c)
            "xss_d" -> handleXssD(sub, c)
            "xss_r" -> handleXssR(sub, c)
            "xss_s" -> handleXssS(sub, c)
            "csp" -> handleCsp(sub, c)
            "javascript" -> handleJavascript(sub, c)
            "authbypass" -> handleAuthBypass(sub, c)
            "open_redirect" -> handleOpenRedirect(sub, c)
            "cryptography" -> handleCryptography(sub, c)
            else -> null
        }
    }

    private fun handleWeakId(sub: String, c: Ctx): Out? {
        if (sub.isNotEmpty()) return null
        var html = ""
        val level = c.level
        if (c.r.method == "POST") {
            when (level) {
                "low" -> {
                    var last = c.s.vars["last_session_id"] as? Int ?: 0
                    last++
                    c.s.vars["last_session_id"] = last
                    c.outCookiesAdd("dvwaSession=$last")
                }
                "medium" -> {
                    val cookieValue = System.currentTimeMillis() / 1000
                    c.outCookiesAdd("dvwaSession=$cookieValue")
                }
                "high" -> {
                    var last = c.s.vars["last_session_id_high"] as? Int ?: 0
                    last++
                    c.s.vars["last_session_id_high"] = last
                    val cookieValue = U.md5(last.toString())
                    val expires = System.currentTimeMillis() + 3600000L
                    c.outCookiesAdd("dvwaSession=$cookieValue; Max-Age=3600; path=/vulnerabilities/weak_id/")
                }
                "impossible" -> {
                    val cookieValue = U.randHex(20)
                    val expires = System.currentTimeMillis() + 3600000L
                    c.outCookiesAdd("dvwaSession=$cookieValue; Max-Age=3600; path=/vulnerabilities/weak_id/; Secure; HttpOnly")
                }
            }
        }
        val body = StringBuilder()
        body.append("<div class=\"body_padded\">\n")
        body.append("\t<h1>Vulnerability: Weak Session IDs</h1>\n")
        body.append("\t<p>\n\t\tThis page will set a new cookie called dvwaSession each time the button is clicked.<br />\n\t</p>\n")
        body.append("\t<form method=\"post\">\n\t\t<input type=\"submit\" value=\"Generate\" />\n\t</form>\n")
        body.append("</div>\n")
        body.append(html)
        return Out(c.page("Vulnerability: Weak Session IDs" + c.titleSeparator() + c.defaultTitle(), "weak_id", body.toString()))
    }

    private fun handleXssD(sub: String, c: Ctx): Out? {
        if (sub.isNotEmpty()) return null
        var vulnerabilityFile = when (c.level) {
            "low" -> "low.php"
            "medium" -> "medium.php"
            "high" -> "high.php"
            else -> "impossible.php"
        }
        val def = c.r.get["default"]
        if (c.level == "medium" && def != null) {
            if (def.contains("<script", ignoreCase = true)) {
                return Out.redirect("?default=English")
            }
        } else if (c.level == "high" && def != null) {
            if (def != "French" && def != "English" && def != "German" && def != "Spanish") {
                return Out.redirect("?default=English")
            }
        }
        val decodeURI = if (vulnerabilityFile == "impossible.php") "" else "decodeURI"
        val body = StringBuilder()
        body.append("<div class=\"body_padded\">\n")
        body.append("\t<h1>Vulnerability: DOM Based Cross Site Scripting (XSS)</h1>\n")
        body.append("\t<div class=\"vulnerable_code_area\">\n")
        body.append(" \t\t<p>Please choose a language:</p>\n")
        body.append("\t\t<form name=\"XSS\" method=\"GET\">\n")
        body.append("\t\t\t<select name=\"default\">\n")
        body.append("\t\t\t\t<script>\n")
        body.append("\t\t\t\t\tif (document.location.href.indexOf(\"default=\") >= 0) {\n")
        body.append("\t\t\t\t\t\tvar lang = document.location.href.substring(document.location.href.indexOf(\"default=\")+8);\n")
        body.append("\t\t\t\t\t\tdocument.write(\"<option value='\" + lang + \"'>\" + $decodeURI(lang) + \"</option>\");\n")
        body.append("\t\t\t\t\t\tdocument.write(\"<option value='' disabled='disabled'>----</option>\");\n")
        body.append("\t\t\t\t\t}\n")
        body.append("\t\t\t\t\tdocument.write(\"<option value='English'>English</option>\");\n")
        body.append("\t\t\t\t\tdocument.write(\"<option value='French'>French</option>\");\n")
        body.append("\t\t\t\t\tdocument.write(\"<option value='Spanish'>Spanish</option>\");\n")
        body.append("\t\t\t\t\tdocument.write(\"<option value='German'>German</option>\");\n")
        body.append("\t\t\t\t</script>\n")
        body.append("\t\t\t</select>\n")
        body.append("\t\t\t<input type=\"submit\" value=\"Select\" />\n")
        body.append("\t\t</form>\n")
        body.append("\t</div>\n")
        body.append("\t<h2>More Information</h2>\n")
        body.append("\t<ul>\n")
        body.append("\t\t<li>" + c.externalLink("https://owasp.org/www-community/attacks/xss/") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://owasp.org/www-community/attacks/DOM_Based_XSS") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://www.acunetix.com/blog/articles/dom-xss-explained/") + "</li>\n")
        body.append("\t</ul>\n")
        body.append("</div>\n")
        return Out(c.page("Vulnerability: DOM Based Cross Site Scripting (XSS)" + c.titleSeparator() + c.defaultTitle(), "xss_d", body.toString()))
    }

    private fun handleXssR(sub: String, c: Ctx): Out? {
        if (sub.isNotEmpty()) return null
        var html = ""
        val level = c.level
        if (level != "impossible") {
            c.headers["X-XSS-Protection"] = "0"
        }
        val name = c.r.get["name"]
        if (name != null) {
            when (level) {
                "low" -> {
                    html += "<pre>Hello $name</pre>"
                }
                "medium" -> {
                    val cleanName = name.replace("<script>", "")
                    html += "<pre>Hello $cleanName</pre>"
                }
                "high" -> {
                    val cleanName = name.replace(Regex("(?i)<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t"), "")
                    html += "<pre>Hello $cleanName</pre>"
                }
                "impossible" -> {
                    c.checkToken(c.r.req("user_token"), "index.php")
                    val cleanName = U.h(name)
                    html += "<pre>Hello $cleanName</pre>"
                }
            }
        }
        if (level == "impossible") {
            c.s.newToken()
        }
        val body = StringBuilder()
        body.append("\n<div class=\"body_padded\">\n")
        body.append("\t<h1>Vulnerability: Reflected Cross Site Scripting (XSS)</h1>\n")
        body.append("\t<div class=\"vulnerable_code_area\">\n")
        body.append("\t\t<form name=\"XSS\" action=\"#\" method=\"GET\">\n")
        body.append("\t\t\t<p>\n")
        body.append("\t\t\t\tWhat's your name?\n")
        body.append("\t\t\t\t<input type=\"text\" name=\"name\">\n")
        body.append("\t\t\t\t<input type=\"submit\" value=\"Submit\">\n")
        body.append("\t\t\t</p>\n")
        if (level == "impossible") {
            body.append("           ").append(c.tokenField()).append("\n")
        }
        body.append("\t\t</form>\n")
        body.append("\t\t$html\n")
        body.append("\t</div>\n")
        body.append("\t<h2>More Information</h2>\n")
        body.append("\t<ul>\n")
        body.append("\t\t<li>" + c.externalLink("https://owasp.org/www-community/attacks/xss/") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://owasp.org/www-community/xss-filter-evasion-cheatsheet") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://en.wikipedia.org/wiki/Cross-site_scripting") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://www.cgisecurity.com/xss-faq.html") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://www.scriptalert1.com/") + "</li>\n")
        body.append("\t</ul>\n")
        body.append("</div>\n")
        return Out(c.page("Vulnerability: Reflected Cross Site Scripting (XSS)" + c.titleSeparator() + c.defaultTitle(), "xss_r", body.toString()))
    }

    private fun handleXssS(sub: String, c: Ctx): Out? {
        if (sub.isNotEmpty()) return null
        val level = c.level
        if (c.r.has("btnClear")) {
            try {
                c.db.vulnExec("DELETE FROM guestbook;")
            } catch (e: SQLiteException) {
                return Out("<pre>${e.message}</pre>")
            }
        }
        var html = ""
        if (c.r.has("btnSign")) {
            val message = c.r.post["mtxMessage"]?.trim() ?: ""
            val name = c.r.post["txtName"]?.trim() ?: ""
            try {
                when (level) {
                    "low" -> {
                        val sm = U.esc(U.stripslashes(message))
                        val sn = U.esc(name)
                        c.db.vulnExec("INSERT INTO guestbook ( comment, name ) VALUES ( '$sm', '$sn' );")
                    }
                    "medium" -> {
                        val sm = U.esc(U.stripTags(U.addslashes(message)))
                        val smed = U.h(sm)
                        val sn = U.esc(name.replace("<script>", ""))
                        c.db.vulnExec("INSERT INTO guestbook ( comment, name ) VALUES ( '$smed', '$sn' );")
                    }
                    "high" -> {
                        val sm = U.esc(U.stripTags(U.addslashes(message)))
                        val smed = U.h(sm)
                        val sn = U.esc(name.replace(Regex("(?i)<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t"), ""))
                        c.db.vulnExec("INSERT INTO guestbook ( comment, name ) VALUES ( '$smed', '$sn' );")
                    }
                    "impossible" -> {
                        c.checkToken(c.r.req("user_token"), "index.php")
                        val sm = U.stripslashes(message)
                        val smesc = U.esc(sm)
                        val smed = U.h(sm)
                        val sn = U.stripslashes(name)
                        val snesc = U.esc(sn)
                        val sned = U.h(sn)
                        c.db.preparedExec("INSERT INTO guestbook ( comment, name ) VALUES ( ?, ? );", smed, sned)
                    }
                }
            } catch (e: SQLiteException) {
                return Out("<pre>${e.message}</pre>")
            }
        }
        if (level == "impossible") {
            c.s.newToken()
        }

        val guestbookHtml = StringBuilder()
        try {
            val rows = c.db.vulnQuery("SELECT name, comment FROM guestbook")
            for (row in rows) {
                val rName = row["name"] ?: ""
                val rComment = row["comment"] ?: ""
                val dispName = if (level == "impossible") U.h(rName) else rName
                val dispComment = if (level == "impossible") U.h(rComment) else rComment
                guestbookHtml.append("<div id=\"guestbook_comments\">Name: $dispName<br />Message: $dispComment<br /></div>\n")
            }
        } catch (_: Exception) {}

        val body = StringBuilder()
        body.append("\n<div class=\"body_padded\">\n")
        body.append("\t<h1>Vulnerability: Stored Cross Site Scripting (XSS)</h1>\n")
        body.append("\t<div class=\"vulnerable_code_area\">\n")
        body.append("\t\t<form method=\"post\" name=\"guestform\">\n")
        body.append("\t\t\t<table width=\"550\" border=\"0\" cellpadding=\"2\" cellspacing=\"1\">\n")
        body.append("\t\t\t\t<tr>\n")
        body.append("\t\t\t\t\t<td width=\"100\">Name *</td>\n")
        body.append("\t\t\t\t\t<td><input name=\"txtName\" type=\"text\" size=\"30\" maxlength=\"10\"></td>\n")
        body.append("\t\t\t\t</tr>\n")
        body.append("\t\t\t\t<tr>\n")
        body.append("\t\t\t\t\t<td width=\"100\">Message *</td>\n")
        body.append("\t\t\t\t\t<td><textarea name=\"mtxMessage\" cols=\"50\" rows=\"3\" maxlength=\"50\"></textarea></td>\n")
        body.append("\t\t\t\t</tr>\n")
        body.append("\t\t\t\t<tr>\n")
        body.append("\t\t\t\t\t<td width=\"100\">&nbsp;</td>\n")
        body.append("\t\t\t\t\t<td>\n")
        body.append("\t\t\t\t\t\t<input name=\"btnSign\" type=\"submit\" value=\"Sign Guestbook\" onclick=\"return validateGuestbookForm(this.form);\" />\n")
        body.append("\t\t\t\t\t\t<input name=\"btnClear\" type=\"submit\" value=\"Clear Guestbook\" onClick=\"return confirmClearGuestbook();\" />\n")
        body.append("\t\t\t\t\t</td>\n")
        body.append("\t\t\t\t</tr>\n")
        body.append("\t\t\t</table>\n")
        if (level == "impossible") {
            body.append("           ").append(c.tokenField()).append("\n")
        }
        body.append("\t\t</form>\n")
        body.append("\t\t$html\n")
        body.append("\t</div>\n")
        body.append("\t<br />\n")
        body.append(guestbookHtml.toString())
        body.append("\t<br />\n")
        body.append("\t<h2>More Information</h2>\n")
        body.append("\t<ul>\n")
        body.append("\t\t<li>" + c.externalLink("https://owasp.org/www-community/attacks/xss") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://owasp.org/www-community/xss-filter-evasion-cheatsheet") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://en.wikipedia.org/wiki/Cross-site_scripting") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://www.cgisecurity.com/xss-faq.html") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://www.scriptalert1.com/") + "</li>\n")
        body.append("\t</ul>\n")
        body.append("</div>\n")
        return Out(c.page("Vulnerability: Stored Cross Site Scripting (XSS)" + c.titleSeparator() + c.defaultTitle(), "xss_s", body.toString()))
    }

    private fun handleCsp(sub: String, c: Ctx): Out? {
        val level = c.level
        if (sub == "source/jsonp.php") {
            val cb = c.r.get["callback"]
            if (cb.isNullOrEmpty()) return Out("", 200, "application/json; charset=UTF-8")
            val outp = "{\"answer\":\"15\"}"
            return Out("$cb($outp)", 200, "application/json; charset=UTF-8")
        }
        if (sub == "source/jsonp_impossible.php") {
            val outp = "{\"answer\":\"15\"}"
            return Out("solveSum ($outp)", 200, "application/json; charset=UTF-8")
        }
        if (sub.isNotEmpty()) return null

        when (level) {
            "low" -> c.headers["Content-Security-Policy"] = "script-src 'self' https://pastebin.com hastebin.com www.toptal.com example.com code.jquery.com https://ssl.google-analytics.com unpkg.com cdn.jsdelivr.net digi.ninja ;"
            "medium" -> {
                c.headers["Content-Security-Policy"] = "script-src 'self' 'unsafe-inline' 'nonce-TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=';"
                c.headers["X-XSS-Protection"] = "0"
            }
            "high", "impossible" -> {
                c.headers["Content-Security-Policy"] = "script-src 'self';"
            }
        }

        val inner = StringBuilder()
        if (level == "low") {
            if (c.r.has("include")) {
                val inc = c.r.post["include"]
                inner.append("\n\t<script src='$inc'></script>\n")
            }
            inner.append("""
<form name="csp" method="POST">
	<p>You can include scripts from external sources, examine the Content Security Policy and enter a URL to include here (Offline note: external hosts are blocked in this app; host your script on this server (e.g. upload a .js via File Upload at /hackable/uploads/ or use /pastebin/)):</p>
	<input size="50" type="text" name="include" value="" id="include" />
	<input type="submit" value="Include" />
</form>
<p>
	You will probably need to do some reading up on what some of the domains allowed by the CSP do and how they can be used.
</p>
""")
        } else if (level == "medium") {
            if (c.r.has("include")) {
                val inc = c.r.post["include"]
                inner.append("\n\t$inc\n")
            }
            inner.append("""
<form name="csp" method="POST">
	<p>Whatever you enter here gets dropped directly into the page, see if you can get an alert box to pop up.</p>
	<input size="50" type="text" name="include" value="" id="include" />
	<input type="submit" value="Include" />
</form>
""")
        } else if (level == "high") {
            if (c.r.has("include")) {
                val inc = c.r.post["include"]
                inner.append("\n\t$inc\n")
            }
            inner.append("""
<form name="csp" method="POST">
	<p>The page makes a call to source/jsonp.php to load some code. Modify that page to run your own code.</p>
	<p>1+2+3+4+5=<span id="answer"></span></p>
	<input type="button" id="solve" value="Solve the sum" />
</form>
<script src="source/high.js"></script>
""")
        } else {
            if (c.r.has("include")) {
                val inc = c.r.post["include"]
                inner.append("\n\t$inc\n")
            }
            inner.append("""
<form name="csp" method="POST">
	<p>Unlike the high level, this does a JSONP call but does not use a callback, instead it hardcodes the function to call.</p><p>The CSP settings only allow external JavaScript on the local server and no inline code.</p>
	<p>1+2+3+4+5=<span id="answer"></span></p>
	<input type="button" id="solve" value="Solve the sum" />
</form>
<script src="source/impossible.js"></script>
""")
        }

        val body = StringBuilder()
        body.append("<div class=\"body_padded\">\n")
        body.append("\t<h1>Vulnerability: Content Security Policy (CSP) Bypass</h1>\n")
        body.append("\t<div class=\"vulnerable_code_area\">\n")
        body.append(inner.toString())
        body.append("\t</div>\n")
        body.append("\t<h2>More Information</h2>\n")
        body.append("\t<ul>\n")
        body.append("\t\t<li>" + c.externalLink("https://content-security-policy.com/", "Content Security Policy Reference") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP", "Mozilla Developer Network - CSP: script-src") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://blog.mozilla.org/security/2014/10/04/csp-for-the-web-we-have/", "Mozilla Security Blog - CSP for the web we have") + "</li>\n")
        body.append("\t</ul>\n")
        body.append("\t<p><i>Module developed by <a href='https://twitter.com/digininja'>Digininja</a>.</i></p>\n")
        body.append("</div>\n")
        return Out(c.page("Vulnerability: Content Security Policy (CSP) Bypass" + c.titleSeparator() + c.defaultTitle(), "csp", body.toString()))
    }

    private fun handleJavascript(sub: String, c: Ctx): Out? {
        if (sub.isNotEmpty()) return null
        val level = c.level
        var message = ""
        if (c.r.method == "POST") {
            val phrase = c.r.post["phrase"]
            val token = c.r.post["token"]
            if (phrase != null && token != null) {
                if (phrase == "success") {
                    when (level) {
                        "low" -> {
                            if (token == U.md5(U.rot13("success"))) {
                                message = "<p style='color:red'>Well done!</p>"
                            } else {
                                message = "<p>Invalid token.</p>"
                            }
                        }
                        "medium" -> {
                            if (token == "XXsuccessXX".reversed()) {
                                message = "<p style='color:red'>Well done!</p>"
                            } else {
                                message = "<p>Invalid token.</p>"
                            }
                        }
                        "high" -> {
                            val innerHash = U.sha256("XX" + "success".reversed())
                            val expected = U.sha256(innerHash + "ZZ")
                            if (token == expected) {
                                message = "<p style='color:red'>Well done!</p>"
                            } else {
                                message = "<p>Invalid token.</p>"
                            }
                        }
                    }
                } else {
                    message = "<p>You got the phrase wrong.</p>"
                }
            } else {
                message = "<p>Missing phrase or token.</p>"
            }
        }

        val body = StringBuilder()
        if (level == "impossible") {
            body.append("<div class=\"body_padded\">\n")
            body.append("\t<h1>Vulnerability: JavaScript Attacks</h1>\n")
            body.append("\t<div class=\"vulnerable_code_area\">\n")
            body.append("\t<p>\n\t\tYou can never trust anything that comes from the user or prevent them from messing with it and so there is no impossible level.\n\t</p>\n")
        } else {
            body.append("<div class=\"body_padded\">\n")
            body.append("\t<h1>Vulnerability: JavaScript Attacks</h1>\n")
            body.append("\t<div class=\"vulnerable_code_area\">\n")
            body.append("\t<p>\n\t\tSubmit the word \"success\" to win.\n\t</p>\n")
            body.append("\t$message\n")
            body.append("\t<form name=\"low_js\" method=\"post\">\n")
            body.append("\t\t<input type=\"hidden\" name=\"token\" value=\"\" id=\"token\" />\n")
            body.append("\t\t<label for=\"phrase\">Phrase</label> <input type=\"text\" name=\"phrase\" value=\"ChangeMe\" id=\"phrase\" />\n")
            body.append("\t\t<input type=\"submit\" id=\"send\" name=\"send\" value=\"Submit\" />\n")
            body.append("\t</form>\n")
            when (level) {
                "low" -> body.append(c.asset("www/vulnerabilities/javascript/source/low_inline.html"))
                "medium" -> body.append("<script src=\"/vulnerabilities/javascript/source/medium.js\"></script>")
                "high" -> body.append("<script src=\"/vulnerabilities/javascript/source/high.js\"></script>")
            }
        }
        body.append("\t</div>\n")
        body.append("\t<h2>More Information</h2>\n")
        body.append("\t<ul>\n")
        body.append("\t\t<li>" + c.externalLink("https://www.w3schools.com/js/") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://www.youtube.com/watch?v=cs7EQdWO5o0&index=17&list=WL") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://ponyfoo.com/articles/es6-proxies-in-depth") + "</li>\n")
        body.append("\t</ul>\n")
        body.append("\t<p><i>Module developed by <a href='https://twitter.com/digininja'>Digininja</a>.</i></p>\n")
        body.append("</div>\n")
        return Out(c.page("Vulnerability: JavaScript Attacks" + c.titleSeparator() + c.defaultTitle(), "javascript", body.toString()))
    }

    private fun handleAuthBypass(sub: String, c: Ctx): Out? {
        val level = c.level
        if (sub == "get_user_data.php") {
            if ((level == "high" || level == "impossible") && c.user != "admin") {
                return Out.json("{\"result\":\"fail\",\"error\":\"Access denied\"}")
            }
            try {
                val rows = c.db.vulnQuery("SELECT user_id, first_name, last_name FROM users")
                val arr = JSONArray()
                for (row in rows) {
                    val uid = row["user_id"]
                    val fn = if (level == "impossible") U.h(row["first_name"]) else row["first_name"]
                    val ln = if (level == "impossible") U.h(row["last_name"]) else row["last_name"]
                    val obj = JSONObject()
                    obj.put("user_id", uid)
                    obj.put("first_name", fn)
                    obj.put("surname", ln)
                    arr.put(obj)
                }
                return Out.json(arr.toString())
            } catch (e: Exception) {
                return Out.json("[]")
            }
        }
        if (sub == "change_user_details.php") {
            if (level == "impossible" && c.user != "admin") {
                return Out.json("{\"result\":\"fail\",\"error\":\"Access denied\"}")
            }
            if (c.r.method != "POST") {
                return Out.json("{\"result\":\"fail\",\"error\":\"Only POST requests are accepted\"}")
            }
            try {
                val jsonStr = c.r.bodyText
                val data = JSONObject(jsonStr)
                val id = data.optString("id")
                val fn = data.optString("first_name")
                val sn = data.optString("surname")
                val query = "UPDATE users SET first_name = '$fn', last_name = '$sn' where user_id = $id"
                c.db.vulnExec(query)
                return Out.json("{\"result\":\"ok\"}")
            } catch (e: SQLiteException) {
                return Out("<pre>${e.message}</pre>")
            } catch (e: Exception) {
                return Out.json("{\"result\":\"fail\",\"error\":\"Invalid format\"}")
            }
        }
        if (sub.isNotEmpty()) return null

        if (level != "low" && c.user != "admin") {
            return Out("Unauthorised", 403)
        }

        val body = StringBuilder()
        body.append("<div class=\"body_padded\">\n")
        body.append("\t<h1>Vulnerability: Authorisation Bypass</h1>\n")
        body.append("\t<p>This page should only be accessible by the admin user. Your challenge is to gain access to the features using one of the other users, for example <i>gordonb</i> / <i>abc123</i>.</p>\n")
        body.append("\t<div class=\"vulnerable_code_area\">\n")
        body.append("\t<div style=\"font-weight: bold;color: red;font-size: 120%;\" id=\"save_result\"></div>\n")
        body.append("\t<div id=\"user_form\"></div>\n")
        body.append("\t<p>\n\t\tWelcome to the user manager, please enjoy updating your user's details.\n\t</p>\n")
        body.append("<script src='authbypass.js'></script>\n")
        body.append("<table id='user_table'>\n")
        body.append("\t<thead>\n")
        body.append("\t\t<th>ID</th>\n")
        body.append("\t\t<th>First Name</th>\n")
        body.append("\t\t<th>Surname</th>\n")
        body.append("\t\t<th>Update</th>\n")
        body.append("\t</thead>\n")
        body.append("\t<tbody>\n")
        body.append("\t</tbody>\n")
        body.append("</table>\n")
        body.append("<script>\n\tpopulate_form();\n</script>\n")
        body.append("\t</div>\n")
        body.append("</div>")
        return Out(c.page("Vulnerability: Authorisation Bypass" + c.titleSeparator() + c.defaultTitle(), "authbypass", body.toString()))
    }

    private fun handleOpenRedirect(sub: String, c: Ctx): Out? {
        if (sub == "source/info.php") {
            val idStr = c.r.get["id"]
            var info = ""
            if (idStr != null && U.isNumeric(idStr)) {
                info = when (idStr.trim().toDouble().toInt()) {
                    1 -> "Why did he come to you?<br />I got a record, I was Zero Cool<br />Zero Cool. Crashed 1507 systems in one day, biggest crash in history, front page, New York Times August 10th 1988."
                    2 -> "Who are you anyway?<br />Johnny.<br />Johnny who?<br />Just... Johnny?"
                    else -> "Some other stuff"
                }
            }
            if (info.isEmpty()) {
                val b = StringBuilder()
                b.append("<p>Missing quote ID.</p>")
                return Out(b.toString(), 500)
            }
            val body = StringBuilder()
            body.append("<div class=\"body_padded\">\n")
            body.append("\t<h1>Vulnerability: Open HTTP Redirect</h1>\n")
            body.append("\t<div class=\"vulnerable_code_area\">\n")
            body.append("\t\t<h2>Hacker Quotes</h2>\n")
            body.append("\t\t<p>\n\t\t\t$info\n\t\t</p>\n")
            body.append("\t\t<p><a href='../'>Back</a></p>\n")
            body.append("\t</div>\n")
            body.append("\t<h2>More Information</h2>\n")
            body.append("\t<ul>\n")
            body.append("\t\t<li>" + c.externalLink("https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html", "OWASP Unvalidated Redirects and Forwards Cheat Sheet") + "</li>\n")
            body.append("\t\t<li>" + c.externalLink("https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect", "WSTG - Testing for Client-side URL Redirect") + "</li>\n")
            body.append("\t\t<li>" + c.externalLink("https://cwe.mitre.org/data/definitions/601.html", "Mitre - CWE-601: URL Redirection to Untrusted Site ('Open Redirect')") + "</li>\n")
            body.append("\t</ul>\n")
            body.append("</div>\n")
            return Out(c.page("Vulnerability: Open HTTP Redirect" + c.titleSeparator() + c.defaultTitle(), "open_redirect", body.toString()))
        }

        if (sub == "source/low.php") {
            val red = c.r.get["redirect"]
            if (!red.isNullOrEmpty()) {
                return Out.redirect(red)
            }
            return Out("<p>Missing redirect target.</p>", 500)
        }
        if (sub == "source/medium.php") {
            val red = c.r.get["redirect"]
            if (!red.isNullOrEmpty()) {
                if (red.contains("http://", true) || red.contains("https://", true)) {
                    return Out("<p>Absolute URLs not allowed.</p>", 500)
                }
                return Out.redirect(red)
            }
            return Out("<p>Missing redirect target.</p>", 500)
        }
        if (sub == "source/high.php") {
            val red = c.r.get["redirect"]
            if (!red.isNullOrEmpty()) {
                if (red.contains("info.php")) {
                    return Out.redirect(red)
                }
                return Out("<p>You can only redirect to the info page.</p>", 500)
            }
            return Out("<p>Missing redirect target.</p>", 500)
        }
        if (sub == "source/impossible.php") {
            val red = c.r.get["redirect"]
            if (red != null && U.isNumeric(red)) {
                val target = when (red.trim().toDouble().toInt()) {
                    1 -> "info.php?id=1"
                    2 -> "info.php?id=2"
                    99 -> "https://digi.ninja"
                    else -> ""
                }
                if (target.isNotEmpty()) {
                    return Out.redirect(target)
                }
                return Out("Unknown redirect target.")
            }
            return Out("Missing redirect target.")
        }

        if (sub.isNotEmpty()) return null

        val level = c.level
        val (link1, link2) = when (level) {
            "low" -> Pair("source/low.php?redirect=info.php?id=1", "source/low.php?redirect=info.php?id=2")
            "medium" -> Pair("source/medium.php?redirect=info.php?id=1", "source/medium.php?redirect=info.php?id=2")
            "high" -> Pair("source/high.php?redirect=info.php?id=1", "source/high.php?redirect=info.php?id=2")
            else -> Pair("source/impossible.php?redirect=1", "source/impossible.php?redirect=2")
        }

        val body = StringBuilder()
        body.append("<div class=\"body_padded\">\n")
        body.append("\t<h1>Vulnerability: Open HTTP Redirect</h1>\n")
        body.append("\t<div class=\"vulnerable_code_area\">\n")
        body.append("\t\t<h2>Hacker History</h2>\n")
        body.append("\t\t<p>\n\t\t\tHere are two links to some famous hacker quotes, see if you can hack them.\n\t\t</p>\n")
        body.append("\t\t<ul>\n")
        body.append("\t\t\t<li><a href='$link1'>Quote 1</a></li>\n")
        body.append("\t\t\t<li><a href='$link2'>Quote 2</a></li>\n")
        body.append("\t\t</ul>\n")
        body.append("\t</div>\n")
        body.append("\t<h2>More Information</h2>\n")
        body.append("\t<ul>\n")
        body.append("\t\t<li>" + c.externalLink("https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html", "OWASP Unvalidated Redirects and Forwards Cheat Sheet") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect", "WSTG - Testing for Client-side URL Redirect") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://cwe.mitre.org/data/definitions/601.html", "Mitre - CWE-601: URL Redirection to Untrusted Site ('Open Redirect')") + "</li>\n")
        body.append("\t</ul>\n")
        body.append("</div>\n")
        return Out(c.page("Vulnerability: Open HTTP Redirect" + c.titleSeparator() + c.defaultTitle(), "open_redirect", body.toString()))
    }

    private fun handleCryptography(sub: String, c: Ctx): Out? {
        val level = c.level
        if (sub == "source/check_token_high.php") {
            if (c.r.method != "POST") return Out.json("{\"status\":405,\"message\":\"Method not supported\"}")
            val ct = c.r.headers["content-type"] ?: ""
            if (!ct.contains("application/json")) {
                return Out.json("{\"status\":527,\"message\":\"Content type must be application/json\"}")
            }
            return Out.json(cryptoCheckTokenHigh(c.r.bodyText))
        }
        if (sub == "source/check_token_impossible.php") {
            if (c.r.method != "POST") return Out.json("{\"status\":405,\"message\":\"Method not supported\"}")
            val ct = c.r.headers["content-type"] ?: ""
            if (!ct.contains("application/json")) {
                return Out.json("{\"status\":527,\"message\":\"Content type must be application/json\"}")
            }
            return Out.json(cryptoCheckTokenImpossible(c.r.bodyText))
        }
        if (sub.isNotEmpty()) return null

        var html = ""
        if (level == "low") {
            val key = "wachtwoord"
            var errors = ""
            var success = ""
            var messages = ""
            var encoded: String? = null
            var encodeRadio = " checked='checked' "
            var decodeRadio = " "
            var message = ""
            if (c.r.method == "POST") {
                try {
                    if (c.r.post.containsKey("message")) {
                        message = c.r.post["message"] ?: ""
                        if (c.r.post["direction"] == "decode") {
                            val decBytes = Base64.decode(message, Base64.DEFAULT)
                            encoded = String(cryptoXor(decBytes, key.toByteArray(Charsets.ISO_8859_1)), Charsets.ISO_8859_1)
                            encodeRadio = " "
                            decodeRadio = " checked='checked' "
                        } else {
                            val xorBytes = cryptoXor(message.toByteArray(Charsets.ISO_8859_1), key.toByteArray(Charsets.ISO_8859_1))
                            encoded = Base64.encodeToString(xorBytes, Base64.NO_WRAP)
                        }
                    }
                    if (c.r.post.containsKey("password")) {
                        val password = c.r.post["password"] ?: ""
                        if (password == "Olifant") {
                            success = "Welcome back user"
                        } else {
                            errors = "Login Failed"
                        }
                    }
                } catch (e: Exception) {
                    errors = e.message ?: "Error"
                }
            }
            html = buildString {
                append("<p>This super secure system will allow you to exchange messages with your friends without anyone else being able to read them. Use the box below to encode and decode messages.</p>")
                append("<form name=\"xor\" method='post' action=\"#\">")
                append("<p><label for='message'>Message:</label><br /><textarea style='width: 600px; height: 56px' id='message' name='message'>${U.h(message)}</textarea></p>")
                append("<p><input type='radio' value='encode' name='direction' id='direction_encode' $encodeRadio><label for='direction_encode'>Encode</label> or <input type='radio' value='decode' name='direction' id='direction_decode' $decodeRadio><label for='direction_decode'>Decode</label></p>")
                append("<p><input type=\"submit\" value=\"Submit\"></p>")
                append("</form>")
                if (encoded != null) {
                    append("<p><label for='encoded'>Message:</label><br /><textarea readonly='readonly' style='width: 600px; height: 56px' id='encoded' name='encoded'>${U.h(encoded)}</textarea></p>")
                }
                append("<hr><p>You have intercepted the following message, decode it and log in below.</p>")
                append("<p><textarea readonly='readonly' style='width: 600px; height: 28px' id='encoded' name='encoded'>Lg4WGlQZChhSFBYSEB8bBQtPGxdNQSwEHREOAQY=</textarea></p>")
                if (errors.isNotEmpty()) append("<div class=\"warning\">$errors</div>")
                if (messages.isNotEmpty()) append("<div class=\"nearly\">$messages</div>")
                if (success.isNotEmpty()) append("<div class=\"success\">$success</div>")
                append("<form name=\"ecb\" method='post' action=\"#\">")
                append("<p><label for='password'>Password:</label><br /><input type='password' id='password' name='password'></p>")
                append("<p><input type=\"submit\" value=\"Login\"></p>")
                append("</form>")
            }
        } else if (level == "medium") {
            val key = "ik ben een aardbei".substring(0, 16)
            var errors = ""
            var success = ""
            var messages = ""
            if (c.r.method == "POST") {
                try {
                    val token = c.r.post["token"] ?: throw Exception("No token passed")
                    if (token.length % 32 != 0) {
                        throw Exception("Token is in wrong format")
                    } else {
                        val decBytes = try { cryptoAesEcbDecrypt(cryptoHexToBin(token), key.toByteArray(Charsets.ISO_8859_1)) } catch (x: Exception) { throw Exception("Decryption failed") }
                        val decrypted = String(decBytes, Charsets.UTF_8)
                        val userObj = try { JSONObject(decrypted) } catch (_: Exception) { null }
                        if (userObj == null) {
                            throw Exception("Could not decode JSON object.")
                        }
                        val uName = userObj.optString("user")
                        val uEx = userObj.optLong("ex")
                        val uLevel = userObj.optString("level")
                        val nowSec = System.currentTimeMillis() / 1000
                        if (uName == "sweep" && uEx > nowSec && uLevel == "admin") {
                            success = "Welcome administrator Sweep"
                        } else {
                            messages = "Login successful but not as the right user."
                        }
                    }
                } catch (e: Exception) {
                    errors = e.message ?: "Error"
                }
            }
            html = buildString {
                append("<p>You have managed to get hold of three session tokens for an application you think is using poor cryptography to protect its secrets:</p>")
                append("<p><strong>Sooty (admin), session expired</strong></p>")
                append("<p><textarea style='width: 600px; height: 56px'>e287af752ed3f9601befd45726785bd9b85bb230876912bf3c66e50758b222d0837d1e6b16bfae07b776feb7afe576305aec34b41499579d3fb6acc8dc92fd5fcea8743c3b2904de83944d6b19733cdb48dd16048ed89967c250ab7f00629dba</textarea></p>")
                append("<p><strong>Sweep (user), session expired</strong></p>")
                append("<p><textarea style='width: 600px; height: 56px'>3061837c4f9debaf19d4539bfa0074c1b85bb230876912bf3c66e50758b222d083f2d277d9e5fb9a951e74bee57c77a3caeb574f10f349ed839fbfd223903368873580b2e3e494ace1e9e8035f0e7e07</textarea></p>")
                append("<p><strong>Soo (user), session valid</strong></p>")
                append("<p><textarea style='width: 600px; height: 56px'>5fec0b1c993f46c8bad8a5c8d9bb9698174d4b2659239bbc50646e14a70becef83f2d277d9e5fb9a951e74bee57c77a3c9acb1f268c06c5e760a9d728e081fab65e83b9f97e65cb7c7c4b8427bd44abc16daa00fd8cd0105c97449185be77ef5</textarea></p>")
                append("<p>Based on the documentation, you know the format of the token is:</p>")
                append("<pre><code>{\n    \"user\": \"example\",\n    \"ex\": 1723620372,\n    \"level\": \"user\",\n    \"bio\": \"blah\"\n}</code></pre>")
                append("<p>You also spot this comment in the docs:</p><blockquote><i>To ensure your security, we use aes-128-ecb throughout our application.</i></blockquote><hr>")
                append("<p>Manipulate the session tokens you have captured to log in as Sweep with admin privileges.")
                if (errors.isNotEmpty()) append("<div class=\"warning\">$errors</div>")
                if (messages.isNotEmpty()) append("<div class=\"nearly\">$messages</div>")
                if (success.isNotEmpty()) append("<div class=\"success\">$success</div>")
                append("<form name=\"ecb\" method='post' action=\"#\">")
                append("<p><label for='token'>Token:</label><br /><textarea style='width: 600px; height: 56px' id='token' name='token'></textarea></p>")
                append("<p><input type=\"submit\" value=\"Submit\"></p>")
                append("</form>")
            }
        } else if (level == "high") {
            val tokenData = cryptoCreateTokenHigh()
            html = buildString {
                append("""
	<script>
		function send_token() {
			const url = 'source/check_token_high.php';
			const data = document.getElementById ('token').value;
			console.log (data);
			fetch(url, { 
					method: 'POST', 
					headers: { 
						'Content-Type': 'application/json' 
					}, 
					body: data
				}) 
				.then(response => { 
					if (!response.ok) { 
						throw new Error('Network response was not ok'); 
				} 
				return response.json(); 
				}) 
				.then(data => { 
					console.log(data);
					message_line = document.getElementById ('message');
					if (data.status == 200) {
						message_line.innerText = 'Welcome back ' + data.user + ' (' + data.level + ')';
						message_line.setAttribute('class', 'success');
					} else {
						message_line.innerText = 'Error: ' + data.message;
						message_line.setAttribute('class', 'warning');
					}
				}) 
				.catch(error => { 
					console.error('There was a problem with your fetch operation:', error); 
			}); 
		}
	</script>
		<p>
			You have managed to steal the following token from a user of the Prognostication application.
		</p>
		<p>
			<textarea style='width: 600px; height: 23px'>${U.h(tokenData)}</textarea>
		</p>
		<p>
			You can use the form below to provide the token to access the system. You have two challenges, first, decrypt the token to find out the secret it contains, and then create a new token to access the system as a other users. See if you can make yourself an administrator.
		</p>
		<hr>
		<form name=\"check_token\" action=\"\">
			<div id='message'></div>
			<p>
				<label for='token'>Token:</label><br />
				<textarea id='token' name='token' style='width: 600px; height: 23px'>${U.h(tokenData)}</textarea>
			</p>
			<p>
				<input type=\"button\" value=\"Submit\" onclick='send_token();'>
			</p>
		</form>
""")
            }
        } else {
            val tokenData = cryptoCreateTokenImpossible()
            html = buildString {
                append("""
	<script>
		function send_token() {
			const url = 'source/check_token_impossible.php';
			const data = document.getElementById ('token').value;
			console.log (data);
			fetch(url, { 
					method: 'POST', 
					headers: { 
						'Content-Type': 'application/json' 
					}, 
					body: data
				}) 
				.then(response => { 
					if (!response.ok) { 
						throw new Error('Network response was not ok'); 
				} 
				return response.json(); 
				}) 
				.then(data => { 
					console.log(data);
					message_line = document.getElementById ('message');
					if (data.status == 200) {
						message_line.innerText = 'Welcome back ' + data.user + ' (' + data.level + ')';
						message_line.setAttribute('class', 'success');
					} else {
						message_line.innerText = 'Error: ' + data.message;
						message_line.setAttribute('class', 'warning');
					}
				}) 
				.catch(error => { 
					console.error('There was a problem with your fetch operation:', error); 
			}); 
		}
	</script>
		<p>
			You have managed to steal the following token from a user of the Impervious application.
		</p>
		<p>
			<textarea style='width: 600px; height: 23px'>${U.h(tokenData)}</textarea>
		</p>
		<p>
			This being the impossible level, you should not be able to mess with the token in any useful way but feel free to try below.
		</p>
		<hr>
		<form name=\"check_token\" action=\"\">
			<div id='message'></div>
			<p>
				<label for='token'>Token:</label><br />
				<textarea id='token' name='token' style='width: 600px; height: 23px'>${U.h(tokenData)}</textarea>
			</p>
			<p>
				<input type=\"button\" value=\"Submit\" onclick='send_token();'>
			</p>
		</form>
""")
            }
        }

        val body = StringBuilder()
        body.append("<div class=\"body_padded\">\n")
        body.append("\t<h1>Vulnerability: Cryptography Problems</h1>\n")
        body.append("\t<div class=\"vulnerable_code_area\">\n")
        body.append(html)
        body.append("\t</div>\n")
        body.append("\t<h2>More Information</h2>\n")
        body.append("\t<ul>\n")
        body.append("\t\t<li>" + c.externalLink("https://www.scottbrady91.com/cryptopals/implementing-and-breaking-aes-ecb", "Implementing and breaking AES ECB") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation", "Wikipedia - Block cipher mode of operation") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://www.nccgroup.com/us/research-blog/cryptopals-exploiting-cbc-padding-oracles/", "Cryptopals: Exploiting CBC Padding Oracles - Best article") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://yurichev.org/pkcs7/", "[Crypto] PKCS#7 padding") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://en.wikipedia.org/wiki/Padding_oracle_attack", "Padding oracle attack") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://medium.com/@masjadaan/oracle-padding-attack-a61369993c86", "Oracle Padding Attack") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://robertheaton.com/2013/07/29/padding-oracle-attack/", "The Padding Oracle Attack") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://en.wikipedia.org/wiki/Padding_%28cryptography%29", "Wikipedia - Padding (cryptography)") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://gchq.github.io/CyberChef/", "CyberChef") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://www.101computing.net/xor-encryption-algorithm/", "XOR Encryption Algorithm") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://en.wikipedia.org/wiki/XOR_cipher", "XOR Cipher") + "</li>\n")
        body.append("\t\t<li>" + c.externalLink("https://www.youtube.com/watch?v=7WySPRERN0Q", "Video walk-through by CryptoCat") + "</li>\n")
        body.append("\t</ul>\n")
        body.append("</div>\n")
        return Out(c.page("Vulnerability: Cryptography Problems" + c.titleSeparator() + c.defaultTitle(), "cryptography", body.toString()))
    }

    private fun cryptoXor(clear: ByteArray, key: ByteArray): ByteArray {
        val out = ByteArray(clear.size)
        var j = 0
        for (i in clear.indices) {
            out[i] = (clear[i].toInt() xor key[j].toInt()).toByte()
            j = (j + 1) % key.size
        }
        return out
    }

    private fun cryptoHexToBin(hex: String): ByteArray {
        val len = hex.length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] = ((Character.digit(hex[i], 16) shl 4) + Character.digit(hex[i + 1], 16)).toByte()
            i += 2
        }
        return data
    }

    private fun cryptoBinToHex(bytes: ByteArray): String {
        val hexChars = CharArray(bytes.size * 2)
        val hexArray = "0123456789abcdef".toCharArray()
        for (j in bytes.indices) {
            val v = bytes[j].toInt() and 0xFF
            hexChars[j * 2] = hexArray[v ushr 4]
            hexChars[j * 2 + 1] = hexArray[v and 0x0F]
        }
        return String(hexChars)
    }

    private fun cryptoAesEcbDecrypt(data: ByteArray, keyBytes: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        val secretKey = SecretKeySpec(keyBytes, "AES")
        cipher.init(Cipher.DECRYPT_MODE, secretKey)
        return cipher.doFinal(data)
    }

    private fun cryptoAesCbcEncrypt(data: ByteArray, keyBytes: ByteArray, ivBytes: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val secretKey = SecretKeySpec(keyBytes, "AES")
        val ivSpec = IvParameterSpec(ivBytes)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
        return cipher.doFinal(data)
    }

    private fun cryptoAesCbcDecrypt(data: ByteArray, keyBytes: ByteArray, ivBytes: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val secretKey = SecretKeySpec(keyBytes, "AES")
        val ivSpec = IvParameterSpec(ivBytes)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
        return cipher.doFinal(data)
    }

    private fun cryptoAesGcmEncrypt(data: ByteArray, keyBytes: ByteArray, ivBytes: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val secretKey = SecretKeySpec(keyBytes, "AES")
        val gcmSpec = GCMParameterSpec(128, ivBytes)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)
        return cipher.doFinal(data)
    }

    private fun cryptoAesGcmDecrypt(ciphertextWithTag: ByteArray, keyBytes: ByteArray, ivBytes: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val secretKey = SecretKeySpec(keyBytes, "AES")
        val gcmSpec = GCMParameterSpec(128, ivBytes)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)
        return cipher.doFinal(ciphertextWithTag)
    }

    private fun cryptoCreateTokenHigh(): String {
        val key = "rainbowclimbinghigh".toByteArray(Charsets.UTF_8).copyOf(16)
        val iv = "1234567812345678".toByteArray(Charsets.UTF_8)
        val token = "userid:2"
        val enc = cryptoAesCbcEncrypt(token.toByteArray(Charsets.UTF_8), key, iv)
        val obj = JSONObject()
        obj.put("token", Base64.encodeToString(enc, Base64.NO_WRAP))
        obj.put("iv", Base64.encodeToString(iv, Base64.NO_WRAP))
        return obj.toString().replace("\\/", "/")
    }

    private fun cryptoCheckTokenHigh(data: String): String {
        val users = mapOf(
            1 to mapOf("name" to "Geoffery", "level" to "admin"),
            2 to mapOf("name" to "Bungle", "level" to "user"),
            3 to mapOf("name" to "Zippy", "level" to "user"),
            4 to mapOf("name" to "George", "level" to "user")
        )
        val dataObj = try { JSONObject(data) } catch (e: Exception) {
            val r = JSONObject()
            r.put("status", 521)
            r.put("message", "Data not in JSON format")
            r.put("extra", e.message)
            return r.toString()
        }
        if (!dataObj.has("token")) {
            val r = JSONObject()
            r.put("status", 523)
            r.put("message", "Missing token")
            return r.toString()
        }
        if (!dataObj.has("iv")) {
            val r = JSONObject()
            r.put("status", 524)
            r.put("message", "Missing IV")
            return r.toString()
        }
        try {
            val ciphertext = Base64.decode(dataObj.getString("token"), Base64.DEFAULT)
            val iv = Base64.decode(dataObj.getString("iv"), Base64.DEFAULT)
            if (iv.size != 16) throw Exception("IV must be 16 bytes")
            val key = "rainbowclimbinghigh".toByteArray(Charsets.UTF_8).copyOf(16)
            val decBytes = cryptoAesCbcDecrypt(ciphertext, key, iv)
            val d = String(decBytes, Charsets.UTF_8)
            val match = Regex("^userid:(\\d+)$").find(d)
            if (match != null) {
                val id = match.groupValues[1].toInt()
                val user = users[id]
                if (user != null) {
                    val r = JSONObject()
                    r.put("status", 200)
                    r.put("user", user["name"])
                    r.put("level", user["level"])
                    return r.toString()
                } else {
                    val r = JSONObject()
                    r.put("status", 525)
                    r.put("message", "User not found")
                    return r.toString()
                }
            } else {
                val r = JSONObject()
                r.put("status", 527)
                r.put("message", "No user specified")
                return r.toString()
            }
        } catch (e: Exception) {
            val r = JSONObject()
            r.put("status", 526)
            r.put("message", "Unable to decrypt token")
            r.put("extra", "Decryption failed")
            return r.toString()
        }
    }

    private fun cryptoCreateTokenImpossible(): String {
        val key = "rainbowclimbinghigh".toByteArray(Charsets.UTF_8).copyOf(32)
        val iv = ByteArray(12)
        U.rnd.nextBytes(iv)
        val token = "userid:2"
        val enc = cryptoAesGcmEncrypt(token.toByteArray(Charsets.UTF_8), key, iv)
        val obj = JSONObject()
        obj.put("token", Base64.encodeToString(enc, Base64.NO_WRAP))
        obj.put("iv", Base64.encodeToString(iv, Base64.NO_WRAP))
        return obj.toString().replace("\\/", "/")
    }

    private fun cryptoCheckTokenImpossible(data: String): String {
        val users = mapOf(
            1 to mapOf("name" to "Geoffery", "level" to "admin"),
            2 to mapOf("name" to "Bungle", "level" to "user"),
            3 to mapOf("name" to "Zippy", "level" to "user"),
            4 to mapOf("name" to "George", "level" to "user")
        )
        val dataObj = try { JSONObject(data) } catch (e: Exception) {
            val r = JSONObject()
            r.put("status", 521)
            r.put("message", "Data not in JSON format")
            r.put("extra", e.message)
            return r.toString()
        }
        if (!dataObj.has("token")) {
            val r = JSONObject()
            r.put("status", 523)
            r.put("message", "Missing token")
            return r.toString()
        }
        if (!dataObj.has("iv")) {
            val r = JSONObject()
            r.put("status", 524)
            r.put("message", "Missing IV")
            return r.toString()
        }
        try {
            val ciphertext = Base64.decode(dataObj.getString("token"), Base64.DEFAULT)
            val iv = Base64.decode(dataObj.getString("iv"), Base64.DEFAULT)
            if (iv.size != 12) throw Exception("IV must be 12 bytes")
            val key = "rainbowclimbinghigh".toByteArray(Charsets.UTF_8).copyOf(32)
            val decBytes = cryptoAesGcmDecrypt(ciphertext, key, iv)
            val d = String(decBytes, Charsets.UTF_8)
            val match = Regex("^userid:(\\d+)$").find(d)
            if (match != null) {
                val id = match.groupValues[1].toInt()
                val user = users[id]
                if (user != null) {
                    val r = JSONObject()
                    r.put("status", 200)
                    r.put("user", user["name"])
                    r.put("level", user["level"])
                    return r.toString()
                } else {
                    val r = JSONObject()
                    r.put("status", 525)
                    r.put("message", "User not found")
                    return r.toString()
                }
            } else {
                val r = JSONObject()
                r.put("status", 527)
                r.put("message", "No user specified")
                return r.toString()
            }
        } catch (e: Exception) {
            val r = JSONObject()
            r.put("status", 526)
            r.put("message", "Unable to decrypt token")
            r.put("extra", "Decryption failed")
            return r.toString()
        }
    }
}