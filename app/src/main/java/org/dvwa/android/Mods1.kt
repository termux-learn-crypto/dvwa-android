package org.dvwa.android

import android.database.sqlite.SQLiteException
import android.widget.EditText
import java.text.SimpleDateFormat
import java.util.Locale

/** Anti-CSRF token as a visible-but-"hidden" field in the tamper panel. */
class Tok(t: Ui?, val enabled: Boolean) {
    val et: EditText? = if (enabled && t != null) t.field(tr("user_token (hidden field)"), Session.token) else null
    fun value(): String = et?.str() ?: ""
    fun valid(v: String) = !enabled || v == Session.token
    fun refresh() { if (enabled) { val n = Session.newToken(); et?.post { et.setText(n) } } }
}

val TOKEN_FAIL: String get() = tr("CSRF token is incorrect")

// =====================================================================================
object BrutePage : Page() {
    override val id = "brute"; override val title = "Brute Force"
    override val links = listOf("https://owasp.org/www-community/attacks/Brute_force_attack", "https://www.golinuxcloud.com/brute-force-attack-web-forms")

    class LoginRes(val ok: Boolean, val lines: List<Pair<String, String>>, val avatar: String? = null)

    /** Kotlin port of vulnerabilities/brute/source/{level}.php */
    fun login(lv: String, user0: String, pass0: String): LoginRes {
        var user = user0; var pass = pass0
        val out = ArrayList<Pair<String, String>>()
        if (lv == "high" || lv == "impossible") { user = U.stripslashes(user); pass = U.stripslashes(pass) }
        if (lv != "low") { user = U.esc(user); pass = U.esc(pass) }
        val hashed = U.md5(pass)
        val db = DvwaApp.I.db
        if (lv == "impossible") {
            val total = 3; val lockMin = 15
            var locked = false
            val d = db.prepared("SELECT failed_login, last_login FROM users WHERE user = ? LIMIT 1;", user)
            if (d.isNotEmpty() && (d[0]["failed_login"]?.toIntOrNull() ?: 0) >= total) {
                val last = try { SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).parse(d[0]["last_login"] ?: "")?.time ?: 0L } catch (e: Exception) { 0L }
                if (System.currentTimeMillis() < last + lockMin * 60_000L) locked = true
            }
            val auth = db.prepared("SELECT * FROM users WHERE user = ? AND password = ? LIMIT 1;", user, hashed)
            val r: LoginRes
            if (auth.size == 1 && !locked) {
                val row = auth[0]
                out += "ok" to tr("Welcome to the password protected area {0}", row["user"])
                val failed = row["failed_login"]?.toIntOrNull() ?: 0
                if (failed >= total) {
                    out += "warn" to tr("Warning: Someone might of been brute forcing your account.\nNumber of login attempts: {0}.\nLast login attempt was at: {1}.", failed, row["last_login"])
                }
                db.preparedExec("UPDATE users SET failed_login = '0' WHERE user = ?;", user)
                r = LoginRes(true, out, row["avatar"])
            } else {
                Thread.sleep(U.rand(2, 4) * 1000L)
                out += "err" to tr("Username and/or password incorrect.\n\nAlternative, the account has been locked because of too many failed logins.\nIf this is the case, please try again in {0} minutes.", lockMin)
                db.preparedExec("UPDATE users SET failed_login = (failed_login + 1) WHERE user = ?;", user)
                r = LoginRes(false, out)
            }
            db.preparedExec("UPDATE users SET last_login = ? WHERE user = ?;", Db.nowStr(), user)
            return r
        }
        val query = "SELECT * FROM `users` WHERE user = '$user' AND password = '$hashed';"
        return try {
            val rows = db.vulnQuery(query)
            if (rows.size == 1) {
                out += "ok" to tr("Welcome to the password protected area {0}", user)
                LoginRes(true, out, rows[0]["avatar"])
            } else {
                if (lv == "medium") Thread.sleep(2000)
                if (lv == "high") Thread.sleep(U.rand(0, 3) * 1000L)
                out += "err" to tr("Username and/or password incorrect.")
                LoginRes(false, out)
            }
        } catch (e: SQLiteException) {
            out += "err" to (e.message ?: "SQL error"); LoginRes(false, out)
        }
    }

    override fun build(ui: Ui, f: PageFragment) {
        val lv = level
        val c = ui.card(tr("Login"))
        val u = c.field(tr("Username"))
        val p = c.field(tr("Password"), password = true)
        val t = c.tamper()
        val tok = Tok(t, lv == "high" || lv == "impossible")
        if (!tok.enabled) t.p(tr("No hidden fields on this level. Request method: GET (parameters visible in the URL)."))
        val res = c.result()
        c.button(tr("Login")) { b ->
            val uu = u.str(); val pp = p.str(); val tv = tok.value()
            Bg.run(b) {
                res.clear()
                val method = if (lv == "impossible") "POST" else "GET"
                res.info("$method /vulnerabilities/brute/" + (if (method == "GET") "?username=${U.urlencode(uu)}&password=${U.urlencode(pp)}&Login=Login" else ""))
                if (!tok.valid(tv)) { res.err(TOKEN_FAIL); tok.refresh(); return@run }
                val t0 = System.currentTimeMillis()
                val r = login(lv, uu, pp)
                show(res, r)
                res.text(tr("Response time: {0} ms", System.currentTimeMillis() - t0))
                tok.refresh()
            }
        }
        // ---- Intruder-style helper
        val i = ui.card(tr("Attack helper (like Burp Intruder)"))
        i.p(tr("Tries each password in order against the same level logic. On High/Impossible it re-reads the page for a fresh user_token before every attempt, like a macro would."))
        val iu = i.field(tr("Username"), "admin")
        val list = i.field(tr("Password list (one per line)"), "123456\npassword1\nletmein\nqwerty\nabc123\nadmin\npassword\ncharley", multiline = true)
        val ir = i.result()
        i.button(tr("Start attack")) { b ->
            val user = iu.str(); val words = list.str().lines().map { it.trimEnd('\r') }.filter { it.isNotEmpty() }.take(200)
            Bg.run(b) {
                ir.clear()
                for ((n, w) in words.withIndex()) {
                    val t0 = System.currentTimeMillis()
                    val r = login(lv, user, w)
                    val ms = System.currentTimeMillis() - t0
                    if (r.ok) { ir.ok("#${n + 1} '$w' → SUCCESS (${ms} ms)\n" + r.lines.joinToString("\n") { it.second }); break }
                    else ir.text("#${n + 1} '$w' → failed (${ms} ms)")
                }
                ir.info(tr("Attack finished."))
            }
        }
    }

    fun show(res: OutBox, r: BrutePage.LoginRes) {
        for ((k, s) in r.lines) when (k) { "ok" -> res.ok(s); "warn" -> res.warn(s); else -> res.err(s) }
        r.avatar?.let { a -> res.image("www" + a) }
    }
}

// =====================================================================================
object ExecPage : Page() {
    override val id = "exec"; override val title = "Command Injection"
    override val links = listOf("https://www.php.net/manual/en/function.shell-exec.php", "https://www.php.net/manual/en/ref.exec.php",
        "https://owasp.org/www-community/attacks/Command_Injection")

    fun exec(lv: String, target0: String): String {
        var target = target0
        val os = DvwaApp.I.os
        when (lv) {
            "medium" -> target = target.replace("&&", "").replace(";", "")
            "high" -> {
                target = target.trim()
                for (k in listOf("||", "&", ";", "| ", "-", "$", "(", ")", "`")) target = target.replace(k, "")
            }
            "impossible" -> {
                target = U.stripslashes(target)
                val o = target.split(".")
                if (o.size == 4 && o.all { U.isNumeric(it) }) target = "${o[0]}.${o[1]}.${o[2]}.${o[3]}"
                else return tr("ERROR: You have entered an invalid IP.")
            }
        }
        return os.shellExec("ping  -c 4 $target")
    }

    override fun build(ui: Ui, f: PageFragment) {
        val lv = level
        val c = ui.card(tr("Ping a device"))
        val ip = c.field(tr("Enter an IP address:"), "127.0.0.1")
        val t = c.tamper()
        val tok = Tok(t, lv == "impossible")
        if (!tok.enabled) t.p(tr("No hidden fields on this level."))
        c.p(tr("The 'server' is simulated: a Kotlin shell interpreter (; && || | & \$() `…`) over a fake Debian file system. Nothing runs on your device."))
        val res = c.result()
        c.button(tr("Submit")) { b ->
            val v = ip.str(); val tv = tok.value()
            Bg.run(b) {
                res.clear()
                if (!tok.valid(tv)) { res.err(TOKEN_FAIL); tok.refresh(); return@run }
                val out = exec(lv, v)
                res.pre(out.ifEmpty { tr("(empty output)") })
                tok.refresh()
            }
        }
    }
}

// =====================================================================================
object CsrfPage : Page() {
    override val id = "csrf"; override val title = "Cross Site Request Forgery (CSRF)"
    override val links = listOf("https://owasp.org/www-community/attacks/csrf", "http://www.cgisecurity.com/csrf-faq.html", "https://en.wikipedia.org/wiki/Cross-site_request_forgery")

    /** Port of csrf/source/{level}.php. params = request parameters, referer = HTTP_REFERER header. */
    fun change(lv: String, params: Map<String, String>, referer: String): Pair<Boolean, String> {
        if (!params.containsKey("Change")) return false to tr("(request ignored: no 'Change' parameter)")
        val user = DvwaApp.I.user ?: ""
        val db = DvwaApp.I.db
        val new = params["password_new"] ?: ""; val conf = params["password_conf"] ?: ""
        try {
            when (lv) {
                "medium" -> if (!referer.contains("127.0.0.1", true)) return false to tr("That request didn't look correct.")
                "high" -> if (params["user_token"] != Session.token) return false to TOKEN_FAIL
                "impossible" -> {
                    if (params["user_token"] != Session.token) return false to TOKEN_FAIL
                    val cur = U.md5(U.esc(U.stripslashes(params["password_current"] ?: "")))
                    val d = db.prepared("SELECT password FROM users WHERE user = ? AND password = ? LIMIT 1;", user, cur)
                    return if (new == conf && d.size == 1) {
                        db.preparedExec("UPDATE users SET password = ? WHERE user = ?;", U.md5(U.esc(U.stripslashes(new))), user)
                        true to tr("Password Changed.")
                    } else false to tr("Passwords did not match or current password incorrect.")
                }
            }
            if (new != conf) return false to tr("Passwords did not match.")
            db.vulnExec("UPDATE `users` SET password = '${U.md5(U.esc(new))}' WHERE user = '$user';")
            return true to tr("Password Changed.")
        } catch (e: SQLiteException) { return false to (e.message ?: "SQL error") }
    }

    override fun build(ui: Ui, f: PageFragment) {
        val lv = level
        val c = ui.card(tr("Change your {0} password", app.user))
        val cur = if (lv == "impossible") c.field(tr("Current password"), password = true) else null
        val n = c.field(tr("New password"), password = true)
        val cf = c.field(tr("Confirm new password"), password = true)
        val t = c.tamper()
        val tok = Tok(t, lv == "high" || lv == "impossible")
        val ref = t.field(tr("Referer header"), "http://127.0.0.1/vulnerabilities/csrf/")
        val res = c.result()
        c.button(tr("Change")) { b ->
            val p = linkedMapOf("password_new" to n.str(), "password_conf" to cf.str(), "Change" to "Change")
            cur?.let { p["password_current"] = it.str() }
            if (tok.enabled) p["user_token"] = tok.value()
            val r = ref.str()
            Bg.run(b) {
                res.clear()
                res.info("GET /vulnerabilities/csrf/?" + p.entries.joinToString("&") { "${it.key}=${U.urlencode(it.value)}" })
                val (ok, msg) = change(lv, p, r)
                if (ok) res.ok(msg) else res.err(msg)
                tok.refresh()
            }
        }

        val a = ui.card(tr("Attacker: forged link / page (victim is logged in)"))
        a.p(tr("Simulates the logged-in victim's browser opening a URL the attacker planted (e.g. <img src=…> on another site). The browser automatically sends the victim's session cookie."))
        val url = a.field(tr("Forged URL"), "http://127.0.0.1/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change")
        val aref = a.field(tr("Referer sent by the victim's browser (the attacker's page)"), "http://evil.example/csrf.html")
        val ares = a.result()
        a.button(tr("Victim opens the link")) { b ->
            val u = url.str(); val r = aref.str()
            Bg.run(b) {
                ares.clear()
                val host = Regex("^https?://([^/:?#]+)").find(u)?.groupValues?.get(1)
                if (host != null && host != "127.0.0.1" && host != "localhost") { ares.warn(tr("That URL points to {0}, not to DVWA — nothing happens (and nothing is fetched).", host)); return@run }
                if (!u.contains("/vulnerabilities/csrf")) { ares.warn(tr("That URL is not the CSRF password-change endpoint.")); return@run }
                val params = U.parseQuery(u.substringAfter('?', "").substringBefore('#'))
                val (ok, msg) = change(lv, params, r)
                if (ok) ares.err(tr("⚠ CSRF succeeded — the victim's password was changed. Response: {0}", msg)) else ares.ok(tr("Request rejected: {0}", msg))
            }
        }

        val tc = ui.card(tr("Test Credentials (test_credentials.php)"))
        val tu = tc.field(tr("Username"), app.user ?: "admin")
        val tp = tc.field(tr("Password"), password = true)
        val tres = tc.result()
        tc.button(tr("Login"), outlined = true) { b ->
            val uu = tu.str(); val pp = tp.str()
            Bg.run(b) {
                tres.clear()
                val user = U.esc(U.stripslashes(uu)); val pass = U.md5(U.esc(U.stripslashes(pp)))
                try {
                    val r = app.db.vulnQuery("SELECT * FROM `users` WHERE user='$user' AND password='$pass';")
                    if (r.size == 1) tres.ok(tr("Valid password for '{0}'", user)) else tres.err(tr("Wrong password for '{0}'", user))
                } catch (e: Exception) { tres.err(tr("Connection error.")) }
            }
        }
    }
}

// =====================================================================================
object FiPage : Page() {
    override val id = "fi"; override val title = "File Inclusion"
    override val links = listOf("https://en.wikipedia.org/wiki/Remote_File_Inclusion",
        "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
        "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion")

    private fun fnmatch(pattern: String, s: String) = Regex(pattern.replace(".", "\\.").replace("*", ".*").replace("?", ".")).matches(s)
    private const val CWD = "/var/www/html/vulnerabilities/fi"

    /** Returns (rendered-html-or-null, raw output). */
    fun include(lv: String, page0: String, params: Map<String, String>, headers: Map<String, String>): Pair<String?, String> {
        var file = page0
        val os = DvwaApp.I.os
        when (lv) {
            "medium" -> { file = file.replace("http://", "").replace("https://", ""); file = file.replace("../", "").replace("..\\", "") }
            "high" -> if (!fnmatch("file*", file) && file != "include.php") return null to tr("ERROR: File not found!")
            "impossible" -> if (file !in listOf("include.php", "file1.php", "file2.php", "file3.php")) return null to tr("ERROR: File not found!")
        }
        val user = DvwaApp.I.user ?: ""
        when (file) {
            "include.php" -> return "<p>[ <b>file1.php</b> ] - [ <b>file2.php</b> ] - [ <b>file3.php</b> ]</p><p>Use the buttons above or edit <i>?page=</i>.</p>" to "(include.php)"
            "file1.php" -> return "<h3>File 1</h3><hr/>Hello <em>$user</em><br/>Your IP address is: <em>127.0.0.1</em>" to "(file1.php)"
            "file2.php" -> return "<h3>File 2</h3><hr/>\"<em>I needed a password eight characters long so I picked Snow White and the Seven Dwarves.</em>\" ~ Nick Helm" to "(file2.php)"
            "file3.php" -> {
                val sb = StringBuilder("<h3>File 3</h3><hr/>Welcome back <em>$user</em><br/>Your IP address is: <em>127.0.0.1</em><br/>")
                headers["X-Forwarded-For"]?.takeIf { it.isNotEmpty() }?.let { sb.append("Forwarded for: <em>$it</em><br/>") }
                sb.append("Your user-agent address is: <em>${headers["User-Agent"]}</em><br/>")
                headers["Referer"]?.takeIf { it.isNotEmpty() }?.let { sb.append("You came from: <em>$it</em><br/>") }
                sb.append("I'm hosted at: <em>127.0.0.1</em>")
                return sb.toString() to "(file3.php)"
            }
            "file4.php" -> return "<h3>File 4 (Hidden)</h3><hr/>Good job!<br/>This file isn't listed at all on DVWA. If you are reading this, you did something right ;-)" to "<!-- You did an even better job to see this :-)! -->"
        }
        val pf = Regex("(?i)^php://filter/(?:read=)?convert\\.base64-encode/resource=(.*)$").find(file)
        if (pf != null) {
            val b = try { os.read(os.normalize(pf.groupValues[1].removePrefix("file://"), CWD)) } catch (e: SecurityException) { null }
            return null to (if (b == null) warn(file, tr("No such file or directory")) else android.util.Base64.encodeToString(b, android.util.Base64.NO_WRAP))
        }
        if (file.startsWith("http://", true) || file.startsWith("https://", true) || file.startsWith("ftp://", true)) {
            return null to "Warning: include(): php_network_getaddresses: getaddrinfo for ${Regex("^\\w+://([^/]+)").find(file)?.groupValues?.get(1)} failed: Temporary failure in name resolution in $CWD/index.php on line 36\n\n" +
                tr("[Offline edition] Remote File Inclusion is allowed at this level (allow_url_include=On) — a real server would fetch and execute that URL. Nothing is fetched here. Tip: upload a .php/.jpg with File Upload and include it locally, or use data://text/plain;base64,…")
        }
        if (file.startsWith("data:", true)) {
            val payload = if (file.contains("base64,")) try { String(android.util.Base64.decode(file.substringAfter("base64,"), android.util.Base64.DEFAULT)) } catch (e: Exception) { "" } else U.urldecode(file.substringAfter(","))
            return null to os.runPhp(payload, params)
        }
        if (file.startsWith("file://", true)) file = file.substring(7)
        val path = os.normalize(file, CWD)
        val bytes = try { os.read(path) } catch (e: SecurityException) { return null to warn(file, tr("Permission denied")) } ?: return null to warn(file, tr("No such file or directory"))
        if (path.endsWith("/hackable/flags/fi.php")) {
            return null to "1.) Bond. James Bond\n\n2.) My name is Sherlock Holmes. It is my business to know what other people don't know.\n\n<br /><br />\n--LINE HIDDEN ;)--\n\n<br /><br />\n4.) The pool on the roof must have a leak.\n\n<!-- 5.) The world isn't run by weapons anymore, or energy, or money. It's run by little ones and zeroes, little bits of data. It's all just electrons. -->\n"
        }
        return null to os.runPhp(String(bytes, Charsets.ISO_8859_1), params)
    }

    private fun warn(f: String, why: String) = "Warning: include($f): Failed to open stream: $why in $CWD/index.php on line 36\n\nWarning: include(): Failed opening '$f' for inclusion (include_path='.:/usr/share/php') in $CWD/index.php on line 36"

    override fun build(ui: Ui, f: PageFragment) {
        val lv = level
        val c = ui.card()
        c.p(tr("The page includes ?page=<file>. Pick a file or edit the parameter."))
        val page = c.field("?page=", "include.php")
        val extra = c.field(tr("Other query parameters (for included webshells), e.g. cmd=id"), "")
        val t = c.tamper()
        val ua = t.field("User-Agent", "Mozilla/5.0 (Linux; Android) DVWA-Native")
        val ref = t.field("Referer", "")
        val xff = t.field("X-Forwarded-For", "")
        t.p(tr("App sandbox path for practice: {0}  (uploads: /var/www/html/hackable/uploads/)", f.requireContext().filesDir.absolutePath))
        val res = c.result()
        fun go(b: android.view.View?) {
            val pg = page.str(); val params = U.parseQuery(extra.str()); val h = mapOf("User-Agent" to ua.str(), "Referer" to ref.str(), "X-Forwarded-For" to xff.str())
            Bg.run(b) {
                res.clear()
                res.info("GET /vulnerabilities/fi/?page=${pg}")
                val (rendered, raw) = include(lv, pg, params, h)
                if (rendered != null) res.html(rendered)
                if (rendered == null || raw.startsWith("<!--")) {
                    res.html(raw.replace("\n", "<br/>").let { if (it.length > 20000) it.take(20000) else it })
                    res.text(tr("Raw response body:"))
                    res.pre(raw.ifEmpty { "(empty)" })
                }
            }
        }
        c.button(tr("Request")) { go(it) }
        for (n in listOf("file1.php", "file2.php", "file3.php")) c.button(n, outlined = true) { page.setText(n); go(it) }
    }
}
