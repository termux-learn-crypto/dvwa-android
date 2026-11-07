package org.dvwa.android

import android.content.Context
import fi.iki.elonen.NanoHTTPD
import java.io.ByteArrayInputStream
import java.io.File
import java.util.concurrent.ConcurrentHashMap

/** Per-request context handed to every module handler. */
class Ctx(val r: Req, val s: Sess, val level: String, val srv: DvwaServer) {
    val db: Db get() = srv.db
    val os: FakeOs get() = srv.os
    val user: String get() = s.user ?: ""
    fun tokenField(): String = "<input type='hidden' name='user_token' value='${s.token}' />"
    fun checkToken(given: String?, back: String = "index.php") { if (given == null || given != s.token) throw TokenFail(back) }
    fun page(title: String, pageId: String, body: String): Out = Out(srv.template(this, title, pageId, body))
    fun asset(path: String): String = srv.assetText(path) ?: ""
    /** extra response headers / cookies that handlers may set before returning */
    val headers = LinkedHashMap<String, String>()
    val pendingCookies = ArrayList<String>()
    fun outCookiesAdd(cookie: String) { pendingCookies += cookie }
    fun titleSeparator(): String = " :: "
    fun defaultTitle(): String = "Damn Vulnerable Web Application (DVWA)"
    fun externalLink(url: String, text: String? = null): String = "<a href=\"$url\" target=\"_blank\">${text ?: url}</a>"
}

class DvwaServer(private val ctx: Context) : NanoHTTPD("127.0.0.1", PORT) {
    val db = Db(ctx)
    val os = FakeOs(ctx, this)
    private val sessions = ConcurrentHashMap<String, Sess>()
    private val pastes = ConcurrentHashMap<String, String>()

    companion object {
        const val PORT = 8080
        const val BASE = "http://127.0.0.1:8080"
        @Volatile private var instance: DvwaServer? = null
        @Synchronized fun ensureStarted(c: Context) {
            if (instance?.isAlive == true) return
            val s = DvwaServer(c)
            s.seed()
            s.start(NanoHTTPD.SOCKET_READ_TIMEOUT, false)
            instance = s
        }
        val LEVELS = listOf("low", "medium", "high", "impossible")
        val MODULES = linkedMapOf(
            "brute" to "Brute Force", "exec" to "Command Injection", "csrf" to "CSRF", "fi" to "File Inclusion",
            "upload" to "File Upload", "captcha" to "Insecure CAPTCHA", "sqli" to "SQL Injection",
            "sqli_blind" to "SQL Injection (Blind)", "weak_id" to "Weak Session IDs", "xss_d" to "XSS (DOM)",
            "xss_r" to "XSS (Reflected)", "xss_s" to "XSS (Stored)", "csp" to "CSP Bypass", "javascript" to "JavaScript Attacks",
            "authbypass" to "Authorisation Bypass", "open_redirect" to "Open HTTP Redirect", "cryptography" to "Cryptography")
    }

    fun seed() {
        db.get()
        val dir = os.uploadsDir
        val f = File(dir, "dvwa_email.png")
        if (!f.exists()) try { ctx.assets.open("www/hackable/uploads/dvwa_email.png").use { i -> f.outputStream().use { i.copyTo(it) } } } catch (e: Exception) {}
    }

    fun assetBytes(path: String): ByteArray? = try { ctx.assets.open(path).use { it.readBytes() } } catch (e: Exception) { null }
    fun assetText(path: String): String? = assetBytes(path)?.let { String(it, Charsets.UTF_8) }

    // ------------------------------------------------------------------ HTTP plumbing
    override fun serve(session: IHTTPSession): Response {
        val out = try { handle(parse(session)) } catch (e: Throwable) {
            Out("<pre>Internal error: " + U.h(e.toString()) + "</pre>", 500)
        }
        return toResponse(out)
    }

    private fun parse(se: IHTTPSession): Pair<Req, Boolean> {
        val headers = se.headers.mapKeys { it.key.lowercase() }
        val len = headers["content-length"]?.trim()?.toIntOrNull() ?: 0
        val body = ByteArray(len.coerceIn(0, 20_000_000))
        var read = 0
        while (read < body.size) { val n = se.inputStream.read(body, read, body.size - read); if (n <= 0) break; read += n }
        val ct = headers["content-type"] ?: ""
        val post = LinkedHashMap<String, String>()
        var upload: Upload? = null
        if (ct.startsWith("application/x-www-form-urlencoded")) post.putAll(U.parseQuery(String(body, Charsets.UTF_8)))
        else if (ct.startsWith("multipart/form-data")) upload = parseMultipart(body, ct, post)
        val cookies = LinkedHashMap<String, String>()
        headers["cookie"]?.split(';')?.forEach { c ->
            val i = c.indexOf('=')
            if (i > 0) cookies[c.substring(0, i).trim()] = U.urldecode(c.substring(i + 1).trim())
        }
        val q = se.queryParameterString ?: ""
        val r = Req(se.method.name, se.uri ?: "/", q, U.parseQuery(q), post, cookies, headers, body, upload)
        return r to true
    }

    private fun parseMultipart(body: ByteArray, ct: String, post: MutableMap<String, String>): Upload? {
        val b = Regex("boundary=\"?([^\";]+)\"?").find(ct)?.groupValues?.get(1) ?: return null
        val s = String(body, Charsets.ISO_8859_1)
        var up: Upload? = null
        for (part in s.split("--$b")) {
            val hEnd = part.indexOf("\r\n\r\n")
            if (hEnd < 0) continue
            val hdr = part.substring(0, hEnd)
            var data = part.substring(hEnd + 4)
            if (data.endsWith("\r\n")) data = data.substring(0, data.length - 2)
            val name = Regex("name=\"([^\"]*)\"").find(hdr)?.groupValues?.get(1) ?: continue
            val fn = Regex("filename=\"([^\"]*)\"").find(hdr)?.groupValues?.get(1)
            if (fn != null) {
                val type = Regex("(?i)Content-Type:\\s*([^\r\n]+)").find(hdr)?.groupValues?.get(1)?.trim() ?: ""
                if (fn.isNotEmpty()) up = Upload(name, fn, type, data.toByteArray(Charsets.ISO_8859_1))
            } else post[name] = String(data.toByteArray(Charsets.ISO_8859_1), Charsets.UTF_8)
        }
        return up
    }

    private fun status(code: Int): Response.IStatus {
        Response.Status.lookup(code)?.let { return it }
        return object : Response.IStatus {
            override fun getDescription() = "$code Status"
            override fun getRequestStatus() = code
        }
    }

    private fun toResponse(o: Out): Response {
        val st = status(o.status)
        var body: Any = o.body
        while (body is Out) body = body.body
        val resp = when (val b = body) {
            is ByteArray -> newFixedLengthResponse(st, o.mime, ByteArrayInputStream(b), b.size.toLong())
            else -> newFixedLengthResponse(st, o.mime, b.toString())
        }
        resp.addHeader("Cache-Control", "no-cache, must-revalidate")
        for ((k, v) in o.headers) resp.addHeader(k, v)
        for (c in o.cookies) resp.addCookieHeader(c)
        return resp
    }

    // ------------------------------------------------------------------ routing
    private fun handle(p: Pair<Req, Boolean>): Out {
        val r = p.first
        var newSess = false
        val sid = r.cookies["PHPSESSID"]?.takeIf { sessions.containsKey(it) } ?: U.randHex(13).also { newSess = true }
        val s = sessions.getOrPut(sid) { Sess(sid) }
        val levelCookie = r.cookies["security"]
        val level = if (levelCookie in LEVELS) levelCookie!! else "low"
        val c = Ctx(r, s, level, this)
        val out = try { route(c) } catch (t: TokenFail) {
            s.messages += "CSRF token is incorrect"
            Out.redirect(t.back)
        } catch (d: Die) { d.out }
        for ((k, v) in c.headers) if (!out.headers.containsKey(k)) out.headers[k] = v
        out.cookies.addAll(c.pendingCookies)
        if (newSess) out.cookies.add("PHPSESSID=$sid; path=/")
        if (levelCookie !in LEVELS && out.cookies.none { it.startsWith("security=") }) out.cookies.add("security=low; path=/")
        return out
    }

    private fun route(c: Ctx): Out {
        val r = c.r
        var path = r.path.replace(Regex("/+"), "/")
        // public resources
        when (path) {
            "/login.php" -> return login(c)
            "/logout.php" -> { c.s.user = null; c.s.messages += "You have logged out"; return Out.redirect("/login.php") }
            "/setup.php" -> return setup(c)
            "/instructions.php" -> return simplePage(c, "Instructions", "instructions", instructions())
            "/about.php" -> return simplePage(c, "About", "about", about())
            "/blocked.php" -> return blocked(c)
            "/favicon.ico" -> return static("www/favicon.ico") ?: notFound()
        }
        if (path.startsWith("/dvwa/") || path.startsWith("/hackable/users/")) return static("www$path") ?: notFound()
        if (path.startsWith("/hackable/uploads/")) return uploaded(c, path.removePrefix("/hackable/uploads/"))
        if (path.startsWith("/pastebin")) return pastebin(c, path)

        if (c.s.user == null) return Out.redirect("/login.php")

        when (path) {
            "/", "/index.php" -> return simplePage(c, "Welcome", "home", home())
            "/security.php" -> return security(c)
            "/phpinfo.php" -> return Out(phpInfoHtml())
            "/vulnerabilities/view_source.php" -> return viewSource(c, false)
            "/vulnerabilities/view_source_all.php" -> return viewSource(c, true)
            "/vulnerabilities/view_help.php" -> return viewHelp(c)
        }
        val m = Regex("^/vulnerabilities/([a-z_]+)(/.*)?$").find(path) ?: return notFound()
        val id = m.groupValues[1]
        if (id !in MODULES) return notFound()
        if (m.groupValues[2].isEmpty()) return Out.redirect("/vulnerabilities/$id/" + (if (r.query.isNotEmpty()) "?" + r.query else ""), 301)
        var sub = m.groupValues[2].removePrefix("/")
        if (sub == "." || sub == "index.php" || sub == "./") sub = ""
        if (sub.endsWith(".js") || sub.endsWith(".css")) static("www$path")?.let { return it }
        return ModA.handle(id, sub, c) ?: ModB.handle(id, sub, c) ?: ModC.handle(id, sub, c) ?: notFound()
    }

    private fun notFound() = Out("<!DOCTYPE HTML><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p><hr><address>Apache/2.4.57 (Debian) Server at 127.0.0.1 Port 8080</address></body></html>", 404)

    private fun mimeOf(name: String): String = when (name.substringAfterLast('.', "").lowercase()) {
        "css" -> "text/css"; "js" -> "application/javascript"; "png" -> "image/png"; "jpg", "jpeg" -> "image/jpeg"
        "gif" -> "image/gif"; "ico" -> "image/x-icon"; "svg" -> "image/svg+xml"; "html", "htm" -> "text/html; charset=utf-8"
        "txt" -> "text/plain; charset=utf-8"; "json" -> "application/json"; "webp" -> "image/webp"; "bmp" -> "image/bmp"
        else -> "application/octet-stream"
    }

    private fun static(asset: String): Out? = assetBytes(asset)?.let { Out(it, 200, mimeOf(asset)) }

    private fun uploaded(c: Ctx, name0: String): Out {
        val name = U.urldecode(name0)
        if (name.contains("..") || name.contains('/')) return notFound()
        val f = File(os.uploadsDir, name)
        if (name.isEmpty()) {
            val items = (os.uploadsDir.list() ?: arrayOf()).sorted().joinToString("") { "<li><a href=\"${U.h(it)}\">${U.h(it)}</a></li>" }
            return Out("<html><head><title>Index of /hackable/uploads</title></head><body><h1>Index of /hackable/uploads</h1><ul>$items</ul></body></html>")
        }
        if (!f.isFile) return notFound()
        val ext = name.substringAfterLast('.', "").lowercase()
        // Apache+PHP would execute these; here they go through the PHP simulator (fake shell only).
        if (ext in listOf("php", "php3", "php4", "php5", "php7", "phtml", "phar")) return Out(os.runPhp(f.readText(), c.r))
        return Out(f.readBytes(), 200, mimeOf(name))
    }

    // ------------------------------------------------------------------ template
    fun template(c: Ctx, title: String, pageId: String, body: String): String {
        val loggedIn = c.s.user != null
        val blocks = ArrayList<List<Pair<String, String>>>()
        blocks += if (loggedIn) listOf("home" to "Home|/", "instructions" to "Instructions|/instructions.php", "setup" to "Setup / Reset DB|/setup.php")
                  else listOf("setup" to "Setup DVWA|/setup.php", "instructions" to "Instructions|/instructions.php")
        if (loggedIn) {
            val v = ArrayList<Pair<String, String>>()
            for ((id, name) in MODULES) {
                if (id == "authbypass" && c.user != "admin") continue
                val url = if (id == "fi") "/vulnerabilities/fi/?page=include.php" else "/vulnerabilities/$id/"
                v += id to "$name|$url"
            }
            blocks += v
            blocks += listOf("security" to "DVWA Security|/security.php", "phpinfo" to "PHP Info|/phpinfo.php", "about" to "About|/about.php")
            blocks += listOf("logout" to "Logout|/logout.php")
        } else blocks += listOf("about" to "About|/about.php")
        val menu = StringBuilder()
        for (b in blocks) {
            menu.append("<ul class=\"menuBlocks\">")
            for ((id, nu) in b) {
                val (n, u) = nu.split('|', limit = 2)
                menu.append("<li class=\"${if (id == pageId) "selected" else ""}\"><a href=\"$u\">$n</a></li>\n")
            }
            menu.append("</ul>")
        }
        val msgs = if (c.s.messages.isEmpty()) "" else "<div class=\"body_padded\">" + c.s.messages.joinToString("") { "<div class=\"message\">$it</div>" } + "</div>"
        c.s.messages.clear()
        var sys = if (loggedIn) "<div align=\"left\"><em>Username:</em> ${U.h(c.user)}<br /><em>Security Level:</em> ${c.level}<br /><em>Locale:</em> en<br /><em>SQLi DB:</em> sqlite</div>" else ""
        if (pageId in MODULES) {
            sys = "<input type=\"button\" value=\"View Help\" class=\"popup_button\" onclick=\"window.location.href='/vulnerabilities/view_help.php?id=$pageId&security=${c.level}&locale=en'\"> " +
                  "<input type=\"button\" value=\"View Source\" class=\"popup_button\" onclick=\"window.location.href='/vulnerabilities/view_source.php?id=$pageId&security=${c.level}'\"> " + sys
        }
        val fullTitle = if (title.contains("Damn Vulnerable")) title else "$title :: Damn Vulnerable Web Application (DVWA)"
        return """<!DOCTYPE html>
<html lang="en-GB">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta name="viewport" content="width=1000" />
<title>$fullTitle</title>
<link rel="stylesheet" type="text/css" href="/dvwa/css/main.css" />
<link rel="icon" type="image/ico" href="/favicon.ico" />
<script type="text/javascript" src="/dvwa/js/dvwaPage.js"></script>
</head>
<body class="home">
<div id="container">
<div id="header"><img src="/dvwa/images/logo.png" alt="Damn Vulnerable Web Application" /></div>
<div id="main_menu"><div id="main_menu_padded">
$menu
</div></div>
<div id="main_body">
$body
<br /><br />
$msgs
</div>
<div class="clear"></div>
<div id="system_info">$sys</div>
<div id="footer"><p>Damn Vulnerable Web Application (DVWA) &mdash; offline Android edition (127.0.0.1 only)</p>
</div>
</div>
</body>
</html>"""
    }

    private fun simplePage(c: Ctx, title: String, id: String, body: String) = c.page(title, id, body)

    // ------------------------------------------------------------------ core pages
    private fun login(c: Ctx): Out {
        val r = c.r
        if (r.method == "POST" && r.post.containsKey("Login")) {
            val u = U.stripslashes(r.post["username"] ?: "")
            val p = U.stripslashes(r.post["password"] ?: "")
            val ok = try { db.prepared("SELECT * FROM users WHERE user = ? AND password = ?", u, U.md5(p)).size == 1 } catch (e: Exception) { false }
            if (ok) {
                c.s.user = u
                c.s.messages += "You have logged in as '${U.h(u)}'"
                return Out.redirect("/index.php")
            }
            c.s.messages += "Login failed"
            return Out.redirect("/login.php")
        }
        val msgs = c.s.messages.joinToString("") { "<div class=\"message\">$it</div>" }; c.s.messages.clear()
        return Out("""<!DOCTYPE html><html lang="en-GB"><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Login :: Damn Vulnerable Web Application (DVWA)</title>
<link rel="stylesheet" type="text/css" href="/dvwa/css/main.css" />
<style>body{background:#f4f4f4;font-family:Tahoma,Arial,sans-serif;text-align:center}#wrapper{max-width:420px;margin:40px auto}
#content{background:#fff;border:1px solid #c0c0c0;padding:20px}fieldset{border:0}.loginInput{width:90%;padding:6px;margin:4px 0 12px}
.message{color:#c00;margin-top:10px}p.submit input{padding:6px 18px}</style></head>
<body><div id="wrapper"><div id="header"><img src="/dvwa/images/login_logo.png" style="max-width:100%" /></div>
<div id="content"><form action="login.php" method="post"><fieldset>
<label for="user">Username</label><br /><input type="text" class="loginInput" size="20" name="username"><br />
<label for="pass">Password</label><br /><input type="password" class="loginInput" AUTOCOMPLETE="off" size="20" name="password"><br />
<p class="submit"><input type="submit" value="Login" name="Login"></p></fieldset></form>
$msgs
<p style="font-size:11px;color:#666">Default credentials: admin / password &middot; <a href="/setup.php">Setup / Reset DB</a> &middot; <a href="/instructions.php">Instructions</a></p>
</div><div id="footer"><p>Damn Vulnerable Web Application (DVWA) &mdash; offline Android edition</p></div></div></body></html>""")
    }

    private fun setup(c: Ctx): Out {
        var html = ""
        if (c.r.method == "POST" && c.r.post.containsKey("create_db")) {
            val log = db.reset()
            os.uploadsDir.listFiles()?.forEach { it.delete() }
            seed()
            pastes.clear()
            html = log.joinToString("") { "<div class=\"message\">$it</div>" } + "<div class=\"message\">Uploads folder emptied.</div><div class=\"message\"><em>Setup successful</em>!</div>"
        }
        val body = """<div class="body_padded">
<h1>Database Setup <img src="/dvwa/images/spanner.png" /></h1>
<p>Click on the 'Create / Reset Database' button below to create or reset your database.<br />
If you get an error make sure you have the correct user credentials in: <em>/var/www/html/config/config.inc.php</em></p>
<p>If the database already exists, <em>it will be cleared and the data will be reset</em>.<br />You can also use this to reset the administrator credentials ("<em>admin</em> // <em>password</em>") at any stage.</p>
<hr /><br />
<h2>Setup Check</h2>
<p>Operating system: <em>Android (simulated Debian 12 web server)</em><br />
Backend database: <em>SQLite (app-private, bundled)</em><br />
Database file: <em>dvwa.db in the app sandbox</em><br />
PHP version: <em>simulated &mdash; logic re-implemented natively</em><br />
Web server: <em>embedded NanoHTTPD on 127.0.0.1:8080 (loopback only)</em><br />
PHPIDS: <em>not included</em><br />
reCAPTCHA: <em>replaced by a local offline CAPTCHA</em><br />
Writable folder hackable/uploads/: <span class="success">Yes</span></p>
<br />
<form action="#" method="post"><input name="create_db" type="submit" value="Create / Reset Database"></form>
<br />$html
</div>"""
        return c.page("Setup", "setup", body)
    }

    private fun security(c: Ctx): Out {
        if (c.r.method == "POST" && c.r.post.containsKey("seclev_submit")) {
            c.checkToken(c.r.post["user_token"], "security.php")
            val lv = c.r.post["security"] ?: "impossible"
            val chosen = if (lv in LEVELS) lv else "impossible"
            c.s.messages += "Security level set to $chosen"
            c.s.newToken()
            val o = Out.redirect("security.php")
            o.cookies.add("security=$chosen; path=/")
            return o
        }
        c.s.newToken()
        val opts = LEVELS.joinToString("") { l -> "<option value=\"$l\"${if (l == c.level) " selected=\"selected\"" else ""}>${l.replaceFirstChar { it.uppercase() }}</option>" }
        val body = """<div class="body_padded">
<h1>DVWA Security <img src="/dvwa/images/lock.png" /></h1><br />
<h2>Security Level</h2>
<div id="security_level_info"><p>Security level is currently: <em>${c.level}</em>.</p></div>
<p>You can set the security level to low, medium, high or impossible. The security level changes the vulnerability level of DVWA:</p>
<ol>
<li> Low - This security level is completely vulnerable and <em>has no security measures at all</em>. It's use is to be as an example of how web application vulnerabilities manifest through bad coding practices and to serve as a platform to teach or learn basic exploitation techniques.</li>
<li> Medium - This setting is mainly to give an example to the user of <em>bad security practices</em>, where the developer has tried but failed to secure an application. It also acts as a challenge to users to refine their exploitation techniques.</li>
<li> High - This option is an extension to the medium difficulty, with a mixture of <em>harder or alternative bad practices</em> to attempt to secure the code. The vulnerability may not allow the same extent of the exploitation, similar in various Capture The Flags (CTFs) competitions.</li>
<li> Impossible - This level should be <em>secure against all vulnerabilities</em>. It is used to compare the vulnerable source code to the secure source code.</li>
</ol>
<form action="#" method="POST">
<select name="security">$opts</select>
<input type="submit" value="Submit" name="seclev_submit">
${c.tokenField()}
</form>
<br /><hr /><br />
<p><em>PHPIDS is not part of this offline edition.</em> The level is stored in the <code>security</code> cookie, exactly like DVWA.</p>
</div>"""
        return c.page("DVWA Security", "security", body)
    }

    private fun home(): String = """<div class="body_padded">
<h1>Welcome to Damn Vulnerable Web Application!</h1>
<p>Damn Vulnerable Web Application (DVWA) is a PHP/MySQL web application that is damn vulnerable. Its main goal is to be an aid for security professionals to test their skills and tools in a legal environment, help web developers better understand the processes of securing web applications and to aid both students &amp; teachers to learn about web application security in a controlled class room environment.</p>
<p>The aim of DVWA is to <em>practice some of the most common web vulnerabilities</em>, with <em>various levels of difficulty</em>, with a simple straightforward interface.</p>
<hr /><br />
<h2>General Instructions</h2>
<p>It is up to the user how they approach DVWA. Either by working through every module at a fixed level, or selecting any module and working up to reach the highest level they can before moving onto the next one. There is not a fixed object to complete a module; however users should feel that they have successfully exploited the system as best as they possible could by using that particular vulnerability.</p>
<p>Please note, there are <em>both documented and undocumented vulnerabilities</em> with this software. This is intentional. You are encouraged to try and discover as many issues as possible.</p>
<p>There is a help button at the bottom of each page, which allows you to view hints &amp; tips for that vulnerability. There are also additional links for further background reading, which relates to that security issue.</p>
<hr /><br />
<h2>About this offline Android edition</h2>
<p>Everything runs inside this app: an embedded web server bound to <em>127.0.0.1:8080</em>, an app-private SQLite database and a simulated Debian file system &amp; shell. Command injection never runs real Android commands; uploads and file inclusion only touch the app's own sandbox; external navigation and resources are blocked. Use <em>Setup / Reset DB</em> to restore the original data at any time.</p>
<hr /><br />
<h2>WARNING!</h2>
<p>Damn Vulnerable Web Application is damn vulnerable! Only practise on systems you own or are authorised to test. The techniques learned here must never be used against third-party systems.</p>
</div>"""

    private fun instructions(): String = """<div class="body_padded">
<h1>Instructions</h1>
<h2>Getting started</h2>
<ol>
<li>Open <a href="/setup.php">Setup / Reset DB</a> and press <em>Create / Reset Database</em> (the database is also created automatically on first launch).</li>
<li>Log in with <em>admin</em> / <em>password</em>. Other accounts: gordonb / abc123, 1337 / charley, pablo / letmein, smithy / password.</li>
<li>Choose a level on <a href="/security.php">DVWA Security</a> (Low, Medium, High, Impossible).</li>
<li>Pick a module from the menu. Every module has <em>View Help</em> and <em>View Source</em> buttons (source shows the original DVWA PHP for the current level; <em>Compare All Levels</em> shows all four).</li>
</ol>
<h2>Differences from the PHP original</h2>
<ul>
<li>The database is SQLite (DVWA's own <code>SQLI_DB = sqlite</code> mode). For convenience MySQL-isms are translated: <code>#</code> comments, <code>user()</code>, <code>database()</code>, <code>version()</code>/<code>@@version</code>, <code>concat()</code>, <code>substring()</code>/<code>mid()</code>, <code>ascii()</code>, <code>sleep(n)</code> (approximate CPU delay) and an <code>information_schema.tables/columns</code> view. <code>sqlite_master</code> also works.</li>
<li>Command Injection uses a simulated shell (ping, whoami, id, uname, pwd, ls, cat, head, tail, grep, wc, find, ps, ifconfig, netstat, env, echo, date, hostname, <code>${'$'}( )</code> and backticks) over a fake Debian file system. Like PHP's <code>shell_exec</code>, only stdout is shown.</li>
<li>Uploaded <code>.php</code> files are run through a tiny PHP simulator: text is printed, and <code>system()/passthru()/shell_exec()/exec()</code> with <code>${'$'}_GET/${'$'}_POST/${'$'}_REQUEST</code> parameters, <code>echo</code> and <code>phpinfo()</code> are emulated (fake shell only).</li>
<li>Insecure CAPTCHA uses a local text CAPTCHA instead of Google reCAPTCHA.</li>
<li>Nothing leaves the device. Remote file inclusion only works against this server (http://127.0.0.1:8080/...). For CSP Bypass, host scripts on this server, e.g. via <a href="/pastebin/">/pastebin/</a> or File Upload.</li>
<li>Pop-up windows open in the same view; use the Android back button to return.</li>
</ul>
</div>"""

    private fun about(): String = """<div class="body_padded">
<h1>About</h1>
<p>Damn Vulnerable Web Application (DVWA) is a PHP/MySQL web application that is damn vulnerable. Its main goal is to be an aid for security professionals to test their skills and tools in a legal environment.</p>
<p>This app is an offline, self-contained Android re-implementation of DVWA's modules for personal practice. The original DVWA is by Ryan Dewhurst (ethicalhack3r), Robin Wood (digininja) and contributors, released under the GNU General Public License v3; its help texts, images and PHP sources (shown via View Source) are bundled under that licence.</p>
<h2>Links</h2>
<ul><li>Project home: https://github.com/digininja/DVWA</li></ul>
<h2>Licence</h2>
<p>DVWA is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.</p>
</div>"""

    private fun blocked(c: Ctx): Out {
        val u = c.r.get["url"] ?: ""
        return Out("""<html><head><link rel="stylesheet" href="/dvwa/css/main.css"/><meta name="viewport" content="width=device-width, initial-scale=1"/></head>
<body style="padding:20px;font-family:sans-serif"><h1>External navigation blocked</h1>
<p>The page tried to leave the sandbox and navigate to:</p><pre style="white-space:pre-wrap;word-break:break-all">${U.h(u)}</pre>
<p>DVWA Offline never contacts external hosts. If you were exploiting an <em>Open Redirect</em> or exfiltrating data via XSS, this is where the victim would have been sent &mdash; the attack worked.</p>
<p><a href="javascript:history.back()">Back</a> &middot; <a href="/">Home</a></p></body></html>""")
    }

    private fun pastebin(c: Ctx, path: String): Out {
        if (path.startsWith("/pastebin/raw/")) {
            val t = pastes[path.removePrefix("/pastebin/raw/")] ?: return notFound()
            return Out(t, 200, "application/javascript; charset=utf-8")
        }
        var msg = ""
        if (c.r.method == "POST") {
            val id = U.randHex(4)
            pastes[id] = c.r.post["content"] ?: ""
            msg = "<p>Created: <a href=\"/pastebin/raw/$id\">http://127.0.0.1:8080/pastebin/raw/$id</a></p>"
        }
        return Out("""<html><head><link rel="stylesheet" href="/dvwa/css/main.css"/></head><body style="padding:20px">
<h1>Local Pastebin</h1><p>Paste raw text/JavaScript; it is served from this server (same origin) for CSP exercises.</p>
<form method="POST"><textarea name="content" style="width:600px;height:150px">alert(document.domain)</textarea><br /><input type="submit" value="Create paste" /></form>$msg
<p><a href="/vulnerabilities/csp/">Back to CSP Bypass</a></p></body></html>""")
    }

    fun phpInfoHtml(): String = """<!DOCTYPE html><html><head><title>PHP 8.2.7 - phpinfo()</title><meta name="viewport" content="width=device-width"/>
<style>body{background:#fff;color:#222;font-family:sans-serif}table{border-collapse:collapse;width:934px;margin:auto}td,th{border:1px solid #666;padding:4px 5px;font-size:75%}.e{background:#ccf;width:300px;font-weight:bold}.v{background:#ddd}.h{background:#99c;font-weight:bold}h1{text-align:center}</style></head><body>
<h1>PHP Version 8.2.7 (simulated)</h1><table>
<tr><td class="e">System</td><td class="v">Linux dvwa 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC Debian x86_64</td></tr>
<tr><td class="e">Server API</td><td class="v">Apache 2.0 Handler</td></tr>
<tr><td class="e">Loaded Configuration File</td><td class="v">/etc/php/8.2/apache2/php.ini</td></tr>
<tr><td class="e">allow_url_fopen</td><td class="v">On</td></tr><tr><td class="e">allow_url_include</td><td class="v">On</td></tr>
<tr><td class="e">display_errors</td><td class="v">On</td></tr><tr><td class="e">disable_functions</td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">DOCUMENT_ROOT</td><td class="v">/var/www/html</td></tr><tr><td class="e">SERVER_ADDR</td><td class="v">127.0.0.1</td></tr>
<tr><td class="e">upload_max_filesize</td><td class="v">2M</td></tr><tr><td class="e">user</td><td class="v">www-data</td></tr>
</table><p style="text-align:center"><a href="/">Back to DVWA</a></p></body></html>"""

    // ------------------------------------------------------------------ help / source
    private val extraSources = mapOf(
        "javascript" to mapOf("medium" to listOf("vulnerabilities/javascript/source/medium.js"), "high" to listOf("vulnerabilities/javascript/source/high_unobfuscated.js")),
        "csp" to mapOf("high" to listOf("vulnerabilities/csp/source/high.js", "vulnerabilities/csp/source/jsonp.php"), "impossible" to listOf("vulnerabilities/csp/source/impossible.js", "vulnerabilities/csp/source/jsonp_impossible.php")),
        "cryptography" to mapOf("high" to listOf("vulnerabilities/cryptography/source/token_library_high.php", "vulnerabilities/cryptography/source/check_token_high.php"), "impossible" to listOf("vulnerabilities/cryptography/source/token_library_impossible.php", "vulnerabilities/cryptography/source/check_token_impossible.php")),
        "authbypass" to mapOf("low" to listOf("vulnerabilities/authbypass/get_user_data.php", "vulnerabilities/authbypass/change_user_details.php"), "medium" to listOf("vulnerabilities/authbypass/get_user_data.php", "vulnerabilities/authbypass/change_user_details.php"), "high" to listOf("vulnerabilities/authbypass/get_user_data.php", "vulnerabilities/authbypass/change_user_details.php"), "impossible" to listOf("vulnerabilities/authbypass/get_user_data.php", "vulnerabilities/authbypass/change_user_details.php")),
        "open_redirect" to mapOf("low" to listOf("vulnerabilities/open_redirect/source/info.php")),
    )

    private fun sourceBlock(id: String, lv: String): String {
        val sb = StringBuilder()
        val files = listOf("vulnerabilities/$id/source/$lv.php") + (extraSources[id]?.get(lv) ?: listOf())
        for (f in files) {
            val t = assetText("www/php/$f") ?: continue
            sb.append("<h3>$f</h3><div id=\"code\"><table width='100%' bgcolor='white' style=\"border:2px #C0C0C0 solid\"><tr><td><div id=\"code\"><pre style=\"white-space:pre-wrap;font-size:12px\">")
                .append(U.h(t)).append("</pre></div></td></tr></table></div><br />")
        }
        return sb.toString()
    }

    private fun popupHtml(title: String, body: String) = """<!DOCTYPE html><html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>$title :: Damn Vulnerable Web Application (DVWA)</title><link rel="stylesheet" type="text/css" href="/dvwa/css/main.css" />
<style>body{padding:10px} .spoiler{background:#333;color:#333} .spoiler:hover,.spoiler:active{color:#fff}</style>
<script>function back(){ if (history.length>1) history.back(); else location.href='/'; }</script></head>
<body><div id="container" style="width:auto">$body<br /><input type="button" value="Back" onclick="back()" /></div></body></html>"""

    private fun viewSource(c: Ctx, all: Boolean): Out {
        val id = c.r.get["id"] ?: ""
        val name = MODULES[id] ?: return Out(popupHtml("Source", "<p>Unknown module</p>"))
        if (all) {
            val b = StringBuilder("<div class=\"body_padded\"><h1>$name Source</h1>")
            for (lv in LEVELS) b.append("<h2>${lv.replaceFirstChar { it.uppercase() }} $name Source</h2>").append(sourceBlock(id, lv))
            return Out(popupHtml("$name Source", b.append("</div>").toString()))
        }
        val lv = c.r.get["security"].takeIf { it in LEVELS } ?: c.level
        val b = "<div class=\"body_padded\"><h1>$name Source</h1>" + sourceBlock(id, lv) +
                "<form action=\"/vulnerabilities/view_source_all.php\" method=\"GET\"><input type=\"hidden\" name=\"id\" value=\"$id\" /><input type=\"submit\" value=\"Compare All Levels\" /></form></div>"
        return Out(popupHtml("$name Source", b))
    }

    private fun viewHelp(c: Ctx): Out {
        val id = c.r.get["id"] ?: ""
        val t = assetText("www/help/$id.html") ?: "<p>No help available.</p>"
        return Out(popupHtml("Help", t))
    }
}
