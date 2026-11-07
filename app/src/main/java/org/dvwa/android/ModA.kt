package org.dvwa.android

import android.database.sqlite.SQLiteException
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.Random

object ModA {
    fun handle(id: String, sub: String, c: Ctx): Out? {
        return when (id) {
            "brute" -> handleBrute(sub, c)
            "exec" -> handleExec(sub, c)
            "csrf" -> handleCsrf(sub, c)
            "fi" -> handleFi(sub, c)
            else -> null
        }
    }

    private fun handleBrute(sub: String, c: Ctx): Out? {
        if (sub.isNotEmpty()) return null
        val method = if (c.level == "impossible") "POST" else "GET"
        var html = ""

        try {
            val loginPressed = if (method == "POST") c.r.has("Login") else c.r.has("Login")
            if (loginPressed) {
                if (c.level == "high" || c.level == "impossible") {
                    c.checkToken(c.r.req("user_token"), "index.php")
                }
                var user = if (method == "POST") c.r.post["username"] ?: "" else c.r.get["username"] ?: ""
                var pass = if (method == "POST") c.r.post["password"] ?: "" else c.r.get["password"] ?: ""

                if (c.level == "high" || c.level == "impossible") {
                    user = U.stripslashes(user)
                    pass = U.stripslashes(pass)
                }
                if (c.level == "medium" || c.level == "high") {
                    user = U.esc(user)
                    pass = U.esc(pass)
                }
                val hashedPass = U.md5(pass)

                if (c.level == "impossible") {
                    val data = c.db.prepared("SELECT failed_login, last_login FROM users WHERE user = ? LIMIT 1;", user)
                    var accountLocked = false
                    val totalFailedLogin = 3
                    val lockoutTime = 15

                    if (data.isNotEmpty()) {
                        val failedLogin = data[0]["failed_login"]?.toIntOrNull() ?: 0
                        val lastLoginStr = data[0]["last_login"] ?: ""
                        if (failedLogin >= totalFailedLogin) {
                            val sdf = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
                            val lastLoginDate = sdf.parse(lastLoginStr)?.time ?: 0L
                            val timeout = lastLoginDate + (lockoutTime * 60 * 1000L)
                            val timeNow = System.currentTimeMillis()
                            if (timeNow < timeout) {
                                accountLocked = true
                            }
                        }
                    }

                    val authData = c.db.prepared("SELECT * FROM users WHERE user = ? AND password = ? LIMIT 1;", user, hashedPass)
                    if (authData.isNotEmpty() && !accountLocked) {
                        val row = authData[0]
                        val avatar = row["avatar"] ?: ""
                        val failedLogin = row["failed_login"]?.toIntOrNull() ?: 0
                        val lastLogin = row["last_login"] ?: ""

                        html += "<p>Welcome to the password protected area <em>${user}</em></p>"
                        html += "<img src=\"${avatar}\" />"

                        if (failedLogin >= totalFailedLogin) {
                            html += "<p><em>Warning</em>: Someone might of been brute forcing your account.</p>"
                            html += "<p>Number of login attempts: <em>${failedLogin}</em>.<br />Last login attempt was at: <em>${lastLogin}</em>.</p>"
                        }
                        c.db.preparedExec("UPDATE users SET failed_login = '0' WHERE user = ? LIMIT 1;", user)
                    } else {
                        Thread.sleep((2 + U.rnd.nextInt(3)) * 1000L)
                        html += "<pre><br />Username and/or password incorrect.<br /><br/>Alternative, the account has been locked because of too many failed logins.<br />If this is the case, <em>please try again in ${lockoutTime} minutes</em>.</pre>"
                        c.db.preparedExec("UPDATE users SET failed_login = (failed_login + 1) WHERE user = ? LIMIT 1;", user)
                    }
                    c.db.preparedExec("UPDATE users SET last_login = ? WHERE user = ? LIMIT 1;", Db.nowStr(), user)
                } else {
                    val query = "SELECT * FROM `users` WHERE user = '$user' AND password = '$hashedPass';"
                    try {
                        val result = c.db.vulnQuery(query)
                        if (result.size == 1) {
                            val row = result[0]
                            val avatar = row["avatar"] ?: ""
                            html += "<p>Welcome to the password protected area ${user}</p>"
                            html += "<img src=\"${avatar}\" />"
                        } else {
                            if (c.level == "medium") {
                                Thread.sleep(2000L)
                            } else if (c.level == "high") {
                                Thread.sleep(U.rnd.nextInt(4) * 1000L)
                            }
                            html += "<pre><br />Username and/or password incorrect.</pre>"
                        }
                    } catch (e: SQLiteException) {
                        return Out("<pre>${e.message}</pre>")
                    }
                }
            }
        } catch (e: TokenFail) {
            throw e
        }

        if (c.level == "high" || c.level == "impossible") {
            c.s.newToken()
        }

        val tokenHtml = if (c.level == "high" || c.level == "impossible") "			" + c.tokenField() else ""

        val body = """
<div class="body_padded">
	<h1>Vulnerability: Brute Force</h1>
	<div class="vulnerable_code_area">
		<h2>Login</h2>
		<form action="#" method="${method}">
			Username:<br />
			<input type="text" name="username"><br />
			Password:<br />
			<input type="password" AUTOCOMPLETE="off" name="password"><br />
			<br />
			<input type="submit" value="Login" name="Login">
${tokenHtml}
		</form>
		${html}
	</div>
	<h2>More Information</h2>
	<ul>
		<li><a href="https://owasp.org/www-community/attacks/Brute_force_attack" target="_blank">https://owasp.org/www-community/attacks/Brute_force_attack</a></li>
		<li><a href="https://www.golinuxcloud.com/brute-force-attack-web-forms" target="_blank">https://www.golinuxcloud.com/brute-force-attack-web-forms</a></li>
	</ul>
</div>
"""
        return Out(c.page("Vulnerability: Brute Force", "brute", body))
    }

    private fun handleExec(sub: String, c: Ctx): Out? {
        if (sub.isNotEmpty()) return null
        var html = ""

        try {
            if (c.r.has("Submit")) {
                if (c.level == "impossible") {
                    c.checkToken(c.r.req("user_token"), "index.php")
                }
                var target = c.r.req("ip") ?: ""
                if (c.level == "impossible") {
                    target = U.stripslashes(target)
                    val octet = target.split(".")
                    if (octet.size == 4 && octet.all { U.isNumeric(it) }) {
                        target = "${octet[0]}.${octet[1]}.${octet[2]}.${octet[3]}"
                        val cmd = c.os.shellExec("ping  -c 4 " + target)
                        html += "<pre>${cmd}</pre>"
                    } else {
                        html += "<pre>ERROR: You have entered an invalid IP.</pre>"
                    }
                } else {
                    if (c.level == "medium") {
                        target = target.replace("&&", "").replace(";", "")
                    } else if (c.level == "high") {
                        target = target.trim()
                        val subs = mapOf("||" to "", "&" to "", ";" to "", "| " to "", "-" to "", "$" to "", "(" to "", ")" to "", "`" to "")
                        for ((k, v) in subs) {
                            target = target.replace(k, v)
                        }
                    }
                    val cmd = c.os.shellExec("ping  -c 4 " + target)
                    html += "<pre>${cmd}</pre>"
                }
            }
        } catch (e: TokenFail) {
            throw e
        }

        if (c.level == "impossible") {
            c.s.newToken()
        }

        val tokenHtml = if (c.level == "impossible") "			" + c.tokenField() else ""

        val body = """
<div class="body_padded">
	<h1>Vulnerability: Command Injection</h1>
	<div class="vulnerable_code_area">
		<h2>Ping a device</h2>
		<form name="ping" action="#" method="post">
			<p>
				Enter an IP address:
				<input type="text" name="ip" size="30">
				<input type="submit" name="Submit" value="Submit">
			</p>
${tokenHtml}
		</form>
		${html}
	</div>
	<h2>More Information</h2>
	<ul>
		<li><a href="https://www.scribd.com/doc/2530476/Php-Endangers-Remote-Code-Execution" target="_blank">https://www.scribd.com/doc/2530476/Php-Endangers-Remote-Code-Execution</a></li>
		<li><a href="http://www.ss64.com/bash/" target="_blank">http://www.ss64.com/bash/</a></li>
		<li><a href="http://www.ss64.com/nt/" target="_blank">http://www.ss64.com/nt/</a></li>
		<li><a href="https://owasp.org/www-community/attacks/Command_Injection" target="_blank">https://owasp.org/www-community/attacks/Command_Injection</a></li>
	</ul>
</div>
"""
        return Out(c.page("Vulnerability: Command Injection", "exec", body))
    }

    private fun handleCsrf(sub: String, c: Ctx): Out? {
        if (sub == "test_credentials.php") {
            return handleTestCredentials(c)
        }
        if (sub.isNotEmpty()) return null

        var html = ""
        try {
            if (c.level == "high") {
                val contentType = c.r.headers["content-type"] ?: ""
                if (c.r.method == "POST" && contentType == "application/json") {
                    val bodyText = c.r.bodyText
                    val json = try { JSONObject(bodyText) } catch (e: Exception) { JSONObject() }
                    val token = c.r.headers["user-token"] ?: ""
                    val passNew = json.optString("password_new", "")
                    val passConf = json.optString("password_conf", "")
                    if (json.has("Change")) {
                        c.checkToken(token, "index.php")
                        var returnMsg = "Request Failed"
                        if (passNew == passConf) {
                            val escPass = U.esc(passNew)
                            val hashed = U.md5(escPass)
                            val currentUser = c.user
                            val insert = "UPDATE `users` SET password = '${hashed}' WHERE user = '${currentUser}';"
                            c.db.vulnExec(insert)
                            returnMsg = "Password Changed."
                        } else {
                            returnMsg = "Passwords did not match."
                        }
                        c.s.newToken()
                        return Out.json(JSONObject().put("Message", returnMsg).toString())
                    }
                } else {
                    if (c.r.has("user_token") && c.r.has("password_new") && c.r.has("password_conf") && c.r.has("Change")) {
                        c.checkToken(c.r.req("user_token"), "index.php")
                        val passNew = c.r.req("password_new") ?: ""
                        val passConf = c.r.req("password_conf") ?: ""
                        if (passNew == passConf) {
                            val escPass = U.esc(passNew)
                            val hashed = U.md5(escPass)
                            val currentUser = c.user
                            val insert = "UPDATE `users` SET password = '${hashed}' WHERE user = '${currentUser}';"
                            c.db.vulnExec(insert)
                            html += "<pre>Password Changed.</pre>"
                        } else {
                            html += "<pre>Passwords did not match.</pre>"
                        }
                    }
                }
            } else if (c.level == "impossible") {
                if (c.r.has("Change")) {
                    c.checkToken(c.r.req("user_token"), "index.php")
                    var passCurr = c.r.req("password_current") ?: ""
                    val passNew = c.r.req("password_new") ?: ""
                    val passConf = c.r.req("password_conf") ?: ""

                    passCurr = U.stripslashes(passCurr)
                    passCurr = U.esc(passCurr)
                    passCurr = U.md5(passCurr)

                    val data = c.db.prepared("SELECT password FROM users WHERE user = ? AND password = ? LIMIT 1;", c.user, passCurr)
                    if (passNew == passConf && data.size == 1) {
                        var cleanNew = U.stripslashes(passNew)
                        cleanNew = U.esc(cleanNew)
                        cleanNew = U.md5(cleanNew)
                        c.db.preparedExec("UPDATE users SET password = ? WHERE user = ?;", cleanNew, c.user)
                        html += "<pre>Password Changed.</pre>"
                    } else {
                        html += "<pre>Passwords did not match or current password incorrect.</pre>"
                    }
                }
            } else if (c.level == "medium") {
                if (c.r.has("Change")) {
                    val referer = c.r.headers["referer"] ?: ""
                    if (referer.contains("127.0.0.1", ignoreCase = true)) {
                        val passNew = c.r.req("password_new") ?: ""
                        val passConf = c.r.req("password_conf") ?: ""
                        if (passNew == passConf) {
                            val escPass = U.esc(passNew)
                            val hashed = U.md5(escPass)
                            val insert = "UPDATE `users` SET password = '${hashed}' WHERE user = '${c.user}';"
                            c.db.vulnExec(insert)
                            html += "<pre>Password Changed.</pre>"
                        } else {
                            html += "<pre>Passwords did not match.</pre>"
                        }
                    } else {
                        html += "<pre>That request didn't look correct.</pre>"
                    }
                }
            } else {
                if (c.r.has("Change")) {
                    val passNew = c.r.req("password_new") ?: ""
                    val passConf = c.r.req("password_conf") ?: ""
                    if (passNew == passConf) {
                        val escPass = U.esc(passNew)
                        val hashed = U.md5(escPass)
                        val insert = "UPDATE `users` SET password = '${hashed}' WHERE user = '${c.user}';"
                        c.db.vulnExec(insert)
                        html += "<pre>Password Changed.</pre>"
                    } else {
                        html += "<pre>Passwords did not match.</pre>"
                    }
                }
            }
        } catch (e: TokenFail) {
            throw e
        } catch (e: SQLiteException) {
            return Out("<pre>${e.message}</pre>")
        }

        c.s.newToken()
        val testCredentials = """
 <button onclick="testFunct()">Test Credentials</button><br /><br />
 <script>
function testFunct() {
  window.open("../../vulnerabilities/csrf/test_credentials.php", "_blank", 
  "toolbar=yes,scrollbars=yes,resizable=yes,top=500,left=500,width=600,height=400");
}
</script>
"""
        val currentPassField = if (c.level == "impossible") """
			Current password:<br />
			<input type="password" AUTOCOMPLETE="off" name="password_current"><br />""" else ""
        val tokenFieldStr = if (c.level == "high" || c.level == "impossible") "			" + c.tokenField() else ""

        val body = """
<div class="body_padded">
	<h1>Vulnerability: Cross Site Request Forgery (CSRF)</h1>
	<div class="vulnerable_code_area">
		<h3>Change your admin password:</h3>
		<br /> 
		<div id="test_credentials">
			${testCredentials}
		</div><br />
		<form action="#" method="GET">
${currentPassField}
			New password:<br />
			<input type="password" AUTOCOMPLETE="off" name="password_new"><br />
			Confirm new password:<br />
			<input type="password" AUTOCOMPLETE="off" name="password_conf"><br />
			<br />
			<input type="submit" value="Change" name="Change">
${tokenFieldStr}
		</form>
		${html}
	</div>
		<p>Note: Browsers are starting to default to setting the <a href='https://web.dev/samesite-cookies-explained/'>SameSite cookie</a> flag to Lax, and in doing so are killing off some types of CSRF attacks. When they have completed their mission, this lab will not work as originally expected.</p>
		<p>Announcements:</p>
		<ul>
			<li><a href='https://chromestatus.com/feature/5088147346030592'>Chromium</a></li>
			<li><a href='https://docs.microsoft.com/en-us/microsoft-edge/web-platform/site-impacting-changes'>Edge</a></li>
			<li><a href='https://hacks.mozilla.org/2020/08/changes-to-samesite-cookie-behavior/'>Firefox</a></li>
		</ul>
		<p>As an alternative to the normal attack of hosting the malicious URLs or code on a separate host, you could try using other vulnerabilities in this app to store them, the Stored XSS lab would be a good place to start.</p>
	<h2>More Information</h2>
	<ul>
		<li><a href="https://owasp.org/www-community/attacks/csrf" target="_blank">https://owasp.org/www-community/attacks/csrf</a></li>
		<li><a href="https://www.cgisecurity.com/csrf-faq.html" target="_blank">https://www.cgisecurity.com/csrf-faq.html</a></li>
		<li><a href="https://en.wikipedia.org/wiki/Cross-site_request_forgery" target="_blank">https://en.wikipedia.org/wiki/Cross-site_request_forgery</a></li>
	</ul>
</div>
"""
        return Out(c.page("Vulnerability: Cross Site Request Forgery (CSRF)", "csrf", body))
    }

    private fun handleTestCredentials(c: Ctx): Out {
        var loginState = ""
        if (c.r.has("Login")) {
            var user = c.r.post["username"] ?: ""
            user = U.stripslashes(user)
            user = U.esc(user)
            var pass = c.r.post["password"] ?: ""
            pass = U.stripslashes(pass)
            pass = U.esc(pass)
            pass = U.md5(pass)
            val query = "SELECT * FROM `users` WHERE user='$user' AND password='$pass';"
            try {
                val res = c.db.vulnQuery(query)
                if (res.size == 1) {
                    loginState = "<h3 class=\"loginSuccess\">Valid password for '${user}'</h3>"
                } else {
                    loginState = "<h3 class=\"loginFail\">Wrong password for '${user}'</h3>"
                }
            } catch (e: Exception) {
                loginState = "<pre>Connection error.</pre>"
            }
        }
        val messagesHtml = ""
        val body = """
		<div class="body_padded">
			<h1>Test Credentials</h1>
			<h2>Vulnerabilities/CSRF</h2>
			<div id="code">
				<form action="../../vulnerabilities/csrf/test_credentials.php" method="post">
					<fieldset>
						${loginState}
						<label for="user">Username</label><br /> <input type="text" class="loginInput" size="20" name="username"><br />
						<label for="pass">Password</label><br /> <input type="password" class="loginInput" AUTOCOMPLETE="off" size="20" name="password"><br />
						<p class="submit"><input type="submit" value="Login" name="Login"></p>
					</fieldset>
				</form>
				${messagesHtml}
			</div>
		</div>
"""
        return Out(c.page("Test Credentials", "csrf", body))
    }

    private fun handleFi(sub: String, c: Ctx): Out? {
        if (sub.isNotEmpty()) return null
        var file = c.r.req("page")
        if (file == null) {
            return Out.redirect("?page=include.php")
        }

        if (c.level == "medium") {
            file = file.replace("http://", "").replace("https://", "")
            file = file.replace("../", "").replace("..\\", "")
        } else if (c.level == "high") {
            if (!fnmatch("file*", file) && file != "include.php") {
                return Out.text("ERROR: File not found!")
            }
        } else if (c.level == "impossible") {
            val allowed = listOf("include.php", "file1.php", "file2.php", "file3.php")
            if (!allowed.contains(file)) {
                return Out.text("ERROR: File not found!")
            }
        }

        if (file == "include.php" || file == "file1.php" || file == "file2.php" || file == "file3.php" || file == "file4.php") {
            val renderedBody = renderFiPage(file, c)
            return Out(c.page("Vulnerability: File Inclusion", "fi", renderedBody))
        }

        if (file.contains("convert.base64-encode")) {
            val resourcePart = file.substringAfter("resource=", file)
            val path = c.os.normalize(resourcePart, "/var/www/html/vulnerabilities/fi")
            val bytes = c.os.read(path) ?:ByteArray(0)
            val b64 = android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
            return Out(b64 + c.page("Vulnerability: File Inclusion", "fi", "").body)
        }

        if (file.startsWith("http://") || file.startsWith("https://")) {
            if (file.startsWith("http://127.0.0.1:8080") || file.startsWith("http://localhost:8080") ||
                file.startsWith("https://127.0.0.1:8080") || file.startsWith("https://localhost:8080")) {
                try {
                    val conn = URL(file).openConnection() as HttpURLConnection
                    conn.connectTimeout = 5000
                    for ((k, v) in c.r.cookies) {
                        conn.addRequestProperty("Cookie", "$k=$v")
                    }
                    val text = conn.inputStream.bufferedReader().use { it.readText() }
                    val phpRun = c.os.runPhp(text, c.r)
                    return Out(phpRun + c.page("Vulnerability: File Inclusion", "fi", "").body)
                } catch (e: Exception) {
                    // fall through to warning
                }
            }
            val origH = U.h(file)
            val warn = "Warning: include(): php_network_getaddresses: getaddrinfo for ${file} failed: Temporary failure in name resolution in /var/www/html/vulnerabilities/fi/index.php on line 36\n"
            return Out(warn + c.page("Vulnerability: File Inclusion", "fi", "").body)
        }

        if (file.startsWith("file://")) {
            file = file.removePrefix("file://")
        }

        if (file.startsWith("data://") || file.startsWith("data:")) {
            val dataPart = file.substringAfter("base64,", "")
            val decoded = String(android.util.Base64.decode(dataPart, android.util.Base64.DEFAULT))
            val phpRun = c.os.runPhp(decoded, c.r)
            return Out(phpRun + c.page("Vulnerability: File Inclusion", "fi", "").body)
        }

        val path = c.os.normalize(file, "/var/www/html/vulnerabilities/fi")
        val bytes = try {
            c.os.read(path)
        } catch (e: SecurityException) {
            val origH = U.h(file)
            val msg = "<br />\n<b>Warning</b>:  include(${origH}): Failed to open stream: Permission denied in <b>/var/www/html/vulnerabilities/fi/index.php</b> on line <b>36</b><br />\n<br />\n<b>Warning</b>:  include(): Failed opening '${origH}' for inclusion (include_path='.:/usr/share/php') in <b>/var/www/html/vulnerabilities/fi/index.php</b> on line <b>36</b><br />\n"
            return Out(msg + c.page("Vulnerability: File Inclusion", "fi", "").body)
        }

        if (bytes == null) {
            val origH = U.h(file)
            val msg = "<br />\n<b>Warning</b>:  include(${origH}): Failed to open stream: No such file or directory in <b>/var/www/html/vulnerabilities/fi/index.php</b> on line <b>36</b><br />\n<br />\n<b>Warning</b>:  include(): Failed opening '${origH}' for inclusion (include_path='.:/usr/share/php') in <b>/var/www/html/vulnerabilities/fi/index.php</b> on line <b>36</b><br />\n"
            return Out(msg + c.page("Vulnerability: File Inclusion", "fi", "").body)
        }

        val text = String(bytes)
        val output = if (path.endsWith("/hackable/flags/fi.php")) {
            "1.) Bond. James Bond\n\n2.) My name is Sherlock Holmes. It is my business to know what other people don't know.\n\n<br /><br />\n--LINE HIDDEN ;)--\n\n<br /><br />\n4.) The pool on the roof must have a leak.\n\n<!-- 5.) The world isn't run by weapons anymore, or energy, or money. It's run by little ones and zeroes, little bits of data. It's all just electrons. -->\n"
        } else {
            c.os.runPhp(text, c.r)
        }

        return Out(output + c.page("Vulnerability: File Inclusion", "fi", "").body)
    }

    private fun fnmatch(pattern: String, str: String): Boolean {
        val regexPattern = pattern
            .replace(".", "\\.")
            .replace("*", ".*")
            .replace("?", ".")
        return Regex(regexPattern).matches(str)
    }

    private fun renderFiPage(file: String, c: Ctx): String {
        return when (file) {
            "include.php" -> {
                val warningHtml = ""
                """
<div class="body_padded">
	<h1>Vulnerability: File Inclusion</h1>
	<p class='notice'>This lab relies on the PHP <code>include</code> and <code>require</code> functions being able to include content from remote hosts. As this is a security risk, PHP have deprecated this in version 7.4 and it will be removed completely in a future version. If this lab is not working correctly for you, check your PHP version and roll back to version 7.4 if you are on a newer version which has lost the feature.</p>
	<p class='notice'>You are running PHP version: 7.4.33
	<p><a href='https://www.php.net/manual/en/filesystem.configuration.php#ini.allow-url-include'>PHP Announcement</a></p>
	${warningHtml}
	<div class="vulnerable_code_area">
		[<em><a href="?page=file1.php">file1.php</a></em>] - [<em><a href="?page=file2.php">file2.php</a></em>] - [<em><a href="?page=file3.php">file3.php</a></em>]
	</div>
	<h2>More Information</h2>
	<ul>
		<li><a href="https://en.wikipedia.org/wiki/Remote_File_Inclusion" target="_blank">Wikipedia - File inclusion vulnerability</a></li>
		<li><a href="https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion" target="_blank">WSTG - Local File Inclusion</a></li>
		<li><a href="https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion" target="_blank">WSTG - Remote File Inclusion</a></li>
	</ul>
</div>
"""
            }
            "file1.php" -> {
                val user = c.user
                val remoteAddr = "127.0.0.1"
                """
<div class="body_padded">
	<h1>Vulnerability: File Inclusion</h1>
	<div class="vulnerable_code_area">
		<h3>File 1</h3>
		<hr />
		Hello <em>${user}</em><br />
		Your IP address is: <em>${remoteAddr}</em><br /><br />
		[<em><a href="?page=include.php">back</a></em>]
	</div>
	<h2>More Information</h2>
	<ul>
		<li><a href="https://en.wikipedia.org/wiki/Remote_File_Inclusion" target="_blank">Wikipedia - File inclusion vulnerability</a></li>
		<li><a href="https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion" target="_blank">WSTG - Local File Inclusion</a></li>
		<li><a href="https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion" target="_blank">WSTG - Remote File Inclusion</a></li>
	</ul>
</div>
"""
            }
            "file2.php" -> {
                """
<div class="body_padded">
	<h1>Vulnerability: File Inclusion</h1>
	<div class="vulnerable_code_area">
		<h3>File 2</h3>
		<hr />
		"<em>I needed a password eight characters long so I picked Snow White and the Seven Dwarves.</em>" ~ Nick Helm<br /><br />
		[<em><a href="?page=include.php">back</a></em>]	</div>
	<h2>More Information</h2>
	<ul>
		<li><a href="https://en.wikipedia.org/wiki/Remote_File_Inclusion" target="_blank">Wikipedia - File inclusion vulnerability</a></li>
		<li><a href="https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion" target="_blank">WSTG - Local File Inclusion</a></li>
		<li><a href="https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion" target="_blank">WSTG - Remote File Inclusion</a></li>
	</ul>
</div>
"""
            }
            "file3.php" -> {
                val user = c.user
                val remoteAddr = "127.0.0.1"
                val userAgent = c.r.headers["user-agent"] ?: ""
                val referer = c.r.headers["referer"]
                val host = c.r.headers["host"] ?: "127.0.0.1"
                val xForwardedFor = c.r.headers["x-forwarded-for"]

                var sb = StringBuilder()
                sb.append("""
<div class="body_padded">
	<h1>Vulnerability: File Inclusion</h1>
	<div class="vulnerable_code_area">
		<h3>File 3</h3>
		<hr />
		Welcome back <em>${user}</em><br />
		Your IP address is: <em>${remoteAddr}</em><br />
""")
                if (xForwardedFor != null) {
                    sb.append("Forwarded for: <em>${xForwardedFor}</em><br />")
                }
                sb.append("Your user-agent address is: <em>${userAgent}</em><br />")
                if (referer != null) {
                    sb.append("You came from: <em>${referer}</em><br />")
                }
                sb.append("""
		I'm hosted at: <em>${host}</em><br /><br />
		[<em><a href="?page=include.php">back</a></em>]
	</div>
	<h2>More Information</h2>
	<ul>
		<li><a href="https://en.wikipedia.org/wiki/Remote_File_Inclusion" target="_blank">Wikipedia - File inclusion vulnerability</a></li>
		<li><a href="https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion" target="_blank">WSTG - Local File Inclusion</a></li>
		<li><a href="https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion" target="_blank">WSTG - Remote File Inclusion</a></li>
	</ul>
</div>
""")
                sb.toString()
            }
            "file4.php" -> {
                """
<div class="body_padded">
	<h1>Vulnerability: File Inclusion</h1>
	<div class="vulnerable_code_area">
		<h3>File 4 (Hidden)</h3>
		<hr />
		Good job!<br />
		This file isn't listed at all on DVWA. If you are reading this, you did something right ;-)<br />
		<!-- You did an even better job to see this :-)! -->
</div>
"""
            }
            else -> ""
        }
    }
}