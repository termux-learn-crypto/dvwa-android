package org.dvwa.android

object Pages {
    val all: List<Page> by lazy {
        listOf(Home, Instructions, Setup, Security, PhpInfoPage, About,
            BrutePage, ExecPage, CsrfPage, FiPage, UploadPage, CaptchaPage, SqliPage, SqliBlindPage, WeakIdPage,
            XssDPage, XssRPage, XssSPage, CspPage, JsPage, AuthBypassPage, OpenRedirectPage, CryptoPage)
    }
    fun byId(id: String): Page = all.firstOrNull { it.id == id } ?: Home

    fun menu(admin: Boolean): List<Pair<String, String>> {
        val m = ArrayList<Pair<String, String>>()
        m += "home" to "Home"; m += "instructions" to "Instructions"; m += "setup" to "Setup / Reset DB"
        m += "#v" to "Vulnerabilities"
        for (id in listOf("brute", "exec", "csrf", "fi", "upload", "captcha", "sqli", "sqli_blind", "weak_id", "xss_d", "xss_r", "xss_s", "csp", "javascript", "authbypass", "open_redirect", "cryptography")) {
            if (id == "authbypass" && !admin) continue // DVWA only lists it for admin
            m += id to byId(id).title
        }
        m += "#s" to "DVWA"
        m += "security" to "DVWA Security"; m += "phpinfo" to "PHP Info"; m += "about" to "About"
        m += "#l" to " "
        m += "logout" to "Logout"
        return m
    }

    /** Map a DVWA URL/path typed in the simulated address bar to a screen. */
    fun idForPath(raw: String): String? {
        var p = raw.trim().replace(Regex("^https?://[^/]+"), "").substringBefore('?').substringBefore('#').trimEnd('/')
        if (p.isEmpty() || p == "/index.php") return "home"
        p = p.removeSuffix("/index.php").removeSuffix(".php")
        Regex("/vulnerabilities/([a-z_]+)").find(p)?.let { m -> return all.firstOrNull { it.id == m.groupValues[1] }?.id }
        return when (p.trimStart('/')) {
            "instructions" -> "instructions"; "setup" -> "setup"; "security" -> "security"; "phpinfo" -> "phpinfo"; "about" -> "about"
            else -> null
        }
    }
}

object Home : Page() {
    override val id = "home"; override val title = "Welcome to Damn Vulnerable Web Application!"; override val vuln = false
    override fun build(ui: Ui, f: PageFragment) {
        ui.p("Damn Vulnerable Web Application (DVWA) is a PHP/MySQL web application that is damn vulnerable. Its main goal is to be an aid for security professionals to test their skills and tools in a legal environment, help web developers better understand the processes of securing web applications and to aid both students & teachers to learn about web application security in a controlled class room environment.")
        ui.p("The aim of DVWA is to practice some of the most common web vulnerabilities, with various levels of difficulty, with a simple straightforward interface.")
        ui.h2("General Instructions")
        ui.p("It is up to the user how they approach DVWA. Either by working through every module at a fixed level, or selecting any module and working up to reach the highest level they can before moving onto the next one. There is not a fixed object to complete a module; however users should feel that they have successfully exploited the system as best as they possible could by using that particular vulnerability.")
        ui.p("Please note, there are both documented and undocumented vulnerabilities with this software. This is intentional. You are encouraged to try and discover as many issues as possible.")
        ui.p("Every module has View Source (the real DVWA PHP for the current level), Compare All and View Help buttons.")
        ui.h2("This native Android edition")
        ui.p("Everything is native Android UI and runs offline inside the app: no WebView, no embedded web server, no INTERNET permission. A bundled SQLite database, a simulated Debian file system/shell and a PHP-behaviour port in Kotlin stand in for the LAMP stack. All vulnerabilities only touch this app's own sandboxed data.")
        ui.h2("WARNING!")
        ui.p("Damn Vulnerable Web Application is damn vulnerable! Only practise on systems you own or are authorised to test.")
        ui.h2("Quick start")
        val c = ui.card()
        c.p("Current user: ${app.user}   ·   Security level: $level")
        c.button("Change security level") { f.main()?.show("security") }
        c.button("Start with Brute Force", outlined = true) { f.main()?.show("brute") }
    }
}

object Instructions : Page() {
    override val id = "instructions"; override val title = "Instructions"; override val vuln = false
    override fun build(ui: Ui, f: PageFragment) {
        ui.h2("Getting started")
        ui.p("1. Setup / Reset DB restores the 5 users and the guestbook (it is also created on first launch).\n2. Log in with admin / password. Other accounts: gordonb / abc123, 1337 / charley, pablo / letmein, smithy / password.\n3. Pick a level in DVWA Security (Low, Medium, High, Impossible).\n4. Choose a module from the menu. Use View Source and View Help on each screen.")
        ui.h2("How web concepts map to this app")
        ui.p("• Hidden form fields, headers (Referer, User-Agent), cookies and client-side limits (maxlength, dropdowns) are editable in each module's orange \"Intercept & tamper\" panel — the native equivalent of Burp Suite / DevTools.\n• The toolbar menu has a simulated address bar (Go to URL…) to request pages directly, e.g. /vulnerabilities/authbypass/.\n• Request timing is shown for blind/time-based attacks.")
        ui.h2("Differences from the PHP original")
        ui.p("• Database: real bundled SQLite. Vulnerable levels build SQL by string concatenation; Impossible uses prepared statements. MySQL-isms are translated: # comments, user(), database(), version()/@@version, concat(), substring()/mid(), ascii(), sleep(n) and an information_schema.tables/columns/schemata emulation. sqlite_master works too.\n" +
            "• Command Injection: a fake shell interpreter (; && || | & \$( ) and backticks; ping, id, whoami, uname, ls, cat, head, tail, grep, wc, find, ps, env, echo …) over a fake Debian file system. No real device command is ever run.\n" +
            "• XSS (DOM/Reflected/Stored), CSP Bypass and JavaScript Attacks: there is no browser. The HTML the vulnerable PHP would have produced is analysed natively; when a browser would have executed script you get “⚠ XSS fired” plus a simulated alert dialog. Safe levels show escaped output.\n" +
            "• File Upload / File Inclusion use the app's private storage; uploaded .php files run through a small webshell simulator.\n" +
            "• Insecure CAPTCHA uses a local text CAPTCHA instead of Google reCAPTCHA.\n" +
            "• Nothing ever leaves the device; external redirects/requests are displayed, not performed.")
    }
}

object About : Page() {
    override val id = "about"; override val title = "About"; override val vuln = false
    override fun build(ui: Ui, f: PageFragment) {
        ui.p("Damn Vulnerable Web Application (DVWA) is a PHP/MySQL web application that is damn vulnerable.")
        ui.p("This app (v2.0.0) is an offline, fully native Android (Kotlin) re-implementation of DVWA's modules for personal practice. The original DVWA is by Ryan Dewhurst (ethicalhack3r), Robin Wood (digininja) and contributors, released under the GNU General Public License v3; its help texts, images and PHP sources (shown via View Source) are bundled under that licence.")
        ui.h2("Links")
        ui.p("Project home: https://github.com/digininja/DVWA\nThis app: https://github.com/termux-learn-crypto/dvwa-android")
        ui.h2("Licence")
        ui.p("DVWA is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.")
    }
}

object PhpInfoPage : Page() {
    override val id = "phpinfo"; override val title = "PHP Info"; override val vuln = false
    override fun build(ui: Ui, f: PageFragment) {
        ui.p("phpinfo() of the simulated server (static, for reconnaissance practice):")
        val c = ui.card("PHP Version 8.2.7")
        for ((k, v) in PhpInfo.rows) c.p("$k:  $v")
    }
}

object Security : Page() {
    override val id = "security"; override val title = "DVWA Security"; override val vuln = false
    override fun build(ui: Ui, f: PageFragment) {
        ui.h2("Security Level")
        ui.p("Security level is currently: $level.")
        ui.p("You can set the security level to low, medium, high or impossible. The security level changes the vulnerability level of DVWA:\n\n" +
            "1. Low - This security level is completely vulnerable and has no security measures at all. It's use is to be as an example of how web application vulnerabilities manifest through bad coding practices and to serve as a platform to teach or learn basic exploitation techniques.\n" +
            "2. Medium - This setting is mainly to give an example to the user of bad security practices, where the developer has tried but failed to secure an application. It also acts as a challenge to users to refine their exploitation techniques.\n" +
            "3. High - This option is an extension to the medium difficulty, with a mixture of harder or alternative bad practices to attempt to secure the code. The vulnerability may not allow the same extent of the exploitation, similar in various Capture The Flags (CTFs) competitions.\n" +
            "4. Impossible - This level should be secure against all vulnerabilities. It is used to compare the vulnerable source code to the secure source code.")
        val sp = ui.spinner("Level", listOf("Low", "Medium", "High", "Impossible"), DvwaApp.LEVELS.indexOf(level).coerceAtLeast(0))
        val res = ui.result()
        ui.button("Submit") {
            app.level = DvwaApp.LEVELS[sp.selectedItemPosition]
            Session.newToken()
            res.clear(); res.ok("Security level set to ${app.level}")
            f.main()?.refreshMenu()
        }
    }
}

object Setup : Page() {
    override val id = "setup"; override val title = "Database Setup"; override val vuln = false
    override fun build(ui: Ui, f: PageFragment) {
        ui.p("Click on the 'Create / Reset Database' button below to create or reset your database. If you get an error make sure you have the correct user credentials.")
        ui.p("If the database already exists, it will be cleared and the data will be reset. You can also use this to reset the administrator credentials (\"admin // password\") at any stage.")
        ui.h2("Setup Check")
        val c = ui.card()
        c.p("Operating system: Android ${android.os.Build.VERSION.RELEASE} (simulating Debian 12 / Apache 2.4.57)\nDatabase backend: SQLite ${sqliteVersion()} (bundled, app-private)\nPHP version: 8.2.7 (behaviour ported to Kotlin)\nWebView: none · INTERNET permission: none\n\nWritable folder hackable/uploads: Yes (app-private)\nWritable folder config: Yes")
        val res = ui.result()
        ui.button("Create / Reset Database") { b ->
            Bg.run(b) {
                val log = app.db.reset()
                java.io.File(f.requireContext().filesDir, "hackable/uploads").deleteRecursively()
                Session.vars.clear()
                res.clear(); log.forEach { res.ok(it) }; res.info("Setup successful! Uploads, guestbook and session data were reset.")
            }
        }
    }
    private fun sqliteVersion(): String = try { DvwaApp.I.db.prepared("select sqlite_version() as v").firstOrNull()?.get("v") ?: "3" } catch (e: Exception) { "3" }
}
