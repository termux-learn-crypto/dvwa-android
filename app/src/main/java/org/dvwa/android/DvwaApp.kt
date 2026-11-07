package org.dvwa.android

import android.app.Application
import android.content.Context
import android.content.SharedPreferences

/** Application object: owns the sandboxed SQLite DB, the fake OS and the "PHP session". */
class DvwaApp : Application() {
    lateinit var db: Db
    lateinit var os: FakeOs
    lateinit var prefs: SharedPreferences

    override fun onCreate() {
        super.onCreate()
        I = this
        prefs = getSharedPreferences("dvwa", Context.MODE_PRIVATE)
        Lang.init()
        db = Db(this)
        os = FakeOs(this)
        Thread { try { db.get() } catch (e: Exception) { } }.start()
    }

    /** DVWA security level, persisted in SharedPreferences (cookie "security" in the original). */
    var level: String
        get() = prefs.getString("security", "low") ?: "low"
        set(v) { prefs.edit().putString("security", v).apply() }

    var user: String?
        get() = prefs.getString("user", null)
        set(v) { prefs.edit().putString("user", v).apply() }

    companion object {
        lateinit var I: DvwaApp
        val LEVELS = listOf("low", "medium", "high", "impossible")
    }
}

/** Per-login state that the PHP original kept in $_SESSION / cookies. */
object Session {
    var id: String = U.randHex(13)
    var token: String = U.md5(U.randHex(16))
    val vars = HashMap<String, Any>()
    fun newToken(): String { token = U.md5(U.randHex(16)); return token }
    fun reset() { id = U.randHex(13); vars.clear(); newToken() }
    fun cookieHeader(): String = "PHPSESSID=$id; security=${DvwaApp.I.level}" +
        (vars["dvwaSession"]?.let { "; dvwaSession=$it" } ?: "")
}

object PhpInfo {
    val rows = listOf(
        "PHP Version" to "8.2.7 (simulated natively)",
        "System" to "Linux dvwa 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 x86_64",
        "Build Date" to "Jun  9 2023 19:37:39",
        "Server API" to "Apache 2.0 Handler",
        "Virtual Directory Support" to "disabled",
        "Configuration File (php.ini) Path" to "/etc/php/8.2/apache2",
        "Loaded Configuration File" to "/etc/php/8.2/apache2/php.ini",
        "PHP API" to "20220829",
        "Zend Extension Build" to "API420220829,NTS",
        "Registered PHP Streams" to "https, ftps, compress.zlib, php, file, glob, data, http, ftp, phar",
        "allow_url_fopen" to "On",
        "allow_url_include" to "On",
        "display_errors" to "On",
        "disable_functions" to "no value",
        "file_uploads" to "On",
        "upload_max_filesize" to "2M",
        "post_max_size" to "8M",
        "open_basedir" to "no value",
        "session.cookie_httponly" to "Off",
        "session.cookie_samesite" to "no value",
        "mysqli.default_host" to "127.0.0.1",
        "GD Support" to "enabled",
        "DOCUMENT_ROOT" to "/var/www/html",
        "SERVER_SOFTWARE" to "Apache/2.4.57 (Debian)",
        "SERVER_ADDR" to "127.0.0.1",
        "REMOTE_ADDR" to "127.0.0.1",
        "USER" to "www-data",
        "HOME" to "/var/www",
    )
    fun text(): String = "PHP Version 8.2.7\n\n" + rows.joinToString("\n") { "${it.first} => ${it.second}" } + "\n"
}
