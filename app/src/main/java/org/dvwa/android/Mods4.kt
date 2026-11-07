package org.dvwa.android

import android.database.sqlite.SQLiteException
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

// =====================================================================================
object AuthBypassPage : Page() {
    override val id = "authbypass"; override val title = "Authorisation Bypass"
    override val links = listOf("https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control",
        "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html", "https://en.wikipedia.org/wiki/Privilege_escalation")

    fun getUserData(lv: String): String {
        val user = DvwaApp.I.user
        if ((lv == "high" || lv == "impossible") && user != "admin") return JSONObject().put("result", "fail").put("error", "Access denied").toString()
        val arr = JSONArray()
        for (r in DvwaApp.I.db.vulnQuery("SELECT user_id, first_name, last_name FROM users")) {
            val fn = r["#1"] ?: ""; val ln = r["#2"] ?: ""
            arr.put(JSONObject().put("user_id", r["#0"]).put("first_name", if (lv == "impossible") U.h(fn) else fn).put("surname", if (lv == "impossible") U.h(ln) else ln))
        }
        return arr.toString()
    }

    fun changeUserDetails(lv: String, method: String, body: String): String {
        if (lv == "impossible" && DvwaApp.I.user != "admin") return JSONObject().put("result", "fail").put("error", "Access denied").toString()
        if (method != "POST") return JSONObject().put("result", "fail").put("error", "Only POST requests are accepted").toString()
        val d = try { JSONObject(body) } catch (e: Exception) { null }
            ?: return JSONObject().put("result", "fail").put("error", "Invalid format, expecting \"{id: {user ID}, first_name: \"{first name}\", surname: \"{surname}\"}").toString()
        return try {
            DvwaApp.I.db.vulnExec("UPDATE users SET first_name = '" + d.opt("first_name") + "', last_name = '" + d.opt("surname") + "' where user_id = " + d.opt("id") + "")
            JSONObject().put("result", "ok").toString()
        } catch (e: SQLiteException) { e.message ?: "SQL error" }
    }

    override fun build(ui: Ui, f: PageFragment) {
        val lv = level
        val admin = app.user == "admin"
        ui.p(tr("This page should only be accessible by the admin user. Your challenge is to gain access to the features using one of the other users, for example gordonb / abc123. (Log out from the menu to switch user.)"))
        val c = ui.card()
        if (lv != "low" && !admin) {
            c.root.addView(android.widget.TextView(f.requireContext()).apply { text = tr("Unauthorised  (HTTP 403)"); textSize = 18f; setTextColor(0xFFB71C1C.toInt()) })
        } else {
            c.p(tr("Welcome to the user manager, please enjoy updating your user's details."))
            val res = c.result()
            val table = c.container()
            fun load() {
                table.removeAllViews()
                val tu = Ui(f.requireContext(), table)
                val json = getUserData(lv)
                val arr = try { JSONArray(json) } catch (e: Exception) { tu.p(json); return }
                for (i in 0 until arr.length()) {
                    val o = arr.getJSONObject(i)
                    val uid = o.optString("user_id")
                    val row = tu.card("ID $uid")
                    val fn = row.field(tr("First Name"), o.optString("first_name"))
                    val sn = row.field(tr("Surname"), o.optString("surname"))
                    row.button(tr("Update"), outlined = true) {
                        val body = JSONObject().put("id", uid.toIntOrNull() ?: uid).put("first_name", fn.str()).put("surname", sn.str()).toString()
                        res.clear(); res.info("POST change_user_details.php  $body")
                        val r = changeUserDetails(lv, "POST", body)
                        if (r.contains("\"ok\"")) res.ok(tr("User updated")) else res.err(r)
                    }
                }
            }
            load()
        }
        // Raw API access — the way an attacker reaches the back-end endpoints directly
        val a = ui.card(tr("API console (like Burp Repeater / curl)"))
        a.p(tr("Requests are sent as the currently logged-in user: {0}", app.user))
        val ares = a.result()
        a.button("GET /vulnerabilities/authbypass/get_user_data.php", outlined = true) {
            ares.clear(); ares.pre(try { getUserData(lv) } catch (e: Exception) { e.toString() })
        }
        val method = a.field(tr("Method"), "POST")
        val body = a.field(tr("Request body (JSON)"), "{\"id\":2,\"first_name\":\"Hacked\",\"surname\":\"ByGordon\"}", multiline = true)
        a.button(tr("Send to /vulnerabilities/authbypass/change_user_details.php")) {
            ares.clear(); ares.pre(changeUserDetails(lv, method.str().trim().uppercase(), body.str()))
        }
    }
}

// =====================================================================================
object OpenRedirectPage : Page() {
    override val id = "open_redirect"; override val title = "Open HTTP Redirect"
    override val links = listOf("https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
        "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect",
        "https://cwe.mitre.org/data/definitions/601.html")

    /** returns (status, Location or body) */
    fun redirect(lv: String, r: String?): Pair<Int, String> {
        when (lv) {
            "low" -> return if (!r.isNullOrEmpty()) 302 to r else 500 to tr("Missing redirect target.")
            "medium" -> {
                if (r.isNullOrEmpty()) return 500 to tr("Missing redirect target.")
                if (Regex("http://|https://", RegexOption.IGNORE_CASE).containsMatchIn(r)) return 500 to tr("Absolute URLs not allowed.")
                return 302 to r
            }
            "high" -> {
                if (r.isNullOrEmpty()) return 500 to tr("Missing redirect target.")
                return if (r.contains("info.php")) 302 to r else 500 to tr("You can only redirect to the info page.")
            }
            else -> {
                if (r == null || !U.isNumeric(r)) return 200 to tr("Missing redirect target.")
                return when (r.trim().toDouble().toInt()) { 1 -> 302 to "info.php?id=1"; 2 -> 302 to "info.php?id=2"; 99 -> 302 to "https://digi.ninja"; else -> 200 to tr("Unknown redirect target.") }
            }
        }
    }

    private fun quote(id: String?): String? {
        if (id == null || !U.isNumeric(id)) return null
        return when (id.trim().toDouble().toInt()) {
            1 -> "Why did he come to you?\nI got a record, I was Zero Cool\nZero Cool. Crashed 1507 systems in one day, biggest crash in history, front page, New York Times August 10th 1988."
            2 -> "Who are you anyway?\nJohnny.\nJohnny who?\nJust... Johnny?"
            else -> "Some other stuff"
        }
    }

    override fun build(ui: Ui, f: PageFragment) {
        val lv = level
        val c = ui.card(tr("Hacker History"))
        c.p(tr("Here are two links to some famous hacker quotes, see if you can hack them."))
        val base = "http://127.0.0.1/vulnerabilities/open_redirect/source/$lv.php?redirect="
        val url = c.field(tr("URL (the link a victim clicks)"), base + if (lv == "impossible") "1" else "info.php?id=1")
        val res = c.result()
        fun follow(u: String) {
            res.clear()
            val q = U.parseQuery(u.substringAfter('?', "").substringBefore('#'))
            res.info("GET " + u.replace(Regex("^https?://[^/]+"), ""))
            val (status, v) = redirect(lv, q["redirect"])
            if (status != 302) { res.text("HTTP $status"); res.pre(v); return }
            res.info("HTTP/1.1 302 Found\nLocation: $v")
            val external = Regex("^(?:[a-z][a-z0-9+.-]*:)?//", RegexOption.IGNORE_CASE).containsMatchIn(v.trim()) || Regex("^[a-z][a-z0-9+.-]*:", RegexOption.IGNORE_CASE).containsMatchIn(v.trim())
            val localHost = Regex("^(?:https?:)?//(127\\.0\\.0\\.1|localhost)(?:[:/]|$)", RegexOption.IGNORE_CASE).containsMatchIn(v.trim())
            if (external && !localHost) {
                res.err(tr("⚠ Open redirect: the victim's browser now goes to {0} (shown only — never opened)", v))
                externalNotice(f, v)
                return
            }
            if (v.contains("info.php")) {
                val text = quote(U.parseQuery(v.substringAfter('?', ""))["id"])
                if (text == null) res.err(tr("HTTP 500 — Missing quote ID.")) else { res.ok(tr("Hacker Quotes (info.php)")); res.text(text) }
            } else {
                val path = v.replace(Regex("^(?:https?:)?//[^/]+"), "")
                if (!(f.main()?.openPath(path) ?: false)) res.warn(tr("404 Not Found: {0}", path))
            }
        }
        c.button(tr("Open link")) { follow(url.str()) }
        c.button(tr("Quote 1"), outlined = true) { url.setText(base + if (lv == "impossible") "1" else "info.php?id=1"); follow(url.str()) }
        c.button(tr("Quote 2"), outlined = true) { url.setText(base + if (lv == "impossible") "2" else "info.php?id=2"); follow(url.str()) }
    }
}

// =====================================================================================
object CryptoPage : Page() {
    override val id = "cryptography"; override val title = "Cryptography Problems"
    override val links = listOf("https://www.scottbrady91.com/cryptopals/implementing-and-breaking-aes-ecb", "https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation",
        "https://en.wikipedia.org/wiki/Padding_oracle_attack", "https://gchq.github.io/CyberChef/", "https://en.wikipedia.org/wiki/XOR_cipher")

    private val users = mapOf(1 to ("Geoffery" to "admin"), 2 to ("Bungle" to "user"), 3 to ("Zippy" to "user"), 4 to ("George" to "user"))
    private fun xor(a: ByteArray, k: ByteArray) = ByteArray(a.size) { i -> (a[i].toInt() xor k[i % k.size].toInt()).toByte() }
    private fun hex2bin(h: String): ByteArray? {
        if (h.length % 2 != 0 || !h.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) return null
        return ByteArray(h.length / 2) { i -> h.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    }
    private fun keyHigh() = "rainbowclimbinghigh".toByteArray().copyOf(16)
    private fun keyImp() = "rainbowclimbinghigh".toByteArray().copyOf(32)

    fun tokenHigh(): String {
        val iv = "1234567812345678".toByteArray()
        val c = Cipher.getInstance("AES/CBC/PKCS5Padding"); c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(keyHigh(), "AES"), IvParameterSpec(iv))
        return JSONObject().put("token", Base64.encodeToString(c.doFinal("userid:2".toByteArray()), Base64.NO_WRAP)).put("iv", Base64.encodeToString(iv, Base64.NO_WRAP)).toString().replace("\\/", "/")
    }
    fun tokenImpossible(): String {
        val iv = ByteArray(12).also { U.rnd.nextBytes(it) }
        val c = Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(keyImp(), "AES"), GCMParameterSpec(128, iv))
        return JSONObject().put("token", Base64.encodeToString(c.doFinal("userid:2".toByteArray()), Base64.NO_WRAP)).put("iv", Base64.encodeToString(iv, Base64.NO_WRAP)).toString().replace("\\/", "/")
    }

    /** check_token_high.php / check_token_impossible.php — high is a CBC padding oracle. */
    fun checkToken(gcm: Boolean, data: String): JSONObject {
        val d = try { JSONObject(data) } catch (e: Exception) { return JSONObject().put("status", 521).put("message", "Data not in JSON format").put("extra", e.message) }
        if (!d.has("token")) return JSONObject().put("status", 523).put("message", "Missing token")
        if (!d.has("iv")) return JSONObject().put("status", 524).put("message", "Missing IV")
        return try {
            val ct = Base64.decode(d.getString("token"), Base64.DEFAULT); val iv = Base64.decode(d.getString("iv"), Base64.DEFAULT)
            val plain = if (gcm) {
                if (iv.size != 12) throw Exception("IV must be 12 bytes, ${iv.size} passed")
                Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, SecretKeySpec(keyImp(), "AES"), GCMParameterSpec(128, iv)) }.doFinal(ct)
            } else {
                if (iv.size != 16) throw Exception("IV must be 16 bytes, ${iv.size} passed")
                Cipher.getInstance("AES/CBC/PKCS5Padding").apply { init(Cipher.DECRYPT_MODE, SecretKeySpec(keyHigh(), "AES"), IvParameterSpec(iv)) }.doFinal(ct)
            }
            val m = Regex("^userid:(\\d+)$").find(String(plain, Charsets.ISO_8859_1))
            if (m != null) {
                val u = users[m.groupValues[1].toIntOrNull() ?: -1]
                if (u != null) JSONObject().put("status", 200).put("user", u.first).put("level", u.second)
                else JSONObject().put("status", 525).put("message", "User not found")
            } else JSONObject().put("status", 527).put("message", "No user specified")
        } catch (e: Exception) {
            JSONObject().put("status", 526).put("message", "Unable to decrypt token").put("extra", e.message ?: "Decryption failed")
        }
    }

    override fun build(ui: Ui, f: PageFragment) {
        when (level) {
            "low" -> low(ui); "medium" -> medium(ui); "high" -> high(ui, false); else -> high(ui, true)
        }
    }

    private fun low(ui: Ui) {
        val key = "wachtwoord".toByteArray(Charsets.ISO_8859_1)
        val c = ui.card()
        c.p(tr("This super secure system will allow you to exchange messages with your friends without anyone else being able to read them. Use the box below to encode and decode messages."))
        val msg = c.field(tr("Message:"), multiline = true)
        val dir = c.radios(tr("Encode"), tr("Decode"))
        val out = c.result()
        c.button(tr("Submit")) {
            out.clear()
            try {
                val m = msg.str()
                val r = if (dir.checkedRadioButtonId == 1001) String(xor(Base64.decode(m, Base64.DEFAULT), key), Charsets.ISO_8859_1)
                        else Base64.encodeToString(xor(m.toByteArray(Charsets.ISO_8859_1), key), Base64.NO_WRAP)
                out.text(tr("Message:")); out.pre(r)
            } catch (e: Exception) { out.err(e.message ?: "error") }
        }
        val l = ui.card()
        l.p(tr("You have intercepted the following message, decode it and log in below."))
        l.code("Lg4WGlQZChhSFBYSEB8bBQtPGxdNQSwEHREOAQY=")
        val pw = l.field(tr("Password:"), password = true)
        val lr = l.result()
        l.button(tr("Login")) { lr.clear(); if (pw.str() == "Olifant") lr.ok("Welcome back user") else lr.err("Login Failed") }
    }

    private fun medium(ui: Ui) {
        val key = "ik ben een aardbei".toByteArray(Charsets.ISO_8859_1).copyOf(16)
        val c = ui.card()
        c.p(tr("You have managed to get hold of three session tokens for an application you think is using poor cryptography to protect its secrets:"))
        c.p(tr("Sooty (admin), session expired")); c.code("e287af752ed3f9601befd45726785bd9b85bb230876912bf3c66e50758b222d0837d1e6b16bfae07b776feb7afe576305aec34b41499579d3fb6acc8dc92fd5fcea8743c3b2904de83944d6b19733cdb48dd16048ed89967c250ab7f00629dba")
        c.p(tr("Sweep (user), session expired")); c.code("3061837c4f9debaf19d4539bfa0074c1b85bb230876912bf3c66e50758b222d083f2d277d9e5fb9a951e74bee57c77a3caeb574f10f349ed839fbfd223903368873580b2e3e494ace1e9e8035f0e7e07")
        c.p(tr("Soo (user), session valid")); c.code("5fec0b1c993f46c8bad8a5c8d9bb9698174d4b2659239bbc50646e14a70becef83f2d277d9e5fb9a951e74bee57c77a3c9acb1f268c06c5e760a9d728e081fab65e83b9f97e65cb7c7c4b8427bd44abc16daa00fd8cd0105c97449185be77ef5")
        c.p(tr("Based on the documentation, you know the format of the token is:"))
        c.code("{\n    \"user\": \"example\",\n    \"ex\": 1723620372,\n    \"level\": \"user\",\n    \"bio\": \"blah\"\n}")
        c.p(tr("You also spot this comment in the docs: \"To ensure your security, we use aes-128-ecb throughout our application.\"\n\nManipulate the session tokens you have captured to log in as Sweep with admin privileges."))
        val tok = c.field(tr("Token:"), multiline = true)
        val r = c.result()
        c.button(tr("Submit")) {
            r.clear()
            try {
                val t = tok.str().trim()
                if (t.length % 32 != 0) throw Exception("Token is in wrong format")
                val bin = hex2bin(t) ?: throw Exception("Decryption failed")
                val dec = try { Cipher.getInstance("AES/ECB/PKCS5Padding").apply { init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES")) }.doFinal(bin) } catch (e: Exception) { throw Exception("Decryption failed") }
                val o = try { JSONObject(String(dec, Charsets.UTF_8)) } catch (e: Exception) { throw Exception("Could not decode JSON object.") }
                if (o.optString("user") == "sweep" && o.optLong("ex") > System.currentTimeMillis() / 1000 && o.optString("level") == "admin") r.ok(tr("Welcome administrator Sweep"))
                else r.warn(tr("Login successful but not as the right user."))
            } catch (e: Exception) { r.err(e.message ?: "error") }
        }
    }

    private fun high(ui: Ui, gcm: Boolean) {
        val c = ui.card()
        c.p(if (!gcm) tr("You have managed to steal the following token from a user of the Prognostication application.") else tr("You have managed to steal the following token from a user of the Impervious application."))
        val token = if (gcm) tokenImpossible() else tokenHigh()
        c.code(token)
        c.p(if (!gcm) tr("You can use the form below to provide the token to access the system. You have two challenges, first, decrypt the token to find out the secret it contains, and then create a new token to access the system as a other users. See if you can make yourself an administrator.")
            else tr("This being the impossible level, you should not be able to mess with the token in any useful way but feel free to try below."))
        val tf = c.field(tr("Token (JSON POSTed as application/json)"), token, multiline = true)
        val msg = c.result()
        c.button(tr("Submit")) { b ->
            val body = tf.str()
            Bg.run(b) {
                val r = checkToken(gcm, body)
                msg.clear()
                if (r.optInt("status") == 200) msg.ok(tr("Welcome back {0} ({1})", r.optString("user"), r.optString("level")))
                else msg.err("Error: ${r.optString("message")}")
                msg.text(tr("Raw response from source/check_token_{0}.php:", if (gcm) "impossible" else "high"))
                msg.pre(r.toString())
            }
        }
    }
}
