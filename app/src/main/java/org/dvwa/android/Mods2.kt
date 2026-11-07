package org.dvwa.android

import android.database.sqlite.SQLiteException
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.net.Uri
import android.provider.OpenableColumns
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import androidx.appcompat.app.AlertDialog
import java.io.ByteArrayOutputStream
import java.io.File

// =====================================================================================
object UploadPage : Page() {
    override val id = "upload"; override val title = "File Upload"
    override val links = listOf("https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload", "https://www.acunetix.com/websitesecurity/upload-forms-threat/")
    private val phpExt = setOf("php", "php3", "php4", "php5", "php7", "phtml", "phar", "pht")

    fun dir(): File = File(DvwaApp.I.filesDir, "hackable/uploads").also { it.mkdirs() }

    private fun isImage(d: ByteArray): Boolean {
        // getimagesize(): accepts any recognised image header (JPEG/PNG/GIF/BMP/WEBP)
        if (d.size < 4) return false
        fun b(i: Int) = d[i].toInt() and 0xff
        return (b(0) == 0xFF && b(1) == 0xD8 && b(2) == 0xFF) || (b(0) == 0x89 && b(1) == 0x50 && b(2) == 0x4E && b(3) == 0x47) ||
            (d.size >= 6 && String(d, 0, 4, Charsets.ISO_8859_1) == "GIF8") || (b(0) == 'B'.code && b(1) == 'M'.code) ||
            (d.size >= 12 && String(d, 0, 4, Charsets.ISO_8859_1) == "RIFF" && String(d, 8, 4, Charsets.ISO_8859_1) == "WEBP")
    }

    /** Port of upload/source/{level}.php */
    fun upload(lv: String, name0: String, type: String, data: ByteArray): Pair<Boolean, String> {
        val name = File(name0).name
        val ext = name.substringAfterLast('.', "").lowercase()
        val target = "../../hackable/uploads/$name"
        val notImg = tr("Your image was not uploaded. We can only accept JPEG or PNG images.")
        when (lv) {
            "low" -> {}
            "medium" -> if (!((type == "image/jpeg" || type == "image/png") && data.size < 100000)) return false to notImg
            "high" -> if (!((ext == "jpg" || ext == "jpeg" || ext == "png") && data.size < 100000 && isImage(data))) return false to notImg
            "impossible" -> {
                if (!((ext == "jpg" || ext == "jpeg" || ext == "png") && data.size < 100000 && (type == "image/jpeg" || type == "image/png") && isImage(data))) return false to notImg
                val bmp = BitmapFactory.decodeByteArray(data, 0, data.size) ?: return false to tr("Your image was not uploaded.")
                // re-encode the image (strips any appended code), random file name
                val newName = U.md5(U.phpUniqid() + name) + "." + ext
                val bos = ByteArrayOutputStream()
                bmp.compress(if (type == "image/jpeg") Bitmap.CompressFormat.JPEG else Bitmap.CompressFormat.PNG, 90, bos)
                File(dir(), newName).writeBytes(bos.toByteArray())
                return true to tr("{0} succesfully uploaded!", newName)
            }
        }
        return try { File(dir(), name).writeBytes(data); true to tr("{0} succesfully uploaded!", target) } catch (e: Exception) { false to tr("Your image was not uploaded.") }
    }

    override fun build(ui: Ui, f: PageFragment) {
        val lv = level
        var picked: ByteArray? = null
        val c = ui.card(tr("Choose an image to upload"))
        val chosen = c.p(tr("No file chosen."))
        val t = c.tamper(tr("🛠 Intercept & tamper (filename, Content-Type, body)"))
        val fname = t.field("filename=", "")
        val ctype = t.field("Content-Type:", "")
        t.p(tr("Or compose the file body yourself (used when no file is chosen):"))
        val body = t.field(tr("File body"), "<?php system(\$_GET['cmd']); ?>", multiline = true)
        val magic = t.check(tr("Prepend GIF89a magic bytes (fools getimagesize)"))
        val tok = Tok(t, lv == "impossible")
        c.button(tr("Choose file…"), outlined = true) {
            f.pickFile { uri: Uri? ->
                if (uri == null) return@pickFile
                val cr = f.requireContext().contentResolver
                var name = "upload.bin"
                cr.query(uri, null, null, null, null)?.use { cur -> if (cur.moveToFirst()) { val i = cur.getColumnIndex(OpenableColumns.DISPLAY_NAME); if (i >= 0) name = cur.getString(i) ?: name } }
                picked = try { cr.openInputStream(uri)?.use { it.readBytes().let { b -> if (b.size > 2_000_000) b.copyOf(2_000_000) else b } } } catch (e: Exception) { null }
                fname.setText(name); ctype.setText(cr.getType(uri) ?: "application/octet-stream")
                chosen.text = tr("Chosen: {0} ({1} bytes)", name, picked?.size ?: 0)
            }
        }
        val res = c.result()
        c.button(tr("Upload")) { b ->
            var data = picked ?: body.str().toByteArray(Charsets.ISO_8859_1)
            if (magic.isChecked) data = "GIF89a;\n".toByteArray() + data
            val n = fname.str().ifEmpty { "shell.php" }
            val ty = ctype.str().ifEmpty { if (n.endsWith(".png")) "image/png" else if (n.endsWith(".jpg") || n.endsWith(".jpeg")) "image/jpeg" else "application/x-php" }
            val tv = tok.value()
            Bg.run(b) {
                res.clear()
                res.info("POST /vulnerabilities/upload/  filename=\"$n\"  Content-Type: $ty  (${data.size} bytes)")
                if (!tok.valid(tv)) { res.err(TOKEN_FAIL); tok.refresh(); return@run }
                val (ok, msg) = upload(lv, n, ty, data)
                if (ok) res.ok(msg) else res.err(msg)
                tok.refresh()
            }
        }

        val w = ui.card(tr("Request an uploaded file (/hackable/uploads/)"))
        w.p(tr("Simulates browsing to the uploaded file. Files with a PHP extension are executed by the built-in webshell simulator (echo, system(), shell_exec(), passthru(), exec(), phpinfo() with \$_GET/\$_POST/\$_REQUEST parameters) against the fake shell. Other files are served as-is."))
        val url = w.field("URL", "/hackable/uploads/shell.php?cmd=id")
        val wr = w.result()
        val list = w.container()
        fun refreshList() {
            list.removeAllViews()
            val files = dir().listFiles()?.sortedBy { it.name } ?: listOf()
            val lu = Ui(f.requireContext(), list)
            lu.p(if (files.isEmpty()) tr("(no uploads yet)") else tr("Uploaded: ") + files.joinToString(", ") { it.name })
        }
        refreshList()
        w.button(tr("Request")) { b ->
            val u = url.str()
            Bg.run(b) {
                wr.clear()
                val path = u.replace(Regex("^https?://[^/]+"), "").substringBefore('?')
                val name = path.substringAfter("/hackable/uploads/", "")
                val file = File(dir(), name)
                if (name.isEmpty() || name.contains("..") || !file.isFile) { wr.err(tr("404 Not Found\nThe requested URL was not found on this server.")); return@run }
                val ext = name.substringAfterLast('.', "").lowercase()
                val data = file.readBytes()
                if (ext in phpExt) {
                    val out = app.os.runPhp(String(data, Charsets.ISO_8859_1), U.parseQuery(u.substringAfter('?', "")))
                    wr.warn(tr("⚠ Server executed {0} as PHP (simulated webshell)", name))
                    wr.pre(out.ifEmpty { tr("(empty response)") })
                } else {
                    val bmp = BitmapFactory.decodeByteArray(data, 0, data.size)
                    if (bmp != null) wr.bitmap(bmp) else wr.pre(String(data, Charsets.ISO_8859_1).take(20000))
                    wr.info(tr("Served as a static file (Apache would not execute .{0}). Tip: include it with File Inclusion.", ext))
                }
            }
            refreshList()
        }
        w.button(tr("Refresh list"), outlined = true) { refreshList() }
    }
}

// =====================================================================================
object CaptchaPage : Page() {
    override val id = "captcha"; override val title = "Insecure CAPTCHA"
    override val links = listOf("https://en.wikipedia.org/wiki/CAPTCHA", "https://www.google.com/recaptcha/", "https://owasp.org/www-project-automated-threats-to-web-applications/assets/oats/EN/OAT-009_CAPTCHA_Defeat")

    private fun newCaptcha(): String {
        val chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        val s = (1..5).map { chars[U.rnd.nextInt(chars.length)] }.joinToString("")
        Session.vars["captcha"] = s
        return s
    }
    private fun draw(s: String): Bitmap {
        val bmp = Bitmap.createBitmap(300, 90, Bitmap.Config.ARGB_8888)
        val c = Canvas(bmp); c.drawColor(Color.rgb(235, 235, 220))
        val p = Paint(Paint.ANTI_ALIAS_FLAG)
        repeat(12) { p.color = Color.rgb(U.rnd.nextInt(200), U.rnd.nextInt(200), U.rnd.nextInt(200)); p.strokeWidth = 2f
            c.drawLine(U.rnd.nextInt(300).toFloat(), U.rnd.nextInt(90).toFloat(), U.rnd.nextInt(300).toFloat(), U.rnd.nextInt(90).toFloat(), p) }
        p.textSize = 54f; p.isFakeBoldText = true
        s.forEachIndexed { i, ch ->
            c.save(); val x = 20f + i * 54; c.rotate(U.rand(-20, 20).toFloat(), x + 20, 50f)
            p.color = Color.rgb(U.rnd.nextInt(120), U.rnd.nextInt(120), U.rnd.nextInt(120)); c.drawText(ch.toString(), x, 65f, p); c.restore()
        }
        return bmp
    }
    private fun check(resp: String): Boolean {
        val ok = (Session.vars["captcha"] as? String)?.equals(resp.trim(), true) == true
        newCaptcha() // one-shot, like the reCAPTCHA verify API
        return ok
    }

    override fun build(ui: Ui, f: PageFragment) {
        val lv = level
        val c = ui.card(tr("Change your password:"))
        val cur = if (lv == "impossible") c.field(tr("Current password"), password = true) else null
        val n = c.field(tr("New password"), password = true)
        val cf = c.field(tr("Confirm new password"), password = true)
        val img = ImageView(f.requireContext())
        c.root.addView(img, LinearLayout.LayoutParams(c.dp(240), c.dp(72)))
        fun refresh() { img.setImageBitmap(draw(newCaptcha())) }
        refresh()
        val ans = c.field(tr("Type the characters above (g-recaptcha-response)"))
        c.button(tr("New CAPTCHA"), outlined = true) { refresh() }
        val t = c.tamper()
        val step = if (lv == "low" || lv == "medium") t.field(tr("step (hidden)"), "1") else null
        val passed = if (lv == "medium") t.field(tr("passed_captcha (hidden, only sent by the step-2 form)"), "") else null
        val ua = t.field(tr("User-Agent header"), "Mozilla/5.0 (Linux; Android) DVWA-Native")
        val ovr = t.field(tr("Override g-recaptcha-response (leave empty to use the box above)"), "")
        val tok = Tok(t, lv == "impossible")
        val res = c.result()

        fun submit(b: android.view.View?, p: Map<String, String>, userAgent: String) {
            Bg.run(b) {
                res.clear()
                val user = app.user ?: ""; val db = app.db
                val new = p["password_new"] ?: ""; val conf = p["password_conf"] ?: ""
                try {
                    when (lv) {
                        "low", "medium" -> {
                            if (p["step"] == "1") {
                                if (!check(p["g-recaptcha-response"] ?: "")) { res.err(tr("The CAPTCHA was incorrect. Please try again.")); img.post { refresh() }; return@run }
                                if (new == conf) {
                                    res.ok(tr("You passed the CAPTCHA! Click the button to confirm your changes."))
                                    res.custom { u ->
                                        u.button(tr("Change (confirm, step 2)")) { b2 ->
                                            val p2 = linkedMapOf("step" to "2", "password_new" to new, "password_conf" to conf, "Change" to "Change")
                                            if (lv == "medium") p2["passed_captcha"] = "true"
                                            submit(b2, p2, userAgent)
                                        }
                                    }
                                } else res.err(if (lv == "low") tr("Both passwords must match.") else tr("Both passwords must match."))
                            } else if (p["step"] == "2") {
                                if (lv == "medium" && (p["passed_captcha"].isNullOrEmpty() || p["passed_captcha"] == "0")) { res.err(tr("You have not passed the CAPTCHA.")); return@run }
                                if (new == conf) {
                                    db.vulnExec("UPDATE `users` SET password = '${U.md5(U.esc(new))}' WHERE user = '$user';")
                                    res.ok(tr("Password Changed."))
                                } else res.err(tr("Passwords did not match."))
                            }
                        }
                        "high" -> {
                            val r = p["g-recaptcha-response"] ?: ""
                            if (check(r) || (r == "hidd3n_valu3" && userAgent == "reCAPTCHA")) {
                                if (new == conf) { db.vulnExec("UPDATE `users` SET password = '${U.md5(U.esc(new))}' WHERE user = '$user';"); res.ok(tr("Password Changed.")) }
                                else res.err(tr("Both passwords must match."))
                            } else res.err(tr("The CAPTCHA was incorrect. Please try again."))
                            tok.refresh()
                        }
                        else -> {
                            if (!tok.valid(p["user_token"] ?: "")) { res.err(TOKEN_FAIL); tok.refresh(); return@run }
                            val pn = U.md5(U.esc(U.stripslashes(new))); val pc = U.md5(U.esc(U.stripslashes(conf)))
                            val pcur = U.md5(U.esc(U.stripslashes(p["password_current"] ?: "")))
                            if (!check(p["g-recaptcha-response"] ?: "")) res.err(tr("The CAPTCHA was incorrect. Please try again."))
                            else {
                                val d = db.prepared("SELECT password FROM users WHERE user = ? AND password = ? LIMIT 1;", user, pcur)
                                if (pn == pc && d.size == 1) { db.preparedExec("UPDATE users SET password = ? WHERE user = ?;", pn, user); res.ok(tr("Password Changed.")) }
                                else res.err(tr("Either your current password is incorrect or the new passwords did not match.\nPlease try again."))
                            }
                            tok.refresh()
                        }
                    }
                } catch (e: SQLiteException) { res.err(e.message ?: "SQL error") }
                img.post { refresh() }
            }
        }

        c.button(tr("Change")) { b ->
            val p = linkedMapOf("password_new" to n.str(), "password_conf" to cf.str(), "Change" to "Change",
                "g-recaptcha-response" to ovr.str().ifEmpty { ans.str() })
            step?.let { p["step"] = it.str() }
            passed?.let { if (it.str().isNotEmpty()) p["passed_captcha"] = it.str() }
            cur?.let { p["password_current"] = it.str() }
            if (tok.enabled) p["user_token"] = tok.value()
            ans.setText("")
            submit(b, p, ua.str())
        }
    }
}

// =====================================================================================
private fun userRows(rows: List<Map<String, String>>, id: String) =
    rows.joinToString("\n\n") { "ID: $id\nFirst name: ${it["#0"] ?: ""}\nSurname: ${it["#1"] ?: ""}" }

object SqliPage : Page() {
    override val id = "sqli"; override val title = "SQL Injection"
    override val links = listOf("https://en.wikipedia.org/wiki/SQL_injection", "https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/",
        "https://owasp.org/www-community/attacks/SQL_Injection", "https://bobby-tables.com/")

    fun query(lv: String, id: String, res: OutBox) {
        val db = DvwaApp.I.db
        try {
            when (lv) {
                "low" -> res.pre(userRows(db.vulnQuery("SELECT first_name, last_name FROM users WHERE user_id = '$id';"), id).ifEmpty { tr("(no rows)") })
                "medium" -> { val e = U.esc(id); res.pre(userRows(db.vulnQuery("SELECT first_name, last_name FROM users WHERE user_id = $e;"), e).ifEmpty { tr("(no rows)") }) }
                "high" -> {
                    val r = try { db.vulnQuery("SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;") } catch (e: SQLiteException) { res.err(tr("Something went wrong.")); return }
                    res.pre(userRows(r, id).ifEmpty { tr("(no rows)") })
                }
                else -> {
                    if (!U.isNumeric(id)) return
                    val r = db.prepared("SELECT first_name, last_name FROM users WHERE user_id = ? LIMIT 1;", id.trim().toDouble().toLong().toString())
                    if (r.size == 1) res.pre(userRows(r, id))
                }
            }
        } catch (e: SQLiteException) { res.err(e.message ?: "SQL error") }
    }

    override fun build(ui: Ui, f: PageFragment) {
        val lv = level
        val c = ui.card()
        val res = c.result()
        when (lv) {
            "low" -> {
                val id = c.field(tr("User ID:"))
                c.button(tr("Submit")) { b -> val v = id.str(); Bg.run(b) { res.clear(); res.info("GET /vulnerabilities/sqli/?id=${U.urlencode(v)}&Submit=Submit"); query(lv, v, res) } }
            }
            "medium" -> {
                val sp = c.spinner(tr("User ID:"), (1..5).map { it.toString() })
                val t = c.tamper()
                val ovr = t.field("POST body id= (override the dropdown)", "")
                c.button(tr("Submit")) { b ->
                    val v = ovr.str().ifEmpty { (sp.selectedItemPosition + 1).toString() }
                    Bg.run(b) { res.clear(); res.info("POST /vulnerabilities/sqli/  id=${U.urlencode(v)}&Submit=Submit"); query(lv, v, res) }
                }
            }
            "high" -> {
                c.p(tr("Click here to change your ID. (opens session-input.php, which stores the ID in your session)"))
                c.button(tr("Change your ID"), outlined = true) {
                    val et = EditText(f.requireContext())
                    AlertDialog.Builder(f.requireContext()).setTitle(tr("Session ID input")).setView(et)
                        .setPositiveButton(tr("Submit")) { _, _ ->
                            val v = et.text.toString(); Session.vars["sqli_id"] = v
                            Bg.run(null) { res.clear(); res.info("Session ID: $v"); query(lv, v, res) }
                        }.setNegativeButton(tr("Close"), null).show()
                }
                Session.vars["sqli_id"]?.let { v -> Bg.run(null) { query(lv, v.toString(), res) } }
            }
            else -> {
                val id = c.field(tr("User ID:"))
                val t = c.tamper(); val tok = Tok(t, true)
                c.button(tr("Submit")) { b ->
                    val v = id.str(); val tv = tok.value()
                    Bg.run(b) { res.clear(); if (!tok.valid(tv)) res.err(TOKEN_FAIL) else query(lv, v, res); tok.refresh() }
                }
            }
        }
    }
}

object SqliBlindPage : Page() {
    override val id = "sqli_blind"; override val title = "SQL Injection (Blind)"
    override val links = listOf("https://en.wikipedia.org/wiki/SQL_injection", "https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/",
        "https://owasp.org/www-community/attacks/Blind_SQL_Injection", "https://bobby-tables.com/")

    /** returns true = exists */
    fun check(lv: String, id: String): Boolean {
        val db = DvwaApp.I.db
        return when (lv) {
            "low" -> try { db.vulnQuery("SELECT first_name, last_name FROM users WHERE user_id = '$id';").isNotEmpty() } catch (e: Exception) { false }
            "medium" -> try { db.vulnQuery("SELECT first_name, last_name FROM users WHERE user_id = ${U.esc(id)};").isNotEmpty() } catch (e: Exception) { false }
            "high" -> {
                val ok = try { db.vulnQuery("SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;").isNotEmpty() } catch (e: Exception) { false }
                if (!ok && U.rand(0, 5) == 3) Thread.sleep(U.rand(2, 4) * 1000L)
                ok
            }
            else -> U.isNumeric(id) && db.prepared("SELECT first_name, last_name FROM users WHERE user_id = ? LIMIT 1;", id.trim().toDouble().toLong().toString()).size == 1
        }
    }

    private fun send(lv: String, id: String, res: OutBox, desc: String) {
        res.clear(); res.info(desc)
        val t0 = System.currentTimeMillis()
        val ok = check(lv, id)
        val ms = System.currentTimeMillis() - t0
        if (ok) res.ok(tr("User ID exists in the database.")) else res.err(tr("User ID is MISSING from the database."))
        res.text(tr("HTTP {0} · response time: {1} ms", if (ok || lv == "impossible") "200 OK" else "404 Not Found", ms))
    }

    override fun build(ui: Ui, f: PageFragment) {
        val lv = level
        val c = ui.card()
        val res = c.result()
        when (lv) {
            "low" -> {
                val id = c.field(tr("User ID:"))
                c.button(tr("Submit")) { b -> val v = id.str(); Bg.run(b) { send(lv, v, res, "GET /vulnerabilities/sqli_blind/?id=${U.urlencode(v)}&Submit=Submit") } }
            }
            "medium" -> {
                val sp = c.spinner(tr("User ID:"), (1..5).map { it.toString() })
                val t = c.tamper(); val ovr = t.field("POST body id= (override the dropdown)", "")
                c.button(tr("Submit")) { b -> val v = ovr.str().ifEmpty { (sp.selectedItemPosition + 1).toString() }; Bg.run(b) { send(lv, v, res, "POST id=${U.urlencode(v)}") } }
            }
            "high" -> {
                c.p(tr("Click here to change your ID. (cookie-input.php sets the 'id' cookie)"))
                val t = c.tamper(); val ck = t.field("Cookie: id=", (Session.vars["blind_id"] as? String) ?: "1")
                c.button(tr("Change your ID"), outlined = true) {
                    val et = EditText(f.requireContext())
                    AlertDialog.Builder(f.requireContext()).setTitle(tr("Cookie ID input")).setView(et)
                        .setPositiveButton(tr("Submit")) { _, _ -> val v = et.text.toString(); Session.vars["blind_id"] = v; ck.setText(v) }
                        .setNegativeButton(tr("Close"), null).show()
                }
                c.button(tr("Reload page (send cookie)")) { b -> val v = ck.str(); Session.vars["blind_id"] = v; Bg.run(b) { send(lv, v, res, "GET /vulnerabilities/sqli_blind/  Cookie: id=$v") } }
            }
            else -> {
                val id = c.field(tr("User ID:"))
                val t = c.tamper(); val tok = Tok(t, true)
                c.button(tr("Submit")) { b ->
                    val v = id.str(); val tv = tok.value()
                    Bg.run(b) { if (!tok.valid(tv)) { res.clear(); res.err(TOKEN_FAIL) } else send(lv, v, res, "GET ?id=${U.urlencode(v)} (prepared statement)"); tok.refresh() }
                }
            }
        }
    }
}

// =====================================================================================
object WeakIdPage : Page() {
    override val id = "weak_id"; override val title = "Weak Session IDs"
    override val links = listOf("https://owasp.org/www-community/attacks/Session_Prediction")
    override fun build(ui: Ui, f: PageFragment) {
        val lv = level
        val c = ui.card()
        c.p(tr("This page will set a new cookie called dvwaSession each time the button is clicked."))
        val res = c.result()
        val hist = ui.card(tr("Cookies received so far")).result()
        c.button(tr("Generate")) {
            val v: String; val attrs: String
            when (lv) {
                "low" -> { val n = ((Session.vars["last_session_id"] as? Int) ?: 0) + 1; Session.vars["last_session_id"] = n; v = n.toString(); attrs = "" }
                "medium" -> { v = (System.currentTimeMillis() / 1000).toString(); attrs = "" }
                "high" -> { val n = ((Session.vars["last_session_id_high"] as? Int) ?: 0) + 1; Session.vars["last_session_id_high"] = n; v = U.md5(n.toString()); attrs = "; expires=+1h; path=/vulnerabilities/weak_id/; domain=127.0.0.1" }
                else -> { v = U.sha1(U.rnd.nextInt(Int.MAX_VALUE).toString() + (System.currentTimeMillis() / 1000) + "Impossible"); attrs = "; expires=+1h; path=/vulnerabilities/weak_id/; domain=127.0.0.1; Secure; HttpOnly" }
            }
            Session.vars["dvwaSession"] = v
            res.clear(); res.info("Set-Cookie: dvwaSession=$v$attrs")
            hist.text("dvwaSession=$v")
        }
    }
}
