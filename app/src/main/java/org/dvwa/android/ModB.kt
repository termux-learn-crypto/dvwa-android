package org.dvwa.android

import android.database.sqlite.SQLiteException
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import java.io.File
import java.io.FileOutputStream
import java.net.URLEncoder

object ModB {
    fun handle(id: String, sub: String, c: Ctx): Out? {
        return when (id) {
            "upload" -> handleUpload(sub, c)
            "captcha" -> handleCaptcha(sub, c)
            "sqli" -> handleSqli(sub, c)
            "sqli_blind" -> handleSqliBlind(sub, c)
            else -> null
        }
    }

    private fun handleUpload(sub: String, c: Ctx): Out? {
        if (sub.isNotEmpty()) return null
        val level = c.level
        var html = ""

        if (c.r.has("Upload")) {
            when (level) {
                "low" -> {
                    val upload = c.r.upload
                    if (upload != null) {
                        val baseName = File(upload.filename).name
                        val targetPath = "../../hackable/uploads/$baseName"
                        try {
                            val dest = File(c.os.uploadsDir, baseName)
                            dest.writeBytes(upload.data)
                            html += "<pre>${targetPath} succesfully uploaded!</pre>"
                        } catch (e: Exception) {
                            html += "<pre>Your image was not uploaded.</pre>"
                        }
                    } else {
                        html += "<pre>Your image was not uploaded.</pre>"
                    }
                }
                "medium" -> {
                    val upload = c.r.upload
                    if (upload != null) {
                        val uploadedName = upload.filename
                        val uploadedType = upload.type
                        val uploadedSize = upload.data.size
                        val baseName = File(uploadedName).name
                        val targetPath = "../../hackable/uploads/$baseName"
                        if ((uploadedType == "image/jpeg" || uploadedType == "image/png") && uploadedSize < 100000) {
                            try {
                                val dest = File(c.os.uploadsDir, baseName)
                                dest.writeBytes(upload.data)
                                html += "<pre>${targetPath} succesfully uploaded!</pre>"
                            } catch (e: Exception) {
                                html += "<pre>Your image was not uploaded.</pre>"
                            }
                        } else {
                            html += "<pre>Your image was not uploaded. We can only accept JPEG or PNG images.</pre>"
                        }
                    } else {
                        html += "<pre>Your image was not uploaded.</pre>"
                    }
                }
                "high" -> {
                    val upload = c.r.upload
                    if (upload != null) {
                        val uploadedName = upload.filename
                        val ext = if (uploadedName.contains('.')) uploadedName.substringAfterLast('.').lowercase() else ""
                        val uploadedSize = upload.data.size
                        val baseName = File(uploadedName).name
                        val targetPath = "../../hackable/uploads/$baseName"
                        val isImage = checkImageMagic(upload.data)
                        if ((ext == "jpg" || ext == "jpeg" || ext == "png") && uploadedSize < 100000 && isImage) {
                            try {
                                val dest = File(c.os.uploadsDir, baseName)
                                dest.writeBytes(upload.data)
                                html += "<pre>${targetPath} succesfully uploaded!</pre>"
                            } catch (e: Exception) {
                                html += "<pre>Your image was not uploaded.</pre>"
                            }
                        } else {
                            html += "<pre>Your image was not uploaded. We can only accept JPEG or PNG images.</pre>"
                        }
                    } else {
                        html += "<pre>Your image was not uploaded.</pre>"
                    }
                }
                "impossible" -> {
                    try {
                        c.checkToken(c.r.req("user_token"))
                    } catch (e: TokenFail) {
                        throw e
                    }
                    val upload = c.r.upload
                    if (upload != null) {
                        val uploadedName = upload.filename
                        val ext = if (uploadedName.contains('.')) uploadedName.substringAfterLast('.').lowercase() else ""
                        val uploadedSize = upload.data.size
                        val uploadedType = upload.type
                        val targetPath = "../../hackable/uploads/"
                        val randomName = U.randHex(16) + "." + ext
                        val tempFile = File(System.getProperty("java.io.tmpdir"), randomName)
                        val isImage = checkImageMagic(upload.data)

                        if ((ext == "jpg" || ext == "jpeg" || ext == "png") && uploadedSize < 100000 && (uploadedType == "image/jpeg" || uploadedType == "image/png") && isImage) {
                            try {
                                val bmp = BitmapFactory.decodeByteArray(upload.data, 0, upload.data.size)
                                if (bmp != null) {
                                    val fos = FileOutputStream(tempFile)
                                    if (uploadedType == "image/jpeg") {
                                        bmp.compress(Bitmap.CompressFormat.JPEG, 100, fos)
                                    } else {
                                        bmp.compress(Bitmap.CompressFormat.PNG, 100, fos)
                                    }
                                    fos.close()
                                    bmp.recycle()

                                    val finalDest = File(c.os.uploadsDir, randomName)
                                    if (tempFile.renameTo(finalDest)) {
                                        html += "<pre><a href='${targetPath}${randomName}'>${randomName}</a> succesfully uploaded!</pre>"
                                    } else {
                                        html += "<pre>Your image was not uploaded.</pre>"
                                    }
                                    if (tempFile.exists()) tempFile.delete()
                                } else {
                                    html += "<pre>Your image was not uploaded.</pre>"
                                }
                            } catch (e: Exception) {
                                html += "<pre>Your image was not uploaded.</pre>"
                            }
                        } else {
                            html += "<pre>Your image was not uploaded. We can only accept JPEG or PNG images.</pre>"
                        }
                    } else {
                        html += "<pre>Your image was not uploaded.</pre>"
                    }
                }
            }
        }

        if (level == "impossible") {
            c.s.newToken()
        }

        val uploadsDirWritable = c.os.uploadsDir.canWrite()
        val warningHtml = if (!uploadsDirWritable) {
            "<div class=\"warning\">Incorrect folder permissions: ${c.os.uploadsDir.absolutePath}<br /><em>Folder is not writable.</em></div>"
        } else {
            ""
        }

        val tokenInput = if (level == "impossible") "			" + c.tokenField() else ""

        val body = StringBuilder()
        body.append("<div class=\"body_padded\">\n")
        body.append("	<h1>Vulnerability: File Upload</h1>\n")
        body.append("	${warningHtml}\n")
        body.append("	<div class=\"vulnerable_code_area\">\n")
        body.append("		<form enctype=\"multipart/form-data\" action=\"#\" method=\"POST\">\n")
        body.append("			<input type=\"hidden\" name=\"MAX_FILE_SIZE\" value=\"100000\" />\n")
        body.append("			Choose an image to upload:<br /><br />\n")
        body.append("			<input name=\"uploaded\" type=\"file\" /><br />\n")
        body.append("			<br />\n")
        body.append("			<input type=\"submit\" name=\"Upload\" value=\"Upload\" />\n")
        if (level == "impossible") {
            body.append("			").append(c.tokenField()).append("\n")
        }
        body.append("		</form>\n")
        body.append("		${html}\n")
        body.append("	</div>\n")
        body.append("	<h2>More Information</h2>\n")
        body.append("	<ul>\n")
        body.append("		<li><a href=\"https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload\" target=\"_blank\">https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload</a></li>\n")
        body.append("		<li><a href=\"https://www.acunetix.com/websitesecurity/upload-forms-threat/\" target=\"_blank\">https://www.acunetix.com/websitesecurity/upload-forms-threat/</a></li>\n")
        body.append("	</ul>\n")
        body.append("</div>")

        return c.page("Vulnerability: File Upload", "upload", body.toString())
    }

    private fun checkImageMagic(data: ByteArray): Boolean {
        if (data.size < 4) return false
        // JPEG: FF D8 FF
        if (data[0] == 0xFF.toByte() && data[1] == 0xD8.toByte() && data[2] == 0xFF.toByte()) return true
        // PNG: 89 50 4E 47
        if (data[0] == 0x89.toByte() && data[1] == 0x50.toByte() && data[2] == 0x4E.toByte() && data[3] == 0x47.toByte()) return true
        // GIF: GIF8
        if (data.size >= 6 && data[0] == 'G'.code.toByte() && data[1] == 'I'.code.toByte() && data[2] == 'F'.code.toByte() && data[3] == '8'.code.toByte()) return true
        // BMP: BM
        if (data[0] == 'B'.code.toByte() && data[1] == 'M'.code.toByte()) return true
        // WEBP: RIFF....WEBP
        if (data.size >= 12 && data[0] == 'R'.code.toByte() && data[1] == 'I'.code.toByte() && data[2] == 'F'.code.toByte() && data[3] == 'F'.code.toByte() &&
            data[8] == 'W'.code.toByte() && data[9] == 'E'.code.toByte() && data[10] == 'B'.code.toByte() && data[11] == 'P'.code.toByte()) return true
        return false
    }

    // Proper re-implementation of captcha render method
    private fun handleCaptcha(sub: String, c: Ctx): Out? {
        if (sub.isNotEmpty()) return null
        val level = c.level
        var html = ""
        var hideForm = false

        val change = c.r.req("Change") != null
        val step = c.r.req("step") ?: "1"

        fun checkCaptchaAnswer(resp: String?): Boolean {
            val stored = c.s.vars["captcha"] as? String
            if (stored != null && resp != null && resp.equals(stored, ignoreCase = true)) {
                c.s.vars.remove("captcha")
                return true
            }
            return false
        }

        if (change) {
            when (level) {
                "low" -> {
                    if (step == "1") {
                        hideForm = true
                        val passNew = c.r.req("password_new") ?: ""
                        val passConf = c.r.req("password_conf") ?: ""
                        val resp = c.r.req("g-recaptcha-response")
                        val ok = checkCaptchaAnswer(resp)
                        if (!ok) {
                            html += "<pre><br />The CAPTCHA was incorrect. Please try again.</pre>"
                            hideForm = false
                        } else {
                            if (passNew == passConf) {
                                html += "<pre><br />You passed the CAPTCHA! Click the button to confirm your changes.<br /></pre>" +
                                        "<form action=\"#\" method=\"POST\">" +
                                        "<input type=\"hidden\" name=\"step\" value=\"2\" />" +
                                        "<input type=\"hidden\" name=\"password_new\" value=\"${U.h(passNew)}\" />" +
                                        "<input type=\"hidden\" name=\"password_conf\" value=\"${U.h(passConf)}\" />" +
                                        "<input type=\"submit\" name=\"Change\" value=\"Change\" />" +
                                        "</form>"
                            } else {
                                html += "<pre>Both passwords must match.</pre>"
                                hideForm = false
                            }
                        }
                    } else if (step == "2") {
                        hideForm = true
                        val passNew = c.r.req("password_new") ?: ""
                        val passConf = c.r.req("password_conf") ?: ""
                        if (passNew == passConf) {
                            val escapedPass = U.esc(passNew)
                            val md5Pass = U.md5(escapedPass)
                            val insert = "UPDATE `users` SET password = '$md5Pass' WHERE user = '${c.user}';"
                            try {
                                c.db.vulnExec(insert)
                                html += "<pre>Password Changed.</pre>"
                            } catch (e: SQLiteException) {
                                return Out("<pre>" + e.message + "</pre>")
                            }
                        } else {
                            html += "<pre>Passwords did not match.</pre>"
                            hideForm = false
                        }
                    }
                }
                "medium" -> {
                    if (step == "1") {
                        hideForm = true
                        val passNew = c.r.req("password_new") ?: ""
                        val passConf = c.r.req("password_conf") ?: ""
                        val resp = c.r.req("g-recaptcha-response")
                        val ok = checkCaptchaAnswer(resp)
                        if (!ok) {
                            html += "<pre><br />The CAPTCHA was incorrect. Please try again.</pre>"
                            hideForm = false
                        } else {
                            if (passNew == passConf) {
                                html += "<pre><br />You passed the CAPTCHA! Click the button to confirm your changes.<br /></pre>" +
                                        "<form action=\"#\" method=\"POST\">" +
                                        "<input type=\"hidden\" name=\"step\" value=\"2\" />" +
                                        "<input type=\"hidden\" name=\"password_new\" value=\"${U.h(passNew)}\" />" +
                                        "<input type=\"hidden\" name=\"password_conf\" value=\"${U.h(passConf)}\" />" +
                                        "<input type=\"hidden\" name=\"passed_captcha\" value=\"true\" />" +
                                        "<input type=\"submit\" name=\"Change\" value=\"Change\" />" +
                                        "</form>"
                            } else {
                                html += "<pre>Both passwords must match.</pre>"
                                hideForm = false
                            }
                        }
                    } else if (step == "2") {
                        hideForm = true
                        val passNew = c.r.req("password_new") ?: ""
                        val passConf = c.r.req("password_conf") ?: ""
                        val passedCaptcha = c.r.req("passed_captcha")
                        if (passedCaptcha != "true") {
                            html += "<pre><br />You have not passed the CAPTCHA.</pre>"
                            hideForm = false
                        } else {
                            if (passNew == passConf) {
                                val escapedPass = U.esc(passNew)
                                val md5Pass = U.md5(escapedPass)
                                val insert = "UPDATE `users` SET password = '$md5Pass' WHERE user = '${c.user}';"
                                try {
                                    c.db.vulnExec(insert)
                                    html += "<pre>Password Changed.</pre>"
                                } catch (e: SQLiteException) {
                                    return Out("<pre>" + e.message + "</pre>")
                                }
                            } else {
                                html += "<pre>Passwords did not match.</pre>"
                                hideForm = false
                            }
                        }
                    }
                }
                "high" -> {
                    hideForm = true
                    val passNew = c.r.req("password_new") ?: ""
                    val passConf = c.r.req("password_conf") ?: ""
                    val resp = c.r.req("g-recaptcha-response")
                    val userAgent = c.r.headers["user-agent"] ?: ""
                    val ok = checkCaptchaAnswer(resp) || (resp == "hidd3n_valu3" && userAgent == "reCAPTCHA")
                    if (ok) {
                        if (passNew == passConf) {
                            val escapedPass = U.esc(passNew)
                            val md5Pass = U.md5(escapedPass)
                            val insert = "UPDATE `users` SET password = '$md5Pass' WHERE user = '${c.user}' LIMIT 1;"
                            try {
                                c.db.vulnExec(insert)
                                html += "<pre>Password Changed.</pre>"
                            } catch (e: SQLiteException) {
                                return Out("<pre>" + e.message + "</pre>")
                            }
                        } else {
                            html += "<pre>Both passwords must match.</pre>"
                            hideForm = false
                        }
                    } else {
                        html += "<pre><br />The CAPTCHA was incorrect. Please try again.</pre>"
                        hideForm = false
                    }
                }
                "impossible" -> {
                    try {
                        c.checkToken(c.r.req("user_token"))
                    } catch (e: TokenFail) {
                        throw e
                    }
                    hideForm = true
                    val passNewRaw = c.r.req("password_new") ?: ""
                    val passConfRaw = c.r.req("password_conf") ?: ""
                    val passCurrRaw = c.r.req("password_current") ?: ""

                    val passNew = U.md5(U.esc(U.stripslashes(passNewRaw)))
                    val passConf = U.md5(U.esc(U.stripslashes(passConfRaw)))
                    val passCurr = U.md5(U.esc(U.stripslashes(passCurrRaw)))

                    val resp = c.r.req("g-recaptcha-response")
                    val ok = checkCaptchaAnswer(resp)
                    if (!ok) {
                        html += "<pre><br />The CAPTCHA was incorrect. Please try again.</pre>"
                        hideForm = false
                    } else {
                        val rows = c.db.prepared("SELECT password FROM users WHERE user = ? AND password = ? LIMIT 1;", c.user, passCurr)
                        if (passNew == passConf && rows.size == 1) {
                            c.db.preparedExec("UPDATE users SET password = ? WHERE user = ?;", passNew, c.user)
                            html += "<pre>Password Changed.</pre>"
                        } else {
                            html += "<pre>Either your current password is incorrect or the new passwords did not match.<br />Please try again.</pre>"
                            hideForm = false
                        }
                    }
                }
            }
        }

        if (level == "high" || level == "impossible") {
            c.s.newToken()
        }

        var captchaCode = c.s.vars["captcha"] as? String
        if (captchaCode == null) {
            val chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
            val sb = StringBuilder()
            for (i in 0 until 6) {
                sb.append(chars[U.rand(0, chars.length - 1)])
            }
            captchaCode = sb.toString()
            c.s.vars["captcha"] = captchaCode
        }

        val captchaHtml = "<div style=\"font:bold 26px monospace;letter-spacing:6px;background:#eee;border:1px solid #999;display:inline-block;padding:6px 12px;transform:skew(-12deg);color:#363;text-decoration:line-through\">$captchaCode</div><br /><label>Type the characters above:</label><br /><input type=\"text\" name=\"g-recaptcha-response\" autocomplete=\"off\" />"

        val body = StringBuilder()
        body.append("<div class=\"body_padded\">\n")
        body.append("	<h1>Vulnerability: Insecure CAPTCHA</h1>\n")
        body.append("	<div class=\"vulnerable_code_area\">\n")
        body.append("		<form action=\"#\" method=\"POST\" ")
        if (hideForm) body.append("style=\"display:none;\"")
        body.append(">\n")
        body.append("			<h3>Change your password:</h3>\n")
        body.append("			<br />\n")
        body.append("			<input type=\"hidden\" name=\"step\" value=\"1\" />\n")
        if (level == "impossible") {
            body.append("			Current password:<br />\n")
            body.append("			<input type=\"password\" AUTOCOMPLETE=\"off\" name=\"password_current\"><br />\n")
        }
        body.append("			New password:<br />\n")
        body.append("			<input type=\"password\" AUTOCOMPLETE=\"off\" name=\"password_new\"><br />\n")
        body.append("			Confirm new password:<br />\n")
        body.append("			<input type=\"password\" AUTOCOMPLETE=\"off\" name=\"password_conf\"><br />\n")
        body.append("			").append(captchaHtml).append("\n")
        if (level == "high") {
            body.append("\n			<!-- **DEV NOTE**   Response: 'hidd3n_valu3'   &&   User-Agent: 'reCAPTCHA'   **/DEV NOTE** -->\n")
        }
        if (level == "high" || level == "impossible") {
            body.append("\n			").append(c.tokenField()).append("\n")
        }
        body.append("			<br />\n")
        body.append("			<input type=\"submit\" value=\"Change\" name=\"Change\">\n")
        body.append("		</form>\n")
        body.append("		${html}\n")
        body.append("	</div>\n")
        body.append("	<h2>More Information</h2>\n")
        body.append("	<ul>\n")
        body.append("		<li><a href=\"https://en.wikipedia.org/wiki/CAPTCHA\" target=\"_blank\">https://en.wikipedia.org/wiki/CAPTCHA</a></li>\n")
        body.append("		<li><a href=\"https://www.google.com/recaptcha/\" target=\"_blank\">https://www.google.com/recaptcha/</a></li>\n")
        body.append("		<li><a href=\"https://owasp.org/www-project-automated-threats-to-web-applications/assets/oats/EN/OAT-009_CAPTCHA_Defeat\" target=\"_blank\">https://owasp.org/www-project-automated-threats-to-web-applications/assets/oats/EN/OAT-009_CAPTCHA_Defeat</a></li>\n")
        body.append("	</ul>\n")
        body.append("</div>")

        return c.page("Vulnerability: Insecure CAPTCHA", "captcha", body.toString())
    }

    private fun handleSqli(sub: String, c: Ctx): Out? {
        val level = c.level
        if (sub == "session-input.php") {
            if (c.r.has("id")) {
                val newId = c.r.req("id") ?: ""
                c.s.vars["sqli_id"] = newId
                var body = "Session ID: ${newId}<br /><br /><br />" +
                        "<script>window.opener.location.reload(true);</script>" +
                        "<form action=\"#\" method=\"POST\">\n" +
                        "	<input type=\"text\" size=\"15\" name=\"id\">\n" +
                        "	<input type=\"submit\" name=\"Submit\" value=\"Submit\">\n" +
                        "</form>\n" +
                        "<hr />\n" +
                        "<br />\n" +
                        "<a href=\"./\">Back</a>"
                return Out("<!DOCTYPE html><html><head><title>SQL Injection Session Input</title><link rel=\"stylesheet\" href=\"/dvwa/css/main.css\"></head><body>$body</body></html>")
            } else {
                var body = "<form action=\"#\" method=\"POST\">\n" +
                        "	<input type=\"text\" size=\"15\" name=\"id\">\n" +
                        "	<input type=\"submit\" name=\"Submit\" value=\"Submit\">\n" +
                        "</form>\n" +
                        "<hr />\n" +
                        "<br />\n" +
                        "<a href=\"./\">Back</a>"
                return Out("<!DOCTYPE html><html><head><title>SQL Injection Session Input</title><link rel=\"stylesheet\" href=\"/dvwa/css/main.css\"></head><body>$body</body></html>")
            }
        }
        if (sub.isNotEmpty()) return null

        var html = ""
        val submit = c.r.req("Submit") != null

        if (submit) {
            when (level) {
                "low" -> {
                    val id = c.r.req("id") ?: ""
                    val query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';"
                    try {
                        val results = c.db.vulnQuery(query)
                        for (row in results) {
                            val first = row["first_name"] ?: ""
                            val last = row["last_name"] ?: ""
                            html += "<pre>ID: ${id}<br />First name: ${first}<br />Surname: ${last}</pre>"
                        }
                    } catch (e: SQLiteException) {
                        return Out("<pre>Caught exception: ${e.message}</pre>")
                    }
                }
                "medium" -> {
                    val idRaw = c.r.req("id") ?: ""
                    val id = U.esc(idRaw)
                    val query = "SELECT first_name, last_name FROM users WHERE user_id = $id;"
                    try {
                        val results = c.db.vulnQuery(query)
                        for (row in results) {
                            val first = row["first_name"] ?: ""
                            val last = row["last_name"] ?: ""
                            html += "<pre>ID: ${id}<br />First name: ${first}<br />Surname: ${last}</pre>"
                        }
                    } catch (e: SQLiteException) {
                        return Out("<pre>Caught exception: ${e.message}</pre>")
                    }
                }
                "high" -> {
                    // handled via session vars below
                }
                "impossible" -> {
                    try {
                        c.checkToken(c.r.req("user_token"))
                    } catch (e: TokenFail) {
                        throw e
                    }
                    val idRaw = c.r.req("id") ?: ""
                    if (U.isNumeric(idRaw)) {
                        val idInt = idRaw.trim().toDouble().toInt()
                        try {
                            val rows = c.db.prepared("SELECT first_name, last_name FROM users WHERE user_id = ? LIMIT 1;", idInt.toString())
                            if (rows.size == 1) {
                                val row = rows[0]
                                val first = U.h(row["first_name"])
                                val last = U.h(row["last_name"])
                                html += "<pre>ID: ${idInt}<br />First name: ${first}<br />Surname: ${last}</pre>"
                            }
                        } catch (e: Exception) {
                        }
                    }
                }
            }
        }

        if (level == "high") {
            val id = c.s.vars["sqli_id"] as? String
            if (id != null) {
                val query = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;"
                try {
                    val results = c.db.vulnQuery(query)
                    for (row in results) {
                        val first = row["first_name"] ?: ""
                        val last = row["last_name"] ?: ""
                        html += "<pre>ID: ${id}<br />First name: ${first}<br />Surname: ${last}</pre>"
                    }
                } catch (e: SQLiteException) {
                    return Out("<pre>Caught exception: ${e.message}</pre>")
                }
            }
        }

        var numberOfRows = 0
        if (level == "medium") {
            try {
                val countRows = c.db.vulnQuery("SELECT COUNT(*) AS cnt FROM users;")
                if (countRows.isNotEmpty()) {
                    numberOfRows = countRows[0]["cnt"]?.toInt() ?: 1
                }
            } catch (e: Exception) {
                numberOfRows = 1
            }
        }

        if (level == "impossible" || level == "high") {
            c.s.newToken()
        }

        val method = if (level == "medium") "POST" else "GET"

        val body = StringBuilder()
        body.append("<div class=\"body_padded\">\n")
        body.append("	<h1>Vulnerability: SQL Injection</h1>\n")
        body.append("	<div class=\"vulnerable_code_area\">")
        if (level == "high") {
            body.append("Click <a href=\"#\" onclick=\"javascript:popUp('session-input.php');return false;\">here to change your ID</a>.")
        } else {
            body.append("\n")
            body.append("		<form action=\"#\" method=\"${method}\">\n")
            body.append("			<p>\n")
            body.append("				User ID:")
            if (level == "medium") {
                body.append("\n				<select name=\"id\">")
                for (i in 1..numberOfRows) {
                    body.append("<option value=\"${i}\">${i}</option>")
                }
                body.append("</select>")
            } else {
                body.append("\n				<input type=\"text\" size=\"15\" name=\"id\">")
            }
            body.append("\n				<input type=\"submit\" name=\"Submit\" value=\"Submit\">\n")
            body.append("			</p>\n")
            if (level == "impossible") {
                body.append("			").append(c.tokenField()).append("\n")
            }
            body.append("		</form>")
        }
        body.append("\n")
        body.append("		${html}\n")
        body.append("	</div>\n")
        body.append("	<h2>More Information</h2>\n")
        body.append("	<ul>\n")
        body.append("		<li><a href=\"https://en.wikipedia.org/wiki/SQL_injection\" target=\"_blank\">https://en.wikipedia.org/wiki/SQL_injection</a></li>\n")
        body.append("		<li><a href=\"https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/\" target=\"_blank\">https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/</a></li>\n")
        body.append("		<li><a href=\"https://owasp.org/www-community/attacks/SQL_Injection\" target=\"_blank\">https://owasp.org/www-community/attacks/SQL_Injection</a></li>\n")
        body.append("		<li><a href=\"https://bobby-tables.com/\" target=\"_blank\">https://bobby-tables.com/</a></li>\n")
        body.append("	</ul>\n")
        body.append("</div>")

        return c.page("Vulnerability: SQL Injection", "sqli", body.toString())
    }

    private fun handleSqliBlind(sub: String, c: Ctx): Out? {
        val level = c.level
        if (sub == "cookie-input.php") {
            if (c.r.has("id")) {
                val newId = c.r.req("id") ?: ""
                val encodedId = URLEncoder.encode(newId, "UTF-8")
                val out = Out()
                out.cookies.add("id=$encodedId; path=/")
                var body = "Cookie ID set!<br /><br /><br />" +
                        "<script>window.opener.location.reload(true);</script>" +
                        "<form action=\"#\" method=\"POST\">\n" +
                        "	<input type=\"text\" size=\"15\" name=\"id\">\n" +
                        "	<input type=\"submit\" name=\"Submit\" value=\"Submit\">\n" +
                        "</form>\n" +
                        "<hr />\n" +
                        "<br />\n" +
                        "<a href=\"./\">Back</a>"
                out.body = "<!DOCTYPE html><html><head><title>Blind SQL Injection Cookie Input</title><link rel=\"stylesheet\" href=\"/dvwa/css/main.css\"></head><body>$body</body></html>"
                return out
            } else {
                var body = "<form action=\"#\" method=\"POST\">\n" +
                        "	<input type=\"text\" size=\"15\" name=\"id\">\n" +
                        "	<input type=\"submit\" name=\"Submit\" value=\"Submit\">\n" +
                        "</form>\n" +
                        "<hr />\n" +
                        "<br />\n" +
                        "<a href=\"./\">Back</a>"
                return Out("<!DOCTYPE html><html><head><title>Blind SQL Injection Cookie Input</title><link rel=\"stylesheet\" href=\"/dvwa/css/main.css\"></head><body>$body</body></html>")
            }
        }
        if (sub.isNotEmpty()) return null

        var html = ""
        var isMissing = false
        val submit = c.r.req("Submit") != null

        if (submit || level == "high") {
            when (level) {
                "low" -> {
                    if (submit) {
                        val id = c.r.req("id") ?: ""
                        var exists = false
                        try {
                            val results = c.db.vulnQuery("SELECT first_name, last_name FROM users WHERE user_id = '$id';")
                            exists = results.isNotEmpty()
                        } catch (e: Exception) {
                            exists = false
                        }
                        if (exists) {
                            html += "<pre>User ID exists in the database.</pre>"
                        } else {
                            isMissing = true
                            html += "<pre>User ID is MISSING from the database.</pre>"
                        }
                    }
                }
                "medium" -> {
                    if (submit) {
                        val id = c.r.req("id") ?: ""
                        var exists = false
                        try {
                            val results = c.db.vulnQuery("SELECT first_name, last_name FROM users WHERE user_id = $id;")
                            exists = results.isNotEmpty()
                        } catch (e: Exception) {
                            exists = false
                        }
                        if (exists) {
                            html += "<pre>User ID exists in the database.</pre>"
                        } else {
                            html += "<pre>User ID is MISSING from the database.</pre>"
                        }
                    }
                }
                "high" -> {
                    val id = c.r.cookies["id"]
                    if (id != null) {
                        var exists = false
                        try {
                            val results = c.db.vulnQuery("SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;")
                            exists = results.isNotEmpty()
                        } catch (e: Exception) {
                            exists = false
                        }
                        if (exists) {
                            html += "<pre>User ID exists in the database.</pre>"
                        } else {
                            if (U.rand(0, 5) == 3) {
                                try {
                                    Thread.sleep((U.rand(2, 4) * 1000).toLong())
                                } catch (e: InterruptedException) {
                                }
                            }
                            isMissing = true
                            html += "<pre>User ID is MISSING from the database.</pre>"
                        }
                    }
                }
                "impossible" -> {
                    if (submit) {
                        try {
                            c.checkToken(c.r.req("user_token"))
                        } catch (e: TokenFail) {
                            throw e
                        }
                        val idRaw = c.r.req("id") ?: ""
                        var exists = false
                        if (U.isNumeric(idRaw)) {
                            val idInt = idRaw.trim().toDouble().toInt()
                            try {
                                val rows = c.db.prepared("SELECT COUNT(first_name) AS numrows FROM users WHERE user_id = ? LIMIT 1;", idInt.toString())
                                if (rows.size == 1) {
                                    val numrows = rows[0]["numrows"]?.toInt() ?: 0
                                    exists = (numrows == 1)
                                }
                            } catch (e: Exception) {
                            }
                        }
                        if (exists) {
                            html += "<pre>User ID exists in the database.</pre>"
                        } else {
                            isMissing = true
                            html += "<pre>User ID is MISSING from the database.</pre>"
                        }
                    }
                }
            }
        }

        if (level == "impossible" || level == "high") {
            c.s.newToken()
        }

        var numberOfRows = 0
        if (level == "medium") {
            try {
                val countRows = c.db.vulnQuery("SELECT COUNT(*) AS cnt FROM users;")
                if (countRows.isNotEmpty()) {
                    numberOfRows = countRows[0]["cnt"]?.toInt() ?: 1
                }
            } catch (e: Exception) {
                numberOfRows = 1
            }
        }

        val method = if (level == "medium") "POST" else "GET"

        val body = StringBuilder()
        body.append("<div class=\"body_padded\">\n")
        body.append("	<h1>Vulnerability: SQL Injection (Blind)</h1>\n")
        body.append("	<div class=\"vulnerable_code_area\">")
        if (level == "high") {
            body.append("Click <a href=\"#\" onclick=\"javascript:popUp('cookie-input.php');return false;\">here to change your ID</a>.")
        } else {
            body.append("\n")
            body.append("		<form action=\"#\" method=\"${method}\">\n")
            body.append("			<p>\n")
            body.append("				User ID:")
            if (level == "medium") {
                body.append("\n				<select name=\"id\">")
                for (i in 1..numberOfRows) {
                    body.append("<option value=\"${i}\">${i}</option>")
                }
                body.append("</select>")
            } else {
                body.append("\n				<input type=\"text\" size=\"15\" name=\"id\">")
            }
            body.append("\n				<input type=\"submit\" name=\"Submit\" value=\"Submit\">\n")
            body.append("			</p>\n")
            if (level == "impossible") {
                body.append("			").append(c.tokenField()).append("\n")
            }
            body.append("		</form>")
        }
        body.append("\n")
        body.append("		${html}\n")
        body.append("	</div>\n")
        body.append("	<h2>More Information</h2>\n")
        body.append("	<ul>\n")
        body.append("		<li><a href=\"https://en.wikipedia.org/wiki/SQL_injection\" target=\"_blank\">https://en.wikipedia.org/wiki/SQL_injection</a></li>\n")
        body.append("		<li><a href=\"https://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet\" target=\"_blank\">https://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet</a></li>\n")
        body.append("		<li><a href=\"https://owasp.org/www-community/attacks/Blind_SQL_Injection\" target=\"_blank\">https://owasp.org/www-community/attacks/Blind_SQL_Injection</a></li>\n")
        body.append("		<li><a href=\"https://bobby-tables.com/\" target=\"_blank\">https://bobby-tables.com/</a></li>\n")
        body.append("	</ul>\n")
        body.append("</div>")

        val out = c.page("Vulnerability: SQL Injection (Blind)", "sqli_blind", body.toString())
        if (isMissing && (level == "low" || level == "high" || level == "impossible")) {
            out.status = 404
        }
        return out
    }
}