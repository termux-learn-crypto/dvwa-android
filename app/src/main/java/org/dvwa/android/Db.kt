package org.dvwa.android

import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import java.io.File
import java.text.SimpleDateFormat
import java.util.*

/** The app's sandboxed SQLite database (users + guestbook), DVWA schema. */
class Db(private val ctx: Context) {
    private val file = File(ctx.filesDir, "dvwa.db")
    private val isFile = File(ctx.filesDir, "information_schema.db")
    @Volatile private var db: SQLiteDatabase? = null

    @Synchronized fun get(): SQLiteDatabase {
        db?.let { if (it.isOpen) return it }
        val fresh = !file.exists()
        val d = SQLiteDatabase.openOrCreateDatabase(file, null)
        db = d
        if (fresh) createTables(d)
        attachInfo(d)
        return d
    }

    @Synchronized fun reset(): List<String> {
        val d = get()
        val log = ArrayList<String>()
        d.execSQL("DROP TABLE IF EXISTS users"); d.execSQL("DROP TABLE IF EXISTS guestbook")
        createTables(d)
        log += tr("Database has been created.")
        log += tr("'users' table was created.")
        log += tr("Data inserted into 'users' table.")
        log += tr("'guestbook' table was created.")
        log += tr("Data inserted into 'guestbook' table.")
        return log
    }

    private fun createTables(d: SQLiteDatabase) {
        d.execSQL("CREATE TABLE users (user_id INTEGER PRIMARY KEY, first_name TEXT, last_name TEXT, user TEXT, password TEXT, avatar TEXT, last_login TEXT, failed_login INTEGER)")
        val now = nowStr()
        val users = listOf(
            arrayOf("1", "admin", "admin", "admin", "password"),
            arrayOf("2", "Gordon", "Brown", "gordonb", "abc123"),
            arrayOf("3", "Hack", "Me", "1337", "charley"),
            arrayOf("4", "Pablo", "Picasso", "pablo", "letmein"),
            arrayOf("5", "Bob", "Smith", "smithy", "password"))
        for (u in users) d.execSQL(
            "INSERT INTO users VALUES (?,?,?,?,?,?,?,0)",
            arrayOf<Any>(u[0].toInt(), u[1], u[2], u[3], U.md5(u[4]), "/hackable/users/${u[3]}.jpg", now))
        d.execSQL("CREATE TABLE guestbook (comment_id INTEGER PRIMARY KEY AUTOINCREMENT, comment TEXT, name TEXT)")
        d.execSQL("INSERT INTO guestbook (comment, name) VALUES ('This is a test comment.', 'test')")
    }

    /** A MySQL-style information_schema so classic payloads work against SQLite. */
    private fun attachInfo(d: SQLiteDatabase) {
        try {
            isFile.delete()
            val i = SQLiteDatabase.openOrCreateDatabase(isFile, null)
            i.execSQL("CREATE TABLE tables (table_catalog TEXT, table_schema TEXT, table_name TEXT, table_type TEXT)")
            i.execSQL("CREATE TABLE columns (table_catalog TEXT, table_schema TEXT, table_name TEXT, column_name TEXT, ordinal_position INTEGER, data_type TEXT)")
            i.execSQL("CREATE TABLE schemata (catalog_name TEXT, schema_name TEXT)")
            i.execSQL("INSERT INTO schemata VALUES ('def','information_schema'),('def','dvwa')")
            val cols = mapOf(
                "users" to listOf("user_id" to "int", "first_name" to "varchar", "last_name" to "varchar", "user" to "varchar", "password" to "varchar", "avatar" to "varchar", "last_login" to "timestamp", "failed_login" to "int"),
                "guestbook" to listOf("comment_id" to "smallint", "comment" to "varchar", "name" to "varchar"))
            for ((t, cs) in cols) {
                i.execSQL("INSERT INTO tables VALUES ('def','dvwa',?,'BASE TABLE')", arrayOf(t))
                cs.forEachIndexed { n, c -> i.execSQL("INSERT INTO columns VALUES ('def','dvwa',?,?,?,?)", arrayOf<Any>(t, c.first, n + 1, c.second)) }
            }
            i.close()
            d.execSQL("ATTACH DATABASE '" + isFile.absolutePath + "' AS information_schema")
        } catch (e: Exception) { /* already attached */ }
    }

    // ---------- helpers ----------
    fun rows(c: Cursor): List<Map<String, String>> {
        val out = ArrayList<Map<String, String>>()
        c.use {
            while (it.moveToNext()) {
                val m = LinkedHashMap<String, String>()
                for (k in 0 until it.columnCount) {
                    val v = try { when (it.getType(k)) {
                        Cursor.FIELD_TYPE_NULL -> ""
                        Cursor.FIELD_TYPE_BLOB -> String(it.getBlob(k), Charsets.ISO_8859_1)
                        else -> it.getString(k) ?: "" } } catch (e: Exception) { "" }
                    // like PHP fetch_assoc: first duplicate name wins positionally -> last wins in PHP; keep last
                    m[it.getColumnName(k)] = v
                    m["#$k"] = v
                }
                out += m
            }
        }
        return out
    }
    /** Run a (possibly injected) string-concatenated query, MySQL dialect emulated. */
    fun vulnQuery(sql: String): List<Map<String, String>> = rows(get().rawQuery(mysqlCompat(sql), null))
    fun vulnExec(sql: String) = get().execSQL(mysqlCompat(sql))
    fun prepared(sql: String, vararg a: String): List<Map<String, String>> = rows(get().rawQuery(sql, arrayOf(*a)))
    fun preparedExec(sql: String, vararg a: Any) = get().execSQL(sql, arrayOf(*a))

    companion object {
        fun nowStr(): String = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())

        /**
         * Make MySQL-flavoured SQL run on SQLite while preserving MySQL string semantics:
         * backslash escapes inside quotes (so mysqli_real_escape_string really protects),
         * '#' comments, user()/database()/version()/@@version, concat(), sleep(n).
         */
        fun mysqlCompat(sql: String): String {
            val sb = StringBuilder()
            var i = 0
            var q: Char? = null
            while (i < sql.length) {
                val c = sql[i]
                if (q == null) {
                    when {
                        c == '\'' || c == '"' -> { q = c; sb.append('\'') }
                        c == '#' -> { sb.append("--"); }
                        c == ';' -> { // mysqli_query runs one statement; SQLite would error on a trailing statement
                            val rest = sql.substring(i + 1).trim()
                            if (rest.isEmpty() || rest.startsWith("--") || rest.startsWith("#")) sb.append(' ') else sb.append(c)
                        }
                        else -> sb.append(c)
                    }
                } else {
                    when {
                        c == '\\' && i + 1 < sql.length -> {
                            val n = sql[i + 1]; i++
                            when (n) { '\'' -> sb.append("''"); 'n' -> sb.append('\n'); 'r' -> sb.append('\r'); '0' -> {}; 'Z' -> sb.append('\u001a'); else -> sb.append(n) }
                        }
                        c == q && i + 1 < sql.length && sql[i + 1] == q -> { sb.append(if (c == '\'') "''" else "\""); i++ }
                        c == q -> { q = null; sb.append('\'') }
                        c == '\'' -> sb.append("''")
                        else -> sb.append(c)
                    }
                }
                i++
            }
            var s = sb.toString()
            s = s.replace(Regex("(?i)\\bcurrent_user\\s*\\(\\s*\\)|\\buser\\s*\\(\\s*\\)|\\bsystem_user\\s*\\(\\s*\\)|\\bsession_user\\s*\\(\\s*\\)"), "'dvwa@localhost'")
            s = s.replace(Regex("(?i)\\bdatabase\\s*\\(\\s*\\)|\\bschema\\s*\\(\\s*\\)"), "'dvwa'")
            s = s.replace(Regex("(?i)@@version\\b|\\bversion\\s*\\(\\s*\\)"), "'10.11.6-MariaDB-0+deb12u1'")
            s = s.replace(Regex("(?i)@@hostname\\b"), "'dvwa'").replace(Regex("(?i)@@datadir\\b"), "'/var/lib/mysql/'")
            s = s.replace(Regex("(?i)\\bsleep\\s*\\(\\s*(\\d+)\\s*\\)")) { m ->
                val n = m.groupValues[1].toLong().coerceAtMost(20) * 1_500_000L
                "(WITH RECURSIVE zz(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM zz WHERE x<$n) SELECT count(*)*0 FROM zz)"
            }
            s = s.replace(Regex("(?i)\\bbenchmark\\s*\\(\\s*(\\d+)\\s*,[^)]*\\)")) { m ->
                "(WITH RECURSIVE zb(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM zb WHERE x<${m.groupValues[1].toLong().coerceAtMost(30_000_000L)}) SELECT count(*)*0 FROM zb)"
            }
            s = s.replace(Regex("(?i)\\bsubstring\\s*\\("), "substr(").replace(Regex("(?i)\\bmid\\s*\\("), "substr(")
            s = s.replace(Regex("(?i)\\bascii\\s*\\("), "unicode(").replace(Regex("(?i)\\bord\\s*\\("), "unicode(")
            s = s.replace(Regex("(?i)\\blength\\s*\\("), "length(")
            s = rewriteConcat(s)
            return s
        }

        /** concat(a,b,...) -> (a||b||...), concat_ws(sep,a,b) -> (a||sep||b) */
        private fun rewriteConcat(input: String): String {
            var s = input
            val re = Regex("(?i)\\bconcat(_ws)?\\s*\\(")
            var guard = 0
            while (guard++ < 50) {
                val m = re.find(s) ?: break
                val start = m.range.last + 1
                var depth = 1; var i = start; var inQ = false
                val args = ArrayList<String>(); var argStart = start
                while (i < s.length && depth > 0) {
                    val c = s[i]
                    if (inQ) { if (c == '\'') { if (i + 1 < s.length && s[i + 1] == '\'') i++ else inQ = false } }
                    else when (c) {
                        '\'' -> inQ = true
                        '(' -> depth++
                        ')' -> { depth--; if (depth == 0) args += s.substring(argStart, i) }
                        ',' -> if (depth == 1) { args += s.substring(argStart, i); argStart = i + 1 }
                    }
                    i++
                }
                if (depth != 0) break
                val ws = m.groupValues[1].isNotEmpty()
                val joined = if (ws && args.size > 1) args.drop(1).joinToString("||${args[0]}||") { "COALESCE($it,'')" }
                             else args.joinToString("||")
                s = s.substring(0, m.range.first) + "(" + joined + ")" + s.substring(i)
            }
            return s
        }
    }
}
