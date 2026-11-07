package org.dvwa.android

import android.content.Context
import java.io.File

/**
 * A simulated Debian web server. Nothing here ever executes a real Android command:
 * the "shell" is an interpreter over canned output and a virtual filesystem.
 * Real files are only read from the app's own private sandbox (uploads etc).
 */
class FakeOs(private val ctx: Context) {
    val webroot = "/var/www/html"
    val uploadsDir: File get() = File(ctx.filesDir, "hackable/uploads").also { it.mkdirs() }

    private val passwd = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
mysql:x:101:102:MySQL Server,,,:/nonexistent:/bin/false
dvwa:x:1000:1000:DVWA,,,:/home/dvwa:/bin/bash
"""
    private val fakeEnv = "APACHE_RUN_DIR=/var/run/apache2\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nAPACHE_LOCK_DIR=/var/lock/apache2\nLANG=C\nAPACHE_RUN_USER=www-data\nAPACHE_RUN_GROUP=www-data\nAPACHE_LOG_DIR=/var/log/apache2\nPWD=/var/www/html/vulnerabilities/exec\n"

    private val files: Map<String, String> = mapOf(
        "/etc/passwd" to passwd,
        "/etc/group" to "root:x:0:\ndaemon:x:1:\nadm:x:4:\nsudo:x:27:dvwa\nwww-data:x:33:\nmysql:x:102:\ndvwa:x:1000:\n",
        "/etc/hostname" to "dvwa\n",
        "/etc/hosts" to "127.0.0.1\tlocalhost\n127.0.1.1\tdvwa\n::1\tlocalhost ip6-localhost ip6-loopback\n",
        "/etc/issue" to "Debian GNU/Linux 12 \\n \\l\n\n",
        "/etc/os-release" to "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nVERSION=\"12 (bookworm)\"\nVERSION_CODENAME=bookworm\nID=debian\nHOME_URL=\"https://www.debian.org/\"\n",
        "/etc/resolv.conf" to "nameserver 127.0.0.11\noptions ndots:0\n",
        "/etc/crontab" to "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n",
        "/proc/version" to "Linux version 6.1.0-18-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 (2024-02-01)\n",
        "/home/dvwa/.bash_history" to "ls\ncd /var/www/html\nsudo nano config/config.inc.php\nmysql -u dvwa -p\n",
        "/home/dvwa/flag.txt" to "DVWA{c0mm4nd_1nj3ct10n_m4st3r}\n",
        "$webroot/config/config.inc.php" to "<?php\n\n# Database management system to use\n\$DBMS = 'MySQL';\n\n# Database variables\n\$_DVWA = array();\n\$_DVWA[ 'db_server' ]   = '127.0.0.1';\n\$_DVWA[ 'db_database' ] = 'dvwa';\n\$_DVWA[ 'db_user' ]     = 'dvwa';\n\$_DVWA[ 'db_password' ] = 'p@ssw0rd';\n\$_DVWA[ 'db_port']      = '3306';\n\n# ReCAPTCHA settings\n\$_DVWA[ 'recaptcha_public_key' ]  = '';\n\$_DVWA[ 'recaptcha_private_key' ] = '';\n\n# Default security level\n\$_DVWA[ 'default_security_level' ] = 'impossible';\n\$_DVWA[ 'SQLI_DB' ] = 'sqlite';\n?>\n",
        "$webroot/robots.txt" to "User-agent: *\nDisallow: /\n",
    )
    private val protectedFiles = setOf("/etc/shadow", "/root/flag.txt", "/etc/sudoers", "/root/.bash_history")
    private val extraDirs = mapOf(
        "/" to listOf("bin", "boot", "dev", "etc", "home", "lib", "media", "mnt", "opt", "proc", "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var"),
        "/etc" to listOf("apache2", "cron.d", "mysql", "php", "shadow", "sudoers"),
        "/home" to listOf("dvwa"), "/root" to listOf(),
        "/var" to listOf("backups", "cache", "lib", "log", "www"), "/var/www" to listOf("html"),
        "/tmp" to listOf(), "/proc" to listOf("version"), "/usr" to listOf("bin", "lib", "local", "sbin", "share"),
        "/bin" to listOf("bash", "cat", "date", "echo", "grep", "hostname", "ls", "nc", "ping", "ps", "pwd", "sh", "uname", "whoami"),
    )

    // ---------------- filesystem ----------------
    fun normalize(path: String, cwd: String): String {
        val full = if (path.startsWith("/")) path else "$cwd/$path"
        val parts = ArrayList<String>()
        for (p in full.split('/', '\\')) when (p) {
            "", "." -> {}
            ".." -> { if (parts.isNotEmpty()) parts.removeAt(parts.size - 1) }
            else -> { parts += p }
        }
        return "/" + parts.joinToString("/")
    }

    private fun sandboxFile(path: String): File? {
        val roots = listOf(ctx.filesDir.parentFile?.absolutePath ?: ctx.filesDir.absolutePath, "/data/data/" + ctx.packageName)
        for (r in roots) if (path == r || path.startsWith("$r/")) return File(path)
        if (path == "$webroot/hackable/uploads" || path.startsWith("$webroot/hackable/uploads/"))
            return File(uploadsDir, path.removePrefix("$webroot/hackable/uploads").trimStart('/'))
        return null
    }

    private fun assetPath(path: String): String? {
        if (!path.startsWith("$webroot/")) return null
        return "www/php/" + path.removePrefix("$webroot/")
    }

    /** returns content, or null if not found; throws SecurityException for permission denied */
    fun read(path: String): ByteArray? {
        if (path in protectedFiles) throw SecurityException("Permission denied")
        files[path]?.let { return it.toByteArray() }
        sandboxFile(path)?.let { f -> return if (f.isFile) f.readBytes() else null }
        if (path.startsWith("$webroot/hackable/users/")) {
            return try { ctx.assets.open("www/hackable/users/" + path.substringAfterLast('/')).use { it.readBytes() } } catch (e: Exception) { null }
        }
        assetPath(path)?.let { a -> return try { ctx.assets.open(a).use { it.readBytes() } } catch (e: Exception) { null } }
        return null
    }

    fun list(path: String): List<String>? {
        sandboxFile(path)?.let { f -> return if (f.isDirectory) (f.list()?.sorted() ?: listOf()) else null }
        val set = sortedSetOf<String>()
        extraDirs[path]?.let { set.addAll(it) }
        for (k in files.keys) if (k.startsWith("$path/") || (path == "/" && k.startsWith("/"))) {
            val rest = if (path == "/") k.removePrefix("/") else k.removePrefix("$path/")
            set += rest.substringBefore('/')
        }
        if (path == webroot || path.startsWith("$webroot/")) {
            val a = ("www/php" + path.removePrefix(webroot)).trimEnd('/')
            try { ctx.assets.list(a)?.let { set.addAll(it) } } catch (e: Exception) {}
            when (path) {
                webroot -> set.addAll(listOf("about.php", "config", "dvwa", "favicon.ico", "hackable", "index.php", "instructions.php", "login.php", "logout.php", "phpinfo.php", "robots.txt", "security.php", "setup.php", "vulnerabilities"))
                "$webroot/hackable" -> set.addAll(listOf("flags", "uploads", "users"))
                "$webroot/hackable/users" -> set.addAll(listOf("1337.jpg", "admin.jpg", "gordonb.jpg", "pablo.jpg", "smithy.jpg"))
                "$webroot/dvwa" -> set.addAll(listOf("css", "images", "includes", "js"))
            }
        }
        if (set.isEmpty() && !extraDirs.containsKey(path)) return null
        return set.toList()
    }

    fun isDir(p: String) = try { list(p) != null } catch (e: Exception) { false }

    // ---------------- shell ----------------
    class Res(val out: String, val code: Int)

    private val cwd0 = "$webroot/vulnerabilities/exec"

    /** Emulates shell_exec("ping  -c 4 " . $target): returns stdout only, like PHP. */
    fun shellExec(cmdline: String): String {
        val segs = splitOps(cmdline)
        val out = StringBuilder()
        var last = 0
        var pipeIn: String? = null
        for (idx in segs.indices) {
            val (op, seg) = segs[idx]
            val skip = when (op) { "&&" -> last != 0; "||" -> last == 0; else -> false }
            if (op != "|") pipeIn = null
            if (skip) continue
            val r = runSimple(expandSubst(seg.trim()), pipeIn)
            last = r.code
            val nextOp = segs.getOrNull(idx + 1)?.first
            if (nextOp == "|") pipeIn = r.out else out.append(r.out)
        }
        return out.toString()
    }

    private fun splitOps(s: String): List<Pair<String, String>> {
        val res = ArrayList<Pair<String, String>>()
        var op = ""
        val cur = StringBuilder()
        var i = 0
        var q: Char? = null
        while (i < s.length) {
            val c = s[i]
            if (q != null) { if (c == q) q = null; cur.append(c); i++; continue }
            if (c == '\'' || c == '"') { q = c; cur.append(c); i++; continue }
            val two = if (i + 1 < s.length) s.substring(i, i + 2) else ""
            val o: String? = when {
                two == "&&" || two == "||" -> two
                c == '|' || c == ';' || c == '&' || c == '\n' -> c.toString()
                else -> null
            }
            if (o != null) {
                res += op to cur.toString(); cur.setLength(0)
                op = if (o == "\n") ";" else o
                i += o.length; continue
            }
            cur.append(c); i++
        }
        res += op to cur.toString()
        return res
    }

    private fun expandSubst(s: String): String {
        var r = Regex("\\$\\(([^()]*)\\)").replace(s) { runSimple(it.groupValues[1].trim(), null).out.trim() }
        r = Regex("`([^`]*)`").replace(r) { runSimple(it.groupValues[1].trim(), null).out.trim() }
        return r
    }

    private fun tokenize(s: String): List<String> {
        val t = ArrayList<String>()
        val cur = StringBuilder()
        var q: Char? = null
        var any = false
        for (c in s) {
            if (q != null) { if (c == q) q = null else cur.append(c); continue }
            when {
                c == '\'' || c == '"' -> { q = c; any = true }
                c.isWhitespace() -> { if (cur.isNotEmpty() || any) { t += cur.toString(); cur.setLength(0); any = false } }
                else -> cur.append(c)
            }
        }
        if (cur.isNotEmpty() || any) t += cur.toString()
        return t
    }

    private fun runSimple(cmd: String, stdin: String?): Res {
        var toks = tokenize(cmd)
        if (toks.any { it.startsWith(">") || it.startsWith("<") }) return Res("", 1) // read-only simulated FS
        toks = toks.filter { it != "2>&1" }
        if (toks.isEmpty()) return Res("", 0)
        val name = toks[0].substringAfterLast('/')
        val args = toks.drop(1)
        val cwd = cwd0
        val fileArgs = args.filter { !it.startsWith("-") }
        return when (name) {
            "ping" -> ping(args)
            "whoami" -> Res("www-data\n", 0)
            "id" -> Res("uid=33(www-data) gid=33(www-data) groups=33(www-data)\n", 0)
            "hostname" -> Res(if ("-I" in args || "-i" in args) "172.17.0.2 \n" else "dvwa\n", 0)
            "pwd" -> Res("$cwd\n", 0)
            "uname" -> Res(uname(args), 0)
            "echo" -> {
                val txt = args.filter { it != "-e" && it != "-n" }.joinToString(" ")
                Res(if ("-n" in args) txt else txt + "\n", 0)
            }
            "date" -> Res(java.text.SimpleDateFormat("EEE MMM d HH:mm:ss zzz yyyy", java.util.Locale.US).format(java.util.Date()) + "\n", 0)
            "uptime" -> Res(" 13:37:00 up 42 days,  3:14,  0 users,  load average: 0.00, 0.01, 0.05\n", 0)
            "ls", "dir" -> ls(args, cwd)
            "cat", "more", "less", "nl" -> if (fileArgs.isEmpty()) Res(stdin ?: "", 0) else cat(fileArgs, cwd)
            "head", "tail" -> {
                val n = args.firstOrNull { it.startsWith("-") }?.trimStart('-', 'n')?.toIntOrNull() ?: 10
                val text = if (fileArgs.isEmpty()) (stdin ?: "") else cat(fileArgs, cwd).out
                var lines = text.split("\n")
                if (lines.lastOrNull() == "") lines = lines.dropLast(1)
                val sel = if (name == "head") lines.take(n) else lines.takeLast(n)
                Res(if (sel.isEmpty()) "" else sel.joinToString("\n") + "\n", 0)
            }
            "grep" -> {
                val pat = fileArgs.firstOrNull() ?: return Res("", 2)
                val text = if (fileArgs.size < 2) (stdin ?: "") else cat(fileArgs.drop(1), cwd).out
                val ci = args.any { it.startsWith("-") && it.contains('i') }
                val inv = args.any { it.startsWith("-") && it.contains('v') }
                val m = text.split("\n").filter { it.isNotEmpty() && (it.contains(pat, ci) != inv) }
                Res(if (m.isEmpty()) "" else m.joinToString("\n") + "\n", if (m.isEmpty()) 1 else 0)
            }
            "wc" -> {
                val text = if (fileArgs.isEmpty()) (stdin ?: "") else cat(fileArgs, cwd).out
                val l = text.count { it == '\n' }
                val w = text.split(Regex("\\s+")).count { it.isNotEmpty() }
                Res(if ("-l" in args) "$l\n" else "      $l      $w     ${text.length}\n", 0)
            }
            "find" -> {
                val base = normalize(fileArgs.firstOrNull() ?: ".", cwd)
                val acc = ArrayList<String>(); walk(base, acc, 0)
                Res(acc.joinToString("\n") + "\n", 0)
            }
            "ps" -> Res("    PID TTY          TIME CMD\n      1 ?        00:00:02 apache2\n     27 ?        00:00:00 mysqld\n    310 ?        00:00:00 apache2\n    311 ?        00:00:00 sh\n    312 ?        00:00:00 ps\n", 0)
            "ifconfig", "ip" -> Res("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 172.17.0.2  netmask 255.255.0.0  broadcast 172.17.255.255\n        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)\n\nlo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n        inet 127.0.0.1  netmask 255.0.0.0\n        loop  txqueuelen 1000  (Local Loopback)\n", 0)
            "netstat", "ss" -> Res("Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\ntcp6       0      0 :::80                   :::*                    LISTEN\n", 0)
            "env", "printenv" -> Res(fakeEnv, 0)
            "which" -> Res(fileArgs.filter { it in (extraDirs["/bin"] ?: listOf()) || it in listOf("php", "python3", "perl", "mysql") }.joinToString("") { "/usr/bin/$it\n" }, 0)
            "php" -> Res(if ("-v" in args) "PHP 8.2.7 (cli) (built: Jun  9 2023 19:37:39) (NTS)\n" else "", 0)
            "cd", "true", ":", "export", "sleep", "history" -> Res("", 0)
            "false", "rm", "touch", "mkdir", "chmod", "sudo", "su", "mysql" -> Res("", 1)
            // no network clients / interactive shells in the simulation
            "nc", "ncat", "netcat", "wget", "curl", "telnet", "ssh", "bash", "sh", "python", "python3", "perl", "nslookup", "dig", "host" -> Res("", 1)
            else -> Res("", 127) // "sh: 1: X: not found" goes to stderr, which shell_exec does not capture
        }
    }

    private fun walk(p: String, acc: MutableList<String>, depth: Int) {
        if (acc.size > 400 || depth > 6) return
        acc += p
        val l = (try { list(p) } catch (e: Exception) { null }) ?: return
        for (c in l) walk(if (p == "/") "/$c" else "$p/$c", acc, depth + 1)
    }

    private fun uname(a: List<String>): String = when {
        a.any { it.startsWith("-") && it.contains('a') } -> "Linux dvwa 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 (2024-02-01) x86_64 GNU/Linux\n"
        "-r" in a -> "6.1.0-18-amd64\n"
        "-n" in a -> "dvwa\n"
        "-m" in a -> "x86_64\n"
        else -> "Linux\n"
    }

    private fun cat(fs: List<String>, cwd: String): Res {
        val sb = StringBuilder()
        var code = 0
        for (f in fs) {
            val p = normalize(f, cwd)
            try {
                val b = read(p)
                if (b == null) code = 1 else sb.append(String(b, Charsets.UTF_8))
            } catch (e: SecurityException) { code = 1 }
        }
        return Res(sb.toString(), code)
    }

    private fun ls(args: List<String>, cwd: String): Res {
        val long = args.any { it.startsWith("-") && it.contains('l') }
        val all = args.any { it.startsWith("-") && it.contains('a') }
        val targets = args.filter { !it.startsWith("-") }.ifEmpty { listOf(".") }
        val sb = StringBuilder()
        var code = 0
        for (t in targets) {
            val p = normalize(t, cwd)
            val l = try { list(p) } catch (e: Exception) { null }
            if (l == null) {
                val exists = try { read(p) != null } catch (e: SecurityException) { true }
                if (exists) sb.append("$t\n") else code = 2
                continue
            }
            if (targets.size > 1) sb.append("$t:\n")
            val names = (if (all) listOf(".", "..") else listOf()) + l.filter { all || !it.startsWith(".") }
            if (long) {
                sb.append("total ${names.size * 4}\n")
                for (n in names) {
                    val child = if (p == "/") "/$n" else "$p/$n"
                    val dir = n == "." || n == ".." || isDir(child)
                    val size = if (dir) 4096 else ((try { read(child)?.size } catch (e: Exception) { 0 }) ?: 0)
                    val owner = if (child.startsWith(webroot)) "www-data www-data" else "root     root    "
                    sb.append(String.format("%s 1 %s %6d Jan 15 13:37 %s\n", if (dir) "drwxr-xr-x" else "-rw-r--r--", owner, size, n))
                }
            } else names.forEach { sb.append(it).append('\n') }
        }
        return Res(sb.toString(), code)
    }

    private fun ping(args: List<String>): Res {
        val host = args.filterIndexed { i, a -> !a.startsWith("-") && !(i > 0 && args[i - 1] == "-c") }.firstOrNull() ?: return Res("", 2)
        val ip4 = Regex("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$")
        val ip = when {
            ip4.matches(host) && host.split('.').all { it.toInt() <= 255 } -> host
            host == "localhost" || host == "dvwa" -> "127.0.0.1"
            host.matches(Regex("^\\d{1,10}$")) -> {
                val n = host.toLong()
                "${(n shr 24) and 255}.${(n shr 16) and 255}.${(n shr 8) and 255}.${n and 255}"
            }
            else -> return Res("", 2) // "Temporary failure in name resolution" (offline sandbox, stderr)
        }
        val local = ip.startsWith("127.")
        val sb = StringBuilder("PING $host ($ip) 56(84) bytes of data.\n")
        val times = (1..4).map { if (local) 0.020 + U.rnd.nextInt(40) / 1000.0 else 0.5 + U.rnd.nextInt(3000) / 1000.0 }
        times.forEachIndexed { i, t ->
            sb.append(String.format(java.util.Locale.US, "64 bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n", ip, i + 1, if (local) 64 else 63, t))
        }
        sb.append("\n--- $host ping statistics ---\n4 packets transmitted, 4 received, 0% packet loss, time 3004ms\n")
        sb.append(String.format(java.util.Locale.US, "rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", times.minOrNull() ?: 0.0, times.average(), times.maxOrNull() ?: 0.0, 0.011))
        try { Thread.sleep(800) } catch (e: Exception) {}
        return Res(sb.toString(), 0)
    }

    // ---------------- mini PHP ----------------
    /**
     * "Executes" a PHP file: text outside PHP tags is output verbatim; inside <?php ?> blocks a
     * few classic webshell idioms are simulated (system/shell_exec/passthru/exec with a request
     * parameter or literal, echo/print of literals, phpinfo()). Commands go to the fake shell.
     */
    fun runPhp(src: String, r: Map<String, String>?): String {
        val sb = StringBuilder()
        var i = 0
        while (i < src.length) {
            val st = src.indexOf("<?", i)
            if (st < 0) { sb.append(src.substring(i)); break }
            sb.append(src.substring(i, st))
            var codeStart = st + 2
            if (src.regionMatches(codeStart, "php", 0, 3, true)) codeStart += 3
            val isEcho = codeStart < src.length && src[codeStart] == '='
            if (isEcho) codeStart++
            val endIdx = src.indexOf("?>", codeStart)
            val end = if (endIdx < 0) src.length else endIdx
            val code = src.substring(codeStart, end)
            sb.append(if (isEcho) evalExpr(code.trim().trimEnd(';'), r) else evalStatements(code, r))
            i = if (endIdx < 0) src.length else end + 2
        }
        return sb.toString()
    }

    private fun evalStatements(code: String, r: Map<String, String>?): String {
        val sb = StringBuilder()
        for (stRaw in code.split(';')) {
            val st = stRaw.trim()
            if (st.isEmpty() || st.startsWith("//") || st.startsWith("#")) continue
            val m = Regex("(?is)^(echo|print)\\s*(.*)$").find(st)
            if (m != null) { sb.append(evalExpr(m.groupValues[2], r)); continue }
            if (st.matches(Regex("(?i)^phpinfo\\s*\\(\\s*\\)$"))) { sb.append(PhpInfo.text()); continue }
            val e = Regex("(?is)^@?(system|passthru|shell_exec|exec)\\s*\\((.*)\\)$").find(st)
            if (e != null) {
                val out = shellExec(evalExpr(e.groupValues[2], r))
                if (e.groupValues[1].lowercase() != "shell_exec" && e.groupValues[1].lowercase() != "exec") sb.append(out)
                continue
            }
        }
        return sb.toString()
    }

    private fun evalExpr(expr0: String, r: Map<String, String>?): String {
        var expr = expr0.trim()
        if (expr.startsWith("(") && expr.endsWith(")")) expr = expr.substring(1, expr.length - 1).trim()
        val parts = ArrayList<String>()
        var cur = StringBuilder()
        var q: Char? = null
        var depth = 0
        for (c in expr) {
            if (q != null) { if (c == q) q = null; cur.append(c); continue }
            when (c) {
                '\'', '"' -> { q = c; cur.append(c) }
                '(', '[' -> { depth++; cur.append(c) }
                ')', ']' -> { depth--; cur.append(c) }
                '.' -> { if (depth == 0) { parts += cur.toString(); cur = StringBuilder() } else cur.append(c) }
                else -> cur.append(c)
            }
        }
        parts += cur.toString()
        return parts.joinToString("") { p0 ->
            val p = p0.trim()
            val sv = Regex("(?i)^\\\$_(GET|POST|REQUEST|COOKIE)\\s*\\[\\s*['\"]?([^'\"\\]]*)['\"]?\\s*\\]$").find(p)
            val ex = Regex("(?is)^(shell_exec|system)\\s*\\((.*)\\)$").find(p)
            when {
                sv != null -> {
                    val k = sv.groupValues[2]
                    r?.get(k) ?: ""
                }
                ex != null -> shellExec(evalExpr(ex.groupValues[2], r))
                p.length >= 2 && p.startsWith("'") && p.endsWith("'") -> p.substring(1, p.length - 1)
                p.length >= 2 && p.startsWith("\"") && p.endsWith("\"") -> p.substring(1, p.length - 1).replace("\\n", "\n")
                p.matches(Regex("(?i)php_uname\\(\\)")) -> "Linux dvwa 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC x86_64"
                p.matches(Regex("(?i)getcwd\\(\\)")) -> "$webroot/hackable/uploads"
                p.matches(Regex("\\d+")) -> p
                else -> ""
            }
        }
    }
}
