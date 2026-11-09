package org.dvwa.android

/**
 * A Content-Security-Policy parser and enforcer for the CSP Bypass module. There is no browser,
 * so the policy a server WOULD have sent is parsed here and applied natively to decide whether
 * each `<script>` a page contains would have been allowed to run. The directives DVWA exercises
 * are supported: source lists, 'self', 'unsafe-inline', scheme sources, host/path matching, and
 * nonces. An allowed script is then handed to the real JS engine ([JsEngine]) to execute.
 */
class Csp(policy: String, private val selfOrigin: String = "http://127.0.0.1") {
    /** directive name (lowercased) -> ordered source expressions */
    private val directives = LinkedHashMap<String, List<String>>()

    init {
        for (part in policy.replace(Regex("^\\s*Content-Security-Policy\\s*:", RegexOption.IGNORE_CASE), "").split(';')) {
            val toks = part.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
            if (toks.isEmpty()) continue
            directives[toks[0].lowercase()] = toks.drop(1)
        }
    }

    private fun scriptSrc(): List<String>? = directives["script-src"] ?: directives["default-src"]

    data class Verdict(val allowed: Boolean, val reason: String)

    /** Would an inline `<script>` (optionally carrying a nonce) run under this policy? */
    fun allowsInline(nonce: String?): Verdict {
        val srcs = scriptSrc() ?: return Verdict(true, "no script-src/default-src directive")
        val nonces = srcs.filter { it.startsWith("'nonce-") }.map { it.removePrefix("'nonce-").removeSuffix("'") }
        if (nonce != null && nonce in nonces) return Verdict(true, "matching nonce")
        // A nonce or hash source makes 'unsafe-inline' be ignored (CSP2+ behaviour DVWA relies on).
        val strict = nonces.isNotEmpty() || srcs.any { it.startsWith("'sha") }
        if (srcs.contains("'unsafe-inline'") && !strict) return Verdict(true, "'unsafe-inline'")
        val why = when {
            nonces.isNotEmpty() && nonce == null -> "inline script without the right nonce ('unsafe-inline' is ignored when a nonce is present)"
            nonces.isNotEmpty() -> "nonce does not match '$nonces'"
            else -> "inline script blocked (no 'unsafe-inline')"
        }
        return Verdict(false, why)
    }

    /** Would an external `<script src=…>` load under this policy? */
    fun allowsSource(url: String): Verdict {
        val srcs = scriptSrc() ?: return Verdict(true, "no script-src/default-src directive")
        if (srcs.contains("*")) return Verdict(true, "* wildcard")
        val (scheme, host, port, path) = parse(url)
        for (expr in srcs) {
            when {
                expr == "'self'" -> if (isSelf(scheme, host, port)) return Verdict(true, "'self'")
                expr.endsWith(":") && !expr.startsWith("'") -> if (expr.lowercase() == "$scheme:") return Verdict(true, "scheme-source $expr")
                expr.startsWith("'") -> {}   // keyword, not a host
                else -> if (matchHost(expr, scheme, host, port, path)) return Verdict(true, "allowed by $expr")
            }
        }
        return Verdict(false, "host not allowed by script-src")
    }

    private data class U4(val scheme: String, val host: String, val port: String, val path: String)
    private fun parse(url: String): U4 {
        val m = Regex("^(?:([a-z][a-z0-9+.-]*):)?(?://([^/?#:]*)(?::(\\d+))?)?([^?#]*)", RegexOption.IGNORE_CASE).find(url)
        val selfM = Regex("^([a-z]+)://([^/:]+)(?::(\\d+))?", RegexOption.IGNORE_CASE).find(selfOrigin)
        val scheme = (m?.groupValues?.get(1)?.ifEmpty { null } ?: selfM?.groupValues?.get(1) ?: "http").lowercase()
        val host = (m?.groupValues?.get(2)?.ifEmpty { null } ?: selfM?.groupValues?.get(2) ?: "127.0.0.1").lowercase()
        return U4(scheme, host, m?.groupValues?.get(3) ?: "", m?.groupValues?.get(4) ?: "")
    }

    private fun isSelf(scheme: String, host: String, port: String): Boolean {
        val s = parse(selfOrigin)
        return scheme == s.scheme && host == s.host && (port.ifEmpty { defPort(scheme) } == s.port.ifEmpty { defPort(s.scheme) })
    }
    private fun defPort(scheme: String) = if (scheme == "https") "443" else "80"

    /** host-source grammar: [scheme://] host-part [:port] [path]  — host-part may start with '*.'. */
    private fun matchHost(expr: String, scheme: String, host: String, port: String, path: String): Boolean {
        var e = expr
        val eScheme = Regex("^([a-z][a-z0-9+.-]*)://", RegexOption.IGNORE_CASE).find(e)?.groupValues?.get(1)?.lowercase()
        if (eScheme != null) { if (eScheme == "http" && scheme == "https") {} else if (eScheme != scheme) return false; e = e.substringAfter("://") }
        else if (scheme != "http" && scheme != "https") return false
        val ePath = if (e.contains('/')) e.substring(e.indexOf('/')) else ""
        if (ePath.isNotEmpty()) e = e.substringBefore('/')
        val ePort = if (e.contains(':')) e.substringAfter(':') else ""
        val eHost = e.substringBefore(':').lowercase()
        val hostOk = when {
            eHost == "*" -> true
            eHost.startsWith("*.") -> host == eHost.drop(2) || host.endsWith("." + eHost.drop(2))
            else -> host == eHost
        }
        if (!hostOk) return false
        if (ePort.isNotEmpty() && ePort != "*" && ePort != port.ifEmpty { defPort(scheme) }) return false
        if (ePath.isNotEmpty()) { if (ePath.endsWith("/")) { if (!path.startsWith(ePath)) return false } else if (path != ePath) return false }
        return true
    }
}
