package org.dvwa.android

import org.mozilla.javascript.BaseFunction
import org.mozilla.javascript.Context
import org.mozilla.javascript.ContextFactory
import org.mozilla.javascript.RhinoException
import org.mozilla.javascript.Scriptable
import org.mozilla.javascript.ScriptableObject
import org.mozilla.javascript.Undefined

/**
 * A real JavaScript engine (Mozilla Rhino 1.9.1, interpreted mode) with a small fake browser
 * DOM. Still no WebView: scripts run inside the app against a sandboxed `window`/`document`.
 * Every visible effect (alert/prompt/confirm, document.write, innerHTML, cookie reads,
 * navigation, network beacons) is recorded instead of performed, so nothing leaves the device.
 */
class JsEngine(cookie: String = "", href: String = "http://127.0.0.1/") {
    data class Effect(val kind: String, val text: String)

    val effects = ArrayList<Effect>()
    /**
     * Called when the page adds `<script src=…>` to the DOM. Return the script body to run it,
     * or null when it cannot load (blocked by CSP, 404, offline). Null loader = record only.
     */
    var loader: ((String) -> String?)? = null
    var cookie: String = cookie
    private val scope: ScriptableObject

    init {
        val cx = enter()
        try {
            scope = cx.initStandardObjects()
            hook("__emit") { a -> effects += Effect(s(a, 0), s(a, 1)); null }
            hook("__cookieGet") { this.cookie }
            hook("__cookieSet") { a ->
                val kv = s(a, 0).substringBefore(';').trim()
                if (kv.isNotEmpty()) {
                    val k = kv.substringBefore('=')
                    val parts = this.cookie.split(';').map { it.trim() }.filter { it.isNotEmpty() && it.substringBefore('=') != k }
                    this.cookie = (parts + kv).joinToString("; ")
                }
                effects += Effect("cookieset", kv); null
            }
            hook("__b64e") { a -> java.util.Base64.getEncoder().encodeToString(s(a, 0).toByteArray(Charsets.ISO_8859_1)) }
            hook("__b64d") { a -> try { String(java.util.Base64.getDecoder().decode(s(a, 0).trim()), Charsets.ISO_8859_1) } catch (e: Exception) { throw RuntimeException("InvalidCharacterError: atob()") } }
            hook("__load") { a -> loader?.invoke(s(a, 0)) }
            hook("__exec") { a ->
                try { Context.getCurrentContext().evaluateString(scope, s(a, 0), s(a, 1), 1, null) }
                catch (e: RhinoException) { effects += Effect("error", (if (e is org.mozilla.javascript.EvaluatorException) "SyntaxError: " else "") + e.details() + " (" + s(a, 1) + ")") }
                null
            }
            ScriptableObject.putProperty(scope, "__href0", href)
            cx.evaluateString(scope, PRELUDE, "dom.js", 1, null)
        } finally { Context.exit() }
    }

    private fun s(a: Array<Any?>, i: Int): String = if (i < a.size && a[i] != null && a[i] !is Undefined) Context.toString(a[i]) else ""

    private fun hook(name: String, f: (Array<Any?>) -> Any?) {
        ScriptableObject.putProperty(scope, name, object : BaseFunction() {
            override fun call(cx: Context, sc: Scriptable, thisObj: Scriptable?, args: Array<Any?>): Any? = f(args) ?: Undefined.instance
        })
    }

    /** Run a script; returns null on success or the JS error message. Pending timers are flushed. */
    fun run(code: String, name: String = "inline"): String? {
        val cx = enter()
        return try {
            cx.evaluateString(scope, code, name, 1, null); flushTimers(cx); null
        } catch (e: RhinoException) { val m = (if (e is org.mozilla.javascript.EvaluatorException) "SyntaxError: " else "") + e.details(); effects += Effect("error", m); m
        } catch (e: Throwable) { val m = e.message ?: e.toString(); effects += Effect("error", m); m
        } finally { Context.exit() }
    }

    /** Evaluate an expression (browser console) and return its value as a string. */
    fun eval(expr: String): String {
        val cx = enter()
        return try {
            val r = cx.evaluateString(scope, expr, "console", 1, null); flushTimers(cx)
            if (r is Undefined) "undefined" else Context.toString(r)
        } catch (e: RhinoException) { "Uncaught ${e.details()}"
        } catch (e: Throwable) { "Uncaught ${e.message}" } finally { Context.exit() }
    }

    fun value(id: String): String = eval("document.getElementById(${q(id)}).value")
    fun setValue(id: String, v: String) { eval("document.getElementById(${q(id)}).value=${q(v)}") }
    /** Make sure an element with this id exists (e.g. the Submit button). */
    fun document(id: String) { eval("document.getElementById(${q(id)})") }
    /** Dispatch an event to an element's listeners (e.g. the Submit button's click handler). */
    fun fire(id: String, event: String = "click") { run("__fire(document.getElementById(${q(id)}), ${q(event)})", "event") }

    private fun flushTimers(cx: Context) {
        var n = 0
        while (n++ < 100) {
            val r = cx.evaluateString(scope, "__runTimer()", "timer", 1, null)
            if (r != true) break
        }
    }

    companion object {
        private const val LIMIT_MS = 3000L
        private class Fx : ContextFactory() {
            override fun makeContext(): Context = super.makeContext().apply {
                setInterpretedMode(true)
                languageVersion = Context.VERSION_ES6
                instructionObserverThreshold = 20000
                putThreadLocal("t0", System.currentTimeMillis())
            }
            override fun observeInstructionCount(cx: Context, count: Int) {
                val t0 = cx.getThreadLocal("t0") as? Long ?: return
                if (System.currentTimeMillis() - t0 > LIMIT_MS) throw Error("script took too long (infinite loop?)")
            }
        }
        private val factory = Fx()
        private fun enter(): Context = factory.enterContext().also { it.putThreadLocal("t0", System.currentTimeMillis()) }

        fun q(s: String): String = buildString {
            append('"'); for (c in s) when (c) { '"' -> append("\\\""); '\\' -> append("\\\\"); '\n' -> append("\\n"); '\r' -> append("\\r"); '\u2028' -> append("\\u2028"); '\u2029' -> append("\\u2029"); else -> append(c) }; append('"')
        }

        private val PRELUDE = """
var window = this, self = this, top = this, parent = this, frames = this, globalThis = this;
function __str(v){ try { return String(v); } catch(e) { return '[object]'; } }
var __timers = [];
function setTimeout(f, ms){ if (typeof f !== 'function') { var src = __str(f); f = function(){ eval(src); }; } __timers.push(f); return __timers.length; }
function setInterval(f, ms){ return setTimeout(f, ms); }
function clearTimeout(id){ if (id > 0 && id <= __timers.length) __timers[id-1] = null; }
var clearInterval = clearTimeout, requestAnimationFrame = setTimeout, queueMicrotask = setTimeout;
function __runTimer(){ for (var i = 0; i < __timers.length; i++) { var f = __timers[i]; if (f) { __timers[i] = null; f(); return true; } } return false; }
function alert(m){ __emit('alert', arguments.length ? __str(m) : ''); }
function confirm(m){ __emit('confirm', arguments.length ? __str(m) : ''); return true; }
function prompt(m, d){ __emit('prompt', arguments.length ? __str(m) : ''); return d === undefined ? '' : __str(d); }
function print(){ __emit('print', ''); }
var console = { log: function(){ __emit('console', Array.prototype.map.call(arguments, __str).join(' ')); } };
console.info = console.warn = console.error = console.debug = console.dir = console.log;
function atob(s){ return __b64d(__str(s)); }
function btoa(s){ return __b64e(__str(s)); }
function __req(kind, u){ __emit('request', kind + ' ' + __str(u)); }
var __els = {};
function __El(tag, id){ this.tagName = __str(tag || 'div').toUpperCase(); this.nodeName = this.tagName; this.id = id || ''; this.value = ''; this.__l = {}; this.children = []; this.childNodes = this.children; this.style = {}; this.dataset = {}; this.attributes = {}; this.__html = ''; this.__src = ''; this.className = ''; this.classList = { add: function(){}, remove: function(){}, toggle: function(){}, contains: function(){ return false; } }; }
__El.prototype.addEventListener = function(ev, f){ (this.__l[ev] = this.__l[ev] || []).push(f); };
__El.prototype.removeEventListener = function(){};
__El.prototype.setAttribute = function(k, v){ v = __str(v); this.attributes[k] = v; if (k === 'id') { this.id = v; __els[v] = this; } else if (k === 'src' || k === 'href' || k === 'value') { this[k] = v; } else if (k.substr(0, 2) === 'on') { var c = v; this[k] = function(){ eval(c); }; } };
__El.prototype.getAttribute = function(k){ return this.attributes[k] === undefined ? null : this.attributes[k]; };
__El.prototype.appendChild = function(c){ this.children.push(c); if (c && c.tagName === 'SCRIPT') { if (c.__src) { __req('script', c.__src); var code = __load(c.__src); if (typeof code === 'string') __exec(code, c.__src); } else if (c.text) __exec(c.text, 'inline'); } return c; };
__El.prototype.insertBefore = __El.prototype.appendChild; __El.prototype.append = __El.prototype.appendChild; __El.prototype.prepend = __El.prototype.appendChild;
__El.prototype.removeChild = function(c){ return c; }; __El.prototype.remove = function(){};
__El.prototype.insertAdjacentHTML = function(p, h){ __emit('html', __str(h)); };
__El.prototype.click = function(){ __fire(this, 'click'); };
__El.prototype.submit = function(){ __emit('request', 'form submit'); };
__El.prototype.focus = function(){}; __El.prototype.blur = function(){};
__El.prototype.querySelector = function(s){ return document.querySelector(s); };
__El.prototype.getElementsByTagName = function(t){ return []; };
__El.prototype.toString = function(){ return '[object HTML' + this.tagName.charAt(0) + this.tagName.substr(1).toLowerCase() + 'Element]'; };
Object.defineProperty(__El.prototype, 'innerHTML', { get: function(){ return this.__html; }, set: function(v){ this.__html = __str(v); __emit('html', this.__html); } });
Object.defineProperty(__El.prototype, 'outerHTML', { get: function(){ return '<' + this.tagName.toLowerCase() + '>' + this.__html + '</' + this.tagName.toLowerCase() + '>'; }, set: function(v){ __emit('html', __str(v)); } });
Object.defineProperty(__El.prototype, 'innerText', { get: function(){ return this.__html; }, set: function(v){ this.__html = __str(v); } });
Object.defineProperty(__El.prototype, 'textContent', { get: function(){ return this.__html; }, set: function(v){ this.__html = __str(v); } });
Object.defineProperty(__El.prototype, 'src', { get: function(){ return this.__src; }, set: function(v){ this.__src = __str(v); if (this.tagName !== 'SCRIPT') __req(this.tagName.toLowerCase(), this.__src); } });
function __fire(el, ev){ var e = { type: ev, target: el, currentTarget: el, preventDefault: function(){}, stopPropagation: function(){} }; var l = (el.__l[ev] || []).slice(); if (typeof el['on' + ev] === 'function') l.push(el['on' + ev]); for (var i = 0; i < l.length; i++) l[i].call(el, e); }
function Image(w, h){ return new __El('img'); }
function Audio(u){ var a = new __El('audio'); if (u) a.src = u; a.play = function(){}; return a; }
function __parse(u){ var m = /^([a-z][a-z0-9+.-]*:)?(?:\/\/([^\/?#:]*)(?::(\d+))?)?([^?#]*)(\?[^#]*)?(#.*)?$/i.exec(__str(u)) || []; return { protocol: m[1] || 'http:', hostname: m[2] || '127.0.0.1', port: m[3] || '', pathname: m[4] || '/', search: m[5] || '', hash: m[6] || '' }; }
var __loc = (function(){ var p = __parse(__href0), o = { href: __href0 }; for (var k in p) o[k] = p[k]; o.host = o.hostname + (o.port ? ':' + o.port : ''); o.origin = o.protocol + '//' + o.host; return o; })();
function __nav(u){ __emit('navigate', __str(u)); }
var __locRef = { assign: function(u){ __nav(u); }, replace: function(u){ __nav(u); }, reload: function(){}, toString: function(){ return __loc.href; } };
['protocol','hostname','port','pathname','search','hash','host','origin'].forEach(function(k){ Object.defineProperty(__locRef, k, { get: function(){ return __loc[k]; }, set: function(v){ if (k === 'hash') { __loc.hash = __str(v); } else __nav(k + '=' + __str(v)); } }); });
Object.defineProperty(__locRef, 'href', { get: function(){ return __loc.href; }, set: function(v){ __nav(v); } });
Object.defineProperty(this, 'location', { get: function(){ return __locRef; }, set: function(v){ __nav(v); } });
var __body = new __El('body'), __head = new __El('head'), __html = new __El('html');
var document = {
  body: __body, head: __head, documentElement: __html, domain: '127.0.0.1', title: 'DVWA', referrer: '', readyState: 'complete', forms: [], images: [], scripts: [], links: [], defaultView: this,
  getElementById: function(id){ id = __str(id); if (!__els[id]) __els[id] = new __El('input', id); return __els[id]; },
  querySelector: function(s){ s = __str(s); if (s.charAt(0) === '#') return this.getElementById(s.substr(1)); if (s === 'body') return __body; if (s === 'head') return __head; return new __El(s.replace(/[^a-z0-9].*$/i, '') || 'div'); },
  querySelectorAll: function(s){ return [this.querySelector(s)]; },
  getElementsByTagName: function(t){ t = __str(t).toLowerCase(); return [t === 'body' ? __body : t === 'head' ? __head : t === 'html' ? __html : new __El(t)]; },
  getElementsByName: function(n){ return [this.getElementById(n)]; },
  getElementsByClassName: function(n){ return [new __El('div')]; },
  createElement: function(t){ return new __El(t); },
  createTextNode: function(t){ var e = new __El('#text'); e.__html = __str(t); return e; },
  write: function(){ __emit('write', Array.prototype.map.call(arguments, __str).join('')); },
  writeln: function(){ __emit('write', Array.prototype.map.call(arguments, __str).join('') + '\n'); },
  open: function(){}, close: function(){}, addEventListener: function(){}, removeEventListener: function(){},
  toString: function(){ return '[object HTMLDocument]'; }
};
Object.defineProperty(document, 'cookie', { get: function(){ return __cookieGet(); }, set: function(v){ __cookieSet(__str(v)); } });
Object.defineProperty(document, 'location', { get: function(){ return __locRef; }, set: function(v){ __nav(v); } });
Object.defineProperty(document, 'URL', { get: function(){ return __loc.href; } });
Object.defineProperty(document, 'documentURI', { get: function(){ return __loc.href; } });
var navigator = { userAgent: 'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 DVWA-Native/2.2', language: 'en-US', platform: 'Linux armv8l', cookieEnabled: true, onLine: false, sendBeacon: function(u, d){ __req('beacon', u); return true; } };
var __thenable = { then: function(){ return __thenable; }, 'catch': function(){ return __thenable; }, 'finally': function(){ return __thenable; } };
function fetch(u, o){ __req('fetch', u && u.url ? u.url : u); return __thenable; }
function XMLHttpRequest(){ this.readyState = 0; this.status = 0; this.responseText = ''; }
XMLHttpRequest.prototype.open = function(m, u){ this.__m = __str(m).toUpperCase(); this.__u = __str(u); this.readyState = 1; };
XMLHttpRequest.prototype.setRequestHeader = function(){};
XMLHttpRequest.prototype.send = function(b){ __req('xhr', this.__m + ' ' + this.__u + (b ? ' body=' + __str(b) : '')); };
XMLHttpRequest.prototype.abort = function(){}; XMLHttpRequest.prototype.addEventListener = function(){};
var history = { pushState: function(s, t, u){ if (u) __nav(u); }, replaceState: function(s, t, u){ if (u) __nav(u); }, back: function(){}, go: function(){}, length: 1 };
var localStorage = (function(){ var d = {}; return { getItem: function(k){ return d.hasOwnProperty(k) ? d[k] : null; }, setItem: function(k, v){ d[k] = __str(v); }, removeItem: function(k){ delete d[k]; }, clear: function(){ d = {}; } }; })();
var sessionStorage = localStorage;
function addEventListener(){} function removeEventListener(){}
function open(u){ __nav(u); return window; }
var screen = { width: 412, height: 915 }, innerWidth = 412, innerHeight = 915, name = '', opener = null, origin = __loc.origin, isSecureContext = false;
"""
    }
}
