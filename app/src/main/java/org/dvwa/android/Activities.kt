package org.dvwa.android

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.text.Html
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.TextView
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.ActionBarDrawerToggle
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.GravityCompat
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.tabs.TabLayout
import org.dvwa.android.databinding.ActivityLoginBinding
import org.dvwa.android.databinding.ActivityMainBinding
import org.dvwa.android.databinding.ActivityTextBinding

// ------------------------------------------------------------------ login
class LoginActivity : AppCompatActivity() {
    private lateinit var b: ActivityLoginBinding
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (DvwaApp.I.user != null) { startActivity(Intent(this, MainActivity::class.java)); finish(); return }
        b = ActivityLoginBinding.inflate(layoutInflater)
        setContentView(b.root)
        b.tvTitle.text = tr("Damn Vulnerable Web Application – Offline Native Edition")
        b.tilUser.hint = tr("Username"); b.tilPass.hint = tr("Password")
        b.btnLogin.text = tr("Login")
        b.btnLang.text = "🌐 " + tr("Language") + ": " + Lang.shortLabel(Lang.code)
        b.btnLang.setOnClickListener { Lang.showPicker(this) }
        b.btnGuide.text = "📘 " + tr("User Guide")
        b.btnGuide.setOnClickListener { startActivity(TextActivity.guide(this)) }
        if (!Lang.chosen && savedInstanceState == null) {
            // First launch: pick a language (Hinglish pre-selected), then a short tutorial.
            Lang.showPicker(this, cancelable = false) { startActivity(Intent(this, OnboardingActivity::class.java)) }
        }
        b.tvHint.text = tr("Default login: admin / password\nOther accounts: gordonb / abc123 · 1337 / charley · pablo / letmein · smithy / password\n\nEverything runs natively & offline: no WebView, no network.")
        b.btnLogin.setOnClickListener {
            val u = b.etUser.text?.toString() ?: ""
            val p = b.etPass.text?.toString() ?: ""
            b.btnLogin.isEnabled = false
            Bg.run(null) {
                // DVWA's own login.php uses a prepared/escaped query (login is not a challenge).
                val ok = try { DvwaApp.I.db.prepared("SELECT user FROM users WHERE user = ? AND password = ?", u, U.md5(p)).isNotEmpty() } catch (e: Exception) { false }
                runOnUiThread {
                    b.btnLogin.isEnabled = true
                    if (ok) {
                        DvwaApp.I.user = u; Session.reset()
                        startActivity(Intent(this, MainActivity::class.java)); finish()
                    } else b.tvMessage.text = tr("Login failed")
                }
            }
        }
    }
}

// ------------------------------------------------------------------ main (drawer + fragments)
class MainActivity : AppCompatActivity() {
    lateinit var b: ActivityMainBinding
    private var current = "home"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (DvwaApp.I.user == null) { startActivity(Intent(this, LoginActivity::class.java)); finish(); return }
        b = ActivityMainBinding.inflate(layoutInflater)
        setContentView(b.root)
        setSupportActionBar(b.toolbar)
        val toggle = ActionBarDrawerToggle(this, b.drawer, b.toolbar, R.string.app_name, R.string.app_name)
        b.drawer.addDrawerListener(toggle); toggle.syncState()
        b.menuList.layoutManager = LinearLayoutManager(this)
        refreshMenu()
        current = savedInstanceState?.getString("page") ?: "home"
        show(current)
        // Users upgrading from v2.0.0 are already logged in: offer the language picker + tutorial once here.
        if (!Lang.chosen && savedInstanceState == null) {
            Lang.showPicker(this, cancelable = false) { startActivity(Intent(this, OnboardingActivity::class.java)) }
        }
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                when {
                    b.drawer.isDrawerOpen(GravityCompat.START) -> b.drawer.closeDrawers()
                    current != "home" -> show("home")
                    else -> finish()
                }
            }
        })
    }

    override fun onSaveInstanceState(outState: Bundle) { super.onSaveInstanceState(outState); outState.putString("page", current) }

    fun refreshMenu() {
        val admin = DvwaApp.I.user == "admin"
        b.menuList.adapter = MenuAdapter(Pages.menu(admin)) { id ->
            b.drawer.closeDrawers()
            when (id) {
                "logout" -> logout()
                "language" -> Lang.showPicker(this)
                "guide" -> startActivity(TextActivity.guide(this))
                "tutorial" -> startActivity(Intent(this, OnboardingActivity::class.java))
                else -> show(id)
            }
        }
        b.tvDrawerHeader.text = tr("Username: {0}\nSecurity Level: {1}\nLanguage: {2}\nSQLi DB: sqlite (bundled)", DvwaApp.I.user, Lang.levelName(DvwaApp.I.level), Lang.shortLabel(Lang.code))
    }

    fun show(id: String) {
        current = id
        val p = Pages.byId(id)
        supportActionBar?.title = p.title
        supportFragmentManager.beginTransaction().replace(R.id.container, PageFragment.of(id)).commitAllowingStateLoss()
        refreshMenu()
    }

    fun logout() {
        DvwaApp.I.user = null; Session.reset()
        startActivity(Intent(this, LoginActivity::class.java)); finish()
    }

    /** Simulated address bar: navigate by DVWA path, e.g. /vulnerabilities/authbypass/ */
    fun openPath(path: String): Boolean {
        val id = Pages.idForPath(path) ?: return false
        if (id == "guide") { startActivity(TextActivity.guide(this)); return true }
        show(id); return true
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menu.add(0, 1, 0, tr("Go to URL…"))
        menu.add(0, 2, 0, tr("Security level…"))
        menu.add(0, 4, 0, tr("Language") + " / भाषा")
        menu.add(0, 5, 0, tr("User Guide"))
        menu.add(0, 3, 0, tr("Logout"))
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            1 -> {
                val et = EditText(this).apply { setText("http://127.0.0.1/vulnerabilities/"); setSingleLine() }
                AlertDialog.Builder(this).setTitle(tr("Go to URL (simulated address bar)")).setView(et)
                    .setPositiveButton(tr("Go")) { _, _ -> if (!openPath(et.text.toString())) OutBox.alert(this, tr("404 Not Found"), tr("The requested URL was not found on this server.\n\nTry e.g. /vulnerabilities/authbypass/")) }
                    .setNegativeButton(tr("Cancel"), null).show()
            }
            2 -> show("security")
            3 -> logout()
            4 -> Lang.showPicker(this)
            5 -> startActivity(TextActivity.guide(this))
        }
        return true
    }
}

class MenuAdapter(private val items: List<Pair<String, String>>, private val click: (String) -> Unit) : RecyclerView.Adapter<RecyclerView.ViewHolder>() {
    class VH(v: View) : RecyclerView.ViewHolder(v)
    override fun getItemViewType(position: Int) = if (items[position].first.startsWith("#")) 1 else 0
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
        val inf = LayoutInflater.from(parent.context)
        return VH(inf.inflate(if (viewType == 1) R.layout.item_menu_header else R.layout.item_menu, parent, false))
    }
    override fun getItemCount() = items.size
    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
        val (id, title) = items[position]
        (holder.itemView as TextView).text = title
        if (!id.startsWith("#")) holder.itemView.setOnClickListener { click(id) } else holder.itemView.setOnClickListener(null)
    }
}

// ------------------------------------------------------------------ View Source / View Help
class TextActivity : AppCompatActivity() {
    private lateinit var b: ActivityTextBinding
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityTextBinding.inflate(layoutInflater)
        setContentView(b.root)
        setSupportActionBar(b.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        val id = intent.getStringExtra("id") ?: ""
        val title = intent.getStringExtra("title") ?: ""
        if (intent.getStringExtra("mode") == "guide") {
            supportActionBar?.title = tr("User Guide")
            b.tabs.visibility = View.GONE; b.codeScroll.visibility = View.GONE; b.tvHelp.visibility = View.VISIBLE
            b.tvHelp.text = guideText(this)
            return
        }
        if (intent.getStringExtra("mode") == "help") {
            supportActionBar?.title = tr("Help - {0}", title)
            b.tabs.visibility = View.GONE; b.codeScroll.visibility = View.GONE; b.tvHelp.visibility = View.VISIBLE
            b.tvHelp.text = helpText(this, id)
            return
        }
        supportActionBar?.title = tr("{0} Source", title)
        val tabs = DvwaApp.LEVELS + "all"
        for (t in tabs) b.tabs.addTab(b.tabs.newTab().setText(if (t == "all") tr("Compare all") else Lang.levelName(t)))
        b.tabs.addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
            override fun onTabSelected(tab: TabLayout.Tab) { b.tvCode.text = Sources.text(this@TextActivity, id, tabs[tab.position]) }
            override fun onTabUnselected(tab: TabLayout.Tab) {}
            override fun onTabReselected(tab: TabLayout.Tab) {}
        })
        val start = tabs.indexOf(intent.getStringExtra("level") ?: "low").coerceAtLeast(0)
        b.tabs.getTabAt(start)?.select()
        b.tvCode.text = Sources.text(this, id, tabs[start])
    }

    override fun onSupportNavigateUp(): Boolean { finish(); return true }

    companion object {
        fun source(c: Context, id: String, title: String, level: String) = Intent(c, TextActivity::class.java)
            .putExtra("mode", "source").putExtra("id", id).putExtra("title", title).putExtra("level", level)
        fun guide(c: Context) = Intent(c, TextActivity::class.java).putExtra("mode", "guide")
        fun help(c: Context, id: String, title: String) = Intent(c, TextActivity::class.java)
            .putExtra("mode", "help").putExtra("id", id).putExtra("title", title)

        @Suppress("DEPRECATION")
        fun helpText(c: Context, id: String): CharSequence {
            fun asset(p: String): String? = try { c.assets.open(p).bufferedReader().use { it.readText() } } catch (e: Exception) { null }
            // Translated help (Hindi / Hinglish) lives in www/help/<lang>/; English is the original DVWA text.
            var h = (if (Lang.code != Lang.EN) asset("www/help/${Lang.assetDir}/$id.html") else null)
                ?: asset("www/help/$id.html") ?: tr("<p>No help available.</p>")
            h = h.replace(Regex("(?is)<table[^>]*>|</table>|<tr>|</tr>|<td>|</td>"), "")
                .replace(Regex("(?is)<span class=\"spoiler\">(.*?)</span>"), "<b><font color='#C62828'>$1</font></b>")
            val note = Sources.helpNote[id]?.let { tr("<p><b><font color='#E65100'>Native edition note:</font></b> {0}</p><hr/>", it) } ?: ""
            val full = note + h
            return if (Build.VERSION.SDK_INT >= 24) Html.fromHtml(full, Html.FROM_HTML_MODE_LEGACY) else Html.fromHtml(full)
        }

        @Suppress("DEPRECATION")
        fun guideText(c: Context): CharSequence {
            val h = try { c.assets.open("guide/${Lang.assetDir}.html").bufferedReader().use { it.readText() } }
                catch (e: Exception) { try { c.assets.open("guide/en.html").bufferedReader().use { it.readText() } } catch (x: Exception) { "<p>User guide missing.</p>" } }
            return Html.fromHtml(h, Html.FROM_HTML_MODE_LEGACY)
        }
    }
}

object Sources {
    private const val BASE = "www/php/vulnerabilities"
    private val extra = mapOf(
        "javascript" to mapOf("medium" to listOf("javascript/source/medium.js"), "high" to listOf("javascript/source/high_unobfuscated.js"), "low" to listOf("javascript/index.php")),
        "csp" to mapOf("high" to listOf("csp/source/high.js", "csp/source/jsonp.php"), "impossible" to listOf("csp/source/impossible.js", "csp/source/jsonp_impossible.php")),
        "cryptography" to mapOf("high" to listOf("cryptography/source/token_library_high.php", "cryptography/source/check_token_high.php"), "impossible" to listOf("cryptography/source/token_library_impossible.php", "cryptography/source/check_token_impossible.php")),
        "authbypass" to DvwaApp.LEVELS.associateWith { listOf("authbypass/get_user_data.php", "authbypass/change_user_details.php") },
        "open_redirect" to DvwaApp.LEVELS.associateWith { listOf("open_redirect/source/info.php") },
        "sqli" to mapOf("high" to listOf("sqli/session-input.php")),
        "sqli_blind" to mapOf("high" to listOf("sqli_blind/cookie-input.php")),
        "csrf" to DvwaApp.LEVELS.associateWith { listOf("csrf/test_credentials.php") },
    )
    private fun read(c: Context, p: String): String? = try { c.assets.open("$BASE/$p").bufferedReader().use { it.readText() } } catch (e: Exception) { null }

    fun one(c: Context, id: String, lv: String): String {
        val sb = StringBuilder()
        sb.append("// " + tr("Source code for the {0} level (PHP code is shown unchanged)", Lang.levelName(lv)) + "\n")
        sb.append("// vulnerabilities/$id/source/$lv.php\n\n").append(read(c, "$id/source/$lv.php") ?: tr("(no source)")).append("\n")
        for (e in extra[id]?.get(lv) ?: listOf()) read(c, e)?.let { sb.append("\n\n// ===== vulnerabilities/$e =====\n// " + tr("Related file used by this level") + "\n\n").append(it) }
        return sb.toString()
    }

    fun text(c: Context, id: String, lv: String): String =
        if (lv == "all") DvwaApp.LEVELS.joinToString("\n\n") { "################ ${it.uppercase()} ################\n// " + tr("Source code for the {0} level (PHP code is shown unchanged)", Lang.levelName(it)) + "\n\n" + (read(c, "$id/source/$it.php") ?: "") }
        else one(c, id, lv)

    private val SIM: String get() = tr("This edition has <b>no WebView and no JavaScript engine</b>. Your input is processed by a Kotlin port of the level's PHP; the resulting HTML is then analysed natively. If a real browser would have executed script (&lt;script&gt;, on*= event handlers, javascript: URLs, CSP-allowed sources, JSONP callbacks), the app shows <b>⚠ XSS fired</b> with a simulated effect (alert/prompt/confirm text in a native dialog, document.cookie value, redirects/exfiltration described but never sent). Safe levels show the escaped output and <b>blocked</b>.")
    val helpNote: Map<String, String> get() = mapOf(
        "xss_d" to SIM + tr(" DOM XSS: type the full URL; the part after <code>#</code> is never sent to the 'server' but is still read by the simulated document.write()."),
        "xss_r" to SIM, "xss_s" to SIM + tr(" Guestbook entries are stored in the bundled SQLite database."),
        "csp" to SIM + tr(" CSP rules (allowed hosts, nonce, 'self', JSONP callback) are evaluated natively. Nothing is fetched: for allowed external URLs you supply the simulated file content."),
        "javascript" to SIM + tr(" The page's client-side token functions (md5(rot13), reverse, sha256 chain) are re-implemented in Kotlin; use the 'Run in console' helpers or tamper the hidden token field."),
        "exec" to tr("Commands run in a simulated shell over a fake Debian file system; no real device command is ever executed."),
        "upload" to tr("Files are saved to the app's private directory. Uploaded .php files can be 'requested' through a tiny PHP/webshell simulator backed by the fake shell."),
        "fi" to tr("Included files come from a bundled fake web root, a fake Debian FS and this app's own sandbox (/data/data/org.dvwa.android/…). Remote URLs are never fetched."),
        "captcha" to tr("Google reCAPTCHA is replaced with a locally drawn text CAPTCHA. Hidden fields and headers can be edited in the tamper panel."),
        "open_redirect" to tr("Redirects to external sites are shown, never followed (no INTERNET permission)."),
    )
}

// ------------------------------------------------------------------ first-run tutorial (3-4 slides)
class OnboardingActivity : AppCompatActivity() {
    private var i = 0
    private val slides: List<Pair<String, String>> get() = listOf(
        "🛡 " + tr("Welcome to DVWA Offline") to tr("DVWA is a deliberately vulnerable practice app. Everything runs offline inside this app: no internet, no WebView. Practise only here or on systems you own or are allowed to test."),
        "🔑 " + tr("Login and security level") to tr("Log in with admin / password. Open the menu (☰) and choose DVWA Security to switch between Low, Medium, High and Impossible. Start with Low."),
        "🧪 " + tr("Try a module") to tr("Pick a module like SQL Injection or XSS from the menu. Type a payload, press Submit and watch the result. Use View Source to read the PHP code and View Help for hints."),
        "🛠 " + tr("Tools and help") to tr("The orange Intercept & tamper panel lets you edit hidden fields, headers and cookies. Go to URL… opens pages directly. The User Guide in the menu explains every module step by step."),
    )
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        i = savedInstanceState?.getInt("i") ?: 0
        val dp = resources.displayMetrics.density
        val root = android.widget.LinearLayout(this).apply { orientation = android.widget.LinearLayout.VERTICAL; setPadding((24 * dp).toInt(), (48 * dp).toInt(), (24 * dp).toInt(), (24 * dp).toInt()); setBackgroundColor(0xFFF5F5F5.toInt()) }
        val step = TextView(this).apply { textSize = 13f; setTextColor(0xFF666666.toInt()) }
        val title = TextView(this).apply { textSize = 24f; setTypeface(typeface, android.graphics.Typeface.BOLD); setTextColor(0xFF1B5E20.toInt()); setPadding(0, (16 * dp).toInt(), 0, (12 * dp).toInt()) }
        val body = TextView(this).apply { textSize = 17f; setTextColor(0xFF222222.toInt()); setLineSpacing(0f, 1.2f) }
        val spacer = View(this)
        val bar = android.widget.LinearLayout(this).apply { orientation = android.widget.LinearLayout.HORIZONTAL }
        val skip = com.google.android.material.button.MaterialButton(this, null, androidx.appcompat.R.attr.borderlessButtonStyle).apply { text = tr("Skip"); isAllCaps = false }
        val back = com.google.android.material.button.MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply { text = tr("Back"); isAllCaps = false }
        val next = com.google.android.material.button.MaterialButton(this).apply { isAllCaps = false }
        val wl = { w: Float -> android.widget.LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, w) }
        bar.addView(skip, wl(1f)); bar.addView(back, wl(1f).also { it.marginStart = (8 * dp).toInt() }); bar.addView(next, wl(1.2f).also { it.marginStart = (8 * dp).toInt() })
        root.addView(step); root.addView(title); root.addView(body)
        root.addView(spacer, android.widget.LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        root.addView(bar)
        setContentView(root)
        fun render() {
            val s = slides
            step.text = "${i + 1} / ${s.size}"
            title.text = s[i].first; body.text = s[i].second
            back.visibility = if (i == 0) View.INVISIBLE else View.VISIBLE
            next.text = if (i == s.size - 1) tr("Get started") else tr("Next")
        }
        back.setOnClickListener { if (i > 0) { i--; render() } }
        next.setOnClickListener { if (i < slides.size - 1) { i++; render() } else finishTutorial() }
        skip.setOnClickListener { finishTutorial() }
        render()
    }
    private fun finishTutorial() { DvwaApp.I.prefs.edit().putBoolean("tutorial_done", true).apply(); finish() }
    override fun onSaveInstanceState(outState: Bundle) { super.onSaveInstanceState(outState); outState.putInt("i", i) }
}
