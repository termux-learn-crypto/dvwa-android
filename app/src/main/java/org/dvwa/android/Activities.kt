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
        b.tvHint.text = "Default login: admin / password\nOther accounts: gordonb / abc123 · 1337 / charley · pablo / letmein · smithy / password\n\nEverything runs natively & offline: no WebView, no network."
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
                    } else b.tvMessage.text = "Login failed"
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
            if (id == "logout") logout() else show(id)
        }
        b.tvDrawerHeader.text = "Username: ${DvwaApp.I.user}\nSecurity Level: ${DvwaApp.I.level}\nLocale: en\nSQLi DB: sqlite (bundled)"
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
        show(id); return true
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menu.add(0, 1, 0, "Go to URL…")
        menu.add(0, 2, 0, "Security level…")
        menu.add(0, 3, 0, "Logout")
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            1 -> {
                val et = EditText(this).apply { setText("http://127.0.0.1/vulnerabilities/"); setSingleLine() }
                AlertDialog.Builder(this).setTitle("Go to URL (simulated address bar)").setView(et)
                    .setPositiveButton("Go") { _, _ -> if (!openPath(et.text.toString())) OutBox.alert(this, "404 Not Found", "The requested URL was not found on this server.\n\nTry e.g. /vulnerabilities/authbypass/") }
                    .setNegativeButton("Cancel", null).show()
            }
            2 -> show("security")
            3 -> logout()
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
        if (intent.getStringExtra("mode") == "help") {
            supportActionBar?.title = "Help - $title"
            b.tabs.visibility = View.GONE; b.codeScroll.visibility = View.GONE; b.tvHelp.visibility = View.VISIBLE
            b.tvHelp.text = helpText(this, id)
            return
        }
        supportActionBar?.title = "$title Source"
        val tabs = DvwaApp.LEVELS + "all"
        for (t in tabs) b.tabs.addTab(b.tabs.newTab().setText(if (t == "all") "Compare all" else t.replaceFirstChar { it.uppercase() }))
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
        fun help(c: Context, id: String, title: String) = Intent(c, TextActivity::class.java)
            .putExtra("mode", "help").putExtra("id", id).putExtra("title", title)

        @Suppress("DEPRECATION")
        fun helpText(c: Context, id: String): CharSequence {
            var h = try { c.assets.open("www/help/$id.html").bufferedReader().use { it.readText() } } catch (e: Exception) { "<p>No help available.</p>" }
            h = h.replace(Regex("(?is)<table[^>]*>|</table>|<tr>|</tr>|<td>|</td>"), "")
                .replace(Regex("(?is)<span class=\"spoiler\">(.*?)</span>"), "<b><font color='#C62828'>$1</font></b>")
            val note = Sources.helpNote[id]?.let { "<p><b><font color='#E65100'>Native edition note:</font></b> $it</p><hr/>" } ?: ""
            val full = note + h
            return if (Build.VERSION.SDK_INT >= 24) Html.fromHtml(full, Html.FROM_HTML_MODE_LEGACY) else Html.fromHtml(full)
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
        sb.append("// vulnerabilities/$id/source/$lv.php\n\n").append(read(c, "$id/source/$lv.php") ?: "(no source)").append("\n")
        for (e in extra[id]?.get(lv) ?: listOf()) read(c, e)?.let { sb.append("\n\n// ===== vulnerabilities/$e =====\n\n").append(it) }
        return sb.toString()
    }

    fun text(c: Context, id: String, lv: String): String =
        if (lv == "all") DvwaApp.LEVELS.joinToString("\n\n") { "################ ${it.uppercase()} ################\n\n" + (read(c, "$id/source/$it.php") ?: "") }
        else one(c, id, lv)

    private const val SIM = "This edition has <b>no WebView and no JavaScript engine</b>. Your input is processed by a Kotlin port of the level's PHP; the resulting HTML is then analysed natively. If a real browser would have executed script (&lt;script&gt;, on*= event handlers, javascript: URLs, CSP-allowed sources, JSONP callbacks), the app shows <b>⚠ XSS fired</b> with a simulated effect (alert/prompt/confirm text in a native dialog, document.cookie value, redirects/exfiltration described but never sent). Safe levels show the escaped output and <b>blocked</b>."
    val helpNote = mapOf(
        "xss_d" to SIM + " DOM XSS: type the full URL; the part after <code>#</code> is never sent to the 'server' but is still read by the simulated document.write().",
        "xss_r" to SIM, "xss_s" to SIM + " Guestbook entries are stored in the bundled SQLite database.",
        "csp" to SIM + " CSP rules (allowed hosts, nonce, 'self', JSONP callback) are evaluated natively. Nothing is fetched: for allowed external URLs you supply the simulated file content.",
        "javascript" to SIM + " The page's client-side token functions (md5(rot13), reverse, sha256 chain) are re-implemented in Kotlin; use the 'Run in console' helpers or tamper the hidden token field.",
        "exec" to "Commands run in a simulated shell over a fake Debian file system; no real device command is ever executed.",
        "upload" to "Files are saved to the app's private directory. Uploaded .php files can be 'requested' through a tiny PHP/webshell simulator backed by the fake shell.",
        "fi" to "Included files come from a bundled fake web root, a fake Debian FS and this app's own sandbox (/data/data/org.dvwa.android/…). Remote URLs are never fetched.",
        "captcha" to "Google reCAPTCHA is replaced with a locally drawn text CAPTCHA. Hidden fields and headers can be edited in the tamper panel.",
        "open_redirect" to "Redirects to external sites are shown, never followed (no INTERNET permission).",
    )
}
