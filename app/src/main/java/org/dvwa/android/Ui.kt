package org.dvwa.android

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.graphics.Typeface
import android.os.Handler
import android.os.Looper
import android.text.Html
import android.text.InputFilter
import android.text.InputType
import android.text.method.LinkMovementMethod
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.*
import androidx.appcompat.app.AlertDialog
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import java.util.concurrent.Executors

/** Small builder for native module screens (EditText / Button / TextView ...). */
class Ui(val ctx: Context, val root: LinearLayout) {
    fun dp(n: Int) = (n * ctx.resources.displayMetrics.density).toInt()
    private fun lp(top: Int = 6) = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).also { it.topMargin = dp(top) }
    private fun <T : View> add(v: T, top: Int = 6): T { root.addView(v, lp(top)); return v }

    fun h2(text: String): TextView = add(TextView(ctx).apply {
        this.text = text; textSize = 18f; setTypeface(typeface, Typeface.BOLD); setTextColor(Color.BLACK)
    }, 14)

    fun p(text: CharSequence): TextView = add(TextView(ctx).apply { this.text = text; textSize = 14f; setTextColor(0xFF333333.toInt()) })

    @Suppress("DEPRECATION")
    fun html(h: String): TextView = add(TextView(ctx).apply {
        text = if (android.os.Build.VERSION.SDK_INT >= 24) Html.fromHtml(h, Html.FROM_HTML_MODE_COMPACT) else Html.fromHtml(h)
        textSize = 14f; setTextColor(0xFF333333.toInt()); movementMethod = LinkMovementMethod.getInstance()
    })

    fun code(s: String): TextView {
        val hs = HorizontalScrollView(ctx)
        val tv = TextView(ctx).apply {
            text = s; typeface = Typeface.MONOSPACE; textSize = 12f
            setTextColor(0xFFE0E0E0.toInt()); setBackgroundColor(0xFF1E1E1E.toInt()); setPadding(dp(10), dp(8), dp(10), dp(8))
            setTextIsSelectable(true)
        }
        hs.addView(tv); add(hs)
        return tv
    }

    fun field(label: String, value: String = "", password: Boolean = false, multiline: Boolean = false, maxLen: Int = 0, numeric: Boolean = false): EditText {
        val til = TextInputLayout(ctx)
        til.boxBackgroundMode = TextInputLayout.BOX_BACKGROUND_OUTLINE
        til.setBoxCornerRadii(dp(4).toFloat(), dp(4).toFloat(), dp(4).toFloat(), dp(4).toFloat())
        til.hint = label
        if (password) til.endIconMode = TextInputLayout.END_ICON_PASSWORD_TOGGLE
        val et = TextInputEditText(til.context)
        et.setText(value)
        et.inputType = when {
            password -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            multiline -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            numeric -> InputType.TYPE_CLASS_TEXT
            else -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
        }
        if (multiline) { et.minLines = 3; et.gravity = Gravity.TOP or Gravity.START } else et.isSingleLine = true
        if (maxLen > 0) et.filters = arrayOf(InputFilter.LengthFilter(maxLen))
        til.addView(et)
        add(til)
        return et
    }

    fun spinner(label: String, items: List<String>, sel: Int = 0): Spinner {
        p(label)
        val sp = Spinner(ctx)
        sp.adapter = ArrayAdapter(ctx, android.R.layout.simple_spinner_dropdown_item, items)
        sp.setSelection(sel)
        add(sp, 0)
        return sp
    }

    fun radios(vararg options: String, checked: Int = 0): RadioGroup {
        val rg = RadioGroup(ctx); rg.orientation = RadioGroup.HORIZONTAL
        options.forEachIndexed { i, o -> rg.addView(RadioButton(ctx).apply { text = o; id = 1000 + i; isChecked = i == checked }) }
        add(rg); return rg
    }

    fun check(label: String, checked: Boolean = false): CheckBox = add(CheckBox(ctx).apply { text = label; isChecked = checked })

    fun button(text: String, outlined: Boolean = false, onClick: (MaterialButton) -> Unit): MaterialButton {
        val b = if (outlined) MaterialButton(ctx, null, com.google.android.material.R.attr.materialButtonOutlinedStyle) else MaterialButton(ctx)
        b.text = text; b.isAllCaps = false
        b.setOnClickListener { onClick(b) }
        root.addView(b, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).also { it.topMargin = dp(6) })
        return b
    }

    fun image(asset: String, sizeDp: Int = 72): ImageView {
        val iv = ImageView(ctx)
        try { ctx.assets.open(asset).use { iv.setImageBitmap(BitmapFactory.decodeStream(it)) } } catch (e: Exception) {}
        root.addView(iv, LinearLayout.LayoutParams(dp(sizeDp), dp(sizeDp)).also { it.topMargin = dp(6) })
        return iv
    }

    fun divider() { add(View(ctx).apply { setBackgroundColor(0xFFCCCCCC.toInt()) }, 12).layoutParams.height = dp(1) }

    /** A white card (DVWA's "vulnerable_code_area"). Returns a nested builder. */
    fun card(title: String? = null): Ui {
        val card = MaterialCardView(ctx)
        card.radius = dp(6).toFloat(); card.cardElevation = dp(1).toFloat(); card.setContentPadding(dp(12), dp(10), dp(12), dp(12))
        val inner = LinearLayout(ctx).apply { orientation = LinearLayout.VERTICAL }
        card.addView(inner)
        add(card, 10)
        val u = Ui(ctx, inner)
        if (title != null) u.h2(title).also { (it.layoutParams as LinearLayout.LayoutParams).topMargin = 0 }
        return u
    }

    /** Collapsible card simulating what an intercepting proxy / DevTools lets you edit. */
    fun tamper(title: String = tr("🛠 Intercept & tamper (hidden fields, headers, cookies)")): Ui {
        val toggle = TextView(ctx)
        toggle.text = "▸ $title"; toggle.setTextColor(0xFFE65100.toInt()); toggle.textSize = 14f
        toggle.setPadding(dp(4), dp(8), dp(4), dp(8)); toggle.isClickable = true
        add(toggle, 8)
        val box = LinearLayout(ctx).apply { orientation = LinearLayout.VERTICAL; visibility = View.GONE; setBackgroundColor(0xFFFFF8E1.toInt()); setPadding(dp(8), dp(4), dp(8), dp(8)) }
        add(box, 0)
        toggle.setOnClickListener {
            val open = box.visibility != View.VISIBLE
            box.visibility = if (open) View.VISIBLE else View.GONE
            toggle.text = (if (open) "▾ " else "▸ ") + title
        }
        return Ui(ctx, box)
    }

    fun result(): OutBox {
        val ll = LinearLayout(ctx).apply { orientation = LinearLayout.VERTICAL }
        add(ll, 8)
        return OutBox(Ui(ctx, ll))
    }

    fun container(): LinearLayout { val ll = LinearLayout(ctx).apply { orientation = LinearLayout.VERTICAL }; add(ll); return ll }
}

/** Output area. All methods are safe to call from a background thread. */
class OutBox(private val u: Ui) {
    private val main = Handler(Looper.getMainLooper())
    private fun ui(f: () -> Unit) { if (Looper.myLooper() == Looper.getMainLooper()) f() else main.post(f) }

    fun clear() = ui { u.root.removeAllViews() }
    fun text(s: CharSequence) = ui { u.p(s) }
    fun pre(s: String) = ui { u.code(s) }
    fun html(s: String) = ui { u.html(s) }
    fun image(asset: String) = ui { u.image(asset) }
    fun bitmap(b: Bitmap) = ui { u.root.addView(ImageView(u.ctx).apply { setImageBitmap(b); adjustViewBounds = true }) }
    fun ok(s: String) = banner(s, 0xFFE8F5E9.toInt(), 0xFF1B5E20.toInt())
    fun warn(s: String) = banner(s, 0xFFFFF3E0.toInt(), 0xFFE65100.toInt())
    fun err(s: String) = banner(s, 0xFFFFEBEE.toInt(), 0xFFB71C1C.toInt())
    fun info(s: String) = banner(s, 0xFFE3F2FD.toInt(), 0xFF0D47A1.toInt())
    fun banner(s: String, bg: Int, fg: Int) = ui {
        u.root.addView(TextView(u.ctx).apply {
            text = s; setBackgroundColor(bg); setTextColor(fg); textSize = 14f
            setPadding(u.dp(10), u.dp(8), u.dp(10), u.dp(8)); setTextIsSelectable(true)
        }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).also { it.topMargin = u.dp(6) })
    }
    fun custom(f: (Ui) -> Unit) = ui { f(u) }

    /** Report XSS analysis of rendered HTML; pops a native "alert" if the payload would have fired. */
    fun xss(rendered: String, blockedReason: String? = null, popup: Boolean = true): List<Xss.Hit> {
        val hits = Xss.scan(rendered)
        if (hits.isEmpty()) {
            ok(tr("✓ No script execution: the output contains no executable markup.") + (blockedReason?.let { " ($it)" } ?: ""))
        } else if (blockedReason != null) {
            warn(tr("🛡 Script blocked: {0}\n", blockedReason) + hits.joinToString("\n") { "• ${it.vector}: ${it.code.take(120)}" })
        } else {
            err(tr("⚠ XSS fired (simulated natively — no browser involved)\n") + hits.joinToString("\n\n") { Xss.describe(it) })
            if (popup) Xss.firstDialog(hits)?.let { msg -> ui { alert(u.ctx, "127.0.0.1 says", msg) } }
        }
        return hits
    }

    companion object {
        fun alert(ctx: Context, title: String, msg: String) {
            try { AlertDialog.Builder(ctx).setTitle(title).setMessage(msg).setPositiveButton("OK", null).show() } catch (e: Exception) {}
        }
    }
}

object Bg {
    private val pool = Executors.newFixedThreadPool(3)
    private val main = Handler(Looper.getMainLooper())
    /** Run work off the UI thread (sleep(), ping, brute force), disabling the button meanwhile. */
    fun run(btn: View?, work: () -> Unit) {
        btn?.isEnabled = false
        pool.execute {
            try { work() } catch (e: Throwable) { main.post { btn?.let { Toast.makeText(it.context, "Error: ${e.message}", Toast.LENGTH_LONG).show() } } }
            main.post { btn?.isEnabled = true }
        }
    }
}

fun EditText.str(): String = text?.toString() ?: ""
