package org.dvwa.android

import android.app.Activity
import android.content.Context
import android.content.res.Configuration
import android.content.res.Resources
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.LocaleList
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import java.util.Locale

/**
 * App language: English, Hindi (Devanagari, values-hi) and Hinglish (Roman-script Hindi, values-b+hi+Latn).
 * The choice is stored in SharedPreferences and applied app-wide:
 *  - AppCompatDelegate.setApplicationLocales() (per-app locale; system "App language" on Android 13+),
 *  - a locale-specific Resources object used by [tr] for every string built in code (works from any thread).
 * English text is the lookup key (see [LKeys]); anything without a translation falls back to English.
 */
object Lang {
    const val EN = "en"; const val HI = "hi"; const val HINGLISH = "hinglish"
    val CODES = listOf(HINGLISH, HI, EN)
    private const val PREF = "app_lang"
    private const val PREF_CHOSEN = "app_lang_chosen"
    private var cachedCode: String? = null
    private var cachedRes: Resources? = null

    fun tag(code: String) = when (code) { HI -> "hi"; HINGLISH -> "hi-Latn"; else -> "en" }
    fun fromTag(t: String): String? {
        val l = t.lowercase(Locale.ROOT)
        return when {
            l.startsWith("hi-latn") || l.startsWith("hi_latn") -> HINGLISH
            l.startsWith("hi") -> HI
            l.startsWith("en") -> EN
            else -> null
        }
    }
    fun label(code: String) = when (code) { HI -> "हिन्दी (Hindi)"; HINGLISH -> "Hinglish (Hindi + English)"; else -> "English" }
    /** Name of the language in itself, for the drawer header. */
    fun shortLabel(code: String) = when (code) { HI -> "हिन्दी"; HINGLISH -> "Hinglish"; else -> "English" }

    private val prefs get() = DvwaApp.I.prefs
    /** Default on first launch: Hinglish. */
    val code: String get() = prefs.getString(PREF, HINGLISH) ?: HINGLISH
    val chosen: Boolean get() = prefs.getBoolean(PREF_CHOSEN, false)
    /** Folder suffix for translated assets (help pages, user guide). */
    val assetDir: String get() = code

    /** Called from Application.onCreate(). */
    fun init() {
        if (Build.VERSION.SDK_INT >= 33) {
            // The user may have changed the language in Android's per-app language settings.
            val sys = try { AppCompatDelegate.getApplicationLocales().toLanguageTags() } catch (e: Exception) { "" }
            if (sys.isNotEmpty()) fromTag(sys)?.let { if (it != code) prefs.edit().putString(PREF, it).apply() }
        }
        applyLocales()
    }

    private fun applyLocales() {
        try { AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(tag(code))) } catch (e: Exception) { }
    }

    /** Persist and apply. Recreates [act] so the visible screen switches language immediately. */
    fun set(newCode: String, act: Activity?) {
        prefs.edit().putString(PREF, newCode).putBoolean(PREF_CHOSEN, true).commit()
        synchronized(this) { cachedCode = null; cachedRes = null }
        applyLocales()
        // AppCompat normally recreates activities itself; make sure the current one is refreshed either way.
        act?.let { a -> Handler(Looper.getMainLooper()).postDelayed({ if (!a.isFinishing && !a.isDestroyed) a.recreate() }, 250) }
    }

    fun markChosen() { prefs.edit().putBoolean(PREF_CHOSEN, true).apply() }

    /** Resources resolved for the selected language, independent of the calling context/thread. */
    fun res(): Resources {
        val c = code
        synchronized(this) {
            if (c == cachedCode && cachedRes != null) return cachedRes!!
            val app = DvwaApp.I
            val conf = Configuration(app.resources.configuration)
            val loc = Locale.forLanguageTag(tag(c))
            conf.setLocales(LocaleList(loc)) // minSdk 24
            val r = app.createConfigurationContext(conf).resources
            cachedCode = c; cachedRes = r
            return r
        }
    }

    fun levelName(lv: String): String = when (lv) {
        "low" -> tr("Low"); "medium" -> tr("Medium"); "high" -> tr("High"); else -> tr("Impossible")
    }

    /** Language chooser dialog (Settings / drawer / login screen / first run). */
    fun showPicker(act: Activity, cancelable: Boolean = true, onDone: (() -> Unit)? = null) {
        val labels = CODES.map { label(it) }.toTypedArray()
        var sel = CODES.indexOf(code).coerceAtLeast(0)
        val d = AlertDialog.Builder(act)
            .setTitle("Language / भाषा / Bhasha")
            .setSingleChoiceItems(labels, sel) { _, w -> sel = w }
            .setPositiveButton("OK") { _, _ ->
                val c = CODES[sel]
                if (c != code) set(c, act) else markChosen()
                onDone?.invoke()
            }
        if (cancelable) d.setNegativeButton(tr("Cancel"), null)
        d.setCancelable(cancelable)
        d.show()
    }
}

/** Translate an English UI string (the key) into the selected language. {0}, {1}… are arguments. */
fun tr(en: String, vararg args: Any?): String {
    val id = LKeys.ids[en]
    if (id != null) {
        try {
            val r = Lang.res()
            return if (args.isEmpty()) r.getString(id) else r.getString(id, *args.map { it?.toString() ?: "" }.toTypedArray())
        } catch (e: Exception) { /* fall through to English */ }
    }
    var s = en
    args.forEachIndexed { i, a -> s = s.replace("{$i}", a?.toString() ?: "") }
    return s
}
