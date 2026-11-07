# DVWA Offline – Native Android edition (v2.1.1)

> **⚠ v2.1.1 update note:** v2.1.1 se aage updates seedha install honge; v2.1.1 install karne se pehle purana app ek baar uninstall karein.
> (v2.1.1 se har build ek hi fixed key `app/dvwa-release.keystore` se sign hota hai. Purane builds random debug key se sign the, isliye unke upar update "App not installed" deta tha.)

## 🇮🇳 Hinglish mein: Install aur Use kaise karein

**DVWA Offline** ek practice app hai jo jaan-boojh kar *vulnerable* banayi gayi hai, taaki aap SQL Injection, XSS, CSRF jaise web attacks **legal tareeke se, offline** seekh sakein. App mein na WebView hai, na `INTERNET` permission – sab kuch phone ke andar, app ke private data par hi chalta hai. Sirf yahan ya apne/permission wale systems par practice karein.

**Install kaise karein**
1. [Releases](https://github.com/termux-learn-crypto/dvwa-android/releases/latest) page kholiye aur `dvwa-native-v2.1.1-debug.apk` download kariye.
2. Phone par APK kholiye. Agar "Install unknown apps" ka message aaye to browser/file manager ko permission de dijiye.
3. Purana version (v2.1.0 ya usse pehle) install hai to pehle use **ek baar uninstall** karein, phir v2.1.1 install karein. v2.1.1 ke baad wale updates seedha upar se install honge (data safe rehta hai).

**Use kaise karein (short mein)**
1. Pehli baar app kholne par **language chuniye** – Hinglish (default), हिन्दी ya English – phir 4 slides ka chhota tutorial aata hai.
2. Login: `admin` / `password` (baaki accounts: `gordonb`/`abc123`, `1337`/`charley`, `pablo`/`letmein`, `smithy`/`password`).
3. Menu ☰ → **DVWA Security** se level chuniye: **Low** (koi protection nahi) → **Medium** → **High** → **Impossible** (secure code).
4. Menu se koi module kholiye (jaise SQL Injection), payload daaliye, **Submit** dabaiye aur result dekhiye. **View Source** se PHP code, **View Help** se hints milte hain.
5. Orange **🛠 Intercept & tamper** panel mein hidden fields, headers, cookies badal sakte hain; ⋮ menu ka **Go to URL…** kisi bhi page ko seedha kholta hai.
6. Kuch gadbad ho (password badal gaya, guestbook bhar gaya) to ☰ → **Setup / Reset DB**.
7. Language kabhi bhi badlein: login screen ka 🌐 button, ☰ → Settings → **Language**, ya ⋮ menu.

Poori guide: **[docs/USER_GUIDE.md](docs/USER_GUIDE.md)** (Hinglish) · **[docs/USER_GUIDE_HI.md](docs/USER_GUIDE_HI.md)** (हिन्दी). App ke andar bhi: ☰ → **Kaise Use Karein (User Guide)**.

---

## English

A fully **native, offline** Android re-implementation of [DVWA – Damn Vulnerable Web Application](https://github.com/digininja/DVWA) for personal security practice.

* **No WebView, no embedded web server, no `INTERNET` permission.** Every screen is native Android UI (Kotlin, Material Components, ViewBinding, RecyclerView drawer menu mirroring DVWA's left menu).
* Login (5 DVWA accounts in a bundled SQLite DB: admin/password, gordonb/abc123, 1337/charley, pablo/letmein, smithy/password), Home, Instructions, About, Setup / Reset DB, DVWA Security (Low / Medium / High / Impossible in SharedPreferences), PHP Info.
* 17 modules, each with the vulnerable behaviour per level, **View Source** (the real DVWA PHP for the current level, plus *Compare all*) and **Help**:
  Brute Force · Command Injection · CSRF · File Inclusion · File Upload · Insecure CAPTCHA · SQL Injection · SQL Injection (Blind) · Weak Session IDs · XSS (DOM) · XSS (Reflected) · XSS (Stored) · CSP Bypass · JavaScript Attacks · Authorisation Bypass · Open HTTP Redirect · Cryptography.
* Each module has an orange **Intercept & tamper** panel for hidden fields, headers (Referer, User-Agent), cookies and client-side limits — the native stand-in for Burp/DevTools. The toolbar has a simulated address bar (*Go to URL…*).

## How the web parts are simulated
* **SQL**: real bundled SQLite. Vulnerable levels concatenate strings; Impossible uses prepared statements. UNION, comments (`-- `, `#`), `user()`, `database()`, `version()`, `information_schema` emulation, `sleep()`.
* **Command Injection**: a Kotlin fake shell (`; && || | & $() backticks`) over a fake Debian FS with canned `/etc/passwd`. No device command is ever executed.
* **File Upload / Inclusion**: app-private storage only; uploaded `.php` files run through a tiny webshell simulator backed by the fake shell.
* **XSS (DOM/Reflected/Stored), CSP Bypass, JavaScript Attacks**: there is no browser or JS engine. The app ports the PHP that builds the page, then analyses the resulting HTML. When a browser would have executed script (`<script>`, `on*=` handlers, `javascript:` URLs, CSP-allowed sources, JSONP callbacks) it shows **⚠ XSS fired** with the simulated effect (native alert dialog with the alert/prompt text, `document.cookie`, redirects/exfiltration described but never sent). Safe levels show escaped output and *blocked*.
* **Cryptography**: real XOR, AES-128-ECB, AES-CBC padding oracle (High) and AES-GCM (Impossible) via `javax.crypto`.

## Languages (v2.1)
* English, हिन्दी (Hindi, `values-hi`) and Hinglish (Roman-script Hindi, `values-b+hi+Latn`, locale tag `hi-Latn`).
* The choice is stored in SharedPreferences and applied with `AppCompatDelegate.setApplicationLocales()` (per-app locale, also visible in Android 13+ app-language settings). Text built in Kotlin goes through `tr("English text")`, which looks up the string resource for the selected locale (`LKeys.kt`, generated) and falls back to English.
* Module help pages: `assets/www/help/{hi,hinglish}/`; in-app User Guide: `assets/guide/{en,hi,hinglish}.html`.

## Build
`./gradlew assembleDebug` (JDK 17, Android SDK 34, Gradle 8.7 wrapper). GitHub Actions builds the APK on every push, checks that the APK has no INTERNET permission, uploads the artifact and publishes release `v2.1.1` (signed with the fixed key; the CI also checks the signing cert) from `main`.

## Licence
DVWA is © its authors and licensed GPL-3.0; bundled DVWA help texts, images and PHP sources (for View Source) remain under that licence. This app is GPL-3.0.

## Signing (v2.1.1+)
All builds (debug and release) are signed with one fixed key committed at `app/dvwa-release.keystore` (alias `dvwa`, passwords in `keystore.properties`). This is intentionally **not secret** — it's a public, deliberately vulnerable training app — and it exists only so every GitHub Actions build installs as an update over the previous one. Certificate SHA-256:
`A9:24:F9:2A:3D:7F:BC:15:A1:82:30:D3:36:29:7E:25:9C:D9:44:DB:74:66:88:42:98:65:A3:59:7E:FF:5D:5D`
