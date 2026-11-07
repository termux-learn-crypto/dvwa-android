# DVWA Offline – Native Android edition (v2)

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

## Build
`./gradlew assembleDebug` (JDK 17, Android SDK 34, Gradle 8.7 wrapper). GitHub Actions builds the APK on every push, checks that the APK has no INTERNET permission, uploads the artifact and publishes release `v2.0.0` from `main`.

## Licence
DVWA is © its authors and licensed GPL-3.0; bundled DVWA help texts, images and PHP sources (for View Source) remain under that licence. This app is GPL-3.0.
