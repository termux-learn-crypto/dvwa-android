# DVWA Offline (Android)

A fully **offline** Android re-implementation of [DVWA – Damn Vulnerable Web Application](https://github.com/digininja/DVWA) for personal security practice.

* Embedded HTTP server (NanoHTTPD) bound to **127.0.0.1:8080 only**, shown in a full-screen WebView.
* App-private SQLite database with DVWA's `users` and `guestbook` tables (admin/password, gordonb/abc123, 1337/charley, pablo/letmein, smithy/password).
* Login, Setup / Reset DB, DVWA Security (Low / Medium / High / Impossible, stored in the `security` cookie), View Help and View Source (original DVWA PHP per level, plus *Compare All Levels*).
* Modules: Brute Force, Command Injection, CSRF, File Inclusion, File Upload, Insecure CAPTCHA, SQL Injection, SQL Injection (Blind), Weak Session IDs, XSS (DOM), XSS (Reflected), XSS (Stored), CSP Bypass, JavaScript Attacks, Authorisation Bypass, Open HTTP Redirect, Cryptography.

## Safety model
* Command Injection runs a **simulated** shell (canned `ping`, `whoami`, `id`, `uname`, `ls`, `cat /etc/passwd`, …) over a fake Debian filesystem — no Android command is ever executed.
* Uploads, file inclusion and SQL only touch the app's own sandbox.
* The WebView blocks every external navigation and sub-resource; the network security config only permits cleartext to 127.0.0.1.

## Build
`./gradlew assembleDebug` (JDK 17, Android SDK 34). GitHub Actions builds the APK on every push and publishes release `v1.0.0` from `main`.

## Licence
DVWA is © its authors and licensed GPL-3.0; bundled DVWA help texts, images and PHP sources (for View Source) remain under that licence. This app is GPL-3.0.
