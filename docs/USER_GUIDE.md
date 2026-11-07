# DVWA Offline – Kaise Use Karein (User Guide)

> Yeh guide app ke andar bhi hai: menu ☰ → **Kaise Use Karein (User Guide)**, ya Home par 📘 button. Hindi version: [USER_GUIDE_HI.md](USER_GUIDE_HI.md)

## 1. DVWA kya hai?

DVWA (Damn Vulnerable Web Application) ek aisi practice app hai jo **jaan-boojh kar vulnerable** banayi gayi hai. Aap iska use yeh seekhne ke liye karte hain ki common web attacks kaise kaam karte hain (SQL Injection, XSS, CSRF aur baaki sab) aur accha code unhe kaise rokta hai.

- Yeh Android edition **fully native aur offline** hai: isme koi WebView nahi hai, koi internet permission nahi hai, aur koi web server nahi hai. Har "attack" sirf app ke apne private data ko touch karta hai.
- **Legal use only:** yahan practice karein, ya un systems par jin par aapka haq hai ya jinko test karne ki aapke paas written permission hai. In payloads ko kabhi bhi real websites par try na karein.
- XSS, CSP Bypass aur JavaScript Attacks **natively simulate** hote hain: yahan koi browser engine nahi hai, isliye app output ko analyse karti hai aur real JavaScript run karne ke bajaye simulated alert dialog ke saath "⚠ XSS fired" dikhati hai.


## 2. Login kaise karein

- Default login: `admin` / `password` (username / password)
- Baaki accounts: `gordonb` / `abc123`, `1337` / `charley`, `pablo` / `letmein`, `smithy` / `password`
- **Logout** use karein (menu ☰ ya phir ⋮ toolbar menu se) user switch karne ke liye. Kuch modules (jaise ki Authorisation Bypass) ke liye non-admin user ki zaroorat padti hai.
- App ki language aap jab chahein change kar sakte hain: login screen par 🌐 button se, drawer mein Settings ke andar **Language** se, ya phir ⋮ menu se.


## 3. Setup / Reset DB

- Menu ☰ kholiye → **Setup / Reset DB** → **Create / Reset Database** dabaiye.
- Yeh action 5 users aur unke passwords ko restore kar deta hai, guestbook ko khali kar deta hai, uploaded files delete kar deta hai aur session data clear kar deta hai.
- Isko tab use karein jab aapne koi password change kiya ho (CSRF, CAPTCHA) aur login na kar pa rahe hon, ya jab Stored XSS entries ki wajah se guestbook messy ho gaya ho.


## 4. Security levels

☰ menu kholiye → **DVWA Security**, ek level select karein aur **Submit** dabayein. Har module par level badge current level show karta hai.

- **Low** – koi protection nahi hai. Basic attack sikhne ke liye sabse best hai.
- **Medium** – developer ne code protect karne ki koshish ki par galtiyan kar di (weak filters, blacklists).
- **High** – zyada mushkil ya alag protections, jaise koi CTF challenge ho. Kuch attacks ke liye ek trick ki zaroorat padti hai.
- **Impossible** – secure version. Sahi defence sikhne ke liye iske source code ko baaki levels ke saath compare karein.

Tip: har module ko Low se start karein, phir ek-ek karke upar ke levels par move karein.


## 5. Har module screen ke tools

- **View Source** – current level ka real DVWA PHP code dikhata hai. Tabs Low / Medium / High / Impossible ke beech switch karte hain. Code ko kabhi translate nahi kiya jata.
- **Compare All** – saare chaaro levels ek ke baad ek dikhata hai, taaki aap dekh sakein ki kya change hua hai.
- **View Help** – vulnerability, goal, aur har level ke hints (red color mein spoilers) aapki chosen language mein explain karta hai.
- **🛠 Intercept & tamper panel** (orange, tap karke kholein) – Burp Suite / browser DevTools ka native replacement hai. Yahan aap hidden form fields, `user_token`, headers (Referer, User-Agent), cookies, file names, Content-Type, aur client-side limits jaise maxlength ko edit kar sakte hain.
- **Go to URL… bar** (⋮ toolbar menu) – ek simulated address bar hai. Kisi bhi page ko directly open karne ke liye koi DVWA path type karein, jaise `/vulnerabilities/authbypass/` ya `/vulnerabilities/sqli/`.
- **Brute Force wordlist runner** – Brute Force module mein, "Attack helper" card aapki list ke har password ko (ek line mein ek) login par try karta hai, bilkul Burp Intruder ki tarah, aur pehli success milte hi ruk jata hai.


## 6. Har module ka walkthrough


### Brute Force
- **Kya try karein:** username `admin`, phir short wordlist ke sath Attack helper run karein.
- **Example:** wordlist mein `123456`, `letmein`, `password` jaise passwords hon.
- **Success kaisa dikhta hai:** "Welcome to the password protected area admin" message aur user ka avatar dikhega.
- **Impossible kaise bachata hai:** CSRF token, ek random delay aur 3 failed logins ke baad account lock hone ke protection ke sath.


### Command Injection
- **Kya try karein:** IP address ke baad ek aur command chain karein.
- **Examples:** `127.0.0.1; cat /etc/passwd` (Low), `127.0.0.1 | whoami` (Medium/High).
- **Success kaisa dikhta hai:** output me command ka result dikhega (ek simulated Debian shell se; aapke phone par kuch nahi chalega).
- **Impossible kaise bachata hai:** IP address ke sirf chaar numeric parts accept karke.


### CSRF
- **Kya try karein:** "Attacker: forged link" card ko use karein taaki logged-in victim ek aisa URL khole jo password change kar de.
- **Example:** `http://127.0.0.1/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change`
- **Success kaisa dikhta hai:** "⚠ CSRF succeeded — the victim's password was changed". Naye password ke saath dobara login karein ya DB reset karein.
- **Impossible kaise bachata hai:** ek anti-CSRF token aur current password ke saath.


### File Inclusion
- **Kya try karein:** `?page=` value ko change karke doosri files read karne ki koshish karein.
- **Examples:** `../../../../../etc/passwd` (Low), `....//....//....//etc/passwd` (Medium), `file:///etc/passwd` (High).
- **Success kaisa dikhta hai:** file ka content dikhne lagega, jaise `../../hackable/flags/fi.php` se hidden quotes.
- **Impossible kaise bachata hai:** ek fixed allow-list ke sath file names ko validate karta hai.


### File Upload
- **Kya try karein:** ek image ki jagah ek PHP webshell upload kariye, aur fir usko request kariye.
- **Example:** file body `<?php system($_GET['cmd']); ?>` ko `shell.php` ke taur par save kariye, aur fir `/hackable/uploads/shell.php?cmd=id` request kariye.
- **Success kaisa dikhta hai:** "⚠ Server executed shell.php as PHP". Medium par tamper panel mein Content-Type ko change karke `image/png` kar dein; High par GIF89a magic bytes add kariye aur File Inclusion ka use kariye.
- **Impossible kaise bachata hai:** extension, type aur real image content ko check karke, fir file ko re-encode aur rename karne ke zariye protection deta hai.


### Insecure CAPTCHA
- **Kya try karein:** tamper panel mein hidden fields ko edit karke CAPTCHA step ko skip karein.
- **Example:** Low level par `step` ko `2` set karein; Medium par `passed_captcha` ko bhi `true` set karein; High par User-Agent `reCAPTCHA` aur response `hidd3n_valu3` use karein.
- **Success kaisa dikhta hai:** Bina CAPTCHA solve kiye "Password Changed." dikhega.
- **Impossible kaise bachata hai:** Ek hi request mein CAPTCHA, ek token, aur current password ko check karke.


### SQL Injection
- **Kya try karein:** SQL query ko break karke doosri rows aur tables padhne ki koshish karein.
- **Examples:** `1' OR '1'='1` aur `1' UNION SELECT user, password FROM users#` (Low); tamper override mein `1 UNION SELECT user, password FROM users` (Medium).
- **Success kaisa dikhta hai:** saare users aur unke password hashes list ho jaate hain.
- **Impossible kaise bachata hai:** prepared statements (parameterised queries) ka use karke.


### SQL Injection (Blind)
- **Kya try karein:** true/false questions poochhiye, kyunki page sirf "exists" ya "MISSING" batata hai.
- **Examples:** `1' AND 1=1#` (exists) vs `1' AND 1=2#` (missing); time-based `1' AND sleep(3)#`.
- **Success kaisa dikhta hai:** aap message ya dikhaye gaye response time se true aur false mein farq pata laga sakte hain.
- **Impossible kaise bachata hai:** prepared statements aur numeric check ke sath.


### Weak Session IDs
- **Kya try karein:** kai baar "Generate" press kariye aur `dvwaSession` values ko dekhiye.
- **Example:** Low mein 1, 2, 3… count hota hai; Medium current time hota hai; High ek counter ka md5 hash hota hai.
- **Success kaisa dikhta hai:** aap next session ID ka andaza laga sakte hain.
- **Impossible kaise bachata hai:** ek random, hashed value aur Secure/HttpOnly cookie flags ke saath.


### XSS (DOM)
- **Kya try karein:** address bar URL me `default=` ke baad edit karein.
- **Examples:** `?default=<script>alert(1)</script>` (Low); `?default=</option></select><img src=x onerror=alert(1)>` (Medium); `?default=English#<script>alert(1)</script>` (High).
- **Success kaisa dikhta hai:** "⚠ XSS fired" aur ek simulated alert dialog dikhega.
- **Impossible kaise bachata hai:** input ko decode nahi karta, isliye yeh kabhi bhi HTML ki tarah parse nahi hota.


### XSS (Reflected)
- **Kya try karein:** name field ke andar HTML/JavaScript daaliye.
- **Examples:** `<script>alert(document.cookie)</script>` (Low); `<SCRIPT>alert(1)</SCRIPT>` (Medium); `<img src=x onerror=alert(1)>` (High).
- **Success kaisa dikhta hai:** Aapke alert text ke sath "⚠ XSS fired" dikhega.
- **Impossible kaise bachata hai:** htmlspecialchars() output encoding aur ek token ke sath karta hai.


### XSS (Stored)
- **Kya try karein:** guestbook mein ek payload ke saath sign karein taaki har visitor use run kare.
- **Examples:** message `<script>alert(1)</script>` (Low); "Remove client-side maxlength" tick karne ke baad name `<svg onload=alert(1)>` (Medium/High).
- **Success kaisa dikhta hai:** guestbook verdict mein "⚠ XSS fired" dikhega. Clean up karne ke liye Clear Guestbook ya Reset DB ka use karein.
- **Impossible kaise bachata hai:** dono fields ko encode karke aur prepared statement use karke defend karta hai.


### CSP Bypass
- **Kya try karein:** ek aise source se script load karein jise Content Security Policy galti se allow kar rahi ho.
- **Examples:** Low: `https://pastebin.com/raw/…` ko simulate kiye gaye content `alert(1)` ke sath include karein; Medium: `<script nonce="TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=">alert(1)</script>`; High: JSONP callback ko change karein, jaise `source/jsonp.php?callback=alert(document.cookie)//`.
- **Success kaisa dikhta hai:** "⚠ CSP allowed the script — it executes (simulated)". Kuch bhi download nahi hota.
- **Impossible kaise bachata hai:** ek hard-coded callback ke sath.


### JavaScript Attacks
- **Kya try karein:** `success` word submit karein ek valid token ke sath.
- **Example:** `success` type karein, tamper panel open karein aur console helper dabayein (jaise `generate_token()`) taaki hidden token match ho jaye, phir Submit karein.
- **Success kaisa dikhta hai:** "Well done!" (Shabaash!) message aata hai.
- **Impossible:** yahan koi asli defence nahi hai – client side par kuch bhi change kiya ja sakta hai. Yeh hi sikhna hai.


### Authorisation Bypass
- **Kya try karein:** `gordonb` / `abc123` se log in karke bhi admin-only user manager use karein.
- **Example:** Low: menu se page open karein ya Go to URL `/vulnerabilities/authbypass/` par jayein; Medium/High: API console use karke POST `{"id":2,"first_name":"Hacked","surname":"ByGordon"}` bhejein.
- **Success kaisa dikhta hai:** "User updated" message dikhega chahe aap admin na ho.
- **Impossible kaise bachata hai:** har API call par user ka role check karke.


### Open HTTP Redirect
- **Kya try karein:** `redirect=` value ko change karein taaki ek trusted link victim ko kisi aur jagah bhej de.
- **Examples:** `?redirect=https://example.com` (Low); `?redirect=//example.com` (Medium); `?redirect=https://example.com/?a=info.php` (High).
- **Success kaisa dikhta hai:** "⚠ Open redirect…" – target dikhaya jaata hai, kabhi open nahi hota.
- **Impossible kaise bachata hai:** numeric IDs ko fixed pages ke saath map karke.


### Cryptography Problems
- **Low:** "secret" message XOR + Base64 encoded hai. Intercept kiye gaye message ko decode karo aur uske andar wale password ke sath login karo.
- **Medium:** session token AES-ECB use karta hai. Sweep ke liye ek valid admin token banane ke liye tokens ke beech mein 16-byte (32 hex) blocks ko swap karo.
- **High:** AES-CBC par ek padding-oracle attack: token/IV mein tamper karo aur error messages ko dekho.
- **Impossible kaise bachata hai:** AES-GCM (authenticated encryption) ke sath, isliye koi bhi change reject kar diya jata hai.


## 7. Troubleshooting (dikkat aaye to)

- **Cannot log in after a CSRF/CAPTCHA test:** password change ho gaya hai. Naya password use karein, ya phir reinstall karein – ya kisi aur user se log in karke Setup / Reset DB run karein.
- **Strange data or errors in a module:** ☰ → Setup / Reset DB run karein.
- **Nothing happens on an XSS payload:** level check karein (higher levels mein zyada filtering hoti hai) aur View Help padhein. Yaad rakhein ki effect simulated hota hai.
- **Wrong language:** ise 🌐 Language option se change karein. Android 13+ par aap Settings → Apps → DVWA Offline → Language ka bhi use kar sakte hain.
- **App still broken:** APK ko uninstall karke dubara install karein – sara data sirf app ke andar hi stored hota hai.
- **Tutorial dobara dekhna hai:** ☰ → Tutorial (first-run slides).
