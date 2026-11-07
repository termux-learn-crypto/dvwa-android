# DVWA Offline – उपयोग गाइड (User Guide)

> यह गाइड ऐप के अंदर भी है: मेनू ☰ → **उपयोग गाइड (User Guide)**, या Home पर 📘 बटन। Hinglish संस्करण: [USER_GUIDE.md](USER_GUIDE.md)

## 1. DVWA क्या है?

DVWA (Damn Vulnerable Web Application) एक प्रैक्टिस ऐप है जिसे **जानबूझकर कमज़ोर (vulnerable)** बनाया गया है। आप इसका उपयोग यह सीखने के लिए करते हैं कि आम वेब अटैक (SQL Injection, XSS, CSRF और अन्य) कैसे काम करते हैं और अच्छा कोड उन्हें कैसे रोकता है।

- यह Android संस्करण **पूरी तरह से नेटिव और ऑफलाइन** है: इसमें कोई WebView, कोई इंटरनेट परमिशन और कोई वेब सर्वर नहीं है। हर "अटैक" (attack) केवल ऐप के अपने प्राइवेट डेटा को प्रभावित करता है।
- **केवल कानूनी उपयोग के लिए:** यहाँ प्रैक्टिस करें, या ऐसे सिस्टम पर जो आपके अपने हैं या जिन्हें टेस्ट करने की आपके पास लिखित अनुमति है। इन payloads को कभी भी असली वेबसाइटों पर आज़माकर न देखें।
- XSS, CSP Bypass और JavaScript Attacks को **नेटिव रूप से सिम्युलेट** किया जाता है: इसमें कोई ब्राउज़र इंजन नहीं है, इसलिए ऐप आउटपुट का विश्लेषण करता है और असली JavaScript चलाने के बजाय एक सिम्युलेटेड अलर्ट डायलॉग के साथ "⚠ XSS fired" दिखाता है।


## 2. लॉग इन करना

- डिफ़ॉल्ट लॉगिन: `admin` / `password`
- अन्य खाते: `gordonb` / `abc123`, `1337` / `charley`, `pablo` / `letmein`, `smithy` / `password`
- उपयोगकर्ता बदलने के लिए **Logout** (मेनू ☰ या ⋮ टूलबार मेनू) का उपयोग करें। कुछ मॉड्यूल (उदाहरण के लिए Authorisation Bypass) के लिए एक गैर-एडमिन उपयोगकर्ता की आवश्यकता होती है।
- ऐप की भाषा किसी भी समय बदलें: लॉगिन स्क्रीन पर 🌐 बटन, सेटिंग्स के तहत ड्रॉवर में **Language**, या ⋮ मेनू।


## 3. Setup / Reset DB (डेटाबेस रीसेट)

- मेनू ☰ खोलें → **Setup / Reset DB** → **Create / Reset Database** दबाएँ।
- यह 5 users और उनके passwords को restore करता है, guestbook को खाली करता है, upload की गई files को delete करता है और session data को clear करता है।
- इसका उपयोग तब करें जब आपने कोई password (CSRF, CAPTCHA) बदल दिया है और आप login नहीं कर पा रहे हैं, या जब Stored XSS entries की वजह से guestbook गंदा हो गया है।


## 4. Security levels (सुरक्षा स्तर)

☰ मेनू खोलें → **DVWA Security**, कोई level चुनें और **Submit** दबाएँ। हर module पर दिखने वाला level badge मौजूदा level बताता है।

- **Low** – कोई सुरक्षा नहीं (no protection at all). बुनियादी अटैक (basic attack) सीखने के लिए सबसे अच्छा है।
- **Medium** – डेवलपर ने कोड को सुरक्षित करने की कोशिश की लेकिन गलतियाँ कर दीं (weak filters, blacklists)।
- **High** – अधिक कठिन या असामान्य सुरक्षा, जैसे CTF चैलेंज (CTF challenge)। कुछ हमलों के लिए एक ट्रिक की आवश्यकता होती है।
- **Impossible** – सुरक्षित संस्करण (the secure version)। सही बचाव (right defence) सीखने के लिए इसके सोर्स कोड (source code) की अन्य स्तरों से तुलना करें।

टिप: हर मॉड्यूल को Low से शुरू करें, फिर एक बार में एक स्तर ऊपर जाएँ।


## 5. हर मॉड्यूल स्क्रीन पर मिलने वाले टूल्स

- **View Source** – मौजूदा लेवल के लिए असली DVWA PHP कोड दिखाता है। टैब Low / Medium / High / Impossible के बीच स्विच करते हैं। कोड को कभी अनुवादित नहीं किया जाता है।
- **Compare All** – चारों लेवल एक के बाद एक, ताकि आप यह पहचान सकें कि क्या बदला है।
- **View Help** – आपकी चुनी हुई भाषा में, हर लेवल के लिए कमज़ोरी, लक्ष्य और संकेत (लाल रंग में स्पॉइलर) समझाता है।
- **🛠 Intercept & tamper panel** (नारंगी रंग का, खोलने के लिए टैप करें) – Burp Suite / ब्राउज़र DevTools का नेटिव विकल्प। यहाँ आप छिपे हुए फॉर्म फील्ड, `user_token`, हेडर (Referer, User-Agent), कुकीज़, फ़ाइल नाम, Content-Type और maxlength जैसी क्लाइंट-साइड सीमाओं को एडिट करते हैं।
- **Go to URL… bar** (⋮ टूलबार मेनू) – एक सिम्युलेटेड एड्रेस बार। उस पेज को सीधे खोलने के लिए `/vulnerabilities/authbypass/` या `/vulnerabilities/sqli/` जैसे किसी DVWA पथ को टाइप करें।
- **Brute Force wordlist runner** – Brute Force मॉड्यूल में, "Attack helper" कार्ड Burp Intruder की तरह लॉगिन पर आपकी सूची के हर पासवर्ड (प्रति लाइन एक) को आज़माता है, और पहली सफलता पर रुक जाता है।


## 6. मॉड्यूल वॉकथ्रूज़


### Brute Force
- **क्या आज़माएँ:** username `admin`, फिर एक छोटी wordlist के साथ Attack helper चलाएँ।
- **उदाहरण:** wordlist जिसमें `123456`, `letmein`, `password` शामिल हों।
- **सफलता कैसी दिखती है:** उपयोगकर्ता के अवतार के साथ "Welcome to the password protected area admin"।
- **Impossible कैसे बचाता है:** एक CSRF token, एक यादृच्छिक देरी (random delay) और 3 असफल लॉगिन के बाद एक account lock के साथ बचाव करता है।


### Command Injection
- **क्या आज़माएँ:** IP address के बाद दूसरी कमांड जोड़ें (chain करें)।
- **उदाहरण:** `127.0.0.1; cat /etc/passwd` (Low), `127.0.0.1 | whoami` (Medium/High).
- **सफलता कैसी दिखती है:** आउटपुट में कमांड का परिणाम दिखाई देता है (एक सिम्युलेटेड Debian शेल से; आपके फोन पर कुछ भी रन नहीं होता)।
- **Impossible कैसे बचाता है:** आईपी पते (IP address) के केवल चार संख्यात्मक हिस्सों (numeric parts) को स्वीकार करके बचाव करता है।


### CSRF
- **क्या आज़माएँ:** "Attacker: forged link" कार्ड का उपयोग करें ताकि लॉगिन किया हुआ पीड़ित ऐसा URL खोले जो पासवर्ड बदल दे।
- **उदाहरण:** `http://127.0.0.1/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change`
- **सफलता कैसी दिखती है:** "⚠ CSRF succeeded — the victim's password was changed"। नए पासवर्ड के साथ फिर से लॉगिन करें या DB को रीसेट (Reset DB) करें।
- **Impossible कैसे बचाता है:** एंटी-CSRF टोकन और वर्तमान पासवर्ड के साथ सुरक्षा करता है।


### File Inclusion
- **क्या आज़माएँ:** `?page=` का मान बदलकर अन्य फ़ाइलें पढ़ें।
- **उदाहरण:** `../../../../../etc/passwd` (Low), `....//....//....//etc/passwd` (Medium), `file:///etc/passwd` (High).
- **सफलता कैसी दिखती है:** फ़ाइल की सामग्री दिखाई देती है, जैसे `../../hackable/flags/fi.php` से छिपे हुए कोट्स।
- **Impossible कैसे बचाता है:** फ़ाइल नामों की एक निश्चित allow-list के साथ बचाव करता है।


### File Upload
- **क्या आज़माएँ:** image की जगह एक PHP webshell upload करें, फिर उसे request करें।
- **उदाहरण:** file body `<?php system($_GET['cmd']); ?>` को `shell.php` नाम से upload करें, फिर `/hackable/uploads/shell.php?cmd=id` request करें।
- **सफलता कैसी दिखती है:** "⚠ Server executed shell.php as PHP". Medium level पर tamper panel में Content-Type को बदलकर `image/png` करें; High level पर GIF89a magic bytes जोड़ें और File Inclusion का उपयोग करें।
- **Impossible कैसे बचाता है:** extension, type और असली image content की जाँच करके, फिर file को re-encode और rename करके बचाव करता है।


### Insecure CAPTCHA
- **क्या आज़माएँ:** टैम्पर पैनल (tamper panel) में हिडन फील्ड्स (hidden fields) को एडिट करके CAPTCHA स्टेप को छोड़ दें।
- **उदाहरण:** Low लेवल पर `step` को `2` सेट करें; Medium लेवल पर `passed_captcha` को भी `true` सेट करें; High लेवल पर User-Agent `reCAPTCHA` और रिस्पॉन्स `hidd3n_valu3` का इस्तेमाल करें।
- **सफलता कैसी दिखती है:** CAPTCHA को सॉल्व किए बिना "Password Changed." दिखना।
- **Impossible कैसे बचाता है:** एक ही रिक्वेस्ट में CAPTCHA, एक टोकन और मौजूदा पासवर्ड की जांच (check) करके सुरक्षा करता है।


### SQL Injection
- **क्या आज़माएँ:** SQL क्वेरी से बाहर निकलकर अन्य पंक्तियों (rows) और तालिकाओं (tables) को पढ़ना।
- **उदाहरण:** `1' OR '1'='1` और `1' UNION SELECT user, password FROM users#` (Low); टैम्पर ओवरराइड में `1 UNION SELECT user, password FROM users` (Medium)।
- **सफलता कैसी दिखती है:** सभी यूज़र और उनके पासवर्ड हैश सूचीबद्ध हो जाते हैं।
- **Impossible कैसे बचाता है:** प्रिपेयर्ड स्टेटमेंट (पैरामीट्राइज्ड क्वेरी) का उपयोग करता है।


### SQL Injection (Blind)
- **क्या आज़माएँ:** true/false प्रश्न पूछें, क्योंकि पेज पर केवल "exists" या "MISSING" दिखाई देता है।
- **उदाहरण:** `1' AND 1=1#` (exists) vs `1' AND 1=2#` (missing); time-based `1' AND sleep(3)#`.
- **सफलता कैसी दिखती है:** आप संदेश या दिखाई जाने वाली response time से true और false में अंतर बता सकते हैं।
- **Impossible कैसे बचाता है:** prepared statements और numeric जाँच से बचाव करता है।


### Weak Session IDs
- **क्या आज़माएँ:** 'Generate' बटन को कई बार दबाएँ और `dvwaSession` के मानों को देखें।
- **उदाहरण:** Low में 1, 2, 3… गिनती होती है; Medium वर्तमान समय (current time) होता है; High एक काउंटर का md5 होता है।
- **सफलता कैसी दिखती है:** आप अगले session ID का अनुमान लगा सकते हैं।
- **Impossible कैसे बचाता है:** एक रैंडम, हैशेड मान और Secure/HttpOnly कुकी फ़्लैग्स के साथ बचाव करता है।


### XSS (DOM)
- **क्या आज़माएँ:** एड्रेस बार URL में `default=` के बाद बदलाव करें।
- **उदाहरण:** `?default=<script>alert(1)</script>` (Low); `?default=</option></select><img src=x onerror=alert(1)>` (Medium); `?default=English#<script>alert(1)</script>` (High).
- **सफलता कैसी दिखती है:** "⚠ XSS fired" और एक सिम्युलेटेड अलर्ट डायलॉग।
- **Impossible कैसे बचाता है:** इनपुट को डिकोड न करके, ताकि इसे कभी भी HTML के रूप में पार्स (parse) न किया जाए।


### XSS (Reflected)
- **क्या आज़माएँ:** name field में HTML/JavaScript डालें।
- **उदाहरण:** `<script>alert(document.cookie)</script>` (Low); `<SCRIPT>alert(1)</SCRIPT>` (Medium); `<img src=x onerror=alert(1)>` (High).
- **सफलता कैसी दिखती है:** आपके alert टेक्स्ट के साथ "⚠ XSS fired" दिखाई देगा।
- **Impossible कैसे बचाता है:** htmlspecialchars() आउटपुट एन्कोडिंग और एक token के साथ सुरक्षा करता है।


### XSS (Stored)
- **क्या आज़माएँ:** guestbook में किसी payload के साथ sign करें ताकि हर आने वाला visitor इसे चला सके।
- **उदाहरण:** message `<script>alert(1)</script>` (Low); name `<svg onload=alert(1)>` "Remove client-side maxlength" पर टिक करने के बाद (Medium/High)।
- **सफलता कैसी दिखती है:** guestbook का verdict "⚠ XSS fired" दिखाता है। साफ़ करने के लिए Clear Guestbook या Reset DB का उपयोग करें।
- **Impossible कैसे बचाता है:** दोनों fields को encode करके और prepared statement का उपयोग करके बचाव करता है।


### CSP Bypass
- **क्या आज़माएँ:** Content Security Policy (CSP) द्वारा गलती से अनुमति दिए गए स्रोत से कोई script लोड करें।
- **उदाहरण:** Low: सिम्युलेटेड सामग्री `alert(1)` के साथ `https://pastebin.com/raw/…` शामिल करें; Medium: `<script nonce="TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=">alert(1)</script>`; High: JSONP callback बदलें, उदा. `source/jsonp.php?callback=alert(document.cookie)//`।
- **सफलता कैसी दिखती है:** "⚠ CSP allowed the script — it executes (simulated)"। कुछ भी डाउनलोड नहीं होता है।
- **Impossible कैसे बचाता है:** एक हार्ड-कोडेड callback के साथ सुरक्षा करता है।


### JavaScript Attacks
- **क्या आज़माएँ:** `success` शब्द को एक वैध टोकन (valid token) के साथ सबमिट करें।
- **उदाहरण:** `success` टाइप करें, टैम्पर पैनल खोलें और कंसोल हेल्पर (उदा. `generate_token()`) दबाएं ताकि छिपा हुआ टोकन (hidden token) मेल खा जाए, फिर Submit करें।
- **सफलता कैसी दिखती है:** "Well done!" (शाबाश!) संदेश दिखता है।
- **Impossible:** यहाँ कोई वास्तविक सुरक्षा (defence) नहीं है – क्लाइंट साइड पर मौजूद किसी भी चीज़ को बदला जा सकता है। यही इस पाठ की सीख है।


### Authorisation Bypass
- **क्या आज़माएँ:** `gordonb` / `abc123` के रूप में लॉग इन करें और फिर भी केवल-admin वाले user manager का उपयोग करें।
- **उदाहरण:** Low: मेनू से पेज खोलें या Go to URL `/vulnerabilities/authbypass/` पर जाएं; Medium/High: API console का उपयोग करके POST करें `{"id":2,"first_name":"Hacked","surname":"ByGordon"}`।
- **सफलता कैसी दिखती है:** भले ही आप admin नहीं हैं, फिर भी "User updated" दिखाई देता है।
- **Impossible कैसे बचाता है:** हर API call पर user की role की जाँच करके सुरक्षा करता है।


### Open HTTP Redirect
- **क्या आज़माएँ:** `redirect=` की वैल्यू बदलें ताकि कोई भरोसेमंद लिंक पीड़ित को किसी और जगह भेज दे।
- **उदाहरण:** `?redirect=https://example.com` (Low); `?redirect=//example.com` (Medium); `?redirect=https://example.com/?a=info.php` (High).
- **सफलता कैसी दिखती है:** "⚠ Open redirect…" – टारगेट दिखाया जाता है, कभी खोला नहीं जाता।
- **Impossible कैसे बचाता है:** न्यूमेरिक ID को तय किए गए पेजेस से मैप करके बचाव करता है।


### Cryptography Problems
- **Low:** "secret" असल में सिर्फ़ XOR + Base64 है। पकड़े गए (intercepted) message को decode करें और उसके अंदर मिले password से login करें।
- **Medium:** session token AES-ECB इस्तेमाल करता है। Sweep के लिए valid admin token बनाने के लिए अलग-अलग tokens के 16-byte (32 hex) blocks आपस में बदलें (swap करें)।
- **High:** AES-CBC पर padding-oracle attack: token/IV में tamper करें और error messages पर ध्यान दें।
- **Impossible कैसे बचाता है:** AES-GCM (authenticated encryption) से, इसलिए token में कोई भी बदलाव reject हो जाता है।


## 7. ट्रबलशूटिंग

- **CSRF/CAPTCHA टेस्ट के बाद लॉगिन नहीं हो पा रहा है:** पासवर्ड बदल गया था। नए पासवर्ड का उपयोग करें, या रीइंस्टॉल करें - या किसी अन्य यूजर के रूप में लॉगिन करें और Setup / Reset DB चलाएं।
- **किसी मॉड्यूल में अजीब डेटा या एरर हैं:** ☰ → Setup / Reset DB चलाएं।
- **XSS payload पर कुछ नहीं होता है:** लेवल की जाँच करें (उच्च लेवल अधिक फ़िल्टर करते हैं) और View Help पढ़ें। याद रखें कि प्रभाव सिमुलेटेड है।
- **गलत भाषा:** इसे 🌐 Language विकल्प से बदलें। Android 13+ पर आप Settings → Apps → DVWA Offline → Language का भी उपयोग कर सकते हैं।
- **ऐप अभी भी खराब है:** APK को अनइंस्टॉल और रीइंस्टॉल करें - सारा डेटा केवल ऐप के अंदर ही संग्रहीत होता है।
- **ट्यूटोरियल फिर से:** ☰ → Tutorial (first-run slides)।
