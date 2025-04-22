# browsPEAS
### 🔍 Browser History & Bookmarks Analysis Script

During my CPTS preparation, I came across a CyberLabs exercise where the goal was to gain initial access through an RCE vulnerability in a web application input field. To escalate privileges, I had to explore the browser bookmarks in the lab environment and locate a specific endpoint that leaked credentials (username and password) through GET parameters.

After completing the lab, I searched for an existing script that could automate this process—but didn’t find anything. So I decided to build my own tool, and here's the result.

### 📜 What It Does

The script automates the following steps:

- Dumps **browser history** and **bookmarks**
    
- Analyzes them to extract all **URLs with parameters**
    
- Saves all discovered endpoints in `parameters.txt`
    
- Hunts for **sensitive keywords** (e.g., credentials, tokens, secrets) and stores matches in `sensetive_params.txt`
    

It’s designed for **labs, CTFs**, and **real-world pentests** where lateral movement or privilege escalation may rely on client-side artifacts.

You can integrate it into tools like **LinPEAS**, or just use the commands standalone. It works with `sqlite3` if available, but includes fallback using native shell tools (`strings`, `grep`, etc.).

---

### ⚙️ Quick Commands

#### 🦊 Firefox

**Extract all URLs:**

```bash
find ~/.mozilla/firefox -name "places.sqlite" -exec strings {} \; | grep -Eo 'https?://[^ ]+'
```

**Extract URLs with juicy/sensitive parameters:**

```bash
find ~/.mozilla/firefox -name "places.sqlite" -exec strings {} \; | grep -Eo 'https?://[^ ]+' \
| grep -E "username|user|user_id|userid|password|pass|pwd|passwd|email|mail|token|access_token|refresh_token|jwt|api_key|session_id|sessionid|sessid|PHPSESSID|JSESSIONID|auth|auth_token|auth_key|authcode|otp|mfa_token|verification_code|remember_me|stay_logged_in|name|first_name|last_name|full_name|address|street|city|zip|postal_code|phone|mobile|telephone|ssn|social_security|national_id|dob|birth_date|age|credit_card|cc_number|cvv|expiry_date|bank_account|iban|swift_code|admin|is_admin|role|privilege|superuser|debug|test_mode|env|environment|secret|secret_key|private_key|encryption_key|config|settings|db_config|csrf_token|csrf|xsrf_token|redirect|return_url|next|callback|query|search|q=|filter|id=|uid|record_id|document_id|table|db|database|collection|limit|offset|page|count|api|endpoint|method|action|sql|query_string|command|file|filename|file_path|upload|dir|directory|path|location|download|export|import|attachment|document|image|invoice|order_id|transaction_id|amount|price|total|quantity|discount|coupon|promo_code|account_id|customer_id|client_id|url|uri|link|src|dest|referer|referrer|origin|user_agent|ua|device_id|ip|client_ip|remote_addr|PHP_SESSION|REQUEST_METHOD|VIEWSTATE|EVENTVALIDATION|ASP\.NET_SessionId|_method|authenticity_token|csrftoken|_token|XSRF-TOKEN|debug|test|dev|stage|show_errors|display_errors|error_reporting|dump|var_dump|console\.log|verbose|trace|stack_trace|hash|md5|sha1|hmac|license|serial|activation_key|captcha|recaptcha_token|timezone|locale|lang"
```

---

#### 🌐 Google Chrome / Chromium

**Extract all URLs:**

```bash
find ~/.config/google-chrome -name "History" -exec strings {} \; | grep -Eo 'https?://[^ ]+'
```

**Extract juicy/sensitive URLs:**

```bash
find ~/.config/google-chrome -name "History" -exec strings {} \; | grep -Eo 'https?://[^ ]+' \
| grep -E "username|user|user_id|userid|password|pass|pwd|passwd|email|mail|token|access_token|refresh_token|jwt|api_key|session_id|sessionid|sessid|PHPSESSID|JSESSIONID|auth|auth_token|auth_key|authcode|otp|mfa_token|verification_code|remember_me|stay_logged_in|name|first_name|last_name|full_name|address|street|city|zip|postal_code|phone|mobile|telephone|ssn|social_security|national_id|dob|birth_date|age|credit_card|cc_number|cvv|expiry_date|bank_account|iban|swift_code|admin|is_admin|role|privilege|superuser|debug|test_mode|env|environment|secret|secret_key|private_key|encryption_key|config|settings|db_config|csrf_token|csrf|xsrf_token|redirect|return_url|next|callback|query|search|q=|filter|id=|uid|record_id|document_id|table|db|database|collection|limit|offset|page|count|api|endpoint|method|action|sql|query_string|command|file|filename|file_path|upload|dir|directory|path|location|download|export|import|attachment|document|image|invoice|order_id|transaction_id|amount|price|total|quantity|discount|coupon|promo_code|account_id|customer_id|client_id|url|uri|link|src|dest|referer|referrer|origin|user_agent|ua|device_id|ip|client_ip|remote_addr|PHP_SESSION|REQUEST_METHOD|VIEWSTATE|EVENTVALIDATION|ASP\.NET_SessionId|_method|authenticity_token|csrftoken|_token|XSRF-TOKEN|debug|test|dev|stage|show_errors|display_errors|error_reporting|dump|var_dump|console\.log|verbose|trace|stack_trace|hash|md5|sha1|hmac|license|serial|activation_key|captcha|recaptcha_token|timezone|locale|lang"
```

---

#### 🧭 Brave Browser

**Extract all URLs:**

```bash
find ~/.config/BraveSoftware/Brave-Browser -name "History" -exec strings {} \; | grep -Eo 'https?://[^ ]+'
```

**Extract juicy/sensitive ones:**

```bash
find ~/.config/BraveSoftware/Brave-Browser -name "History" -exec strings {} \; | grep -Eo 'https?://[^ ]+' | grep -E "username|user|user_id|userid|password|pass|pwd|passwd|email|mail|token|access_token|refresh_token|jwt|api_key|session_id|sessionid|sessid|PHPSESSID|JSESSIONID|auth|auth_token|auth_key|authcode|otp|mfa_token|verification_code|remember_me|stay_logged_in|name|first_name|last_name|full_name|address|street|city|zip|postal_code|phone|mobile|telephone|ssn|social_security|national_id|dob|birth_date|age|credit_card|cc_number|cvv|expiry_date|bank_account|iban|swift_code|admin|is_admin|role|privilege|superuser|debug|test_mode|env|environment|secret|secret_key|private_key|encryption_key|config|settings|db_config|csrf_token|csrf|xsrf_token|redirect|return_url|next|callback|query|search|q=|filter|id=|uid|record_id|document_id|table|db|database|collection|limit|offset|page|count|api|endpoint|method|action|sql|query_string|command|file|filename|file_path|upload|dir|directory|path|location|download|export|import|attachment|document|image|invoice|order_id|transaction_id|amount|price|total|quantity|discount|coupon|promo_code|account_id|customer_id|client_id|url|uri|link|src|dest|referer|referrer|origin|user_agent|ua|device_id|ip|client_ip|remote_addr|PHP_SESSION|REQUEST_METHOD|VIEWSTATE|EVENTVALIDATION|ASP\.NET_SessionId|_method|authenticity_token|csrftoken|_token|XSRF-TOKEN|debug|test|dev|stage|show_errors|display_errors|error_reporting|dump|var_dump|console\.log|verbose|trace|stack_trace|hash|md5|sha1|hmac|license|serial|activation_key|captcha|recaptcha_token|timezone|locale|lang"
```

---

#### 🧪 Microsoft Edge (Linux)

**Extract all URLs:**

```bash
find ~/.config/microsoft-edge -name "History" -exec strings {} \; | grep -Eo 'https?://[^ ]+'
```

**Juicy:**

```bash
find ~/.config/microsoft-edge -name "History" -exec strings {} \; | grep -Eo 'https?://[^ ]+' | grep -E "username|user|user_id|userid|password|pass|pwd|passwd|email|mail|token|access_token|refresh_token|jwt|api_key|session_id|sessionid|sessid|PHPSESSID|JSESSIONID|auth|auth_token|auth_key|authcode|otp|mfa_token|verification_code|remember_me|stay_logged_in|name|first_name|last_name|full_name|address|street|city|zip|postal_code|phone|mobile|telephone|ssn|social_security|national_id|dob|birth_date|age|credit_card|cc_number|cvv|expiry_date|bank_account|iban|swift_code|admin|is_admin|role|privilege|superuser|debug|test_mode|env|environment|secret|secret_key|private_key|encryption_key|config|settings|db_config|csrf_token|csrf|xsrf_token|redirect|return_url|next|callback|query|search|q=|filter|id=|uid|record_id|document_id|table|db|database|collection|limit|offset|page|count|api|endpoint|method|action|sql|query_string|command|file|filename|file_path|upload|dir|directory|path|location|download|export|import|attachment|document|image|invoice|order_id|transaction_id|amount|price|total|quantity|discount|coupon|promo_code|account_id|customer_id|client_id|url|uri|link|src|dest|referer|referrer|origin|user_agent|ua|device_id|ip|client_ip|remote_addr|PHP_SESSION|REQUEST_METHOD|VIEWSTATE|EVENTVALIDATION|ASP\.NET_SessionId|_method|authenticity_token|csrftoken|_token|XSRF-TOKEN|debug|test|dev|stage|show_errors|display_errors|error_reporting|dump|var_dump|console\.log|verbose|trace|stack_trace|hash|md5|sha1|hmac|license|serial|activation_key|captcha|recaptcha_token|timezone|locale|lang"
```

---

### 💬 Final Note

This script is made to help spot **sensitive URLs** that can give you a quick edge in labs, bug bounty, CTFs, and real-life pentests. You’re welcome to improve or expand it—feel free to add it to **your own recon toolset** or fork it into **LinPEAS**.

Hope it helps you someday . 🚀
