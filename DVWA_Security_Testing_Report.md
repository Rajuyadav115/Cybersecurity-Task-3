# Security Testing Report - DVWA
## Task 3: Web Application Security

**Date:** September 12, 2026  
**Tester:** Cybersecurity Intern  
**Target:** DVWA (Damn Vulnerable Web Application)  
**Security Level:** Low

---

## Executive Summary

Comprehensive security assessment of DVWA identified critical vulnerabilities in SQL Injection, Cross-Site Scripting (XSS), and Cross-Site Request Forgery (CSRF). All findings are documented below with exploitation proof and mitigation strategies.

---

## 1. SQL Injection Vulnerability

### Risk Level: **CRITICAL**

### Description
DVWA SQL Injection module allows attackers to manipulate database queries through unsanitized user input.

### Vulnerability Details
- **Parameter:** User ID input field
- **Affected Endpoint:** `/vulnerabilities/sqli/`
- **Attack Vector:** Direct input manipulation

### Exploitation Method
```
Input: 1' OR '1'='1
Result: Retrieved all users (admin, user)
```

**Findings:**
- User ID: 1
- First Name: admin
- Surname: admin

### Impact
- Unauthorized database access
- Complete user credential exposure
- Potential data exfiltration

### Mitigation

**Code Fix - Before (Vulnerable):**
```php
$query = "SELECT first_name, surname FROM users WHERE user_id = '" . $_GET['id'] . "'";
$result = mysqli_query($GLOBALS["___mysqli_ston"], $query);
```

**Code Fix - After (Secure):**
```php
$query = "SELECT first_name, surname FROM users WHERE user_id = ?";
$stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], $query);
mysqli_stmt_bind_param($stmt, "i", $_GET['id']);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
```

**Prevention Best Practices:**
1. ✅ Use Prepared Statements
2. ✅ Implement Input Validation
3. ✅ Apply Principle of Least Privilege to DB accounts
4. ✅ Enable SQL error suppression

---

## 2. Stored Cross-Site Scripting (XSS)

### Risk Level: **HIGH**

### Description
Stored XSS allows attackers to inject malicious JavaScript that persists in the application.

### Vulnerability Details
- **Parameter:** Guest Message field
- **Storage:** Database
- **Execution:** On every page load

### Exploitation Method
```javascript
Payload: Hello <script>alert('Stored XSS')</script>
Result: Script executes for all users viewing the page
```

**Findings:**
- Name: Test
- Message: Hello <script>alert('Stored XSS')</script>
- Persistence: Data stored in database
- Scope: All users affected

### Impact
- Session hijacking via cookie theft
- Malware distribution
- Keylogging capabilities
- Account takeover

### Mitigation

**Prevention Code:**
```php
// Input Validation
$message = filter_var($_POST['message'], FILTER_SANITIZE_STRING);

// Output Encoding
$safe_message = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
echo $safe_message;

// Content Security Policy Header
header("Content-Security-Policy: script-src 'self'");
```

**Best Practices:**
1. ✅ HTML encode output
2. ✅ Implement Content Security Policy (CSP)
3. ✅ Use input validation
4. ✅ Sanitize user inputs

---

## 3. Reflected Cross-Site Scripting (XSS)

### Risk Level: **HIGH**

### Description
Reflected XSS executes injected scripts immediately without persistence.

### Vulnerability Details
- **Parameter:** Name query parameter
- **Execution:** Immediate, single request
- **Storage:** None (reflected in response)

### Exploitation Method
```
URL: ?name=Hello <script>alert('Reflected XSS')</script>
Result: Script executes in victim's browser
```

**Output Captured:**
```
Hello <script>alert('Reflected XSS')</script>
```

### Impact
- Phishing attacks
- Credential harvesting
- Malware delivery
- Session hijacking

### Mitigation

**Prevention Code:**
```php
// Secure Implementation
$name = isset($_GET['name']) ? htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') : '';
echo "Hello " . $name;

// Alternative: Output Encoding Library
$name = html_entity_encode($_GET['name']);
```

**Best Practices:**
1. ✅ Never trust user input
2. ✅ Apply output encoding
3. ✅ Use security headers
4. ✅ Implement input validation

---

## 4. Cross-Site Request Forgery (CSRF)

### Risk Level: **HIGH**

### Description
CSRF allows attackers to perform unauthorized actions on behalf of authenticated users.

### Vulnerability Details
- **Target Function:** Password change
- **Method:** POST (no token validation)
- **Affected Parameter:** New password field

### Exploitation Method

**Malicious Page:**
```html
<form action="http://dvwa/change_password.php" method="POST">
    <input type="hidden" name="password_new" value="hacked">
    <input type="hidden" name="password_conf" value="hacked">
    <input type="submit" value="Click Here">
</form>
```

**Result:** Admin password changed without confirmation

### Impact
- Unauthorized password changes
- Account takeover
- Sensitive action execution
- Privilege escalation

### Mitigation

**Prevention Implementation:**

```php
// Generate CSRF Token
session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Validate Token
if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die('CSRF token validation failed');
}
```

**HTML Form (Secure):**
```html
<form method="POST" action="change_password.php">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
    <input type="password" name="password_new" required>
    <input type="password" name="password_conf" required>
    <button type="submit">Change Password</button>
</form>
```

**Best Practices:**
1. ✅ Implement CSRF tokens
2. ✅ Use SameSite cookie attribute
3. ✅ Validate referrer headers
4. ✅ Require re-authentication for sensitive actions

---

## 5. Web Security Headers Analysis

### Current Configuration: **MISSING**

### Server Headers Detected
```
Server: Apache/2.4.68 (Debian)
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin
```

### Recommended Security Headers

```apache
# Add to Apache config: /etc/apache2/conf-available/security-headers.conf

Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "DENY"
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
```

### Enable Modules
```bash
sudo a2enmod headers
sudo a2enmod rewrite
sudo systemctl restart apache2
```

---

## Vulnerability Summary Table

| Vulnerability | Risk Level | CVSS | Status |
|---|---|---|---|
| SQL Injection | CRITICAL | 9.8 | Exploited ✓ |
| Stored XSS | HIGH | 7.5 | Exploited ✓ |
| Reflected XSS | HIGH | 7.5 | Exploited ✓ |
| CSRF | HIGH | 6.5 | Exploited ✓ |
| Missing Security Headers | MEDIUM | 5.3 | Found |

---

## Remediation Timeline

- **Immediate (0-24 hours):** Implement CSRF tokens, output encoding
- **Short-term (1-7 days):** Deploy security headers, prepared statements
- **Long-term (1-4 weeks):** Security training, automated testing

---

## Conclusion

DVWA demonstrates common web vulnerabilities. All identified issues have clear mitigation strategies. Immediate implementation of prepared statements and CSRF tokens is critical.

**Recommendation:** Deploy fixes in priority order and implement security testing in development pipeline.

---

**Report Generated:** September 12, 2026  
**Next Review:** Post-remediation security assessment
