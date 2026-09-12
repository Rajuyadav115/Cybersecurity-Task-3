# Quick Reference Guide - DVWA Security Testing

## 🚀 One-Page Summary

### SQL Injection
```
ATTACK:    1' OR '1'='1
FIX:       $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
RESULT:    All user data exposed → Protected with prepared statements
```

### Stored XSS
```
ATTACK:    <script>alert('XSS')</script>
FIX:       $safe = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
RESULT:    Script executes on page load → Safely encoded output
```

### Reflected XSS
```
ATTACK:    ?name=<img src=x onerror="alert('XSS')">
FIX:       htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
RESULT:    Script in URL executes → Prevented via output encoding
```

### CSRF
```
ATTACK:    Form on attacker site changes victim's password
FIX:       $token = bin2hex(random_bytes(32)); // Validate on submit
RESULT:    Password changed without consent → Protected with tokens
```

---

## 🛡️ Mitigation Matrix

| Vulnerability | Attack | Quick Fix | Full Implementation |
|---|---|---|---|
| **SQLi** | `1' OR '1'='1` | Prepared statements | Input validation + parameterized queries |
| **Stored XSS** | `<script>alert('X')</script>` | `htmlspecialchars()` | Input sanitize + output encode + CSP |
| **Reflected XSS** | `?name=<img onerror=alert()>` | Output encoding | Input validation + encoding + security headers |
| **CSRF** | Auto-submit form | CSRF token | Token + SameSite cookie + referer check |

---

## 💻 Code Snippets

### Prepared Statement (SQL Injection Fix)
```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);
```

### Output Encoding (XSS Fix)
```php
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
```

### CSRF Token (CSRF Fix)
```php
// Generate
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));

// Validate
if ($_POST['token'] !== $_SESSION['csrf_token']) {
    die('CSRF Attack!');
}
```

### Security Headers
```php
header("Content-Security-Policy: script-src 'self'");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
```

---

## ✅ Testing Checklist

- [ ] **SQLi Test:** Enter `1' OR '1'='1` in numeric field
- [ ] **XSS Test:** Enter `<script>alert('XSS')</script>` in text field
- [ ] **CSRF Test:** Create external form that auto-submits
- [ ] **All Mitigations:** Verify attacks are blocked
- [ ] **Security Headers:** Check with `curl -i http://localhost`

---

## 📊 Risk Assessment

| Vulnerability | CVSS | CVSS Score | Status |
|---|---|---|---|
| SQL Injection | Critical | 9.8 | ✅ FIXED |
| Stored XSS | High | 7.5 | ✅ FIXED |
| Reflected XSS | High | 7.5 | ✅ FIXED |
| CSRF | High | 6.5 | ✅ FIXED |

---

## 🔗 Key Resources

- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **SQL Injection Prevention:** https://owasp.org/www-community/attacks/SQL_Injection
- **XSS Prevention:** https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- **CSRF Prevention:** https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

---

## 📝 Apache Security Headers Configuration

```apache
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Strict-Transport-Security "max-age=31536000"
    Header always set Content-Security-Policy "default-src 'self'"
</IfModule>
```

**Enable & Apply:**
```bash
sudo a2enmod headers
sudo a2enconf security-headers
sudo systemctl restart apache2
```

---

## 🎯 Attack Payloads Cheat Sheet

### SQL Injection
```sql
1' OR '1'='1
1' UNION SELECT NULL, NULL --
1'; DROP TABLE users; --
1' AND SLEEP(5) --
```

### XSS
```html
<script>alert('XSS')</script>
<img src=x onerror="alert('XSS')">
<svg onload="alert('XSS')">
javascript:alert('XSS')
```

### CSRF
```html
<form method="POST" action="http://target/change.php">
    <input type="hidden" name="new_password" value="hacked">
</form>
<script>document.forms[0].submit();</script>
```

---

## 📈 Proof of Exploitation

**From DVWA Testing:**
- ✅ SQL Injection: Extracted all users (admin, user)
- ✅ Stored XSS: Executed JavaScript on page load
- ✅ Reflected XSS: Payload in URL executed script
- ✅ CSRF: Changed password from external form

**After Mitigation:**
- ✅ All queries use prepared statements
- ✅ All output HTML encoded
- ✅ All forms include CSRF tokens
- ✅ Security headers configured

---

## 🔐 Security Best Practices Summary

1. **Never trust user input** - Always validate and sanitize
2. **Use prepared statements** - For ALL database queries
3. **Encode output** - Use `htmlspecialchars()` for HTML context
4. **Implement CSRF tokens** - For all state-changing requests
5. **Add security headers** - CSP, X-Frame-Options, etc.
6. **Use HTTPS** - For secure cookie transmission
7. **Keep software updated** - Regular patches and updates
8. **Log security events** - Monitor for attacks
9. **Security training** - For all developers
10. **Regular audits** - Penetration testing and code review

---

## 🚨 Common Mistakes to Avoid

❌ **DON'T:** Use string concatenation in SQL queries  
✅ **DO:** Use prepared statements with parameterized queries

❌ **DON'T:** Output user input directly to HTML  
✅ **DO:** Always use `htmlspecialchars()` or similar

❌ **DON'T:** Skip CSRF protection on POST forms  
✅ **DO:** Always validate CSRF tokens

❌ **DON'T:** Disable security warnings/errors  
✅ **DO:** Enable error logging (not displaying)

❌ **DON'T:** Hardcode security credentials  
✅ **DO:** Use environment variables or secure vaults

---

## 📞 Testing Tools

- **Burp Suite:** Intercept and modify requests
- **OWASP ZAP:** Automated security scanning
- **Wireshark:** Network traffic analysis
- **sqlmap:** SQL injection testing
- **Browser DevTools:** XSS payload testing

---

**Last Updated:** September 12, 2026  
**Status:** All vulnerabilities documented and mitigated ✅
