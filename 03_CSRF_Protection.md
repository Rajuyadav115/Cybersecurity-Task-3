# Cross-Site Request Forgery (CSRF) - Attack Scenarios & Mitigation

---

## Vulnerability Overview
- **Type:** Cross-Site Request Forgery
- **Severity:** HIGH (6.5/10)
- **Target:** Password change functionality
- **Method:** POST request without token validation

---

## Attack Scenarios

### Scenario 1: Hidden Form Attack

**Attacker's Malicious Website:**
```html
<!DOCTYPE html>
<html>
<head>
    <title>Watch Cat Videos!</title>
</head>
<body onload="document.csrf.submit()">

<!-- Hidden form -->
<form name="csrf" method="POST" action="http://dvwa/change_password.php" style="display:none;">
    <input type="hidden" name="password_new" value="attacker123">
    <input type="hidden" name="password_conf" value="attacker123">
    <input type="submit" value="Submit">
</form>

<h1>Loading amazing cat videos...</h1>

</body>
</html>
```

**Attack Flow:**
1. Victim logged into DVWA
2. Victim visits attacker's site in another tab
3. Form auto-submits using victim's authenticated session
4. Admin password changed without consent
5. Attacker logs in with new password

### Scenario 2: Image Tag Vector

```html
<img src="http://dvwa/change_password.php?password_new=hacked&password_conf=hacked" 
     style="display:none;">

<!-- GET request sent automatically -->
```

### Scenario 3: AJAX Exploit

```html
<script>
fetch('http://dvwa/change_password.php', {
    method: 'POST',
    credentials: 'include', // Send cookies
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: 'password_new=hacked&password_conf=hacked'
});
</script>
```

### Scenario 4: Session Hijacking via CSRF

```html
<!-- Change email to attacker's email -->
<form method="POST" action="http://dvwa/profile.php">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="action" value="update">
</form>
<!-- Attacker gains account access via password reset -->
```

---

## Mitigation Strategy 1: CSRF Tokens

### Implementation

**Step 1: Generate Token**
```php
<?php
session_start();

// Generate token if not exists
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>
```

**Step 2: Include in Form**
```html
<form method="POST" action="change_password.php">
    <!-- CSRF Token -->
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
    
    <!-- Actual form fields -->
    <label>New Password:</label>
    <input type="password" name="password_new" required>
    
    <label>Confirm Password:</label>
    <input type="password" name="password_conf" required>
    
    <button type="submit">Change Password</button>
</form>
```

**Step 3: Validate Token on Submit**
```php
<?php
session_start();

// Only process POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // Token validation
    if (empty($_POST['csrf_token']) || 
        $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        
        http_response_code(403);
        die('CSRF token validation failed. Request rejected.');
    }
    
    // Token is valid, proceed with password change
    $password_new = $_POST['password_new'];
    $password_conf = $_POST['password_conf'];
    
    if ($password_new === $password_conf) {
        // Update password in database
        // ... your code here ...
        echo "Password Changed!";
    }
}
?>
```

---

## Mitigation Strategy 2: SameSite Cookie

### How It Works
Restricts cookie transmission to same-site requests only.

### Implementation

**PHP Configuration:**
```php
<?php
session_set_cookie_params([
    'samesite' => 'Strict',  // Most restrictive
    'secure' => true,         // HTTPS only
    'httponly' => true        // JavaScript can't access
]);

session_start();
?>
```

### SameSite Options

| Option | Behavior | Security |
|--------|----------|----------|
| `Strict` | Cookie sent ONLY to same site | Highest |
| `Lax` | Cookie sent for top-level navigation | Medium |
| `None` | Cookie sent to all sites (requires Secure) | Lowest |

**Complete Cookie Config:**
```php
<?php
session_set_cookie_params([
    'lifetime' => 3600,
    'path' => '/',
    'domain' => '.example.com',
    'samesite' => 'Strict',
    'secure' => true,
    'httponly' => true
]);

session_start();
?>
```

---

## Mitigation Strategy 3: Double Submit Cookie

```php
<?php
// Generate token and set both in session and cookie
$token = bin2hex(random_bytes(32));
$_SESSION['csrf_token'] = $token;
setcookie('csrf_token', $token, 0, '/', '', true, true);
?>

<!-- In Form -->
<input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

<!-- Validate -->
<?php
if ($_POST['csrf_token'] !== $_COOKIE['csrf_token']) {
    die('CSRF attack detected!');
}
?>
```

---

## Mitigation Strategy 4: Referer Header Validation

```php
<?php
// Validate request origin
$allowed_origins = [
    'http://dvwa.local',
    'https://dvwa.local'
];

$referer = parse_url($_SERVER['HTTP_REFERER'] ?? '', PHP_URL_HOST);

if (!in_array($referer, $allowed_origins)) {
    http_response_code(403);
    die('Invalid request origin');
}
?>
```

---

## Complete Secure Implementation

```php
<?php
session_start();

// CSRF token generation (on page load)
function generateCSRFToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

// CSRF token validation (on form submit)
function validateCSRFToken($token) {
    return !empty($_SESSION['csrf_token']) && 
           hash_equals($_SESSION['csrf_token'], $token);
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // Validate CSRF token
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        http_response_code(403);
        die('CSRF token validation failed');
    }
    
    // Validate referrer
    $referer = parse_url($_SERVER['HTTP_REFERER'] ?? '', PHP_URL_HOST);
    if ($referer !== $_SERVER['HTTP_HOST']) {
        http_response_code(403);
        die('Invalid request origin');
    }
    
    // Token is valid, process request
    echo "Password Changed Successfully!";
}

// Get token for form
$token = generateCSRFToken();
?>

<!DOCTYPE html>
<html>
<body>
<form method="POST">
    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($token); ?>">
    
    <label>New Password:</label>
    <input type="password" name="password_new" required>
    
    <label>Confirm:</label>
    <input type="password" name="password_conf" required>
    
    <button type="submit">Change Password</button>
</form>
</body>
</html>
```

---

## Prevention Checklist

### Code Level
- [ ] Generate unique CSRF token per session
- [ ] Include token in all state-changing forms
- [ ] Validate token on every POST/PUT/DELETE
- [ ] Use SameSite cookies
- [ ] Validate referrer headers
- [ ] Regenerate token after authentication

### Server Level
- [ ] Use HTTPS (for Secure cookie flag)
- [ ] Set appropriate cookie flags (Secure, HttpOnly, SameSite)
- [ ] Implement Content-Security-Policy
- [ ] Monitor for CSRF attempts
- [ ] Log all state-changing operations

### Operational
- [ ] Regular security audits
- [ ] Penetration testing
- [ ] Security training for developers
- [ ] Code review process
- [ ] Update frameworks regularly

---

## Testing CSRF Protection

**Test Case 1: Valid Token**
```
Expected: Password changed ✓
Result: SUCCESS
```

**Test Case 2: Missing Token**
```
Expected: Rejection
Result: 403 Forbidden ✓
```

**Test Case 3: Invalid Token**
```
Expected: Rejection
Result: 403 Forbidden ✓
```

**Test Case 4: Cross-site Form**
```
Expected: SameSite blocking request
Result: Cookie not sent ✓
```

---

## Real-World Impact

### Before Mitigation:
- ✗ Admin password changeable from external site
- ✗ No token validation
- ✗ CSRF attacks possible
- ✗ Session hijacking risk

### After Mitigation:
- ✓ CSRF token required
- ✓ Token validation enforced
- ✓ SameSite cookies active
- ✓ Referer validation implemented
- ✓ All CSRF vectors blocked

---

## Additional Resources

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Mozilla: SameSite Cookie Explained](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)
