# SQL Injection - Attack Scenarios & Mitigation

## Overview
SQL Injection is a code injection attack where malicious SQL code is inserted into user input fields to manipulate database queries.

---

## Attack Scenarios

### Scenario 1: Classic SQLi - Union Based

**Target:** User ID input field  
**Goal:** Extract all user credentials

```sql
-- Payload
1' UNION SELECT user, password FROM users --

-- Resulting Query
SELECT first_name, surname FROM users WHERE user_id = '1' UNION SELECT user, password FROM users --'

-- Output
admin | admin
```

### Scenario 2: Blind SQLi - Time Based

**Target:** Login form  
**Goal:** Determine database structure

```sql
-- Payload
admin' AND SLEEP(5) --

-- Result: 5 second delay = TRUE condition
-- Database responds with timing information
```

### Scenario 3: Error-Based SQLi

**Target:** Search parameter  
**Goal:** Extract table names

```sql
-- Payload
' AND extractvalue(1, concat(0x7e, (SELECT table_name FROM information_schema.tables LIMIT 1))) --

-- Output: Error message reveals table name
```

---

## Mitigation Strategies

### Strategy 1: Prepared Statements (BEST)

**Vulnerable Code:**
```php
<?php
$user_id = $_GET['id'];
$query = "SELECT first_name, surname FROM users WHERE user_id = '" . $user_id . "'";
$result = mysqli_query($conn, $query);
?>
```

**Secure Code:**
```php
<?php
$user_id = $_GET['id'];
$query = "SELECT first_name, surname FROM users WHERE user_id = ?";
$stmt = mysqli_prepare($conn, $query);
mysqli_stmt_bind_param($stmt, "i", $user_id); // "i" = integer
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
?>
```

### Strategy 2: Input Validation

```php
<?php
// Whitelist Approach
$user_id = filter_var($_GET['id'], FILTER_VALIDATE_INT);

if ($user_id === false) {
    http_response_code(400);
    die("Invalid user ID");
}

// Now safe to use
$query = "SELECT * FROM users WHERE user_id = " . $user_id;
$result = mysqli_query($conn, $query);
?>
```

### Strategy 3: Parameterized Queries (PDO)

```php
<?php
try {
    $pdo = new PDO('mysql:host=localhost;dbname=dvwa', 'root', 'password');
    $stmt = $pdo->prepare("SELECT first_name, surname FROM users WHERE user_id = :id");
    $stmt->execute(['id' => $_GET['id']]);
    $result = $stmt->fetchAll();
} catch (PDOException $e) {
    error_log($e->getMessage());
    die("Database error occurred");
}
?>
```

### Strategy 4: ORM Framework

```php
<?php
// Using Eloquent ORM
$user = User::where('id', $_GET['id'])->first();
// Automatically uses prepared statements
?>
```

---

## Testing Payloads

| Payload | Purpose | Expected Result |
|---------|---------|-----------------|
| `1' OR '1'='1` | Boolean logic | All records |
| `1'; DROP TABLE users; --` | Destructive | Table deleted |
| `1' UNION SELECT NULL, NULL --` | Determine columns | Column count |
| `admin' --` | Comment injection | Bypass password |
| `1' AND SLEEP(10) --` | Time-based blind | Delay response |

---

## Prevention Checklist

- [ ] Use prepared statements for ALL database queries
- [ ] Implement input validation (type, length, format)
- [ ] Apply principle of least privilege to database users
- [ ] Use security headers (Content-Security-Policy)
- [ ] Enable SQL error suppression in production
- [ ] Log and monitor suspicious queries
- [ ] Conduct regular security audits
- [ ] Keep database software updated

---

## Real-World Impact

**From DVWA Exploitation:**
- Extracted admin credentials
- Accessed all user information
- Potential for data exfiltration
- Privilege escalation possible

**Mitigation Result:**
All payloads blocked with prepared statements ✅
