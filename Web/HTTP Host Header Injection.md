# HOST HEADER INJECTION

It is a type of web security vulnerability that occurs when a web application improperly handles the "Host" header in HTTP requests. The "Host" header specifies the domain name of the server that the client is trying to reach. If an application does not validate or sanitize this header correctly, an attacker can manipulate it to perform malicious actions.

## `Method to perform Host Header Injection`

### 1. Malformed Host Header Value

Attackers can inject a malformed Host header value in the HTTP request. For instance, including a newline character can create a new header field, which may confuse the server.
```text
GET /index.html HTTP/1.1  
Host: www.example.com%0d%0aX-Forwarded-For: attacker.com  
```
### 2. Multiple Host Header Values
By injecting multiple Host header values, attackers can exploit servers that read more than one Host header. This can lead to unexpected behavior.
```text
GET /example HTTP/1.1  
Host: malicioussite  
Host: vulnerable-website.com  
```
### 3.Spoofed Host Header
Attackers can spoof the Host header to make it appear as if the request is coming from a trusted domain. This can trick the server into processing the request as legitimate.
```text
GET /index.html HTTP/1.1  
Host: www.example.com.attacker.com  
```
### 4. Using X-Forwarded-Host Header
The X-Forwarded-Host header can be manipulated to inject malicious input while bypassing validation on the Host header.
```text
GET / HTTP/1.1  
Host: vulnerable-website.com  
X-Forwarded-Host: attacker.com  
```
### 5. Open Redirects
By injecting a malicious Host header, attackers can exploit open redirect vulnerabilities to redirect users to phishing sites.

`Request:`
```text
GET /redirect?url=http://malicious.com HTTP/1.1  
Host: vulnerable-website.com
``` 
`Response:`

The server may redirect the user to the attacker-controlled site, leading to potential credential theft.

### 6. Cross-Site Scripting (XSS)
By injecting a crafted Host header, attackers can exploit XSS vulnerabilities in applications that reflect the Host header in their responses.

`Request:`
```text
GET /search?q=<script>alert('XSS')</script> HTTP/1.1  
Host: vulnerable-website.com  
```
`Response:`

If the application reflects the input without sanitization, it may execute the injected script in the user's browser.

### 7. Account takeover via reset password

A user requests a password reset link via email:
```text
POST /reset-password HTTP/1.1
Host: *exploit-server-ip*
Content-Type: application/json

{"email": "victim@example.com"}
```
The application generates a password reset link like this:
```text
https://example.com/reset?token=ABC123
```

## `Mitigation of Host header injection:`

### 1️. Enforce a Strict Allowlist of Trusted Hostnames

Only allow approved domain names in the Host header.
Block requests with unexpected or empty Host headers.
🔹 Example (Enforcing Allowed Hostnames in Python/Django)
```text
ALLOWED_HOSTS = ["example.com", "www.example.com"]
```
🔹 Example (Enforcing Allowed Hosts in Apache .htaccess)
```text
RewriteEngine On
RewriteCond %{HTTP_HOST} !^(www\.)?example\.com$ [NC]
RewriteRule ^ - [F]
```
🔹 Example (Enforcing Allowed Hosts in Nginx)
```text
server {
    listen 80;
    server_name example.com www.example.com;
    if ($host !~* ^(example\.com|www\.example\.com)$) {
        return 403;
    }
}
```
### 2️. Do Not Trust User-Supplied "Host" Headers in Application Logic

Avoid using $_SERVER['HTTP_HOST'] (PHP) or request.get_host() (Django) directly.
Use hardcoded values for password reset links instead of relying on the Host header.

🔹 Example (Secure Password Reset Link in PHP)

```text
$reset_link = "https://example.com/reset-password?token=$token";
```
### 3️. Configure Web Server to Reject Invalid Host Headers

Set strict Host header validation in your server configuration.
Reject requests that contain multiple Host headers.
🔹 Example (Blocking Host Header Attacks in Apache)
```text
<If "%{HTTP_HOST} !~ /^example\.com$/">
    Require all denied
</If>
```
🔹 Example (Blocking Host Header Attacks in Nginx)
```text
if ($http_host !~* ^(example\.com|www\.example\.com)$) {
    return 403;
}
```
## 4️. Prevent Web Cache Poisoning
If a web application uses a cache system (CDN, Varnish, etc.), attackers can exploit it by injecting Host headers to store malicious responses.

Ensure cache keys include only trusted Host values.
Set a strict Cache-Control policy.
🔹 Example (Prevent Cache Poisoning in Apache)
```text
Header set Cache-Control "no-cache, no-store, must-revalidate"
```
🔹 Example (Prevent Cache Poisoning in Nginx)
```text
proxy_cache_key "$scheme$request_method$host$request_uri";
```
## 5️. Implement a Web Application Firewall (WAF)

Deploy a WAF to detect and block Host Header Injection attempts.
Filter requests that contain multiple Host headers or malformed inputs.
🔹 Example (ModSecurity Rule to Block Host Header Injection)

```text
SecRule REQUEST_HEADERS:Host "!^example\.com$" "deny,status:403"
```
## 6️. Use Strict Transport Security (HSTS)


Enforce HTTPS and prevent HTTP downgrade attacks.
Block browsers from accepting modified Host headers.
🔹 Example (Enable HSTS in Apache/Nginx)
```text
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

