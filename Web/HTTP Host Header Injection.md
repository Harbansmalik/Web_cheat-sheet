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


