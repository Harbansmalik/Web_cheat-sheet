# HTTP REQUEST SMUGGLING
HTTP request smuggling is a web vulnerability that exploits discrepancies in how different servers interpret HTTP requests, allowing attackers to bypass security controls, manipulate requests, or perform unauthorized actions.

## Types of HTTP Request Smuggling

### 1. CL.TE (Content-Length and Transfer-Encoding) Smuggling
This type occurs when a server accepts both Content-Length and Transfer-Encoding headers, leading to ambiguity in how the request body is interpreted.
Example: An attacker sends a request with both headers, causing the server to misinterpret the length of the request body.
Request Example:
```text
POST / HTTP/1.1
Host: example.com
Transfer-Encoding: chunked
Content-Length: 5

0

GET /malicious HTTP/1.1
Host: example.com
```
### 2. TE.CL (Transfer-Encoding and Content-Length) Smuggling
This variant is similar to CL.TE but involves the server processing the Transfer-Encoding header before the Content-Length header, leading to request smuggling.
Example: The server processes the Transfer-Encoding header first, allowing the attacker to craft a second request.
Request Example:
```text
POST / HTTP/1.1
Host: example.com
Transfer-Encoding: chunked
Content-Length: 10

0

GET /malicious HTTP/1.1
Host: example.com
```
### 3. Chunked Transfer Encoding Smuggling
This type exploits the chunked transfer encoding mechanism, where the attacker sends a request with improperly formatted chunks, leading to confusion about the end of the request.
Example: An attacker sends a chunked request that is interpreted differently by the front-end and back-end servers.
Request Example:
```text
POST / HTTP/1.1
Host: example.com
Transfer-Encoding: chunked

4
test
0

GET /malicious HTTP/1.1
Host: example.com
```

## MITIGATION OF HTTP REUQEST SMUGGLING
### 1️⃣ Use a Single HTTP Parsing Standard
🔹 Ensure both front-end (CDN, Proxy, Load Balancer) and back-end servers follow the same HTTP request processing rules.

✅ How to Fix:

Configure all servers to follow the same HTTP request parsing rules (e.g., use only Content-Length or only Transfer-Encoding).
Disable ambiguous parsing options in proxies, CDNs, and WAFs.

### 2️⃣ Block Conflicting Headers (Content-Length vs Transfer-Encoding)
✅ Best Practice:

If a request contains both Content-Length and Transfer-Encoding, reject it immediately.
🔹 Example: Nginx Configuration (Reject Conflicting Headers)
```text
if ($http_transfer_encoding ~* "chunked") {
    return 400;
}
```
🔹 Example: Apache Configuration (Disable Transfer-Encoding Parsing)
```text
SetEnvIf Request_URI .+ no-gzip
```
✅ Why? Prevents parsing confusion between front-end and back-end servers.

### 3️⃣ Use a Web Application Firewall (WAF) to Detect Smuggling
✅ Deploy a WAF (Web Application Firewall) that can detect and block request smuggling attacks.

🔹 Example: ModSecurity Rule to Block Suspicious Requests
```text
SecRule REQUEST_HEADERS:Transfer-Encoding "chunked" "id:12345,deny,status:403,msg:'Possible Request Smuggling Attack'"
```
✅ Why? Prevents attackers from injecting extra requests via Transfer-Encoding: chunked.

### 4️⃣ Normalize HTTP Headers & Enforce Strict Parsing
✅ Best Practice:

Configure all HTTP servers (Apache, Nginx, HAProxy, etc.) to strictly enforce HTTP standards.
🔹 Example: Apache Configuration (Strict Header Parsing)
```text
Header unset Transfer-Encoding
Header edit Transfer-Encoding "chunked" "identity"
```
✅ Why? Prevents attackers from injecting additional headers.

### 5️⃣ Upgrade & Patch All Web Components
✅ Best Practice:

Regularly update your web servers, proxies, and load balancers.
Use latest versions of Apache, Nginx, HAProxy, AWS ALB, Cloudflare, etc.
🔹 Why?
Older versions may still be vulnerable to HTTP request smuggling due to outdated parsing methods.

 ### 6️⃣ Disable HTTP/1.1 Pipeline Requests
✅ Best Practice:

Disable HTTP/1.1 pipelining to prevent multiple requests being smuggled in a single connection.
🔹 Example: Nginx (Disable HTTP Pipelining)

```text
keepalive_requests 1;
```
🔹 Example: Apache (Disable Keep-Alive for HTTP/1.1)
```text
KeepAlive Off
```
✅ Why? Prevents multiple requests from being handled incorrectly.
