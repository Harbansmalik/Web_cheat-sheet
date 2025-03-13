# Web Cache Poisoning :- 
Web cache poisoning is a type of attack that targets the caching mechanisms of web applications, usually to manipulate or corrupt the content that is stored in a cache. A web cache is used by websites to temporarily store copies of frequently accessed resources (like web pages, images, or scripts) to reduce server load and speed up user access. However, if an attacker can inject malicious data into this cache, they can alter the content served to users. 

## `METHOD OF PERFORMING WEB CACHE POISONING`

### 1. HTTP Header Manipulation
`Technique:` Attackers manipulate HTTP headers to influence caching behavior.

`Example:` An attacker sends a request with a custom Cache-Control header:
```text
GET /profile HTTP/1.1
Host: example.com
Cache-Control: no-cache
```

If the server does not properly handle this header, it may cache the response despite the request indicating it should not be cached. The attacker could then exploit this by sending a request that results in a malicious response being cached.

## 2. Parameter Pollution
`Technique:` Injecting additional parameters into the URL to create a unique cache entry.

`Example:` An attacker sends a request like:
```text
GET /search?q=valid_query&user_id=123&malicious_param=<script>alert('Hacked!');</script> HTTP/1.1
```
If the application caches the response based on the user_id and does not sanitize malicious_param, the cache may store the response containing the script. When other users access the same search query, they may execute the script.

## 3. Content-Type Confusion
`Technique:` Exploiting the way the application handles different content types.

`Example:` An attacker sends a request that causes the server to respond with a different content type:
```text
GET /download?file=report.pdf HTTP/1.1
Host: example.com
Accept: application/json
```
If the server responds with a JSON payload instead of the expected PDF, and this response is cached, the attacker can poison the cache with malicious JSON content. When other users download the file, they receive the malicious response.

## 4. Cache Key Manipulation
`Technique:` Manipulating request parameters to create a unique cache key.

`Example:` An attacker sends a request with a crafted URL:
```text
GET /item?id=1&session=12345&malicious=<script>alert('XSS');</script> HTTP/1.1
```
If the application caches responses based on the id and session parameters without validating malicious, the cache may store the response containing the script. Subsequent requests for the same item could serve the malicious content.

## 5. Using GET Requests
`Technique:` Exploiting the fact that many caching mechanisms cache GET requests.

`Example:` An attacker sends a GET request with a malicious payload:
```text
GET /comments?post_id=1&comment=<script>alert('Hacked!');</script> HTTP/1.1
```
If the application caches the response without sanitizing the comment, the cache may store the malicious script. When other users view the comments, they execute the script.

## 6. Cache Bypass
`Technique:` Attempting to bypass cache mechanisms to deliver malicious content directly.

`Example:` An attacker might exploit a vulnerability in the application to send a request that bypasses the cache:
```text
POST /submit-comment HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

comment=<script>alert('Hacked!');</script>
```
If the application does not properly handle POST requests and caches the response, the malicious comment could be served to other users.

## 7. Cross-Site Scripting (XSS)
`Technique:` Injecting scripts that are cached and executed by other users.

`Example:` An attacker exploits an XSS vulnerability:
```text
GET /profile?user=<script>alert('Hacked!');</script> HTTP/1.1
```
If the application caches the response without sanitizing the user parameter, the script gets stored. When other users access the profile, they execute the script.

## 8. Cache-Control Misconfigurations
`Technique:` Exploiting misconfigured cache settings.

`Example:` An attacker sends a request that should not be cached:
```text
GET /sensitive-data HTTP/1.1
Host: example.com
Cache-Control: no-store
```
If the server ignores the no-store directive and caches the response, the attacker can later access this cached sensitive data.

## Mitigation of Web Cache Poisoning:

### 1️⃣ Sanitize and Validate User Input
Attackers often inject harmful payloads into headers, URLs, or parameters that get cached.

✅ Solution:

Whitelist allowed characters for query parameters.
Use server-side validation to reject unexpected inputs.
Apply input sanitization to prevent injection of scripts or control characters.
Example (Sanitizing User Input in PHP)
```text
$input = filter_input(INPUT_GET, 'user', FILTER_SANITIZE_STRING);
echo htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
```
### 2️⃣ Avoid Caching Untrusted User Inputs
Certain headers and query parameters should never be cached, especially those containing user-specific data.

✅ Solution:

Disable caching for dynamic pages that rely on user input.
Prevent caching of responses containing cookies, authentication headers, or sensitive data.
Example (Prevent Caching in HTTP Headers)
```text

Cache-Control: no-store, no-cache, must-revalidate, max-age=0
Pragma: no-cache
```

### 3️⃣ Implement Strong Cache Key Policies
If cache servers consider only the URL and ignore headers, attackers can poison the cache using header-based injections.

✅ Solution:

Ensure that caching includes important request headers (e.g., User-Agent, Authorization).
Use Vary headers to define correct cache policies.
Example (Secure Vary Header in Nginx)
```text
proxy_cache_key "$scheme$request_method$host$request_uri$http_user_agent";
```
### 4️⃣ Use Content Security Policy (CSP) to Prevent XSS
If an attacker injects malicious JavaScript through a poisoned cache, CSP can prevent execution.

✅ Solution:
Set a strict CSP policy to block unauthorized scripts.

Example (CSP Header to Prevent XSS from Poisoned Cache)
```text
Content-Security-Policy: default-src 'self'; script-src 'self';
```
### 5️⃣ Enable Proper Cache Invalidation
Cache poisoning occurs when old, manipulated content is stored too long.

✅ Solution:

Set short cache expiration for dynamic content.
Use Cache Purging (CDN APIs) to remove outdated content.
Implement ETag validation to serve fresh responses.
Example (Setting a Short Cache Lifetime in Apache)

```text
ExpiresActive On
ExpiresDefault "access plus 5 minutes"
```
### 6️⃣ Restrict HTTP Header Manipulation
Attackers often exploit untrusted headers like X-Forwarded-Host or X-Forwarded-For.

✅ Solution:

Whitelist allowed headers and reject unexpected ones.
Strip out untrusted headers from incoming requests before they reach the cache.
Example (Stripping Untrusted Headers in Nginx)
```text
proxy_set_header X-Forwarded-Host "";
proxy_set_header X-Forwarded-For "";
```
### 7️⃣ Use Web Application Firewalls (WAFs)
WAFs can detect and block cache poisoning attempts in real time.

✅ Solution:

Configure a WAF to block suspicious payloads.
Use rate limiting to prevent repeated exploitation attempts.
Example (Blocking Malicious Query Strings in ModSecurity WAF)
```text
SecRule ARGS "(\<script\>|document\.cookie)" "deny,status:403"
```
### 8️⃣ Secure Content Delivery Networks (CDN)
Many CDNs cache responses aggressively, making them a target for poisoning.

✅ Solution:

Enable authentication for cache purging APIs.
Use cache segmentation to prevent sharing across users.
Monitor logs for unexpected cache behavior.

