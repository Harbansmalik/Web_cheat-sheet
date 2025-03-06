# Web Cache Poisoning :- 
Web cache poisoning is a type of attack that targets the caching mechanisms of web applications, usually to manipulate or corrupt the content that is stored in a cache. A web cache is used by websites to temporarily store copies of frequently accessed resources (like web pages, images, or scripts) to reduce server load and speed up user access. However, if an attacker can inject malicious data into this cache, they can alter the content served to users. 

## METHOD OF PERFORMING WEB CACHE POISONING

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
