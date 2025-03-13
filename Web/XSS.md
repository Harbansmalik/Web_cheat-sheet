# CROSS SITE SCRIPTING(XSS)

Cross Site Scripting (XSS) is a security vulnerability that allows attackers to inject malicious scripts into web pages viewed by users, potentially compromising user data and session integrity.

## Types of XSS: 

###  1. Stored XSS (Persistent XSS):
Malicious scripts are stored on the server (e.g., in a database) and served to users when they access the affected page. This type can affect multiple users and is often more dangerous.

###  2. Reflected XSS (Non Persistent XSS):
Malicious scripts are reflected off a web server, typically via a URL or form submission. The script is executed immediately when the user clicks a link or submits a form, affecting only that user.

### 3. DOM based XSS:
The vulnerability exists in the client side code (JavaScript) rather than the server. The malicious script is executed as a result of modifying the DOM (Document Object Model) in the browser, often through unsafe JavaScript functions.

###  4. Self XSS:
A less common variant where users are tricked into executing scripts in their own browsers, often through social engineering.

### 5. Blind XSS:
A type of stored XSS where the attacker does not see the immediate effect of the attack, as the payload is executed in an admin panel or another context.





## Methods to perform Stored XSS
### - Using HTML Injection:

Attackers can inject HTML tags along with JavaScript to manipulate the DOM or create misleading content.
```text
<script>alert('Stored XSS Attack!');</script>
```
When a user visits the page that displays the stored content, the script executes.

### - Exploiting Event Handlers:
Attackers can use event handlers (like onload, onclick, etc.) to execute scripts when certain events occur.
```text
<img src="invalid.jpg" onerror="alert('XSS via Event Handler!');">
```
This script executes when the image fails to load.

### - Using JavaScript URL:
Attackers can inject JavaScript URLs that execute when the user interacts with the link.
```text
<a href="javascript:alert('XSS via JavaScript URL!')">Click me</a>
```
When the user clicks the link, the alert executes.

### - Base64 Encoding:
Attackers can encode their payload in Base64 to bypass certain filters that may block direct script tags.
```text
<script src="data:text/javascript;base64,YWxlcnQoJ1hTUyBhdHRhY2snKTs="></script>
```
This Base64 encoded script will execute when the page is loaded.

### - Using Malicious Payloads in Form Fields:
Attackers can inject scripts into form fields that are later displayed on the page.
```text
<input type="text" value="<script>alert('XSS in Form Field!');</script>">
```
When the form is submitted and the input is displayed, the script executes.

### - Exploiting JSON Responses:
If the application returns JSON data that is not properly sanitized, attackers can inject scripts into the JSON response.
```text
{
    "message": "<script>alert('XSS in JSON!');</script>"
}
```
If this JSON is rendered directly into the HTML without sanitization, the script will execute.

### - Using Third Party Libraries:
Attackers can exploit vulnerabilities in third party libraries that do not properly handle user input.
If a web application uses a library that allows HTML rendering without sanitization, an attacker can inject:
```text
<div><script>alert('XSS via Library!');</script></div>
```
