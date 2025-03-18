# Prototype Pollution

WebSockets provide full-duplex, real-time communication between a client and a server over a single TCP connection. Unlike HTTP, which follows a request-response model, WebSockets allow persistent bidirectional communication without the overhead of multiple HTTP requests.

## MITIGATIONS
### 1️⃣ Prevent Overwriting __proto__, constructor, or prototype Properties
Avoid allowing user input to modify sensitive properties like __proto__, constructor, and prototype.

🛠 Secure Object Property Check
```text
function isPrototypePolluted(key) {
    return ["__proto__", "constructor", "prototype"].includes(key);
}

function safeMerge(target, source) {
    for (let key in source) {
        if (!isPrototypePolluted(key)) {
            target[key] = source[key];
        }
    }
}
```
✅ Ensures that malicious properties cannot be injected!

### 2️⃣ Use Object.create(null) Instead of {}
By default, JavaScript objects inherit from Object.prototype, making them vulnerable to prototype pollution. Using Object.create(null) prevents this:

❌ Vulnerable Code
```text
let obj = {}; 
console.log(obj.toString); // Exists because it inherits from Object.prototype
✅ Secure Code
```text
let obj = Object.create(null); 
console.log(obj.toString); // undefined (No prototype pollution possible)
```
✅ Prevents prototype inheritance manipulation!

### 3️⃣ Use Map Instead of Plain Objects
Map does not inherit from Object.prototype, making it immune to prototype pollution.

✅ Example
```text
let secureStorage = new Map();
secureStorage.set("isAdmin", false);

console.log(secureStorage.get("isAdmin")); // false
console.log(secureStorage.__proto__); // undefined (Safe from pollution)
```
✅ Safer alternative to objects for key-value storage!

### 4️⃣ Deep Clone Objects Securely
Many deep merge functions do not properly sanitize inputs, allowing prototype pollution. Use structured cloning or libraries like lodash.cloneDeep().

❌ Vulnerable Deep Merge
```text
Object.assign(target, source); // Allows pollution
```
✅ Secure Deep Clone
```text
const _ = require("lodash");
let secureCopy = _.cloneDeep(userInput); //
```
✅ Safe deep cloning
✅ Prevents prototype manipulation during deep merging!

### 5️⃣ Update Dependencies (Avoid Vulnerable Libraries)
Many libraries (e.g., lodash < 4.17.11) have been vulnerable to prototype pollution.

🔍 Check Dependencies for Vulnerabilities
```text
npm audit fix
```
✅ Always use the latest secure versions of dependencies!


