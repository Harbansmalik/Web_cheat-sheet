# INSECURE DESERILIZATION

Insecure deserialization is a vulnerability where untrusted data is deserialized without proper validation, potentially allowing attackers to execute arbitrary code, manipulate application logic, or escalate privileges.

## METHODS TO PERFORM INSECURE DESERIALIZATION


### 1. Manipulating Serialized Objects
Attackers can modify serialized objects to change their properties or methods, leading to unexpected behavior when deserialized.
Example: Suppose an application serializes user objects with a method that grants admin privileges:
```example
class User:
    def __init__(self, username, is_admin):
        self.username = username
        self.is_admin = is_admin
```
- Serialized object
serialized_data = b'...'
An attacker modifies the serialized data to set is_admin to True:
```text
# Attacker's modified serialized data
modified_data = b'...<is_admin=True>...'
```
When the application deserializes this object, the attacker gains admin access.

 ### 2. Code Injection via Deserialization
Attackers can inject malicious code into serialized data, which gets executed upon deserialization.
Example: In a PHP application, an attacker crafts a serialized object that includes a payload:
```text
// Original serialized object
$data = serialize($user);
```
```text
// Attacker's payload
$malicious_payload = 'O:4:"User ":1:{s:8:"username";s:4:"test";s:8:"is_admin";b:1;}'; // Injected code
```
When the application deserializes this payload, it executes the injected code.

### 3. Using Unsafe Libraries
Some libraries or frameworks may have known vulnerabilities that can be exploited through deserialization.
Example: An attacker uses a vulnerable library to deserialize data:
```text
import pickle

# Attacker crafts a malicious payload
malicious_payload = b'...'
```

- Deserializing using a vulnerable library
result = pickle.loads(malicious_payload) 
### 4. Exploiting Object Injection
Attackers can exploit object injection vulnerabilities by crafting serialized data that creates unexpected objects or modifies application state.
Example: In a Ruby on Rails application, an attacker sends a serialized object that modifies application behavior:
```text
# Original serialized object
serialized_data = Marshal.dump(user)
```
```text

# Attacker's payload
malicious_payload = Marshal.dump(MaliciousClass.new)
```

- Deserialization
```text
user = Marshal.load(malicious_payload)  # Executes malicious code
```
### 5. Deserialization of Untrusted Data
Attackers can send untrusted data directly to the application, which deserializes it without validation.
Example: An attacker sends a crafted JSON object to a web application:
```text
{
    "username": "attacker",
    "is_admin": true
}
```
If the application deserializes this data without validation, the attacker may gain elevated privileges.
