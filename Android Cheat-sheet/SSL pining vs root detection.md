# SSL pining
SSL pinning is a security technique that binds a client application to a specific SSL certificate or public key, preventing man-in-the-middle attacks by ensuring only trusted certificates are accepted.

## CODE in android manifest file:

- ### android:networkSecurityConfig	
Links to network security configuration file.
- ### usesCleartextTraffic="false"
  Ensures HTTPS is enforced.
- ### network-security-config
  Defines security rules in XML.
- ### domain-config
  Specifies domains for pinning.
- ### pin-set
  Contains pinned certificate fingerprints.
- ### pin digest="SHA-256"
  Defines the hash of a trusted certificate.
