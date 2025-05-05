# SSL pining

Ensures the app only trusts a specific server certificate (or public key), even if the system trust store has other valid CAs.
Prevents man-in-the-middle (MITM) attacks even if the user installs a rogue root certificate.

##  How to Bypass SSL Pinning:

| Method  |  Description |
| ---  |  ---  |
Frida hook  | Inject code to override SSL validation
Objection tool | Disable pinning in runtime
Patch smali code | Modify logic to always accept cert
Xposed module (JustTrustMe) | Hooks trust manager
Recompile APK | Remove pinning code using apktool

# ROOT DETECTION

Blocks app execution if it detects that the Android device is rooted.

## Typical Checks:
- Presence of `su` binary
- Rooted apps like `Magisk, SuperSU`
- Writable `/system`
- Build.TAGS includes test-keys

## How to Bypass Root Detection:

| Method | Description |
| --- | --- |
Magisk Hide | Hides root status from apps
Patch APK | Remove root check logic in smali
Frida Hook | Override methods like isRooted()
Xposed Module | Modules like RootCloak or HideMyRoot
Magisk modules | E.g., Universal SafetyNet Fix
