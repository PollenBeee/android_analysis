# 📱 Android APK Security Analysis Framework

**Author**: Pradeep Kumar D S (M.S., Ph.D)  
**Project Type**: Static and Dynamic Android App Security Analyzer  
**Test App**: `net.programmierecke.radiodroid2.apk`

---

## 📌 1. Project Scope

This project provides a complete framework for performing in-depth **security analysis of Android APKs**. It combines:

- Static code analysis (APK decompilation, string scanning)
- Dynamic runtime analysis (Frida hooking, network interception)
- Certificate and signature verification
- Token/API endpoint leak detection

The final aim is to help **security researchers** and **analysts** automate repetitive tasks and assess the risk of Android apps in a standardized way.

---

## ⚠️ 2. Limitations

- Requires **rooted Android emulator** (no Frida Gadget support yet).
- Obfuscation detection is **limited to string matching**.
- No deep analysis of native ARM `.so` files.
- HTTPS traffic visibility is limited without **certificate pinning bypass**.
- Depends on tools like: `adb`, `apktool`, `jadx`, `frida`, `mitmproxy`, etc.

---

## 🏗️ 3. Architecture Overview

```
+------------------+     +-----------------+
|  Emulator Layer  | --> |  Frida Layer    |
+------------------+     +-----------------+
         ↓                        ↓
+------------------+     +-----------------+
| Static Analysis  | --> | Dynamic Analysis|
+------------------+     +-----------------+
         ↓                        ↓
          +----------------------+
          |   Reporting Layer    |
          +----------------------+
```

### Layers

- **Emulator Layer**: API 28 AVD with root access  
- **Frida Layer**: Live method hooking with Frida  
- **Static Analysis**: Uses `apktool`, `jadx`, `apkid`  
- **Dynamic Analysis**: Frida + mitmproxy  
- **Reporting**: Consolidates analysis into logs/reports  

---

## 🧠 4. Detailed Module Descriptions

### 📦 APK Pulling

- Uses `adb` to extract APK from emulator  
- Function: `pull_apk(package_name)`

### 🔏 APK Signature Verification

- Tool: `apksigner`, `keytool`, `openssl`  
- Function: `extract_apk_signature()`

### 🧩 APK Decompilation

- `apktool` → Smali output  
- `jadx` → Java source output

### 🔎 Keyword and URL Scanning

- `grep_keywords()`: Finds secrets, tokens, auth keys  
- `extract_urls()`: Scans for embedded endpoints  

### 🔐 Obfuscation & Encryption Detection

- Tool: `apkid`  
- Functions:
  - `obfuscation_and_encryption_analysis_java()`
  - `obfuscation_and_encryption_analysis()`

### 🧬 Dynamic Hooking with Frida

- Hooks critical functions (`android.os.Debug`, etc.)
- Injects anti-debug bypass using `hook_antidebug.js`

### 🌐 MITM Proxy Monitoring

- Captures HTTP/S traffic using `mitmdump` or `mitmproxy`  
- Logs saved for analysis (`traffic_log.txt`)

### 🔑 Token & API Call Extraction

- `extract_tokens_from_log()`: Parses captured network logs  
- `extract_api_calls()`: Analyzes app communication code

### 📝 Report Generation

- Function: `write_report()`
- Outputs:
  - URLs and endpoints
  - Security keywords
  - Token leaks
  - Obfuscation indicators

---

## 🔭 5. Future Enhancements

- Detect exposed components (Activities, Services, etc.)
- Secure Intent Communication analysis
- PendingIntent misuse detection
- Custom permissions validation
- Reflection and DexClassLoader detection
- Cryptographic API misuse (e.g., ECB, hardcoded keys)
- Third-party SDK risk scoring
- Runtime behavior monitoring using Frida or Objection

---

## ✅ 6. Conclusion

This framework offers an end-to-end methodology for analyzing Android APKs using:

- **Static methods** for structure and code
- **Dynamic methods** for runtime behavior and API monitoring

> It’s extendable to real devices, obfuscated apps, and native code analysis.

---

## 🧪 7. Manual Testing Instructions

### 🛠️ Tools Required

| Tool        | Purpose                                    | Platform | Sample Command |
|-------------|--------------------------------------------|----------|----------------|
| `apktool`   | Decompile APK to smali code                | CLI      | `apktool d app.apk` |
| `jadx.bat`  | Convert APK to Java                        | CLI      | `jadx -d out app.apk` |
| `grep`      | Search for sensitive patterns              | CLI      | `grep -i base64 -r out` |
| `frida`     | Runtime API hooking                        | CLI      | `frida -U -f com.example -l hook.js` |
| `keytool`   | Check certificate fingerprint              | CLI      | `keytool -printcert -jarfile app.apk` |
| `mitmproxy` | Network monitoring                         | GUI      | `mitmproxy --listen-port 8080` |

### 🔐 Certificate Extraction Steps

```bash
# Unzip APK
7z x net.programmierecke.radiodroid2.apk -o output_dir

# Locate certificate
ls output_dir/META-INF/*.RSA

# Print certificate
keytool -printcert -file output_dir/META-INF/XXX.RSA

# Convert to PEM
openssl pkcs7 -in XXX.RSA -inform DER -print_certs -out cert.pem

# Output certificate info
openssl x509 -in cert.pem -text -noout >> certificate.txt
```

---

## 🧰 8. Automation Using Python

### Emulator Setup

1. Create **API 28 AVD** in Android Studio
2. Root the emulator:
```bash
adb root
adb remount
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
```

3. Start Frida:
```bash
adb shell
cd /data/local/tmp
./frida-server &
```

### Python Modules

- `pull_apk()`: Downloads APK
- `decompile_apk()`, `decompile_java()`: Converts to smali/Java
- `grep_keywords()`, `extract_urls()`: Finds secrets
- `extract_api_calls()`: Detects critical APIs
- `obfuscation_and_encryption_analysis_java()`: Java-based obfuscation stats
- `obfuscation_and_encryption_analysis()`: APKID-based detection
- `write_report()`: Writes analysis summary

### Example Frida Hook

```bash
frida -U -f com.example -l ./scripts/hook_antidebug.js
```

---

## 🗂️ 9. Project Structure

```
project-root/
├── m2.py                        # Main controller script
├── traffic_monitor.py           # MITM traffic handler
├── urlSafety.py                 # URL reputation checker
├── code_safety_analysis.py      # Manifest/smali checks
│   ├── Debuggable check
│   ├── Exported components
│   ├── Native libraries
│   ├── Obfuscated class check
│   └── Dynamic loading flags
```

---

## 📄 Sample Obfuscation Output (APKID)

```
[+] APKiD 3.0.0 :: from RedNaga :: rednaga.io
[*] ./net.programmierecke.radiodroid2.apk!classes.dex
 |-> anti_vm : Build.FINGERPRINT check, Build.MANUFACTURER check
 |-> compiler : r8
[*] ./net.programmierecke.radiodroid2.apk!classes2.dex
 |-> compiler : r8 without marker (suspicious)
```

---

## 📊 Evaluation Summary (Example)

- **Obfuscated Classes**: 3 of 5115 (0.058%)
- **Obfuscated Methods**: 25 of 70,538 (0.035%)
- **Encrypted Strings**: 12 of 452 (2.65%)
---

## 📬 Contact

For queries, enhancements, or contributions, please contact:

**Pradeep Kumar D S**  
Email: _[pradeepkumarst@example.com]_  
Webpage: _[https://dspradeepkumar.github.io/]_
[LinkedIn:](https://www.linkedin.com/in/dspradeep/)
---

> ✅ _Feel free to fork, extend, or integrate this into your own Android malware analysis pipelines._
