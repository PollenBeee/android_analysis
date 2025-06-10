import re
import os
import xml.etree.ElementTree as ET
    
def analyze_manifest(logfile, manifestfile):
    logfile.write("\n"+"-"*50+"\n")
    logfile.write("\n(2) App Safety - Analyzing AndroidManifest.xml...")
    if not os.path.exists(manifestfile):
        logfile.write(f"[-] Manifest not found: {manifestfile}")
        logfile.write("\n")
        return

    try:
        tree = ET.parse(manifestfile)
        root = tree.getroot()

        android_ns = "http://schemas.android.com/apk/res/android"
        ns = {'android': android_ns}

        for application in root.iter("application"):
            debuggable = application.get(f"{{{android_ns}}}debuggable")
            if debuggable == "true":
                logfile.write("[+] Debuggable is enabled (Security Risk)")
                logfile.write("\n")

        # Check exported components
        component_tags = ["activity", "receiver", "service"]
        for tag in component_tags:
            for elem in root.iter(tag):
                exported = elem.get(f"{{{android_ns}}}exported")
                name = elem.get(f"{{{android_ns}}}name")
                if exported == "true":
                    logfile.write(f"[+] Exported {tag}: {name}")
                    logfile.write("\n")

        # Check for native library usage
        for uses_lib in root.iter("uses-library"):
            lib_name = uses_lib.get(f"{{{android_ns}}}name", "unknown")
            logfile.write(f"[+] Native Library declared: {lib_name}")
            logfile.write("\n")

    except ET.ParseError as e:
        logfile.write(f"[-] XML parsing error: {e}")
        logfile.write("\n")


def analyze_smali(logfile, smali_dir):
    obfuscated_class_pattern = re.compile(r"\.class[^\n]*?L([a-z]{1,2}/){2,}[a-z]{1,2};")
    dynamic_loading_pattern = re.compile(r"DexClassLoader|PathClassLoader|loadClass")
    native_lib_pattern = re.compile(r"System\.loadLibrary")
    logfile.write("\n"+"-"*50+"\n")
    logfile.write("\n(2a) Scanning Smali files.\n")
    for root, _, files in os.walk(smali_dir):
        for file in files:
            if file.endswith(".smali"):
                path = os.path.join(root, file)
                with open(path, encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    if obfuscated_class_pattern.search(content):
                        logfile.write(f"[+] Obfuscated class detected in: {path}")
                        logfile.write("\n")

                    if dynamic_loading_pattern.search(content):
                        logfile.write(f"[+] Dynamic Code Loading (Security Risk) in: {path}")
                        logfile.write("\n")

                    if native_lib_pattern.search(content):
                        logfile.write(f"[+] Native Library Loaded in: {path}")
                        logfile.write("\n")

