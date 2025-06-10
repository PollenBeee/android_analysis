import os
import subprocess
import re
from pathlib import Path
import frida
import time
import socket
import zipfile
import json
import zipfile
from urlSafety import *
from code_safety_analysis import *
import sys
import asyncio
from mitmproxy import http
import logging
logging.getLogger("androguard").setLevel(logging.CRITICAL)
from apkid import apkid

from androguard.misc import AnalyzeAPK


#pip install bcrypt==4.0.1

def run_cmd(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print("[-] Failed:", e)
        return ""

def pull_apk(package_name):
    print(f"[+] Pulling APK for {package_name}")
    path = run_cmd(f"adb shell pm path {package_name}")
    match = re.search(r'package:(.*)', path)
    if match:
        apk_path = match.group(1).strip()
        output_apk = f"{package_name}.apk"
        run_cmd(f"adb pull {apk_path} {output_apk}")
        print(f"[>] Pulled APK")
        return output_apk
    else:
        print(f"[-] Could not find APK for {package_name}")
        return None

def extract_apk_signature(apk_file, apksigner_path="D:/Android/Sdk/build-tools/35.0.1/apksigner.bat"):
    try:
        cmd = f'"{apksigner_path}" verify --print-certs "{apk_file}"'
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)

        if result.returncode == 0:
            with open("signature.txt", "w", encoding="utf-8") as f:
                f.write(result.stdout)
            print("[+] APK signature saved")
        else:
            print("[-] Failed to get APK signature:")
            print(result.stderr)

    except FileNotFoundError:
        print("[-] apksigner not found. Provide correct path or install it via Android SDK.")

def decompile_apk(apk_file, output_folder):
    apktool_jar = "apktool.jar"
    command = f"java -jar {apktool_jar} d -f {apk_file} -o {output_folder}"
    run_cmd(command)
    # print("[>>] Extracting APK Summary Info...")
    # summary(apk_file)
    print("[>>] Extracting APK Signature Info...")
    extract_apk_signature(apk_file)


# command = f"java -jar {jadx_jar} -d {output_folder}/java {apk_file}"
def decompile_java(apk_file, output_folder):
    # jadx_jar = "jadx-cli.jar"
    output_path = Path(f"{output_folder}/java")
    output_path.mkdir(parents=True, exist_ok=True)
    command = f".\\bin\\jadx.bat -d \"{output_path}\" \"{apk_file}\""
    run_cmd(command)

def is_obfuscated_name(name):
    return (
        len(name) <= 2 and name.islower()
        and not name in ['if', 'do', 'on', 'to']  
    )

def count_resource_strings(res_folder):
    strings_file = os.path.join(res_folder, "values", "strings.xml")
    if not os.path.exists(strings_file):
        return 0
    try:
        tree = ET.parse(strings_file)
        root = tree.getroot()
        return len(root.findall("string"))
    except ET.ParseError:
        return 0

def obfuscation_and_encryption_analysis_java(root_folder="./decompiled/java"):

    base64_pattern = re.compile(r'"[A-Za-z0-9+/]{20,}={0,2}"')
    hex_pattern = re.compile(r'"0x[0-9A-Fa-f]{8,}"')
    _classes = set()
    _methods = set()
    encoded_strings = []
    encoded_strings_in_res = []
    total_classes = 0
    total_methods = 0


    for dirpath, _, filenames in os.walk(root_folder):
        for file in filenames:
            if file.endswith('.java'):
                file_path = os.path.join(dirpath, file)
                with open(file_path, encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                    for i, line in enumerate(lines):
                        # Detect class names
                        if 'class ' in line:
                            match = re.search(r'class\s+([a-zA-Z0-9_]+)', line)
                            if match:
                                total_classes += 1
                                name = match.group(1)
                                if is_obfuscated_name(name):
                                    _classes.add(name)

                        match = re.search(r'(public|private|protected)?\s*(static)?\s*\w+\s+(\w+)\s*\(', line)
                        if match:
                            total_methods += 1
                            method_name = match.group(3)
                            if is_obfuscated_name(method_name):
                                _methods.add(method_name)

                        for match in base64_pattern.findall(line):
                            encoded_strings.append((file_path, i+1, match.strip()))
                        for match in hex_pattern.findall(line):
                            encoded_strings.append((file_path, i+1, match.strip()))

                        if "res" in file_path.replace("\\", "/"):
                            for match in base64_pattern.findall(line):
                                encoded_strings_in_res.append((file_path, i+1, match.strip()))
                            for match in hex_pattern.findall(line):
                                encoded_strings_in_res.append((file_path, i+1, match.strip()))

    total_resource_strings = count_resource_strings("./decompiled/res")

    with open("ObfuscationAndEncryptionAnalysis.txt", "w", encoding="utf-8") as report:
        report.write(f"Total Classes: {total_classes} :: Obfuscated Classes: {len(_classes)}\n\n")
        report.write(f"Total Methods: {total_methods} :: Obfuscated Methods: {len(_methods)}\n\n")
        report.write(f"Total Resource Strings inside resource folder: {total_resource_strings}  :: Encrypted/Encoded Strings: {len(encoded_strings_in_res)}\n\n")
        report.write(f"Total Encrypted/Encoded Strings in APK: {len(encoded_strings)}\n\n")

        report.write("Class Names:\n")
        for cls in sorted(_classes):
            report.write(f"  - {cls}\n")

        report.write("\Method Names:\n")
        for method in sorted(_methods):
            report.write(f"  - {method}\n")

        report.write("\n Encrypted or Encoded Strings:\n")
        for file_path, line_num, string_val in encoded_strings:
            report.write(f"  - [{file_path}:{line_num}] {string_val}\n")


def grep_keywords(base_dir, keywords):
    findings = []
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file.endswith(".smali") or file.endswith(".java"):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for keyword in keywords:
                            for match in re.finditer(keyword, content):
                                snippet = content[match.start():match.end()+120]
                                findings.append((filepath, keyword, snippet.strip()))
                except Exception:
                    continue
    return findings

def extract_urls(base_dir):
    url_pattern = r"https?://[^\s\"']+"
    urls = set()
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file.endswith(".smali") or file.endswith(".java"):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        urls.update(re.findall(url_pattern, content))
                except:
                    continue
    return sorted(urls)

def write_report(api_findings, urls, api_info, obfuscated_classes, encrypted_strs):
    with open(RESULT_FILE, "w", encoding="utf-8") as f:
        f.write("[A] Android APK Static Analysis Report\n\n")
        f.write("(1) API Endpoints / URLs Found:\n")
        for url in urls:
            flag, reason = is_url_safe(url)
            condition = f"{'[UNSAFE]' if flag else '[SAFE]  '} {url} --> {reason}"
            f.write(f"- {condition}")
            f.write("\n")

        f.write("\n\n-- URLs and Parameters:\n")
        for item in api_info:
            f.write(f"  - {item['endpoint']}  |  Params: {item['params']}")
            f.write("\n")

        f.write("\n\n-- Obfuscated Classes and Encrypted Methods/Strs:\n")
        for o in obfuscated_classes:
            f.write(f"[obfs_cls]  - {o}")
            f.write("\n")
        for o in encrypted_strs:
            f.write(f"[enc_strs]  - {o}")
            f.write("\n")

        analyze_manifest(f, "./decompiled/AndroidManifest.xml")
        analyze_smali(f, "./decompiled/smali")

        f.write("\n"+"-"*50+"\n")
        f.write("\n(3) Key Classes and Methods related to Network Communication and Authentication:\n")
        for path, keyword, snippet in api_findings:
            f.write(f"\n[File: {path}]\nKeyword: {keyword}\nCode: {snippet}\n")
    print(f"\n >> Analysis saved to: {RESULT_FILE}")

def hook_getAllClasses(package, script_path):
    print(f"Hooking and listing classes in {package}")
    loaded_classes = []

    try:
        with open(script_path, "r") as f:
            js_code = f.read()

        device = frida.get_usb_device(timeout=5)
        pid = device.spawn([package])
        session = device.attach(pid)

        script = session.create_script(js_code)
        script.load()
        device.resume(pid)
        time.sleep(1)
        loaded_classes = script.exports_sync.listclasses()

        session.detach()
        print(f"[+] Retrieved {len(loaded_classes)} classes")

    except Exception as e:
        print(f"[-] Error: {e}")

    return loaded_classes

def start_mitmproxy(log_file="traffic_log.txt", listen_host="0.0.0.0", listen_port=8080, duration=60):
    command = [
        "mitmdump",
        "-s", "./traffic_monitor.py",
        "--listen-host", listen_host,
        "--listen-port", str(listen_port)
    ]

    print(f"[*] Starting mitmproxy for {duration} seconds on {listen_host}:{listen_port}...")

    try:
        process = subprocess.Popen(command)
        time.sleep(duration)
    finally:
        process.terminate()
        print("[*] mitmproxy stopped.")


def extract_tokens_from_log(log_file):
    token_pattern = r"(Bearer|Token|JWT)[\s:]+([A-Za-z0-9\-._~+/=]+)"
    tokens = []
    if os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8", errors='ignore') as f:
            content = f.read()
            tokens = re.findall(token_pattern, content)
    return [match[1] for match in tokens]

def extract_api_calls(source_dir):
    endpoints = []

    url_regex = re.compile(r'["\'](https?://[^\s"\'<>]+)["\']')
    param_regex = re.compile(r'\.add(Query|Header|Body)Parameter\(\s*["\']([^"\']+)["\']')

    for root, _, files in os.walk(source_dir):
        for file in files:
            if file.endswith(".java") or file.endswith(".smali"):
                with open(os.path.join(root, file), encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                    urls = url_regex.findall(content)
                    params = param_regex.findall(content)

                    for url in urls:
                        endpoints.append({"endpoint": url, "params": params})

    return endpoints

def obfuscation_and_encryption_analysis(apk_path):
    obfuscated_classes = []
    encrypted_strs = []

    with open("Obfuscation_Info.txt", 'w') as f:
        subprocess.run(['apkid', apk_path], stdout=f, stderr=subprocess.STDOUT)

    # results = apkid.scan(apk_path)
    # for dex_name, detections in results.items():
    #     for category, labels in detections.items():
    #         label_str = ', '.join(labels)
    #         obfuscated_classes.append(f" |-> {dex_name} - {category} : {label_str}")

    encryption_keywords = [
        "base64", "decrypt", "encrypt", "cipher", "aes", "des", "rsa", 
        "blowfish", "keygenerator", "secretkey", "mac", "sha", "md5", "hmac"
    ]

    for root, dirs, files in os.walk("./decompiled"):
        for file in files:
            if file.endswith((".smali", ".java")):
                filepath = os.path.join(root, file)
                with open(filepath, "r", errors="ignore") as f:
                    content = f.read().lower()
                    if any(keyword in content for keyword in encryption_keywords):
                        encrypted_strs.append(f"Found encryption keyword in {filepath}")

    # for method in dx.get_methods():
    #     method_name = method.name.lower()
    #     class_name = method.class_name.lower()

    #     if any(keyword in method_name or keyword in class_name for keyword in encryption_keywords):
    #         encrypted_strs.append(f"  - {method.class_name}->{method.name}")

    return obfuscated_classes, encrypted_strs

def on_message(message, data):
    if message['type'] == 'send':
        # print("[*] Log:", message['payload'])
        with open("frida_bypass_log.txt", "a") as f:
            f.write(message['payload'] + "\n")
    elif message['type'] == 'error':
        print("[!] Error:", message['stack'])

applications_to_monitor = ["net.programmierecke.radiodroid2"]
scripts = ["./scripts/hook_antidebug.js"]
        #    "./scripts/hook_getAllClasses.js",
        #    "./scripts/hook_extract_tokens_from_sharedPreference.js",
        #    "./scripts/hook_okhttp.js"]

OUTPUT_DIR = "decompiled"
RESULT_FILE = "analysis_report.txt"
TRAFFIC_LOG = "traffic.log"
Path(OUTPUT_DIR).mkdir(exist_ok=True)

if __name__ == "__main__":
    for pkg in applications_to_monitor:
        print(f"\n\n==== Analyzing {pkg} ====")
        apk = pull_apk(pkg)
        if apk:
            decompile_apk(apk, OUTPUT_DIR)
            decompile_java(apk, OUTPUT_DIR)
            obfuscation_and_encryption_analysis_java()

            keywords = [
                "http", "https", "token", "Auth", "Bearer", "login",
                "OkHttpClient", "Retrofit", "HttpURLConnection",
                "authenticate", "Session", "JWT"
            ]
            findings = grep_keywords(OUTPUT_DIR, keywords)
            urls = extract_urls(OUTPUT_DIR)

            api_info = extract_api_calls(OUTPUT_DIR)

            obfuscated_classes, encrypted_strs = obfuscation_and_encryption_analysis(f"./{pkg}.apk")

            write_report(findings, urls, api_info, obfuscated_classes, encrypted_strs)
            
            print("\n[>>] Completed Static Analysis")
            print("\n[+] Starting Dynamic Analysis (Hooking Methods)")
            cmd = [
                "frida",
                "-U",  
                "-f", pkg,     
                "-l", "./scripts/hook_okhttp.js"
            ]

            with open("frida_debug_bypass_log.txt", "w") as outfile:
                process = subprocess.Popen(cmd, stdout=outfile, stderr=subprocess.STDOUT)
                time.sleep(10)
                process.terminate()
                print("[*] Frida hook completed. Logs in frida_bypass_log.txt")

            time.sleep(2)
            cmd_trace = [
                "frida-trace",
                "-U",  
                "-f", pkg,     
                "-j", "android.os.Debug!*"
            ]
            with open("instrumentation_status.txt", "w") as outfile:
                process = subprocess.Popen(cmd_trace, stdout=outfile, stderr=subprocess.STDOUT)
                time.sleep(10)
                process.terminate()
                print("[*] Frida-trace completed. Logs in instrumentation_status.txt")

            start_mitmproxy("traffic_log.txt")
        else:
            print(f"[-] Skipping {pkg}, APK not found.")





#Summary Code Not working properly (or expected output is not produced), need to do testing.. Skipping for the moment
# def summary(apk_path, decompiled_java_dir="./decompiled/java"):
#     summary = {}
#     with zipfile.ZipFile(apk_path, 'r') as zipf:
#         dex_files = [f for f in zipf.namelist() if f.endswith(".dex")]
#         bin_files = [f for f in zipf.namelist() if f.endswith(".bin")]
#         code_sources = {'dex': dex_files, 'bin': bin_files}

#     class_count = 0
#     method_count = 0
#     field_count = 0
#     instruction_count = 0

#     for root, _, files in os.walk(decompiled_java_dir):
#         for file in files:
#             if file.endswith(".java"):
#                 with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
#                     content = f.read()
#                     class_count += content.count("class ")
#                     method_count += len(re.findall(r"\b(public|private|protected)\s+[\w<>]+\s+\w+\(", content))
#                     field_count += len(re.findall(r"\b(public|private|protected)\s+[\w<>]+\s+\w+\s*;", content))
#                     instruction_count += content.count(";")
    
#     code_counts = {
#         'classes': class_count,
#         'methods': method_count,
#         'fields': field_count,
#         'instructions': instruction_count
#     }

#     summary['Input'] = apk_path
#     summary['Code Sources'] = code_sources
#     summary['Native Libs'] = "Not parsed"
#     summary['Counts'] = code_counts
#     summary['Decompilation'] = {
#         'Top level classes': code_counts['classes'],
#         'Processed': 0,
#         'Code generated': 0
#     }
#     summary['Issues'] = {
#         'Errors': 0,
#         'Warnings': 0,
#         'Nodes with issues': 0
#     }
#     with open("summary.json", "w") as f:
#         json.dump(summary, f, indent=2)
