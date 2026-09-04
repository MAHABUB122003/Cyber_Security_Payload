# Cyber Security Payload List (Bug Bounty + Pentesting) 2026
> **Author:** MD MAHABUBUR RAHMAN

A curated arsenal of **working payloads** for bug bounty hunting, penetration testing, WordPress security testing, plugin testing, and exploitation.

All payloads in this repository are intended for **authorized security testing only** (your own systems, labs, or targets you have written permission to test). Use responsibly.

---

## Quick Start (how to actually use this)

1. **Recon first.** Before you fire payloads at anything, map the target:
   - `subfinder -silent -d target.com | anew subdomains.txt`
   - `httpx -l subdomains.txt -sc -title -td`
   - `waybackurls target.com > urls.txt` (and `gau target.com`)
   - `nuclei -l live.txt -t cves/` for fast low-hanging fruit
2. **Read the priority list below** and pick the highest-value test class for your target.
3. **New in 2026: use the one-file playbook first** — `ALL_In_One_Manual_Test/bug-bounty-pentest-manual-test-a-to-z.md` walks a target A-to-Z with the most important payload per section.
4. **Open the matching folder.** Every folder has a `README` that explains *when* and *how* to use the payloads, a `how-to-test-2026.md` step-by-step manual testing guide with worked examples, plus payload lists you can paste into Burp Intruder / ffuf / your tool of choice.
5. **Replace placeholders** (e.g. `YOUR-COLLABORATOR`, `ATTACKER-IP`, `evil.com`) with your values before testing.
6. **Confirm impact** with a proof-of-concept, then write the report.

---

## Top 10 Bug Bounty Priorities 2026 (test these first)

Frequent, valuable, and realistic to find on modern targets:

| # | Category | Why it matters in 2026 | Folder |
|---|----------|------------------------|--------|
| 1 | **Access Control / IDOR** | #1 on OWASP list, most common bounty | `Access control vulnerabilities/` |
| 2 | **XSS (stored/blind/reflected)** | Still the most reported web bug | `XSS_Payloads/` |
| 3 | **SSRF** | Cloud metadata = instant critical | `SSRF/` |
| 4 | **SQLi** | Full DB compromise possible | `SQL-Injection-Payloads/` |
| 5 | **JWT / auth bypass** | Every modern API uses JWTs | `JWT_Attacks/` |
| 6 | **WordPress** | 40%+ of the web, plugin bugs everywhere | `WordPress/` |
| 7 | **Insecure Deserialization** | Direct RCE when found (Java/PHP/.NET) | `Insecure_Deserialization/` |
| 8 | **NoSQL injection** | Node/mongo backends are common | `NoSQL_Injection/` |
| 9 | **Prototype pollution** | Frame/object pollution = auth bypass + XSS + RCE | `Prototype_Pollution/` |
| 10 | **Host header + cache poisoning** | Easy wins on CDN-backed apps | `Host_Header_Injection/`, `Web_Cache_Poisoning/` |

---

## Full Folder Index

| Folder | Contents | Difficulty |
|--------|----------|------------|
| `Access control vulnerabilities/` | IDOR, broken access control, forced browsing | Easy |
| `CORS Misconfigaretion/` | Origin reflection, null origin, wildcard tests | Easy |
| `Credentials/` | Default creds + top passwords lists | Easy |
| `CSRF_Clickjacking/` | CSRF PoC templates, clickjacking test | Easy |
| `DOM XSS/` | DOM-based vectors, PortSwigger notes | Medium |
| `Email_Header_Injection/` | CRLF injection into mail headers | Medium |
| `File_Upload/` | Extension/MIME/magic-byte bypasses | Medium |
| `Framework_RCE/` | Log4Shell, Spring4Shell, Struts, WebLogic, Fastjson | Hard |
| `GraphQL/` | Introspection, injection, batching DoS | Medium |
| `HTTP_Request_Smuggling/` | CL.TE / TE.CL / TE.TE / HTTP/2 downgrade | Hard |
| `Host_Header_Injection/` | Password reset poisoning, routing attacks | Medium |
| `Insecure_Deserialization/` | PHP object injection, Java ysoserial, pickle, .NET | Hard |
| `Information_Disclosure/` | .env, backups, git exposure paths | Easy |
| `JWT_Attacks/` | alg none, key confusion, weak secret, kid | Medium |
| `LDAP_Injection/` | Authentication & info-disclosure bypass | Medium |
| `MySQL/` | MySQL client attacks, UDF, file ops | Medium |
| `NoSQL_Injection/` | MongoDB `$ne`/`$where`, Redis | Medium |
| `OpenRedirect/` | 2026 payloads: protocol-relative, @-confusion, CRLF, scheme abuse, OAuth redirect_uri, cache poisoning + auto console scanner | Easy |
| `OS_Command_Injection/` | Linux + Windows cmd injection, blind, SSI, WAF-bypass 2026 | Medium |
| `Previlage_Esclation/` | Linux + Windows privesc cheatsheets (2026 CVEs) | Medium |
| `Port_Scanning_Vuln_Discovery/` | Port scanning: basic code (Python/Bash/PowerShell), specific-port->vuln map, 2026+ vuln-finding mindset, lab service-access + brute-force cheatsheet (hydra/medusa/ncrack/crackmapexec/patator) | Easy-Med |
| `Prototype_Pollution/` | Client + server-side pollution | Hard |
| `php-reverse-shell/` | Classic + one-liners + WAF/AV-bypass obfuscated shells + stagers | Medium |
| `Reverse_Shells/` | Multi-language reverse shell one-liners | Easy |
| `SQL-Injection-Payloads/` | 2026 rebuild: union/error, blind, stacked, OOB, MSSQL RCE, modern DBMS+NoSQL, WAF bypass | Medium |
| `SSRF/` | Cloud metadata, gopher, blind callbacks, param-fuzz wordlist | Medium |
| `SSTI/` | Jinja2/Twig/Freemarker/ERB etc. to RCE | Hard |
| `Subdomain_Takeover/` | Cloud service fingerprints for takeover | Easy |
| `Username/` | Username wordlists + base64 admin list + pairing guide | Easy |
| `Web_Cache_Poisoning/` | Cache key deception, unkeyed inputs | Hard |
| `WordPress/` | Enum, xmlrpc, REST API, auth/login bypass, upload bypass, plugin CVE payloads, wpscan | Easy-Med |
| `XML external entity/` | XXE file read, blind OOB, billion laughs | Medium |
| `XPath_Injection/` | XPath auth bypass + data extraction | Medium |
| `XSS_Payloads/` | Full XSS arsenal: 2026 WAF bypass, svg/image, DOM clobber/mXSS, framework matrix, PortSwigger lab solutions | Easy-Med |
| `WAF_Bypass/` | Universal cheat sheet + tools + per-WAF payload ladders | Medium |
| `ALL_In_One_Manual_Test/` | One-file A-to-Z manual testing playbook + complete 20-attack payload arsenal + lab service access / enumeration / brute-force cheatsheet | All |

---

## Suggested Tooling

| Step | Tool |
|------|------|
| Recon / subdomains | subfinder, amass, assetfinder, crt.sh |
| Probing / screenshots | httpx, aquatone |
| Parameter discovery | waybackurls, gau, paramspider, Arjun |
| Scanning | nuclei, nikto, wpscan (WP-only) |
| Manual testing | Burp Suite Community/Pro, ZAP |
| Wordlist fuzzing | ffuf, gobuster |
| Payload automation | Burp Intruder, turbo intruder |

---

## Report Writing Cheat Sheet

Good bounty reports answer 4 questions:
1. **Location** — URL + method + parameter/header
2. **Severity rationale** — what can an attacker actually do? (steal admin session, read cloud keys, RCE)
3. **Reproduction steps** — exact request/response so the triager can replay it in 30 seconds
4. **Impact demo** — screenshot + PoC payload, not just "it reflected"

When in doubt use the CVSS calculator for the severity score and include a recommendation.

---

## License & Ethics

This content is provided as a **learning and legitimate testing resource**. Do not use any payload against a system you do not own or have explicit authorization to test. The creator assumes no liability for misuse.

---

## Author

**MD MAHABUBUR RAHMAN**

- Created & maintained by **MD MAHABUBUR RAHMAN**.
- Every file in this repository carries attribution to the author.
- Built for bug bounty hunters and penetration testers; payloads are refreshed for **2026+** techniques.
- For feedback, corrections, or new payload contributions, open an issue or pull request.
