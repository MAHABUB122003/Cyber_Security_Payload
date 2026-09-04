# CVE TRACKING WORKFLOW — STAY 2 DAYS AHEAD (2026)
> **Author:** MD MAHABUBUR RAHMAN

> A repeatable routine to catch exploitable CVEs the moment they publish — for bug bounty and pentest scoping. **Authorized testing only.**

---

## 1. Sources to watch (10 min/day)

```text
Feeds (RSS)
  NVD (nvd.nist.gov/vuln/data-feeds)   — JSON 2.0 feeds, daily
  CISA Known Exploited Vulnerabilities — https://www.cisa.gov/known-exploited-vulnerabilities-catalog  (KEV list = in-the-wild)
  GitHub Security Advisories           — https://github.com/advisories
  Exploit-DB                           — https://www.exploit-db.com
  Packet Storm Security               — https://packetstormsecurity.com
  ProjectDiscovery (nuclei templates) — https://github.com/projectdiscovery/nuclei-templates

People / reports (X + Discord)
  #bugbountytips, #infosec, CVE aggregators, Twitter lists of top hunters.
  Vendor advisories the moment they drop: MSRC, Cisco, Fortinet, PAN-OS, Apache, GitLab/GitHub.

PoC aggregators
  https://github.com/SecureWithUmer/CVE-2026-PoCs        (community 2026 PoCs)
  https://github.com/wvu0x6c/CVE-2026*                  (hunt variations)
  google-dork:  "CVE-2026-XXXX" exploit OR poc OR proof-of-concept
```

## 2. The daily triage filter

```text
Rank ONLY by hunting value (in this order):
  1. Unauthenticated RCE                → highest payout, easiest to demo
  2. Auth bypass / OAuth / takeover
  3. SSRF to cloud metadata             → connection to infra
  4. SQLi / NoSQL unauth
  5. Stored XSS / DOM XSS on high-traffic path
  6. Path traversal / arbitrary file read/write
  7. Anything "exploited in the wild" on the CISA KEV list

Skip unless scope-match:
  local-only LPE on OS you don't run in scope, CVEs for products absent from your program.
```

## 3. Fast triage commands

```bash
# 1) Pull today's NVD entries (last 24h) as CSV
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=$(date -u -d '1 day ago' +%Y-%m-%dT00:00:00.000)&pubEndDate=$(date -u +%Y-%m-%dT23:59:59.999)" | jq -r '.vulnerabilities[] | [.cve.id, .cve.metrics.cvssMetricV31[0].cvssData.baseScore] | @tsv' | sort -k2 -nr | head -40

# 2) CISA KEV — in-the-wild, must-check
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | jq -r '.vulnerabilities[] | [.cveID, .product, .shortDescription] | @tsv' | grep -iE "2026" | head -30

# 3) Nuclei scan against fresh templates
nuclei -update-templates && nuclei -u https://TARGET -t http/cves/2026/ -severity high,critical

# 4) Search exploit-db for a product
searchsploit --cve CVE-2026-44578
searchsploit "drupal" 2>/dev/null | grep -i 2026
```

## 4. Weekly deep-dive (30 min)

```text
1. Update nuclei-templates + wpscan + nmap script db
   (wpscan --update ; nuclei -update-templates ; nmap --script-updatedb)
2. Fingerprint your in-scope inventory once a week:
   whatweb -a 3, curl headers, login pages → make a "product + version" matrix.
3. Map matrix → this repo's index (CVE_Directory/Full_2026_CVE_Index.md)
   Any match = scheduled verification + report.
4. Read the PUBS of the matching CVEs (source repo PoC folder) BEFORE testing.
5. Log everything: CVE, product, version, tested?, confirmed?, date.
```

## 5. Version-fingerprint cheat sheet

```bash
# WordPress → plugin/theme versions via API
curl -s "https://TARGET/wp-json/wp/v2/plugins" -H 'Authorization: Bearer XXXXX' | jq -r '.[] | [.plugin, .version] | @tsv'
# unauthenticated: read plugin README / /wp-content/plugins/<slug>/readme.txt

# Drupal
curl -sk "https://TARGET/core/CHANGELOG.txt" | head -5

# Apache / Nginx / PHP
curl -skI https://TARGET | grep -iE "server|via|x-powered-by"

# Next.js (self-hosted)
curl -skI https://TARGET | grep -i "x-powered-by"
curl -sk https://TARGET/_next/static/ -o /dev/null -w "%{http_code}\n"   # build id page
grep -ro "buildId" /path 2>/dev/null | head -1

# Docker / other services per Service Access cheat sheet
```

## 6. Output → your hunting log (template)

```text
[] CVE:          CVE-2026-XXXXX
[] Product/Ver:  n8n 1.118.0
[] Class:        Unauthenticated file read
[] In scope?:    YES — client hosts self-hosted n8n
[] Fingerprint:  GET / → x-powered-by header, dashboard login
[] Verified:     lab PoC from ../CVE-2026-PoCs/2026/CVE-2026-XXXXX → same result on target (screenshot)
[] Impact:       reads /etc/passwd-equivalent server file
[] Report:       product, version, CVE, PoC proof, CVSS, fix version (1.121.0)
```

---
**Author:** MD MAHABUBUR RAHMAN
**CVE Tracking Workflow — Version 1.0 • September 2026**
Copyright © 2026 • All Rights Reserved | Security Research Handbook