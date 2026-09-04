# CVE DIRECTORY — 2026 BUG BOUNTY & PENTESTING INDEX
> **Author:** MD MAHABUBUR RAHMAN
> **Security Research Handbook • September 2026**
> ⚠️ **Authorized testing only.** These are attack-focused notes for bug bounty, labs, CTFs, and scoped paid pentests — never against systems you don't own or have written permission to test.

## What this directory is

A curated, categorized index of the **most important active CVEs for 2026** — plus a **2020–2025 year-by-year archive** of the most damaging CVEs (each with real exploitation payloads) for bug-bounty and pentest history/recon. It includes a priority list for bug bounty, a full 75-entry reference index, and a repeatable workflow for staying current. The 2026 items come from the community PoC index:

> **Source repo:** https://github.com/SecureWithUmer/CVE-2026-PoCs
> (community-curated, verified 2026 CVE PoCs — clone it: `git clone https://github.com/SecureWithUmer/CVE-2026-PoCs`)

## Files in this directory

| File | Purpose |
|------|---------|
| `2026_BugBounty_Priority.md` | The ~20 CVEs with the best 2026 bug-bounty ROI + detection checks |
| `Full_2026_CVE_Index.md` | All 75 entries with product, type, PoC status |
| `CVE_Tracking_Workflow.md` | Daily/weekly routine + tools (feeds, nuclei, exploit-db) |
| `CVE_2020.md` | ⭐ Year archive 2020 — top CVEs + exploitation payloads (Zerologon, F5 5902, WebLogic, SMBGhost) |
| `CVE_2021.md` | ⭐ Year archive 2021 — Log4Shell, ProxyLogon/ProxyShell, Confluence RCE, PwnKit, PrintNightmare |
| `CVE_2022.md` | ⭐ Year archive 2022 — Spring4Shell, Confluence OGNL, F5 1388, Dirty Pipe, ProxyNotShell |
| `CVE_2023.md` | ⭐ Year archive 2023 — MOVEit, PaperCut, Citrix Bleed, Confluence 22515/22527, TeamCity |
| `CVE_2024.md` | ⭐ Year archive 2024 — PAN-OS 3400, Jenkins 23897, TeamCity 27198, xz, PHP-CGI 4577 |
| `CVE_2025.md` | ⭐ Year archive 2025 — React2Shell, Next.js bypass, Erlang SSH, Tomcat, Langflow, CitrixBleed2 |
| `ALL_CVE_Exploit_Playbook_2020-2026.md` | ⭐⭐ **ONE-FILE master playbook** — every important CVE 2020→2026 with name + copy-paste payload/how-to-exploit |
| `CVE_2026_deep_dive.md` | (future) 2026 payload deep-dives on top of Priority list |

## How to use

```bash
# 1) Grab the source PoC repo
git clone https://github.com/SecureWithUmer/CVE-2026-PoCs && cd CVE-2026-PoCs
ls 2026/                                   # one folder per CVE with PoC + notes

# 2) Scan for these in scope — nuclei with 2026 templates
nuclei -u https://TARGET -t cves/2026/

# 3) Fingerprint versions that map to CVEs
whatweb -a 3 https://TARGET
curl -skI https://TARGET | grep -i -E "server|via|x-powered-by"

# 4) Verify a specific CVE manually (replace with the file's guide)
#    e.g. for the WordPress role-tampering trio: try registering with role=administrator
curl -sk -X POST https://TARGET/wp-json/wp/v2/users \
  -d 'username=a&password=b&email=a@b.c&role=administrator' -H 'Content-Type: application/json'
```

## Category quick-map

| Category | CVEs | Where |
|----------|------|-------|
| Web app / bug bounty | CVE-2026-8206 · 5118 · 9082 · 3891 · 1492 · 1512 · 1405 · 21643 · 30655 · 22200 · 22557 · 27470 · 21858 · 29909 · 5027 · 23980 · 22241 · 44578 · 48710 · 40175 · 31802 · 27607 | Priority + Index |
| AI Agent / MCP (2026 hot) | CVE-2026-42271 · 42208 · 0770 · 23744 · 33032 · 27825 · 26118 · 22812 · 25253 · 32013 · 22738 | Priority + Index |
| Network / firewalls | CVE-2026-0257 · 0265 · 0300 · 10520 · 1731 · 20045 · 20131 · 20182 · 21962 · 3055 · 35616 · 48172 · 45185 · 24061 · 42945 · 23918 · 34486 | Index |
| Windows / Microsoft / OS | CVE-2026-45585 · 33824 · 41091 · 21509 · 45659 · 41651 · 3888 · 29923 · 29909 · 23398 · 46300 · 31431 · 20687 · 20643 | Index |
| Frameworks / libraries | CVE-2026-27172 · 25769 · 29000 · 26980 · 27579 · 3854 · 1999 · 32809 · 0897 · 24688 | Index |

## Golden rules

```text
1. PoC Status: Available = public PoC exists. Unavailable = still patch, don't PoC-guess.
2. An "old" CVE is not useless — unpatched appliances leak into scope every week.
3. Version fingerprint FIRST, CVE hunt SECOND. Nuclei without recon is noise.
4. For every hit: confirm version + config, then write PoC proof (screenshot/timing/DNS beat).
5. Report with product, version, CVE, CWSS/CVSS, impact, and the fix version.
```

---
**Author:** MD MAHABUBUR RAHMAN
**CVE Directory — Version 1.0 • September 2026**
Copyright © 2026 • All Rights Reserved | Security Research Handbook