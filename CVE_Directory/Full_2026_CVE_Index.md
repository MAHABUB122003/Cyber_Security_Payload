# FULL 2026 CVE INDEX — 75 ENTRIES (Bug Bounty + Pentest)
> **Author:** MD MAHABUBUR RAHMAN
> Indexed from the community PoC repo: https://github.com/SecureWithUmer/CVE-2026-PoCs — entries, products, and PoC status per that index. **Authorized testing only.**

---

## A. WEB APP / BUG BOUNTY

| CVE | Product | Type | PoC |
|-----|---------|------|-----|
| CVE-2026-9082 | Drupal core (8.9.0→11.3.10) | SQL Injection | Available |
| CVE-2026-8206 | Kirki WP plugin 6.0.0–6.0.6 | Account takeover via password-reset-to-arbitrary-email | Available |
| CVE-2026-5118 | Divi Form Builder ≤5.1.2 | Admin privesc via `role` param (unauth) | Available |
| CVE-2026-3891 | Pix for WooCommerce ≤1.5.0 | Arbitrary file upload → RCE (unauth) | Available |
| CVE-2026-1492 | User Registration & Membership ≤5.1.2 | Admin account creation via role param | Available |
| CVE-2026-1512 | Essential Addons for Elementor ≤6.5.9 | Stored XSS (Info Box widget) | Available |
| CVE-2026-1405 | Slider Future ≤1.0.5 | Arbitrary file upload → RCE | Available |
| CVE-2026-21643 | FortiClientEMS 7.4.4 | SQLi (unauth) | Available |
| CVE-2026-30655 | esiclivre v0.2.2 | SQLi via `cpfcnpj` in /reset/index.php (unauth) | Available |
| CVE-2026-22200 | osTicket <1.18.3/1.17.7 | Arbitrary file read via PHP filter in PDF export | Available |
| CVE-2026-22557 | UniFi Network Application | Path traversal → file read | Available |
| CVE-2026-27470 | ZoneMinder ≤1.36.37/1.37.61–1.38.0 | Second-order SQLi (getNearEvents) | Available |
| CVE-2026-21858 | n8n 1.65.0→1.121.0 | Unauthenticated file access via form workflows | Available |
| CVE-2026-29909 | MRCMS V3.1.2 | Unauth directory listing (`/admin/file/list.do`) | Unavailable |
| CVE-2026-5027 | Generic API `/api/v2/files` | Path traversal in `filename` → arbitrary file write | Available |
| CVE-2026-23980 | Apache Superset <6.0.0 | Auth'd error-based SQLi (sqlExpression/where) | Available |
| CVE-2026-22241 | Open eClass <4.2 | Zipped theme upload (admin) → RCE | Unavailable |
| CVE-2026-44578 | Next.js 13.4.13→15.5.16/16.2.5 (self-hosted) | SSRF via crafted WebSocket upgrade | Available |
| CVE-2026-48710 | Starlette <1.0.1 | Host-header → request.url/path mismatch → auth bypass | Available |
| CVE-2026-40175 | Axios <1.15.0/0.3.1 | Prototype pollution → header injection chain | Unavailable |
| CVE-2026-31802 | node-tar <7.5.11 | Drive-relative symlink → file overwrite during extract | Available |
| CVE-2026-27607 | RustFS 1.0.0-a56→a82 | Presigned POST policy bypass (size/key/CT) | Available |
| CVE-2026-26980 | Ghost CMS 3.24.0→6.19.0 | Unauth arbitrary DB read | Available |

## B. AI AGENT / MCP — 2026 HOT

| CVE | Product | Type | PoC |
|-----|---------|------|-----|
| CVE-2026-42271 | LiteLLM 1.74.2→1.83.7 | MCP test endpoints spawn stdio proc → host RCE (low-priv key) | Available |
| CVE-2026-42208 | LiteLLM 1.81.16→1.83.7 | SQLi in API-key check → proxy DB read/modify (unauth) | Available |
| CVE-2026-0770 | Langflow | `exec_globals` unauth RCE as root (ZDI-CAN-27325) | Available |
| CVE-2026-23744 | MCPJam inspector ≤1.4.2 | Unauth RCE (binds 0.0.0.0) | Available |
| CVE-2026-33032 | NginxUI MCP ≤2.3.5 | `/mcp_message` w/o auth → full nginx takeover | Available |
| CVE-2026-27825 | MCP Atlassian <0.17.0 | Attachment download path → write anywhere → cron RCE | Available |
| CVE-2026-26118 | Azure MCP Server | SSRF → privesc | Available |
| CVE-2026-22812 | OpenCode <1.0.216 | Unauth local HTTP server + CORS → shell commands | Unavailable |
| CVE-2026-25253 | OpenClaw <2026.1.29 | One-click RCE (gatewayUrl + token auto-send) | Available |
| CVE-2026-32013 | OpenClaw <2026.2.25 | Symlink traversal (files.get/set) → host read/write | Available |
| CVE-2026-22738 | Spring AI 1.0.0→1.0.5/1.1.0→1.1.4 | SpEL injection (SimpleVectorStore filter) | Unavailable |

## C. NETWORK / FIREWALL / INFRASTRUCTURE (Pentest gold)

| CVE | Product | Type | PoC |
|-----|---------|------|-----|
| CVE-2026-0257 | PAN-OS GlobalProtect | Auth bypass (unauth VPN) | Unavailable* |
| CVE-2026-0265 | PAN-OS (CAS enabled) | Auth bypass | Unavailable* |
| CVE-2026-0300 | PAN-OS User-ID Captive Portal | Buffer overflow → RCE as root | Unavailable* |
| CVE-2026-10520 | Ivanti Sentry pre-R10.5.2/10.6.2/10.7.1 | OS command injection → root RCE (unauth) | Available |
| CVE-2026-1731 | BeyondTrust Remote Support/PRA | Pre-auth RCE | Available |
| CVE-2026-20045 | Cisco Unified CM/IM&P/Unity/Webex Dedicated | Unauth HTTP RCE → root (Critical) | Unavailable |
| CVE-2026-20131 | Cisco Secure Firewall MC | Insecure deserialization → RCE as root | Available |
| CVE-2026-20182 | Cisco Catalyst SD-WAN | Peering auth bypass → admin + NETCONF | Available |
| CVE-2026-21962 | Oracle HTTP Server / WebLogic Proxy Plug-in | Unauthenticated compromise, CVSS 10.0 | Unavailable* |
| CVE-2026-3055 | NetScaler ADC/Gateway (SAML IdP) | Insufficient validation → memory overread | Available |
| CVE-2026-35616 | Fortinet FortiClientEMS 7.4.5–7.4.6 | Unauth code execution via crafted requests | Available |
| CVE-2026-48172 | LiteSpeed cPanel plugin <2.4.5 | Privesc to root (exploited in the wild May 2026) | Unavailable |
| CVE-2026-45185 | Exim <4.99.3 (GnuTLS) | UAF in BDAT path → heap corruption → RCE | Available |
| CVE-2026-24061 | GNU inetutils telnetd ≤2.7 | Auth bypass via `-f root` USER env | Available |
| CVE-2026-42945 | NGINX (rewrite module) | PCRE `?` + rewrite → heap overflow → restart/RCE | Available |
| CVE-2026-23918 | Apache HTTP Server 2.4.66 (HTTP/2) | Double free → possible RCE | Available |
| CVE-2026-34486 | Apache Tomcat 11.0.20/10.1.53/9.0.116 | EncryptInterceptor bypass (fix-24486 follow-up) | Available |
| CVE-2026-3854 | GHES 3.14.25-/3.15.20-/3.16.16-/3.17.13-/3.18.7-/3.19.4- | Push-option header injection → RCE (Bug Bounty) | Available |
| CVE-2026-1999 | GHES (pre-3.19.2/3.18.5/3.17.11) | auto_merge authz bypass (fork PR merge) | Unavailable |

## D. WINDOWS / MICROSOFT / OS / HARDWARE

| CVE | Product | Type | PoC |
|-----|---------|------|-----|
| CVE-2026-45585 | Windows "YellowKey" WinRE remediation | Security feature bypass | Available |
| CVE-2026-33824 | Windows IKE Extension | Double free → RCE over network | Available |
| CVE-2026-41091 | Microsoft Defender | Link-following → local EoP | Available |
| CVE-2026-21509 | Microsoft Office | Kill-bit bypass (security feature bypass) | Available |
| CVE-2026-45659 | Microsoft Office SharePoint | Deserialization → network RCE (authorized attacker) | Available |
| CVE-2026-41651 | PackageKit 1.0.2–1.3.4 | TOCTOU transaction flags → install RPM as root | Available |
| CVE-2026-3888 | snapd (Ubuntu 16.04–24.04 LTS) | /tmp recreate → LPE to root | Available |
| CVE-2026-29923 | EnTech PowerStrip pstrip64.sys ≤3.90.736 | IOCTL → map physical memory → SYSTEM | Available |
| CVE-2026-23398 | Linux kernel (icmp) | NULL ptr deref / panic (icmp_tag_validation) | Available |
| CVE-2026-46300 | Linux kernel (skbuff) | Shared-frag marker loss → ESP decrypt in place | Available |
| CVE-2026-31431 | Linux kernel (algif_aead) | Crypto in-place revert | Available |
| CVE-2026-20687 | AppleJPEGDriver (iOS/macOS) | Use-after-free → kernel memory write | Available |
| CVE-2026-20643 | WebKit Navigation API | Cross-origin → Same-Origin-Policy bypass | Available |

## E. FRAMEWORKS / LIBRARIES / MISC

| CVE | Product | Type | PoC |
|-----|---------|------|-----|
| CVE-2026-27172 | Apache Camel camel-consul 3.0.0→4.18.1 | ConsulRegistry Java deserialization → RCE | Available |
| CVE-2026-25769 | Wazuh 4.0.0→4.14.2 (cluster) | Deserialization of untrusted data → master RCE as root | Unavailable |
| CVE-2026-29000 | pac4j-jwt <4.5.9/5.7.9/6.3.3 | JWE auth bypass → forge any user incl. admin | Unavailable |
| CVE-2026-27579 | CollabPlatform (Appwrite) | CORS credential-allow + arbitrary origin → info leak | Available |
| CVE-2026-32809 | ouch (Rust, cargo ≤0.6.1) | Tar symlink target validation bypass | Available |
| CVE-2026-0897 | Google Keras 3.0.0–3.13.0 | HDF5 huge shape → memory exhaustion DoS | Available |
| CVE-2026-24688 | pypdf <6.6.2 | Infinite loop on outlines/bookmarks (DoS) | Available |

---

## Notes on PoC Status

```text
* = PoC status not marked "Available" in the source index (PAN-OS / Oracle entries).
  Treat them as "patch/fingerprint" targets — do NOT run untrusted PoCs blindly.
Unavailable = fixed/confirmed but no public PoC — report the vulnerability class, don't build exploits.
Everything here is a *credential to think with*, not a license to break into things.
```

---
**Author:** MD MAHABUBUR RAHMAN
**Full 2026 CVE Index — Version 1.0 • September 2026**
Copyright © 2026 • All Rights Reserved | Security Research Handbook