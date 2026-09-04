# 2026 BUG BOUNTY PRIORITY CVEs — THE ~20 THAT PAY
> **Author:** MD MAHABUBUR RAHMAN

> Attack-first list: unauthenticated → RCE/auth-bypass wins the biggest bounties. All PoCs verified publicly in 2026. **Authorized scope only.**

---

## TIER 1 — Unauthenticated RCE / auth bypass (max payout)

### 1. WordPress plugin trio — role tampering to admin account takeover
```text
CVE-2026-8206  Kirki plugin          password-reset → arbitrary email (account takeover, unauth)
CVE-2026-5118  Divi Form Builder     user-supplied 'role' param → create admin (unauth)
CVE-2026-1492  User Registration & Membership  supply role during registration → admin (unauth)
```
**Check:** register on the target WP and tamper `role=administrator`; reset any user to your email. Report **critical**.

### 2. WordPress plugin file-upload trio → RCE
```text
CVE-2026-3891  Pix for WooCommerce  missing capability + type check → arbitrary upload → RCE
CVE-2026-1405  Slider Future        missing file-type validation → arbitrary upload → RCE
```
**Check:** upload `shell.php` disguised (`Content-Type: image/jpeg`, `.php.jpg`); visit stored path → executes.

### 3. LiteLLM — the new AI-gateway bounty magnet
```text
CVE-2026-42208  SQLi in API-key check → read/write proxy DB (unauth, error-path reachable)
CVE-2026-42271  /mcp-rest/test/{connection,tools} spawn stdio subprocess → host RCE (any low-priv key)
```
**Check:** bad `Authorization` header to `/chat/completions` → DB error = SQLi; POST an MCP stdio config → RCE.

### 4. Langflow — unauth RCE as root
```text
CVE-2026-0770  exec_globals on /validate endpoint → include untrusted control sphere → RCE as root, NO auth
```
**Check:** crafted POST to `validate` with `exec_globals`; **lab only** — this is a root shell.

### 5. Drupal core SQLi
```text
CVE-2026-9082  Drupal core 8.9.0 → 11.3.10  SQL Injection in core
```
**Check:** identify version via CHANGELOG.txt/`/core/CHANGELOG.txt`, then run confirmed Drupal SQLi technique in lab.

### 6. Ghost CMS — unauthenticated arbitrary DB read
```text
CVE-2026-26980  Ghost 3.24.0 → 6.19.0  unauth arbitrary reads from database
```
**Check:** Ghost API/routes that read DB without auth; lab-verified PoC exists.

### 7. Starlette Host-header bypass
```text
CVE-2026-48710  Starlette < 1.0.1  Host header made request.url differ from raw path → auth/route bypass
```
**Check:** send malformed `Host` (with bad syntax) → middleware that trusts `request.url` passes an unauthorized route.

### 8. Next.js SSRF via WebSocket upgrade
```text
CVE-2026-44578  self-hosted Next.js 13.4.13 → 15.5.16 / 16.2.5  SSRF through crafted WS upgrade
```
**Check:** open a WebSocket upgrade to `/route?url=http://169.254.169.254/...` → SSRF to metadata (Vercel not affected).

---

## TIER 2 — High-value bug-bounty (XSS / path traversal / SQLi)

### 9. Stored XSS in Elementor addon
```text
CVE-2026-1512  Essential Addons for Elementor ≤6.5.9  stored XSS via Info Box widget (contributor+)
```
**Check:** contributor publishes page with crafted Info Box attribute → fires for any viewer.

### 10. osTicket authenticated/guest arbitrary file read
```text
CVE-2026-22200  osTicket <1.18.3/1.17.7  PHP filter expressions in ticket → mPDF export embeds server files as bitmap
```
**Check:** submit ticket with `php://filter` text → export PDF → read local file contents (public guest ticket flows).

### 11. UniFi Network Application path traversal
```text
CVE-2026-22557  path traversal → read files → potentially reach underlying account
```
**Check:** traverse to config/keys in the UniFi API; if it reads an account key — account takeover chain.

### 12. ZoneMinder second-order SQLi
```text
CVE-2026-27470  ≤1.36.37 / 1.37.61–1.38.0  event Name/Cause → raw SQL WHERE via getNearEvents()
```
**Check:** set event Name with SQL → trigger AJAX status query → SQL error/behavior change.

### 13. n8n unauthenticated file access
```text
CVE-2026-21858  n8n 1.65.0 → 1.121.0  form-based workflows expose server files (may be unauth reachable)
```
**Check:** if any exposed form workflow is public → read files/SSRF.

### 14. Apache Superset authenticated SQLi
```text
CVE-2026-23980  <6.0.0  error-based SQLi via sqlExpression / where (user with read access)
```
**Check:** low-priv user hits `/sql/` with crafted expression → DB error = confirmed.

---

## TIER 3 — AI/MCP agent RCE (fast-moving 2026 space, high severity)

```text
CVE-2026-23744  MCPJam inspector ≤1.4.2  binds 0.0.0.0 → unauth RCE via HTTP (patched 1.4.3)
CVE-2026-33032  NginxUI MCP /mcp_message  no auth (empty IP whitelist = allow all) → full nginx takeover
CVE-2026-27825  MCP Atlassian <0.17.0  attachment download path → write anywhere → cron RCE
CVE-2026-26118  Azure MCP Server  SSRF (authorized attacker → privesc)
CVE-2026-22812  OpenCode <1.0.216  unauth local HTTP server + permissive CORS → shell commands (fix 1.0.216)
CVE-2026-25253  OpenClaw one-click RCE  gatewayUrl from query → auto WebSocket + token leak
CVE-2026-32013  OpenClaw symlink traversal  files.get/set out-of-workspace → host file read/write
CVE-2026-22738  Spring AI SpEL injection  SimpleVectorStore filter key → code exec
```
**Why hunt these:** AI agents/MCP servers often run with broad creds and no firewalling — the 2026 bounty frontier.

---

## VERIFICATION QUICK SHEET

```bash
# Product fingerprint → CVEs
whatweb -a 3 https://TARGET
curl -skI https://TARGET | grep -iE "server|x-powered-by|via"
curl -sk "https://TARGET/core/CHANGELOG.txt" | head -5          # Drupal
curl -sk "https://TARGET/wp-json/wp/v2/" | head -c 300           # WP = plugin hunt

# Scan with nuclei against 2026 CVE templates
nuclei -u https://TARGET -t cves/2026/ -severity high,critical

# Manual checks (from source repo PoC folders)
git clone https://github.com/SecureWithUmer/CVE-2026-PoCs
ls CVE-2026-PoCs/2026/CVE-2026-8206/          # read the PoC, replicate ONLY in scope
```

---
**Author:** MD MAHABUBUR RAHMAN
**2026 Bug-Bounty Priority CVEs — Version 1.0 • September 2026**