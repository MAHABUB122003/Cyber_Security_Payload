# SSRF (2026 edition)
> **Author:** MD MAHABUBUR RAHMAN

## File index

| File | Use |
|------|-----|
| `ssrf-2026-ultimate.txt` | Host/port brute list: loopback, RFC1918, link-local, metadata URLs, gopher/smb connector seeds |
| `SSRF-Advanced-Exploitation.md` | Protocol hijack playbooks: DNS AXFR, FastCGI, Memcached, MySQL, Redis, SMTP, WSGI, Zabbix (Swissky-style) |
| `SSRF-Cloud-Instances.md` | Cloud metadata URLs: AWS/GCP/Azure/DO/OCI/Alibaba/Scaleway etc. (incl. IMDSv2 flow) |
| `Blind_SSRF_payload.txt` | Blind SSRF trigger shapes + collaborator-based confirmation samples |
| `ssrf-param-fuzz-wordlist.txt` | Parameter names + payload URL values for automated fuzzing |

## Workflow
1. Find a url/src/href/redirect/import/fetch/style param or any URL that the server pulls server-side.
2. Confirm outbound with a ping/payload to YOUR-COLLABORATOR (Burp Collaborator / interactsh / dnslog).
3. Map the reachable network: loopback -> RFC1918 -> metadata. Use `ssrf-2026-ultimate.txt`.
4. Try to GET sensitive data: /admin, /internal, /health, /v1/*, /actuator, /api*, cloud metadata.
5. Escalate protocol: gopher:// for Redis/Memcached/MySQL/FastCGI/SMTP via `SSRF-Advanced-Exploitation.md`.
6. Watch for write-capable services (Redis EVAL, MySQL INTO OUTFILE) -> webshell on webroot.
7. Bypass WAF/filters (see below); then report with impact proof.

## Filter bypass quick-ref
- 127.0.0.1 -> 127.1, `localhost`, `0`, `0x7f000001`, `0177.0.0.1`, `2130706433`, `[::1]`, `127.0.0.1.nip.io`, `<hex>IPv6`, decimal.
- Redirect: open-redirect cherry on top; 30x loops; DNS rebinding (small TTL + CNAME to 127.0.0.1).
- Encodings: IPv6 tricks, `http://127.0.0.1@pub.attacker` scheme confusion, `//127.0.0.1` protocol-relative, `http:/\\127.0.0.1`, backslash variants for node/go.
- Cloud meta: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`

## Tools
- ffuf with this wordlist; `ssrfmap` (gopher auto), `gopher_flipper` (memory-safe gopher encoder),
  Burp + Collaborator for blind, curl `-x` test harness on your box for payload validation.
- Interactsh for blind OOB; pair with sqlmap `--oob-dns` where applicable.
