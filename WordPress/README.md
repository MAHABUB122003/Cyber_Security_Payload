# WordPress Security Testing
> **Author:** MD MAHABUBUR RAHMAN

WordPress powers ~43% of all websites. It is the #1 bug-bounty hunting ground for web vulnerabilities — and the easiest place to find a real bug with simple payloads.

## How to use this folder

1. First confirm the site is WordPress:
   - `/wp-login.php`, `/wp-admin/`, `/wp-license.php`
   - Look for `wp-content/`, `wp-includes/` in HTML source
   - `curl -s <target> | grep -i wp-content`
2. Run `wpscan --url <target> --enumerate u,vp,vt --plugins-detection aggressive` for automated coverage.
3. Then use the manual payloads in this folder for things wpscan misses (xmlrpc, REST API user enum, cache poisoning, config backups).

## Files

| File | What it tests |
|------|----------------|
| `wpscan-cheatsheet.md` | Full wpscan usage + flags for bug bounty |
| `wp-user-enumeration.txt` | User enum via REST API, author archives, login errors, sitemaps |
| `wp-xmlrpc-attacks.txt` | xmlrpc.php pingback (SSRF), brute-force amplification, DoS |
| `wp-rest-api-enum.txt` | REST API endpoints leaking data (users, plugins, media, etc.) |
| `wp-config-and-file-discovery.txt` | /.env, backups, wp-config.php copies, debug.log, upload shells |
| `wp-known-plugin-exploits.txt` | High-CVE plugin/theme exploit list + what to check |

## Fastest wins (in order)

1. **User enumeration** → gives you usernames for login brute force.
2. **xmlrpc.php enabled** → `system.multicall` lets you brute force 100s of passwords per request per account.
3. **Unauthenticated plugin CVE** → Plugins > 70% of WP compromises. Check version numbers against CVE lists.
4. **Config/backup exposure** → `.env` or `wp-config.php.bak` = full DB creds + auth keys.
5. **Default admin + weak password** → `admin:admin`, `admin:password` still works on many old sites.

## Legal note

Only test WordPress sites you own or have explicit authorization to assess. Plugin exploits can deface or take over sites — run them only against approved targets.
