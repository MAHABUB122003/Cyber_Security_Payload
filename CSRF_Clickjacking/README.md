# CSRF & Clickjacking

Cross-Site Request Forgery (CSRF) + Clickjacking are low-effort, still-readily-found gaps on state-changing endpoints.

## CSRF — the concept
If a "change password / email / transfer" POST accepts a request WITHOUT a CSRF token (and uses cookie auth), an attacker page can fire it from the victim's browser → state change without consent.

### Detection
1. Does the state-changing request require a CSRF token? Remove it / send wrong one.
2. If the request still succeeds → CSRF.
3. Check if "SameSite" cookie is `Strict`/`Lax` (Lax allows top-level GET navigations) → still exploitable for GET-based changes.

## Files
- `csrf-poc-templates.txt` — HTML auto-submitting PoCs (GET & POST)
- `clickjacking.txt` — frame test + PoC iframe

## Clickjacking
Test if the page sets `X-Frame-Options` or `Content-Security-Policy: frame-ancestors`:
```
curl -sI https://target.com/ | grep -i frame
```
Missing both + a sensitive page (account, admin, 2FA setup) = clickjacking report.

## Reporting
CSRF: show (1) no-token request succeeds, (2) an HTML PoC that changes victim data.
Clickjacking: iframe screenshot with buttons aligned over target buttons.