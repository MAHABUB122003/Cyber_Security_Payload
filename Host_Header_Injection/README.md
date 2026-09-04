# Host Header Injection

If the app builds URLs or looks up users with the `Host` header, you can inject a malicious host → **password reset poisoning, cache poisoning, routing attacks, SSRF**.

## When to test
- Endpoints that generate links/emails: password reset, invites, email verification.
- Anything using `$_SERVER['HTTP_HOST']`, `request.headers['host']`, `req.get('host')`.
- Apps behind misconfigured proxies (X-Forwarded-Host trusted to build URLs).

## Priority attacks
1. **Password reset poisoning** → send victim a reset link pointing to evil.com → steal their reset token → account takeover.
2. **Cache poisoning** → cache page with poisoned host → serve to everyone.
3. **Routing/SSRF** → proxy honors Host → reach internal services.
4. **Virtual-host confusion** → access other vhosts / admin panels.

## Payloads file: `host-header-payloads.txt`

## Fastest reproduction for reset poisoning
1. Trigger reset for victim email.
2. Set `Host: evil.com`.
3. Check the reset link in the email (if it reads `http://evil.com/reset?token=...`) → vuln.
4. Intercept token → take over.



## Tools
- Burp: `Active Scan > Host header` / manual Repeater edits
- `HostHeaderInjectionDNSRebinding` lab practice: PortSwigger labs
- `smuggler`/`http-smuggling` tables don't cover header stuff - just craft manually.