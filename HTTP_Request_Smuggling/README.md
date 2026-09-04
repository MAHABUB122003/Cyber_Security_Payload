# HTTP Request Smuggling
> **Author:** MD MAHABUBUR RAHMAN

Front-end (proxy/CDN/WAF) and back-end (app server) disagree about where one HTTP request ends and the next begins. This lets you smuggle a second request that the front-end thinks is part of the first — enabling **request queue poisoning, cache poisoning, auth bypass, and XSS**.

## When to test
- Target sits behind any reverse proxy / CDN / LB: nginx, HAProxy, Cloudflare, Akamai, AWS ALB, Netlify.
- HTTP/1.1 raw sockets (Burp Repeater `HTTP/1.1`).
- HTTP/2 endpoints (H2.CL, H2.TE smuggling).

## Technique types
| Type | Frontend uses | Backend uses |
|------|---------------|--------------|
| **CL.TE** | Content-Length | Transfer-Encoding → smuggled body is a NEW request |
| **TE.CL** | Transfer-Encoding | Content-Length |
| **TE.TE** | One obeyed TE header | another TE header (obfuscated) |
| **H2.CL / H2.TE** | HTTP/2 (length known) | HTTP/1.1 smuggling via injected CL/TE |

## Detection basics
1. Send request; if a normal request follows and gets interpreted as a smuggled prefix — you've found it. Usually you detect via:
   - **Timing detections** — `POST` with a body that sleeps, followed by another request that takes ~N seconds.
   - **Response-based** — pairing a request with an unexpected reflected value.
2. PortSwigger's Burp **HTTP Request Smuggler** extension automates detection.

## Payload files
- `smuggling-payloads.txt` — CL.TE / TE.CL / TE.TE / HTTP2 copies

## Impact once confirmed
- User request queue poisoning → steal/reflect victim traffic in your response
- Bypass front-end ACL/WAF → hit admin-only endpoints
- Cache poisoning → serve malicious file.js to everyone
- Credential/CSRF token capture → account takeover

## Automation
```bash
# burp extension
# 1. Install "HTTP Request Smuggler" (PortSwigger).
# 2. Send to "Smuggler" tab for auto-detect of each variant.
nuclei -t http/request-smuggling -u https://target.com
```
Manual: use Repeater in "update Content-Length" off + raw CRLF editing.
