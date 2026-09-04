# Web Cache Poisoning

Attack the cache, not the origin. By adding a **non-cache-key** (unkeyed) input that influences the response, you poison a cached copy that gets served to every visitor.

## When to test
- Anything behind a CDN / reverse-proxy cache: Cloudflare, Akamai, AWS CloudFront, AWS ALB, nginx caching.
- Static-ish pages that still reflect headers/cookies/session/URL params.

## Core concepts
- **Cache key** = usually `method + path + query + Host (+ maybe Accept/Lang)`.
- **Unkeyed inputs** = headers/params not in the key that still change the response: `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Original-URL`, `X-Rewrite-URL`, `Cookie`, `Referer`, custom headers.
- **Poison** = craft an unkeyed-input that flips the page to attacker-controlled AND that page is cacheable. First visitor (or bot) caches your poisoned page.

## Priority attacks
1. Unkeyed header reflected → XSS / or rewritten link (e.g. cache poisoned `Host` header).
2. Unkeyed header used in redirect / `Location` → open redirect via cache.
3. Cache key confusion (`%2f` vs `/`, param pollution) → serve wrong content.
4. Cache deception: force a response not meant to be cached (user page) into the cache → private data leak.

## Files
- `cache-poisoning-payloads.txt` — header+param matrix.

## Real-world shortcut
1. Load page with a unique `?cb=<random>`.
2. Add candidate unkeyed header with marker value (`X-Test: <marker>`).
3. Does response echo marker anywhere (header/body/redirect)?
4. Repeat a few times > cache hit/hot ratio; if a plain visitor request returns your marker page → cache poisoning.

## Tools
- `Param Miner` (Burp, by PortSwigger) — automated unkeyed header/param discovery
- `cached` npm script — detect cache behavior
- Burp Match/Replace + caching conventions
- `Cache Poisoning Automation` nuclei template set