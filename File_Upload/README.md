# File Upload Exploitation — 2026 Arsenal
> **Author:** MD MAHABUBUR RAHMAN

File upload is the highest-impact bug class: chained with a served directory it becomes **RCE** (webshell), with an image viewer it becomes **stored XSS**, with a poor parser it becomes **XXE / SSRF / deserialization**. One miss in the upload chain = full compromise.

## Attack priority (in this order)
1. **Extension → RCE** — get `.php/.jsp/.aspx/.cgi` interpreted on the server.
2. **Content-type / magic-byte bypass** — server trusts MIME/Magic only.
3. **Filename tricks** — trailing dot/space, null byte, unicode, double ext, path traversal.
4. **.htaccess / .user.ini** — drop a config file that turns any upload into code.
5. **Polyglot** — a file that is a valid image *and* valid code.
6. **Stored XSS** — SVG/SVGZ/HTML/DOCX landing in an `<img>`/iframe/attachment viewer.
7. **XXE / SSRF** — SVG/OOXML/PDF parsers with external entities.
8. **IDOR / access control** — uploaded files fetchable/guessable by others.
9. **DoS / zip-bomb / resource abuse** — parser or storage exhaustion.

## Files
| File | Purpose |
|------|---------|
| `upload-bypass-payloads.txt` | **The total chrome-moly bypass matrix** — extensions, magic bytes, filename tricks, polyglots, webshells, post-upload checks. |
| `waf-bypass-payloads.txt` | **WAF/AV evasion for uploads** — signature spoofing, encodings, multipart tricks, per-WAF ladders. |
| `how-to-test-2026.md` | Structured manual-test walkthrough with worked examples + false-positive rules. |

## Golden rule
> If you can write a single executable file into a **web-served** directory, you have RCE.
> Priority: the upload location must be web-accessible:
> `/uploads/`, `/wp-content/uploads/`, `/media/`, avatar, attachment, document, import, cover-image, CSV-import, ZOO/zip import endpoints.

## Minimum toolbelt
- **exiftool** — inject PHP into EXIF comments / polyglots
- **Burp Intruder** — extension ladder, MIME fuzz, multipart tampering
- **upload-fuzz / seclists** — `Fuzzing/file-upload`, `Web-Content/*` wordlists
- **nuclei** — `-tags file-upload` for known plugin uploaders
- **rkhunter / clam** — check if AV fingerprints your payload (for AV-evasion testing)
- **PHP webshell** — keep a minimal one for the final execution proof
- **collaborator/burp** — for SVG/XXE/SSRF out-of-band confirmation

## Ethics
Only test targets you are authorized to attack. Use `<?php echo "POC";?>`-style harmless payloads, then remove them. Uploading malicious webshells to systems you don't own is a crime.
