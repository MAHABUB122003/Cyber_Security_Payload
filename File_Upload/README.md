# File Upload Bypass

Upload vulnerabilities = arbitrary file write → often direct RCE (webshell) or stored XSS (uploaded SVG/HTML). This is one of the highest-impact bugs.

## Priority attacks
1. **Extension bypass** → get `.php`/`.jsp`/`.aspx` on the server.
2. **Content-type / magic-byte bypass** → server validates MIME only.
3. **Filename tricks** (`shell.php.png`, trailing dots, null bytes, unicode).
4. **Polyglot files** → valid image + embedded script.
5. **Stored XSS** via SVG/HTML/DOCX upload.
6. **Full path disclosure** → payload errors tell you webroot.

## Files
- `upload-bypass-payloads.txt` — full bypass matrix + webshells

## Golden rule
If you can write a `.php` file to a served directory, you have RCE. Prioritize: → upload location must be web-accessible (`/uploads/`, `/wp-content/uploads/`, avatars, attachments).

## Tools
- `ImageTragick`/polyglot helpers: `exiftool`, `poc-php` upload testers
- Burp Upload scanner: `extensions` guessing
- `upload-fuzz` wordlists: seclists Web `fuzz/` dirs
- `fileioc` / `wordlists for extensions`