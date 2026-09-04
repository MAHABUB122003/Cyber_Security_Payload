# Information Disclosure / Sensitive File Discovery
> **Author:** MD MAHABUBUR RAHMAN

Finding a leaked `.env`, `.git`, backup, or debug file is often the easiest critical finding. Run these paths with ffuf/gobuster on every target.

## Priority
1. `.env` / `.env.local` — DB creds, API keys, secrets
2. `.git/HEAD`, `.git/config` — clone the source
3. Backup files — `.bak`, `.zip`, `.tar`, `~`, `.swp`
4. Logs, stack traces, and `/actuator` endpoints
5. Cloud metadata — see SSRF folder

## Files
- `sensitive-paths.txt` — the wordlist + curl one-liners

## Tools
```bash
ffuf -u https://target.com/FUZZ -w sensitive-paths.txt -mc 200,301,302,403 -c
gobuster dir -u https://target.com -w sensitive-paths.txt
# git extractor after you find .git:
git-dumper https://target.com/.git/ out/
```
## Report tips
A `.env` leak with an AWS key or DB password is usually **Critical**. Show the leaked file content (redact live secrets) + the URL.
