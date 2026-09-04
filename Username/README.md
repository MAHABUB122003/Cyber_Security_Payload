# Username Wordlists

Curated usernames for login/SSH/RDP/application enumeration and spraying.
Pair with password lists in `../Credentials/`. Authorized targets only.

## Files

| File | Contents | Use |
|------|----------|-----|
| `top-usernames-shortlist.txt` | 16 highest-value usernames (root, admin, ec2-user, vagrant, azureuser...) | Manual fuzz / ffuf first pass |
| `cirt-default-usernames.txt` | CIRT default usernames (appliance/device/admin defaults) | Device/panel login fuzz |
| `mssql-usernames-nansh0u-guardicore.txt` | MSSQL-specific usernames (nansh0u + guardicore merge) | MSSQL auth brute/service accounts |
| `sap-default-usernames.txt` | SAP system default usernames | SAP panels/routers |
| `CommonAdminBase64.txt` | Common admin usernames: `name:base64(name)` dual format (both sections base64-clean, verified) | Burp Intruder where params must be base64 |
| `xato-net-10-million-usernames-dup.txt` | 10M user corpus (SecLists source, dedup'd) | Offline targeted brute after username-from-email |
| `Names/` | USA/India/USA-family forename & family-name lists (top1000) | Username guessing from real names (`j.doe`, `doe.j`...) |
| `Honeypot-Captures/` | Real attacker username captures | Default-cred brute on honeypot-style panels |

## Recommended workflow

```bash
# 1. quick spray with top list
ffuf -u "https://HOST/login" -X POST -d "user=FUZZ&pass=x" \
     -w Username/top-usernames-shortlist.txt -fc 302

# 2. username-from-email regex (already have one mail? build rules)
#    j.doe  john.doe  jdoe  doe.j  johnj  johnd

# 3. device/panel defaults
#    cirt-default-usernames.txt against /administration, /status, router UIs

# 4. full user corpus only when you have a leaker (only use dedup'd file for ids)
```

## Base64 helper (Password Spray / JWT / url-encoded forms)

```bash
# convert top-usernames to base64 (useful for encoded login forms)
while read u; do printf "%s:" "$u"; printf "%s" "$u" | base64 -w0; echo; done \
  < Username/top-usernames-shortlist.txt > Username/top-usernames-b64.txt
```

## Notes
- `xato-net-10-million-usernames-dup.txt` is large; don't feed it to ffuf directly — filter first.
- Passwords for spraying: `../Credentials/top-passwords.txt` and password-spray README.
- Always respect lockout/throttle policies on the target (authorization covers testing, not DoS of the login endpoint).