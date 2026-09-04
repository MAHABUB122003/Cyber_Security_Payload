# HOW TO USE CREDENTIAL / LOGIN-LIST TARGETS (2026 expert guide)
> **Author:** MD MAHABUBUR RAHMAN
These lists are for AUTH-AUDITING your own accounts, lab boxes, and authorized tests
(default creds on appliances, idrives, cameras, routers). Not for brute force against strangers.

## The N ways to test legitimate cred use
1. Default & vendor creds: vendor-name+password, admin/admin, admin/password on firmware/appliances.
2. Reuse spotting on YOUR devices: which box still runs default creds?
3. Hash-cracking flows (john/hashcat) when you have legitly-held hashes.
4. Bilingual/password-spec wordlists (passwords.txt lists) for your own lab environments.
5. Base64-encoded admin list (CommonAdminBase64) -> decode for your own scripts.
6. Username enumeration: signup/forgot flow leaks "user exists" - on YOUR apps only.
7. Rate-limit audit: your own login endpoint allowing unlimited tries (fix it, don't exploit it).

## Using the lists correctly
- Asia-pacific password entries (passwords, Bangla/global list): filter latin-only for APIs.
- Pair Username/CommonAdminBase64 with your OWN username files for dashboard testing.
- For authorized SMB/SSH lab tests: hydra/ftp with rockyou not these lists unless scoped.

## Step-by-step audit on a target you authorize
1. Enumerate usernames first (Username/ folder) - leaking patterns, not brute force.
2. Apply default-per-device creds table (e.g., router password = 'admin').
3. Test the signup/SSO reuse vector: many defaults are 'admin/password' -> password reset admin.
4. Audit MFA gaps with the creds you already have.

## False positives & safety
- A valid login on a box you own = OK; don't reuse others' accounts = always consent-based.
- Distinguish "weak password on legit account" (report to owner) vs "default cred left" (fix).

## Tools
- Burp, hydra/medusa (authorized scope), john/hashcat (hashes you hold), ffuf (enumeration), patator.

## WORKED EXAMPLES (concrete)
A. Decode base64 admin list for your own scripts:
AdminBase64 entry "Admin:QWRtaW4="  ->  [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("QWRtaW4="))   -> Admin
(bash) echo "QWRtaW4=" | base64 -d   -> Admin
B. Vendor-default check on a device you own:
hydra -l admin -P rokcyou_mini.txt ssh://10.0.0.5    # only YOUR device
medusa -h 10.0.0.5 -u admin -P defaults.txt -M ssh
C. Username enum on your app (rate-limit audit):
```
for u in admin test user; do curl -s -X POST -d "user=$u&pass=x" https://target.com/login | grep -i "does not exist\|invalid user"; done
D. Credential reuse on your own filtered set:
username found via /forgot "user not found" -> try it against default-password list on the device.
E. Hash cracking (hashes from YOUR target with authorization):
```
john --wordlist=passwords.txt hash.txt
```
hashcat -m 1800 hash.txt passwords.txt
```
