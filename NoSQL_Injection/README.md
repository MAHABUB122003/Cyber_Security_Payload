# NoSQL Injection
> **Author:** MD MAHABUBUR RAHMAN

Node.js + MongoDB (and Redis) backends are everywhere. NoSQL injection bypasses login, extracts data, and can even get you RCE via `$where` / JS engine abuse.

## MongoDB — the most common

### How it works
App code like `db.users.findOne({username: req.body.user, password: req.body.pass})`
If the app does string concat, injecting JSON operators turns it into:
```js
db.users.findOne({username: {"$ne": null}, password: {"$ne": null}})
```
→ matches the FIRST user regardless of password.

### Priority attacks
1. **Login bypass** with `$ne` / `$gt` / `$nin`
2. **Blind data extraction** with `$regex`, `$where`, `$ne`
3. **Operator injection on any query param** (search, filter, sort)
4. **`$where` JS execution** → RCE (injection into JS engine)
5. **Server-side JS injection** (SSJS) → RCE

## Redis
- Unauthenticated access on `6379` → write crontab / SSH keys / webshell (SSRF → Redis → RCE chains).
- Use gopher:// to reach Redis via SSRF (see `SSRF/` folder).
- Lua sandbox escape attempts (rare).

## Testing matrix (paste into Burp / postman)
Headers to try JSON body + URL-encoded operator forms. `{"$ne":null}` in JSON body is the send test for every login field, followed by URL-encoded versions when the backend uses query strings.

## Tools
- SQLMap has NoSQL support: `sqlmap -u 'http://target/user?id=1' --dbms=mongodb`
- nosqlmap (python, dedicated scanner)
- Burp extension "NoSQL Injection"
- `mongo-express` playground for building queries
