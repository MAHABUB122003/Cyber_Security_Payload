# LDAP Injection

LDAP injection attacks directory services (Active Directory, OpenLDAP) via web forms that build LDAP filters from user input. Effects: authentication bypass, info disclosure, filter manipulation.

## Where
- Login/portal fields that query AD: "username", "search user", "email lookup"
- Admin panels, "forgot password" forms, user-search features
- Parameters like `uid`, `mail`, `sn`, `cn`, `ou`

## Priority
1. **Auth bypass** — inject into a filter like `(&(uid=USER)(userPassword=PASS))`.
2. **Filter manipulation** — reveal DB info via `*`/`)(&)`, wildcards.
3. **Mass extraction** — `uid=*` returns all records.

## Files
- `ldap-injection-payloads.txt` — full list

## Test basics
```
*            → returns everything
*)(uid=*     → closes filter early
)
)(cn=*))(|(cn=*
admin)(|(password=*
```
Code frequently concatenates `(&(objectClass=user)(uid="+user+"))`.

## Tools
- Burp Intruder wordlist below.
- `nmap --script ldap*` if directory exposed directly (different scenario).
- SQLMap has `--dbms=ldap` (blind extraction) with `--prefix/--suffix`.