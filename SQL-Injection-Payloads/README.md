# SQL-Injection-Payloads
> **Author:** MD MAHABUBUR RAHMAN

Curated, attack-order SQLi arsenal (2026 edition). Replace `attacker.com` with your collaborator/DNS server.

## File index (attack order)

| File | Use when |
|------|----------|
| `sqli-Detected-payloads.txt` | First pass: CDN/WAF bypass, detection chars, HPP, JSON, GraphQL, blind + time framework |
| `01-union-error-based.txt` | Found an injectable param -> order-by column count -> UNION ext layer -> error-based data pull |
| `02-blind-boolean-time.txt` | No visible output: binary-search conditional queries + per-DB sleep/time functions |
| `03-stacked-second-order.txt` | Multiple statements allowed, or injection in stored/saved data (profile, pending review) |
| `04-oob-dns-exfil.txt` | Blind injection with outbound DNS/HTTP: exfil column values to your collaborator |
| `05-mssql-rce-functions.txt` | MSSQL backend -> full chain: xp_cmdshell / Agent/OLE->CLR/OPENROWSET file read, UNC |
| `06-modern-dbms-2026.txt` | Detect uncommon DB: NoSQL, JSON/array tricks, ClickHouse, DuckDB, SQLite, H2, TimeScaleDB, cloud |
| `07-sqli-waf-bypass-2026.txt` | WAF is eating payloads: expensive-scan, encoding, comment, error-shield, terminator-only, `IF`-chaining |

## Quick fingerprint cheat-sheet

| Backend | Verdict strings (error messages, banner pages) |
|---------|-------------------------------------------|
| MySQL/MariaDB | `mysqli`, `SQLSTATE`, `Duplicate entry`, `42000` |
| PostgreSQL | `psycopg2`, `pg_query`, `invalid input syntax for`, `42703` |
| MSSQL | `[Microsoft][ODBC SQL Server Driver]`, `Unclosed quotation mark`, `245` |
| Oracle | `ORA-01756`, `ORA-01789`, `ORA-00933` |
| SQLite | `SQLite/JDBCDriver`, `sqlite3.OperationalError` |

## Comment terminators by DB

| Backend | Terminator |
|---------|-----------|
| MySQL | `-- ` (space required) and `#` / `%23` |
| PostgreSQL | `-- ` |
| MSSQL | `-- ` |
| Oracle | `-- ` (no space needed) |
| SQLite | `-- ` and `/* */` |

## OOB/DNS collaborator

- Replace `attacker.com` with your Collaborator / Burp or Interactsh / dnslog.
- Use `<data>.attacker.com` so the exfiltrated value lands in the subdomain record.

## Lab practice
- PortSwigger SQLi labs cover every class here (detection, union, blind math, stacked, Oracle/MSSQL/Postgres quirks). See `OS_Command_Injection/Blind_OS_Command.md` for the same walkthrough style.
