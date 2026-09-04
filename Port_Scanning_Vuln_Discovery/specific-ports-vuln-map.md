# SPECIFIC PORTS -> SERVICE -> VULNERABILITY MAP (2026)
> **Author:** MD MAHABUBUR RAHMAN

> Port open is NOT a vulnerability. Open port + outdated/default/weak config IS. Verify before reporting.
> All checks below are passive/read-only: banner, version, config probe. No brute force without written scope.

## 21 - FTP
- ftp anonymous login: `ftp TARGET-IP` user `anonymous`/`anonymous` -> can you READ/WRITE? (bounce, exfil)
- vsftpd 2.3.4 = CVE-2011-2523 backdoor (legacy pearl, still on old IoT).
- Version -> searchsploit (ProFTPD 1.3.3C mod_copy CVE-2015-3306 = arbitrary file copy).
- NSE: `nmap --script ftp-anon,ftp-vsftpd-backdoor,ftp-proftpd-backdoor -p 21 TARGET-IP`.

## 22 - SSH
- Default creds on routers/cloud images (root/root, admin/admin on IoT, `test` on Moxa etc).
- Old keys: host key in a public PoC/image -> MITM in the right scenario (rarely exploitable externally).
- `-o` weak ciphers / no password auth flags -> not a vuln by itself.
- Ethic guard: do NOT hydra SSH unless scope explicitly allows brute force.

## 23 - Telnet (plaintext!) / 25 - SMTP
- Telnet: default creds on cameras/embedded (admin/1234, root/xc3511). DCS Pan/Tilt CVE-2018-9995 class.
- SMTP open relay: `HELO`, `MAIL FROM:<>`, `RCPT TO:target@elsewhere.com` -> 250 = relay. Auth disclosure via
  `VRFY`/`EXPN` (user enumeration), banner -> searchsploit (Exim, Postfix, Qmail CVEs).

## 53 - DNS
- AXFR zone transfer: `dig @TARGET-IP TARGET.com AXFR` -> full zone=subdomain treasure map.
- Version response `dig @TARGET-IP version.bind chaos txt` -> dnsmasq/BIND -> CVE search.

## 80 / 443 / 8080 / 8443 - Web (THE biggest 2026 attack surface)
- HTTP title/headers, redirects, tech stack (whatweb).
- Standard web tests apply (see ALL_In_One_Manual_Test + every `how-to-test-2026.md` in this repo).
- TLS: `testssl.sh --full TARGET.com` -> old TLS, weak ciphers, expired cert, heartbleed.
- Auth control, api versions exposed, dev/stag instances on unusual ports.

## 111 / 2049 - rpcbind / NFS
- Showmount: `showmount -e TARGET-IP` -> exported shares; mount without auth = full file access.
- NFS no_root_squash -> you can create setuid binaries.

## 135 / 139 / 445 - Windows (MSRPC / NetBIOS / SMB)
- SMB null session: `smbmap -H TARGET-IP`, `crackmapexec smb TARGET-IP`, `enum4linux -a TARGET-IP`.
- SMBv1 + EternalBlue class: `nmap --script smb-vuln-ms17-010 -p 445 TARGET-IP`.
- Shares flagged, SMB signing off -> relay potential.
- Responder-style LLMNR/NetBIOS poisoning for internal 135/139/445 (ONLY on your own lab).

## 873 - rsync
- `rsync --list-only rsync://TARGET-IP/module` -> readable modules, sometimes writeable -> file write/exfil.

## 1099 / 7001 / 8009 - Java (RMI / WebLogic / AJP)
- RMI: `rmi` issuer + `JRMP` deserialization (ysoserial) -> legacy Java RCE chains (only test if in scope).
- WebLogic 7001: CVE-2020-14882/14883 RCE, CVE-2017-10271, console default creds.
- AJP 8009 (Ghostcat CVE-2020-1938): read arbitrary WEB-INF files / file include -> tomcat check.

## 1433 - MSSQL / 1521 - Oracle
- MSSQL: default `sa`/empty or weak, xp_cmdshell enable -> RCE. `nmap --script ms-sql-info`.
- Oracle: 1521 + TNS poisoning (CVE-2012-1675), default accounts (scott/tiger, system), SID brute is noisy -> be careful.

## 2375/2376 - Docker
- Unauthenticated REST: `curl http://TARGET-IP:2375/containers/json` -> if OK: full container takeover
  -> mount host `/` in a privileged container = HOST RCE. Highest impact 2026 finding.

## 3000 - Grafana / 5601 - Kibana / 9200 - Elasticsearch
- Elasticsearch 9200: `curl TARGET-IP:9200/_cat/indices` -> exposed data (PII) if no auth. ES CVE-2015-1427 (old RCE).
- Kibana 5601 (older): CVE-2019-7609 timediff proto pollution RCE; newer -> console bypass issues (verify version).
- Grafana: auth bypass CVEs (CVE-2021-43798 path traversal == read arbitrary files, CVE-2023-6152).

## 3306 - MySQL
- Remote root login + empty/weak password (common on old DB instances inside misconfigured VPC).
- Unauthenticated plugin reads, `SELECT @@version` -> CVE map. Decrypt stored creds in config files.

## 3389 - RDP
- BlueKeep-class on old (CVE-2019-0708) -> `nmap --script rdp-vuln-ms12-020,rdp-ntlm-info`.
- NLA disabled + weak creds -> RDP brute (only if in written scope). Always audit lockdown.

## 4369 - RabbitMQ / 9090 - Prometheus / 10000 - Webmin
- RabbitMQ: guest/guest default, management console exposed -> queue read.
- Prometheus 9090: `curl TARGET-IP:9090/api/v1/targets` -> data + scraping configs (cloud creds).
- Webmin: CVE-2019-15107 = "Password_change.cgi" RCE (pre-1.970) — one of the easiest authenticated RCEs.

## 5432 - PostgreSQL
- Default `postgres`/`postgres`; file read via `COPY ... FROM PROGRAM` (post 9.3) -> if you can run SQL = RCE.
- `pg_hba.conf` trust on misconfigured clouds -> unrestricted.

## 5000/8000/9000/8888 - misc HTTP / 5900 - VNC
- Dev/registration/monitoring panels with default auth or no auth (Docker registry!).
- VNC 5900: no-auth VNC servers (old), 8-char password brute (NOT in default scope).

## 5985/5986 - WinRM
- If you have stolen/weak creds -> PowerShell remoting = RCE. From external usually needs creds first.

## 6379 - Redis
- Unauthenticated (classic 2026 finding on cloud): `redis-cli -h TARGET-IP info` returns data -> run `CONFIG SET dir / var/lib/redis` + `dbfilename` -> write webshell or crontab >> RCE (only on your own assets).
- CVE-2022-0543 (Lua sandbox escape) sensitive `debian/rules`; CVE-2015-8080 key loader.

## 11211 - Memcached
- `printf "stats\n" | nc TARGET-IP 11211` -> stats dump -> sensitive cache values if no auth.

## 27017/28017 - MongoDB
- Default ports + no auth on old deployments -> `mongosh "mongodb://TARGET-IP:27017"` -> show dbs -> PII dump.
- 28017 HTTP status page = default instance fingerprint.

## 50070 - HDFS NameNode / 61616 - ActiveMQ
- NameNode web UI (nobody) -> browse/read HDFS files + configs.
- ActiveMQ: CVE-2016-3088 (fileserver PUT -> webshell), CVE-2023-46604 (OpenWire RCE) — one of the top 2023-Mass CVEs.

## Bonus: UDP top-50 (rarely monitored, great 2026 wins)
- 53 DNS (recursion open -> amplification), 69 TFTP (no-auth file read/write), 123 NTP (monlist amplification),
  161/162 SNMP (public/private community strings -> full device config dump), 500 IPSec keying, 514 syslog read,
  1645/1812 RADIUS, 5353 mDNS, 11211 Memcached UDP (amplification).
- Scan: `nmap -sU --top-ports 50 -sV TARGET-IP`. Check SNMP: `snmpwalk -v2c -c public TARGET-IP`.

## The 2026 + future mindset
- Every open port is only a *door*; the value is: (1) default/no auth, (2) outdated version, (3) sensitive
  data reachable, (4) chain-ability to RCE. Attackers look for cloud-exposed DB/Redis/Docker/MongoDB and
  service meshes (k8s, Kubernetes control-plane ports 6443/10250/30000+), so test those FIRST.
- Verify every finding with 2 tools (nmap + nuclei + manual curl) before writing the report.