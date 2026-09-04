# HOW TO SCAN PORTS AND FIND VULNERABILITIES (2026 expert guide)
> **Author:** MD MAHABUBUR RAHMAN

> Authorized testing only. Replace `TARGET.com`, `TARGET-IP`, `YOUR-IP` with your real (written-permission) scope.

## The N ways to test
1. Full connect() scan of the top-1000 TCP ports -> which services are open.
2. SYN/half-open scan (needs raw sockets / root) -> faster, often bypasses no-logs firewalls.
3. Service version fingerprinting (banner grab + nmap -sV) -> version -> CVE lookup.
4. UDP top-50 (DNS, SNMP 161, NTP 123, TFTP 69) -> UDP services are rarely tested = free wins.
5. Host discovery first (-sn), then port scan only live hosts -> saves time on big ranges.
6. Service-specific probes (HTTP methods, SMTP VRFY, SSH banners, TLS certs) -> weak config evidence.
7. 2026 approach: scan only exposed + rarely-monitored ranges (cloud IPs, floating DHCP, backup/VPN nets).
8. Combine port scan output with an authenticator: shodan/censys lookup of the same IP:port for prior banners.
9. Nmap NSE scripts for the detected service -> targeted check instead of shotgun CVE guessing.
10. Automated pipeline: masscan (fast) -> nmap -sV (precise) -> nuclei/headers/sslscan (vuln) -> report.

## Step-by-step on target
1. Ask scope: which IPs/domains, which ports are OFF-LIMITS (some scopes forbid fuzzing or SSH login).
2. Host discovery: `nmap -sn TARGET-IP/24` or `fping -ag 10.0.0.0/24`.
3. Fast port scan: `nmap -T4 -p- --min-rate=2000 TARGET-IP` (all 65535, ~seconds on good links).
4. Version scan on found ports: `nmap -sV -sC -p <open ports> TARGET-IP` -> banner + default checks.
5. For the 25 most dangerous services run the NSE script group: `nmap --script vuln -p <ports>`.
6. Manual probe high-value services (see `specific-ports-vuln-map.md`): Redis, Docker, MongoDB, RDP, SMB, SMTP.
7. Cross-reference version strings with CVE databases (nuclei -T, cve.org, exploit-db) -> pick exploit path.
8. Test for **default credentials** + **weak auth** on exposed dashboards (Grafana 3000, Kibana 5601, etc.).
9. Confirm impact with the LEAST intrusive proof (read a harmless file, run `id`, dump one banner), then stop.
10. Write the report: IP, port, service, version, evidence, CVSS, remediation (patch, firewall, auth).

## Quickfire commands (copy-paste)
```
# Fast host discovery
nmap -sn TARGET-IP/24
fping -ag TARGET-IP/24

# Full port sweep (all TCP)
nmap -T4 -p- --min-rate=2000 TARGET-IP | tee ports.txt

# Precise fingerprinting of the open ports
nmap -sV -sC -O -p $(paste -sd, ports-open.txt) TARGET-IP

# Top dangerous ports only, fast
masscan -p21,22,23,25,53,80,110,135,139,143,443,445,873,1080,1099,1433,1521,2049,2375,3000,3306,3389,4369,5000,5432,5601,5900,5985,5986,6379,7001,8080,8443,8888,9000,9090,9200,10000,11211,27017,50070,61616 TARGET-IP

# Service-specific NSE (quick wins)
nmap --script redis-info -p 6379 TARGET-IP
nmap --script smb-vuln* -p 139,445 TARGET-IP
nmap --script http-enum,http-title -p 80,443,8080 TARGET-IP
nmap --script docker-version-info -p 2375 TARGET-IP
nmap --script ssl-enum-ciphers -p 443 TARGET-IP

# CVE followers (2026 standard)
nuclei -u https://TARGET.com -t cves/ -stats
searchsploit <exact-version-string>
```

## Worked example (real flow)
```
# 1 - host is alive
ping TARGET-IP

# 2 - sweep
nmap -T4 -p- --min-rate=2000 TARGET-IP
# ... 3306/tcp open  mysql, 6379/tcp open  redis, 80/tcp open http

# 3 - version
nmap -sV -sC -p 3306,6379,80 TARGET-IP
#   redis 5.0.7, nginx 1.18, mysql 8.0.30

# 4 - probe redis (unauthenticated is the classic 2026 bug)
redis-cli -h TARGET-IP info
#   -> "NOAUTH" missing = unauthenticated = NOT OK, you can read keys:
redis-cli -h TARGET-IP keys '*'    # proof: list db keys, don't modify them

# 5 - correlate version
searchsploit redis 5.0    # and nuclei -t cves/2020/... Redis-related
# MySQL 8.0.30 => exploit for CVE-2022-XXXX area, guide from map file
```

## False positives & ethics
- Banner says version X but service is patched -> verify by actual behavior, don't report pure guesses.
- Firewall may let SYN connect() pass but drop real sessions -> re-test top 2 ports twice.
- `nmap --script vuln` will flag theoretical mismatches -> confirm before reporting.
- Do NOT brute force, Do NOT drop data, Do NOT install backdoors. Only prove, screenshot, report.
- Logged SSH brute attempts are usually OUT of scope -> never use hydra against SSH unless written in scope.

## Tools
- masscan (fast sweep), nmap + NSE (state of the art), rustscan (blazing full-port), nuclei (CVE templates),
  sslscan/testssl.sh (TLS), whatweb/wappalyzer (HTTP stack), shodan/censys (internet-wide context),
  rcrack/naabu (alt), powershell Test-NetConnection (ad-hoc), your own code in this folder.
- Service access & brute-force one-shot manual: see `lab-service-access-cheatsheet.md` in this folder.