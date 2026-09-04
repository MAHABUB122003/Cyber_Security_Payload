#!/usr/bin/env python3
"""
Basic multi-threaded TCP port scanner + service guess + banner grab.
Authorized use only. Replace TARGET-IP and ports to scan.

Usage:
    python port-scanner-basic.py 192.168.1.1
    python port-scanner-basic.py 192.168.1.1 -p 1-1000
    python port-scanner-basic.py 192.168.1.1 -p 21,22,80,443 --timeout 2

Reads no root needed (connect scan). For SYN you need nmap/scapy.
"""
import argparse
import socket
from concurrent.futures import ThreadPoolExecutor

# Known services by port -> say which port, which service
SERVICE_GUESS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "rpcbind", 135: "MSRPC",
    139: "NetBIOS-SSN", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    873: "rsync", 1080: "SOCKS", 1099: "Java RMI", 1433: "MSSQL",
    1521: "Oracle", 2049: "NFS", 2375: "Docker", 3000: "Grafana",
    3306: "MySQL", 3389: "RDP", 4369: "RabbitMQ", 5000: "Web",
    5432: "PostgreSQL", 5601: "Kibana", 5900: "VNC", 5985: "WinRM",
    5986: "WinRM-HTTPS", 6379: "Redis", 7001: "WebLogic", 8000: "HTTP-alt",
    8443: "HTTPS-alt", 8888: "HTTP-proxy", 9000: "PHP-FPM", 9090: "Prometheus",
    9200: "Elasticsearch", 10000: "Webmin", 11211: "Memcached",
    27017: "MongoDB", 28017: "MongoDB-Status", 50070: "HDFS-NameNode",
    61616: "ActiveMQ",
}


def grab_banner(host, port, timeout):
    """Ask the service to talk; many leak version in <5 chars."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        # Typical quick probes: SMTP, SSH, HTTP, FTP answer back for free
        probe = b""
        if port in (80, 443, 8000, 8080, 8443, 8888, 9000, 9200, 5601, 3000, 9090):
            probe = b"HEAD / HTTP/1.0\r\n\r\n"
        s.send(probe)
        data = s.recv(256)
        s.close()
        return data.decode("utf-8", "ignore").strip().replace("\r", " ").replace("\n", " | ")
    except Exception:
        return ""


def scan_port(host, port, timeout):
    """Try to connect -> open? service? banner?"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
    except Exception:
        return None
    s.close()

    service = SERVICE_GUESS.get(port, "?")
    banner = grab_banner(host, port, timeout)  # can be ""
    return port, service, banner


def parse_ports(spec):
    """'1-1000' or '21,80,443' or mix '1-100,443' -> sorted list."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def main():
    ap = argparse.ArgumentParser(description="Basic TCP port scanner (authorized use only)")
    ap.add_argument("host", help="target IP or hostname (you own it / written permission)")
    ap.add_argument("-p", "--ports", default="1-1024", help="ports, e.g. 1-1000 or 21,22,80")
    ap.add_argument("-t", "--timeout", type=float, default=1.0, help="connect timeout sec")
    ap.add_argument("-T", "--threads", type=int, default=200, help="concurrent threads")
    args = ap.parse_args()

    ports = parse_ports(args.ports)
    print(f"[*] scanning {args.host} -> {len(ports)} ports, {args.threads} threads, timeout {args.timeout}s")

    open_ports = []
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        for res in ex.map(lambda p: scan_port(args.host, p, args.timeout), ports):
            if res:
                open_ports.append(res)
                port, service, banner = res
                print(f"[+] {args.host}:{port:<6} {service:<12} {banner[:80]}")

    print("\n[+] Summary of open ports:")
    for port, service, banner in open_ports:
        note = f"  :: banner: {banner[:80]}" if banner else ""
        print(f"  {port:<6} {service:<12}{note}")

    if not open_ports:
        print("[-] no open ports found in the given range (firewall possible)")


if __name__ == "__main__":
    main()