#!/usr/bin/env bash
# Basic Bash TCP port scanner using /dev/tcp (no extra tools needed).
# Authorized use only. Replace TARGET-IP.
#
# Usage:
#   ./port-scan-bash.sh 192.168.1.1 80 443 3306 6379
#   ./port-scan-bash.sh 192.168.1.1 1-1000        (range)
#   PORTLIST="21 22 80 443" ./port-scan-bash.sh 192.168.1.1

TARGET="${1:?Usage: $0 TARGET-IP [PORT...|START-END]}"
shift

# default: top interesting ports
if [ $# -eq 0 ]; then
    PORTS="21 22 23 25 53 80 110 111 135 139 143 443 445 873 1099 1433 1521 2049 2375 3000 3306 3389 4369 5000 5432 5601 5900 5985 5986 6379 7001 8000 8080 8443 8888 9000 9090 9200 10000 11211 27017 61616"
else
    PORTS="$*"
fi

# allow "80-1000" style single arg -> expand
case "$PORTS" in
  *-*) IFS='-' read -r START END <<< "$PORTS"; PORTS=$(seq "$START" "$END") ;;
esac

echo "[*] scanning $TARGET ..."

for P in $PORTS; do
    if timeout 2 bash -c "</dev/tcp/$TARGET/$P" 2>/dev/null; then
        # cheap banner: some services (SSH/FTP/HTTP) greet on connect
        BANNER=$(timeout 2 bash -c "exec 3<>/dev/tcp/$TARGET/$P; head -c 80 <&3; exec 3>&-" 2>/dev/null | tr '\r\n' ' ')
        echo "[+] OPEN  $TARGET:$P  $BANNER"
    fi
done
echo "[*] done."