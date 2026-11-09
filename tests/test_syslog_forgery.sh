#!/bin/sh
# Forged syslog lines must not whitelist anything; real kernel lines still count.
# Usage: tests/test_syslog_forgery.sh [path/to/firewall.sh]
S="${1:-firewall.sh}"; T="${TMPDIR:-/tmp}/pr-test.$$"; mkdir -p "$T" || exit 1; trap 'rm -rf "$T"' EXIT; rc=0
sed -n "/function private_ip/,/\"\${1:-\$syslogloc}\"/p" "$S" | sed '$d' > "$T/p.awk"
cat > "$T/log" <<'L'
Nov  8 04:00:00 miniupnpd[99]: x kernel: [BLOCKED - INBOUND] SRC=10.0.0.0/1 DST=1.1.1.1
Nov  8 04:00:01 miniupnpd[99]: x kernel: [BLOCKED - OUTBOUND] DST=192.168.0.0/1 SRC=1.1.1.1
Nov  8 04:00:02 prog: kernel: [BLOCKED - INBOUND] SRC=10.9.9.9 DST=1.1.1.1
Nov  8 04:00:03 kernel: [BLOCKED - INBOUND] SRC=10.0.0.0/1 DST=1.1.1.1
Nov  8 04:00:04 kernel: [BLOCKED - INBOUND] IN=eth0 SRC=10.1.2.3 DST=1.1.1.1
Nov  8 04:00:05 myhost kernel: [BLOCKED - OUTBOUND] IN=br0 SRC=1.1.1.1 DST=192.168.77.7
L
awk -f "$T/p.awk" "$T/log" > "$T/out" 2>&1
for bad in 10.0.0.0 192.168.0.0 10.9.9.9; do grep -qF "$bad" "$T/out" && { echo "FAIL forged $bad accepted"; rc=1; } || echo "PASS forged $bad ignored"; done
for good in 10.1.2.3 192.168.77.7; do grep -qF "$good" "$T/out" && echo "PASS real $good kept" || { echo "FAIL real $good lost"; rc=1; }; done
exit $rc
