#!/bin/sh
# Runs the startup, update, lookup and WAN code from firewall.sh with stubbed commands.
# Usage: tests/test_startup_update.sh [path/to/firewall.sh]
S="$(cd "$(dirname "${1:-firewall.sh}")" && pwd)/$(basename "${1:-firewall.sh}")"
T="${TMPDIR:-/tmp}/pr-test.$$"; mkdir -p "$T" || exit 1; trap 'rm -rf "$T"' EXIT; rc=0; cd "$T" || exit 1
ok() { echo "PASS $1"; }; no() { echo "FAIL $1"; rc=1; }
check() { if eval "$2"; then ok "$1"; else no "$1"; fi; }
fn() { awk -v n="$1() {" '$0==n{f=1} f{print} f&&/^}/{exit}' "$S"; }
Log() { :; }

# Restored rules are enforced even if a later optional step fails.
for f in Apply_Rule_Registry_Candidate Update_Domain_Rules Reconcile_Firewall_Rules Whitelist_VPN; do eval "$f() { echo $f >> trace; }"; done
Whitelist_Blocked_Private_IPs() { echo Whitelist_Blocked_Private_IPs >> trace; return 1; }
{ echo 'startup() {'; awk '$0=="Restore_Startup_Policy() {"{f=1} f&&/Apply_Rule_Registry_Candidate/{p=1} p{print} p&&/Whitelist_VPN/{exit}' "$S"; echo '}'; } > start.sh
. ./start.sh; startup
check "rules enforced before optional steps" "grep -q Reconcile_Firewall_Rules trace"
check "failed optional step still stops startup" "! grep -q Whitelist_VPN trace"

# A cold start waits for swap, which comes up just after the mount.
{ echo 'coldstart() {'; sed -n '/^\tstartupswapwait="0"$/,/^\tdone$/p' "$S"; printf '\tCheck_Settings || return 1\n}\n'; } > cold.sh; . ./cold.sh
Swap_Required() { :; }; Check_Swap() { [ -e swapon ]; }; sleep() { : > swapon; }; Check_Settings() { [ -e swapon ]; }
check "cold start waits for swap" "coldstart"
unset -f sleep

# A lower version is refused unless forced. The block is empty if the check is missing.
{ echo '# 31/10/2026 - v9.1.1'; eval "printf '%s\n' \"\$(fn Filter_Version)\""
  awk '/^\tif \[ "\$2" != "-f" \] && ! printf/{p=1} p{print} p&&/^\tfi$/{exit}' "$S"; echo 'exit 0'; } > guard.sh
updatetmp=none; export updatetmp
run_guard() { remotever=$1 sh guard.sh update "$2" > /dev/null 2>&1; }
Log_stub='Log() { :; }'; sed -i "1a $Log_stub" guard.sh
check "lower version refused" "! run_guard v9.0.9 ''"
check "lower version allowed with -f" "run_guard v9.0.9 -f"
check "newer version allowed" "run_guard v9.1.2 ''"
check "same version allowed" "run_guard v9.1.1 ''"

# PPTP and L2TP use ppp0, as PPPoE does; other protocols keep the WAN interface.
awk '/^iface="\$\(nvram get wan0_ifname\)"$/{p=1;print;next} p{print;exit}' "$S" > iface.sh
wan() { nvram() { case "$1 $2" in "get wan0_proto") echo "$proto";; *) echo eth0;; esac; }; . ./iface.sh; echo "$iface"; }
for proto in pppoe pptp l2tp; do check "$proto uses ppp0" "[ \"\$(wan)\" = ppp0 ]"; done
proto=dhcp; check "dhcp keeps its interface" "[ \"\$(wan)\" = eth0 ]"

# CIDR entries pass the IP line filter.
eval "$(fn Filter_IPLine)"
check "CIDR entry accepted" "echo 'add Skynet-Whitelist 192.168.50.0/24 comment x' | Filter_IPLine | grep -q 192.168.50.0/24"
check "plain address accepted" "echo 'add Skynet-Whitelist 8.8.8.8 comment x' | Filter_IPLine | grep -q 8.8.8.8"
check "non-address rejected" "! echo 'add Skynet-Whitelist example.com comment x' | Filter_IPLine | grep -q ."

# Only the answer address on a line is used, not an IP-shaped reverse name after it.
eval "$(fn Domain_Lookup)"; TMP_DIR=.
nslookup() { printf 'Server:    127.0.0.1\nAddress 1: 127.0.0.1 localhost\n\nName:      example.com\nAddress 1: 93.184.216.34 5.6.7.8\n'; }
Domain_Lookup example.com 3 '' t > lookup.out 2>&1; cat ./ns.example_com.t.answers >> lookup.out 2>/dev/null
check "answer address used" "grep -q 93.184.216.34 lookup.out"
check "reverse name ignored" "! grep -q 5.6.7.8 lookup.out"

sh -n "$S" && ok syntax || no syntax
exit $rc
