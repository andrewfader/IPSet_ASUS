#!/bin/sh
# Runs the lock, start retry and syslog cleanup code from firewall.sh with stubbed commands.
# Usage: tests/test_cron_lock_and_start_retry.sh [path/to/firewall.sh]
S="$(cd "$(dirname "${1:-firewall.sh}")" && pwd)/$(basename "${1:-firewall.sh}")"
T="${TMPDIR:-/tmp}/pr-test.$$"; mkdir -p "$T" || exit 1; trap 'rm -rf "$T"' EXIT; rc=0; cd "$T" || exit 1
ok() { echo "PASS $1"; }; no() { echo "FAIL $1"; rc=1; }
check() { if eval "$2"; then ok "$1"; else no "$1"; fi; }
fn() { awk -v n="$1() {" '$0==n{f=1} f{print} f&&/^}/{exit}' "$S"; }
Log() { :; }; cru() { echo "$*" >> cru.log; }

hold() { ( exec 9<>lock; flock 9; : > held; sleep "$1" ) & holder=$!; while [ ! -e held ]; do sleep 1; done; rm -f held; }

# A scheduled job waits for the lock and reloads settings; anything else exits at once.
eval "$(fn Check_Lock)"
LOCK_FILE=lock; skynetcfg=cfg; : > cfg; Load_Config() { : > reloaded; }
hold 3
( SKYNET_ACTION_ORIGIN=cli; Check_Lock banmalware > /dev/null 2>&1; echo "$?" > cli.rc ) 2> /dev/null
check "interactive command doesn't wait" "kill -0 $holder 2>/dev/null"
( SKYNET_ACTION_ORIGIN=cron; Check_Lock banmalware > /dev/null 2>&1 && : > cron.ok ) 2> /dev/null
check "scheduled job gets the lock after waiting" "[ -e cron.ok ]"
check "settings reload after a wait" "[ -e reloaded ]"
wait "$holder" 2>/dev/null; rm -f reloaded
( SKYNET_ACTION_ORIGIN=cron; Check_Lock banmalware > /dev/null 2>&1 ) 2> /dev/null
check "no reload without a wait" "[ ! -e reloaded ]"

# A failed start schedules a retry and a good one removes it, before the optional work runs.
{ awk '/^if \[ "\$1" = "start" \]; then$/{p=1} p{print} p&&/^fi$/{exit}' "$S"; } > footer.sh
: > cru.log; ( commandstatus=1; set -- start; . ./footer.sh )
check "failed start schedules a retry" "grep -q '^a Skynet_startretry' cru.log"
: > cru.log; ( commandstatus=0; set -- start; . ./footer.sh )
check "good start removes the retry" "grep -q '^d Skynet_startretry' cru.log"
: > cru.log; ( commandstatus=1; set -- banmalware; . ./footer.sh )
check "other commands schedule nothing" "[ ! -s cru.log ]"

# A start that can't reach its USB directory retries too.
eval "$(fn Find_Install_Dir)"
Wait_For_Lock() { :; }; Check_Lock() { :; }; sleep() { :; }; skynetloc=./missing
: > cru.log; ( Find_Install_Dir start > /dev/null 2>&1 )
check "missing USB directory schedules a retry" "grep -q '^a Skynet_startretry' cru.log"
: > cru.log; ( Find_Install_Dir banmalware > /dev/null 2>&1 )
check "missing USB directory, other command: no retry" "[ ! -s cru.log ]"
unset -f sleep

# A retry never queues behind a running command.
{ printf 'LOCK_FILE=lock\nUptime_Seconds() { :; }\nFind_Install_Dir() { echo RAN; }\n'
  awk '/^stime="\$\(Uptime_Seconds\)"$/{p=1} p{print} p&&/^Find_Install_Dir "\$@" \|\| exit 1$/{exit}' "$S"; } > guard.sh
hold 2
check "retry leaves when the lock is busy" "[ -z \"\$(SKYNET_ACTION_ORIGIN=cron sh guard.sh start)\" ]"
wait "$holder" 2>/dev/null
check "retry runs when the lock is free" "[ \"\$(SKYNET_ACTION_ORIGIN=cron sh guard.sh start)\" = RAN ]"

# Disabling removes a pending retry.
eval "$(fn Unload_Cron)"
: > cru.log; Unload_Cron all
check "unloading all schedules removes the retry" "grep -q '^d Skynet_startretry' cru.log"

# IoT settings are read after the lock is taken.
check "IoT settings reload under the lock" "grep -B1 'Apply_WebUI_IOT || commandfailed' '$S' | grep -q Load_Config"

# Only a real kernel line is treated as a DROP record.
eval "$(fn Filter_Syslog_Cleanup)"
cat > sys <<'L'
Nov  8 04:00:00 router kernel: DROP IN=eth0 SRC=1.1.1.1
Nov  8 04:00:01 miniupnpd[9]: x kernel: DROP IN=forged
Nov  8 04:00:02 dnsmasq[1]: ordinary line
L
Filter_Syslog_Cleanup sys > sys.out
check "real DROP line is removed" "! grep -q 'SRC=1.1.1.1' sys.out"
check "forged DROP line stays" "grep -q forged sys.out"

sh -n "$S" && ok syntax || no syntax
exit $rc
