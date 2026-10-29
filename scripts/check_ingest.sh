#!/usr/bin/env bash
# Run from Git Bash on the laptop: bash scripts/check_ingest.sh <run-folder-name>
#   e.g. bash scripts/check_ingest.sh baseline-20261021T210332Z
#
# Checks that Wazuh holds every event of one analysis run: for each log type it compares
# the number of lines shipped from the tools VM with the number of Wazuh alerts for that
# run's files. conn.log and dce_rpc.log events are level 0/1 (counted by rules, not stored
# as alerts), so they are not compared here; their detections are tested by test_detections.py.
set -euo pipefail
RUN=${1:?usage: check_ingest.sh <run-folder-name>}
[[ $RUN =~ ^[a-z0-9-]+-[0-9]{8}T[0-9]{6}Z$ ]] || { echo "error: not a run folder name: $RUN" >&2; exit 2; }
SSH=/c/Windows/System32/OpenSSH/ssh.exe
DIR=/var/log/nsm/cases/$RUN

# Lines shipped, per file (tools VM)
declare -A SENT
while read -r n f; do SENT[$f]=$n; done < <("$SSH" -o BatchMode=yes fathia@192.168.145.20 \
    "cd $DIR && for f in suricata/alerts.json zeek/dns.log zeek/http.log zeek/ssl.log zeek/files.log zeek/notice.log zeek/dhcp.log zeek/kerberos.log zeek/software.log; do [ -f \$f ] && echo \$(wc -l < \$f) \$f; done")

# Alerts stored, per file (Wazuh server)
declare -A GOT
while read -r n f; do GOT[$f]=$n; done < <("$SSH" -o BatchMode=yes fathia@192.168.145.128 \
    "sudo cat /var/ossec/logs/alerts/alerts.json | jq -rR --arg d '$DIR/' 'fromjson? | select(.location|startswith(\$d)) | .location | ltrimstr(\$d)' | sort | uniq -c")

fail=0
printf '%-22s %8s %8s\n' file shipped in-wazuh
for f in $(printf '%s\n' "${!SENT[@]}" | sort); do
    s=${SENT[$f]}; g=${GOT[$f]:-0}
    mark=OK; [[ $s == "$g" ]] || { mark=MISSING; fail=1; }
    printf '%-22s %8s %8s  %s\n' "$f" "$s" "$g" "$mark"
done
exit $fail
