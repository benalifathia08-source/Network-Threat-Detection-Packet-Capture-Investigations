#!/usr/bin/env bash
# Runs on the Wazuh server. Installs detections/wazuh/nsm_rules.xml as
# /var/ossec/etc/rules/ntd_rules.xml, checks the whole rule set, and restarts the
# manager only if the check passes. On failure the previous file is put back.
# Usage: sudo bash install_rules.sh /path/to/nsm_rules.xml
set -euo pipefail
SRC=${1:?usage: install_rules.sh <nsm_rules.xml>}
DST=/var/ossec/etc/rules/ntd_rules.xml

[[ $EUID -eq 0 ]] || { echo "error: run with sudo" >&2; exit 2; }

BAK=""
if [[ -f $DST ]]; then
    cmp -s "$SRC" "$DST" && { echo "rules unchanged, nothing to do"; exit 0; }
    BAK="$DST.bak-$(date +%Y%m%d%H%M%S)"
    cp -p "$DST" "$BAK"
fi
install -o wazuh -g wazuh -m 0660 "$SRC" "$DST"

if ! /var/ossec/bin/wazuh-analysisd -t >/tmp/ntd-analysisd-test.txt 2>&1; then
    cat /tmp/ntd-analysisd-test.txt >&2
    if [[ -n $BAK ]]; then cp -p "$BAK" "$DST"; else rm -f "$DST"; fi
    echo "error: rule check failed, previous state restored, manager not restarted" >&2
    exit 1
fi
systemctl restart wazuh-manager
echo "rules installed and manager restarted"
