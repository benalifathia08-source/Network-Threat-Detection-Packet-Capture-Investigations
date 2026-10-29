#!/usr/bin/env bash
# Refreshes the ET Open rules and applies our disable list, then checks the result.
# Run before each case so its report can name the ruleset date (also in run-info.json).
# Usage: sudo bash update_rules.sh
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
[[ $EUID -eq 0 ]] || { echo "error: run with sudo" >&2; exit 2; }

install -o root -g suricata -m 0644 "$HERE/suricata-disable.conf" /etc/suricata/disable.conf
suricata-update --no-test -q --disable-conf /etc/suricata/disable.conf
chmod 0644 /var/lib/suricata/rules/*.rules
suricata -T -c /etc/suricata/suricata.yaml >/dev/null
RULES=/var/lib/suricata/rules/suricata.rules
echo "ET Open: $(grep -c '^alert' "$RULES") active rules, $(grep -c '^# *alert' "$RULES") disabled; config test OK"
echo "checksum rules still active (must be 0): $(grep '^alert' "$RULES" | grep -c 'invalid checksum' || true)"
