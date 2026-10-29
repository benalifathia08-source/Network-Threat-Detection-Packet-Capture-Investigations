#!/usr/bin/env bash
# analyze_pcap.sh <case-id>
#
# Runs Suricata and Zeek offline on the one capture in /srv/cases/<case-id>/pcap/ and
# writes their JSON logs to /var/log/nsm/cases/<case-id>-<UTC time>/{suricata,zeek}/.
# The Wazuh agent ships those logs to Wazuh (tools-vm/wazuh-agent-localfile.xml).
#
# - Both sensors run sandboxed with no network (lib_sandbox.sh).
# - Output is written to a hidden temp folder first; publish_logs.py then moves it into
#   place in the way the Wazuh agent needs (empty files first, then the lines, throttled).
# - Wazuh gets Suricata ALERTS only (suricata/alerts.json); the full eve.json (flows, DNS,
#   HTTP, TLS...) stays on the VM for analysis, since Zeek already ships those details.
# - Every run has its own folder <case-id>-<UTC time>; /var/log/nsm/latest/<case-id> is the newest.
#
# Usage: sudo bash analyze_pcap.sh case-1
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/lib_sandbox.sh"

need_root
CASE=${1:-}
check_case_id "$CASE"
PCAP=$(case_pcap "$CASE")

# Each run gets a folder name that can never repeat. The Wazuh agent remembers every
# path it has watched, even after the folder is deleted, and skips a reused one.
# /var/log/nsm/latest/<case> points to the newest run (outside the watched folder).
RUN=$CASE-$(date -u +%Y%m%dT%H%M%SZ)
OUT=$NSM_ROOT/$RUN
LATEST=/var/log/nsm/latest
TMP=$NSM_ROOT/.tmp-$RUN
rm -rf "$TMP"
install -d -o nsm -g nsm -m 2750 "$TMP" "$TMP/suricata" "$TMP/zeek"

START=$(date -u +%FT%TZ)
echo "[$START] case $CASE (run $RUN): $(basename "$PCAP")"

echo "  suricata ..."
# -k none: don't drop packets with bad checksums (common in captures)
# unix-command off: no control socket needed offline
sandbox_run "$TMP/suricata" "$TMP/suricata" \
    /usr/bin/suricata -c /etc/suricata/suricata.yaml -r "$PCAP" -k none \
        -l "$TMP/suricata" --set unix-command.enabled=no \
    > "$TMP/suricata/console.txt" 2>&1 || { echo "error: suricata failed, see $TMP/suricata/console.txt" >&2; exit 1; }
jq -c 'select(.event_type=="alert")' "$TMP/suricata/eve.json" > "$TMP/suricata/alerts.json"

echo "  zeek ..."
# -C: ignore checksums. ntd.zeek = Zeek's site policy without outside lookups, plus
# Community ID (the same flow ID Suricata writes) and MAC addresses; JSON output.
sandbox_run "$TMP/zeek" "$TMP/zeek" \
    /opt/zeek/bin/zeek -C -r "$PCAP" /usr/local/share/ntd/ntd.zeek \
    > "$TMP/zeek/console.txt" 2>&1 || { echo "error: zeek failed, see $TMP/zeek/console.txt" >&2; exit 1; }

END=$(date -u +%FT%TZ)

# Run record: what was analysed, with which versions and rules
RULES=/var/lib/suricata/rules/suricata.rules
jq -n \
    --arg case "$CASE" --arg run "$RUN" \
    --arg pcap "$(basename "$PCAP")" \
    --arg sha256 "$(sha256sum "$PCAP" | cut -d' ' -f1)" \
    --argjson bytes "$(stat -c %s "$PCAP")" \
    --arg suricata "$(/usr/bin/suricata -V 2>/dev/null | head -1)" \
    --arg zeek "$(/opt/zeek/bin/zeek --version 2>/dev/null)" \
    --arg ruleset_date "$(date -u -r "$RULES" +%FT%TZ)" \
    --argjson ruleset_rules "$(grep -c '^alert' "$RULES" || true)" \
    --argjson alerts "$(wc -l < "$TMP/suricata/alerts.json")" \
    --arg start "$START" --arg end "$END" \
    --argjson zeek_logs "$(cd "$TMP/zeek" && for f in *.log; do jq -n --arg f "$f" --argjson n "$(wc -l < "$f")" '{($f): $n}'; done | jq -s add)" \
    '{case:$case, run:$run, pcap:$pcap, sha256:$sha256, bytes:$bytes, suricata:$suricata,
      zeek:$zeek, ruleset_date:$ruleset_date, ruleset_rules:$ruleset_rules,
      suricata_alerts:$alerts, zeek_log_lines:$zeek_logs, started_utc:$start, finished_utc:$end}' \
    > "$TMP/run-info.json"
chown -R nsm:nsm "$TMP"; chmod -R g+r,o-rwx "$TMP"

cat "$TMP/run-info.json"
echo "  publishing to $OUT ..."
python3 -I "$HERE/publish_logs.py" "$TMP" "$OUT" "${RATE:-300}"
install -d -o nsm -g nsm -m 2750 "$LATEST"
ln -sfn "../cases/$RUN" "$LATEST/$CASE"
echo "done: $OUT  (also $LATEST/$CASE)"
