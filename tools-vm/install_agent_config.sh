#!/usr/bin/env bash
# Installs or updates the NTD block in the Wazuh agent's ossec.conf (tools VM), then
# restarts the agent. The block sits between two marker comments, so running this again
# replaces it instead of adding a second copy. A dated backup is kept.
# Also copies our Suricata rules next to the ET Open rules, if Suricata is installed.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
CONF=/var/ossec/etc/ossec.conf
BEGIN='<!-- NTD-BEGIN (Project 4, managed by install_agent_config.sh) -->'
END='<!-- NTD-END -->'

[[ $EUID -eq 0 ]] || { echo "error: run with sudo" >&2; exit 2; }

cp -p "$CONF" "$CONF.bak-ntd-$(date +%Y%m%d%H%M%S)"
# Drop the old managed block (if any), then append the new one as its own <ossec_config>
python3 - "$CONF" "$BEGIN" "$END" "$HERE/wazuh-agent-localfile.xml" <<'PY'
import sys, re
conf, begin, end, snippet = sys.argv[1:]
text = open(conf).read()
text = re.sub(re.escape(begin) + r".*?" + re.escape(end) + r"\n?", "", text, flags=re.S)
block = begin + "\n<ossec_config>\n" + open(snippet).read().rstrip() + "\n</ossec_config>\n" + end + "\n"
open(conf, "w").write(text.rstrip("\n") + "\n\n" + block)
PY
grep -c "NTD-BEGIN" "$CONF" | grep -qx 1 || { echo "error: marker count is not 1" >&2; exit 1; }

systemctl restart wazuh-agent
sleep 5
systemctl is-active --quiet wazuh-agent || { echo "error: agent did not start; backup kept next to $CONF" >&2; exit 1; }
echo "agent restarted with the NTD localfile block"

install -D -o root -g root -m 0644 "$HERE/ntd.zeek" /usr/local/share/ntd/ntd.zeek
echo "Zeek policy installed to /usr/local/share/ntd/ntd.zeek"

if [[ -d /var/lib/suricata/rules ]]; then
    install -o root -g root -m 0644 "$HERE/../detections/suricata/local.rules" /var/lib/suricata/rules/ntd-local.rules
    echo "Suricata custom rules copied to /var/lib/suricata/rules/ntd-local.rules"
fi
