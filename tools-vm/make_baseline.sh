#!/usr/bin/env bash
# make_baseline.sh [seconds]
#
# Records a CLEAN capture on the tools VM: ordinary traffic to well-known sites, an apt
# index refresh, DNS lookups and the Wazuh agent's own traffic. Our detection rules
# must stay silent on it (false-positive test, detections/README.md).
# The SSH session to the VM (port 22) is left out of the capture.
# Output: /srv/cases/baseline/pcap/baseline-tools-<UTC date>.pcap (read-only)
#
# Usage: sudo bash make_baseline.sh 90
set -euo pipefail
SECS=${1:-90}
[[ $EUID -eq 0 ]] || { echo "error: run with sudo" >&2; exit 2; }
DIR=/srv/cases/baseline/pcap
install -d -o fathia -g nsm -m 2750 /srv/cases/baseline "$DIR"
rm -f "$DIR"/*.pcap
OUT=$DIR/baseline-tools-$(date -u +%Y%m%d).pcap

tcpdump -i ens33 -s 0 -Z fathia -w "$OUT" 'not port 22' 2>/dev/null &
TCPDUMP=$!
sleep 2

# Ordinary activity, repeated until the time is up
END=$((SECONDS + SECS))
while (( SECONDS < END )); do
    for url in https://ubuntu.com/ https://www.wikipedia.org/ https://github.com/ \
               https://www.debian.org/ http://example.com/ http://neverssl.com/; do
        curl -s -o /dev/null -m 10 -A "Mozilla/5.0 (X11; Linux x86_64) baseline" "$url" || true
    done
    for name in microsoft.com google.com cloudflare.com ntp.ubuntu.com; do
        getent hosts "$name" >/dev/null || true
    done
    apt-get update -qq >/dev/null 2>&1 || true
    sleep 10
done

kill "$TCPDUMP"; wait "$TCPDUMP" 2>/dev/null || true
chown fathia:nsm "$OUT"; chmod 0440 "$OUT"
ls -l "$OUT"
sha256sum "$OUT"
