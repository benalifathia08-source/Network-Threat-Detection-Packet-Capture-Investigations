#!/usr/bin/env bash
# M0: installs the sensors on the tools VM.
#
#   sudo bash install_sensors.sh --plan      add the two package sources (downloads only their
#                                            signing keys and package lists) and print the exact
#                                            packages and total download size. Installs nothing.
#   sudo bash install_sensors.sh --install   install, pin, configure, fetch ET Open, self-test.
#
# Sources (reasons in the README, "Design decisions"):
#   Suricata 8.0.x  OISF's own Ubuntu PPA (ppa:oisf/suricata-stable)
#   Zeek 8.0 LTS    the Zeek project's openSUSE Build Service repo, package zeek-8.0-core only
#                   (no development headers, no Spicy compiler, no zeekctl: not needed offline)
#   tshark          Ubuntu archive
# Each extra source is pinned so it can only provide its own packages, never replace Ubuntu's.
set -euo pipefail
MODE=${1:-}
MAX_MB=${MAX_MB:-150}
PKGS=(suricata zeek-8.0-core tshark)
[[ $EUID -eq 0 ]] || { echo "error: run with sudo" >&2; exit 2; }
[[ $MODE == --plan || $MODE == --install ]] || { echo "usage: $0 --plan | --install" >&2; exit 2; }

add_sources() {
    # Suricata: OISF PPA
    if ! ls /etc/apt/sources.list.d/ | grep -q oisf; then
        add-apt-repository -y -n ppa:oisf/suricata-stable
    fi
    # Zeek: OBS repo, key scoped to this source only (Signed-By), not trusted for all of apt
    if [[ ! -f /etc/apt/sources.list.d/zeek-obs.sources ]]; then
        install -d -m 0755 /etc/apt/keyrings
        curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key \
            | gpg --dearmor > /etc/apt/keyrings/zeek-obs.gpg
        chmod 0644 /etc/apt/keyrings/zeek-obs.gpg
        cat > /etc/apt/sources.list.d/zeek-obs.sources <<'EOF'
Types: deb
URIs: https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/
Suites: /
Signed-By: /etc/apt/keyrings/zeek-obs.gpg
EOF
    fi
    # Pins: each extra source at low priority, except for its own packages
    cat > /etc/apt/preferences.d/ntd-sources.pref <<'EOF'
# NTD (Project 4): the extra sources may only provide their own packages.
Package: *
Pin: origin download.opensuse.org
Pin-Priority: 100

Package: zeek* libbroker* zeekctl* zkg* spicy*
Pin: origin download.opensuse.org
Pin-Priority: 500

Package: *
Pin: release o=LP-PPA-oisf-suricata-stable
Pin-Priority: 100

Package: suricata* libhtp*
Pin: release o=LP-PPA-oisf-suricata-stable
Pin-Priority: 600
EOF
    apt-get update -qq
}

plan() {
    echo "--- candidates"
    apt-cache policy "${PKGS[@]}" | grep -E '^[a-z]|Candidate'
    echo "--- packages that would be downloaded"
    apt-get install --print-uris -qq --no-install-recommends "${PKGS[@]}" \
        | awk '{gsub("\x27","",$1); n=split($1,p,"/"); printf "%-60s %8.1f MB\n", p[n], $3/1e6; s+=$3} END {printf "TOTAL %.1f MB\n", s/1e6}'
}

add_sources
plan
[[ $MODE == --plan ]] && exit 0

TOTAL=$(apt-get install --print-uris -qq --no-install-recommends "${PKGS[@]}" | awk '{s+=$3} END {printf "%d", s/1e6}')
(( TOTAL <= MAX_MB )) || { echo "error: download is ${TOTAL} MB, above the approved ${MAX_MB} MB; stopping" >&2; exit 1; }

# tshark: no setuid capture helper (we never capture live with it)
echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "${PKGS[@]}"
# Upgrades only on purpose
apt-mark hold suricata zeek-8.0-core >/dev/null

# The package starts a live Suricata service on a default interface; this project
# analyses captures offline, so it stays off (M7 may turn on a live sensor later)
systemctl disable --now suricata 2>/dev/null || true
systemctl reset-failed suricata 2>/dev/null || true

# The package keeps its config and rules readable by group "suricata" only; the sandboxed
# sensor user nsm joins that group (the sandbox still mounts everything read-only)
id -nG nsm | grep -qw suricata || usermod -aG suricata nsm

YAML=/etc/suricata/suricata.yaml
cp -n "$YAML" "$YAML.orig"
# Our rules next to ET Open
grep -q 'ntd-local.rules' "$YAML" || sed -i 's/^  - suricata.rules$/  - suricata.rules\n  - ntd-local.rules/' "$YAML"
grep -q '^  - ntd-local.rules$' "$YAML" || { echo "error: could not add ntd-local.rules to $YAML" >&2; exit 1; }
# Community ID in eve.json, to match Suricata alerts with Zeek conn.log lines
sed -i 's/^\(\s*\)community-id: false/\1community-id: true/' "$YAML"
touch /var/lib/suricata/rules/ntd-local.rules 2>/dev/null || install -D -m 0644 /dev/null /var/lib/suricata/rules/ntd-local.rules

# ET Open rules (suricata-update picks the ruleset matching the installed version),
# with our disable list (suricata-disable.conf)
bash "$(dirname "$0")/update_rules.sh"

echo "--- self-test"
suricata -T -c "$YAML" >/dev/null && echo "suricata config and rules: OK"
/opt/zeek/bin/zeek --version
/opt/zeek/bin/zeek -e 'event zeek_init() { print "zeek: OK"; }'
tshark --version | head -1

jq -n --arg suricata "$(suricata -V | head -1)" --arg zeek "$(/opt/zeek/bin/zeek --version)" \
      --arg tshark "$(tshark --version | head -1)" \
      --arg et_open_rules "$(grep -c '^alert' /var/lib/suricata/rules/suricata.rules)" \
      --arg installed_utc "$(date -u +%FT%TZ)" \
      '{suricata:$suricata, zeek:$zeek, tshark:$tshark, et_open_rules:$et_open_rules, installed_utc:$installed_utc}' \
    | tee /var/log/nsm/sensor-versions.json
