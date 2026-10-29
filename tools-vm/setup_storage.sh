#!/usr/bin/env bash
# Creates the locked storage for malware captures on the tools VM (docs/SAFETY.md section 1).
#   nsm              system user with no shell, no sudo, no home: Suricata and Zeek run as this user
#   /srv/cases       separate 10 GB logical volume, mounted noexec,nosuid,nodev:
#                    nothing stored there can be run, even by mistake.
#                    Owner fathia, group nsm (read only for the sensors)
#   /var/log/nsm     sensor output (Suricata, Zeek), written by nsm, readable by fathia;
#                    the Wazuh agent (logcollector runs as root) ships it to Wazuh
# Safe to run twice: each step checks whether it is already done.
set -euo pipefail

VG=ubuntu-vg
LV=cases
SIZE=10G
MNT=/srv/cases
OWNER=fathia

if ! id nsm >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin nsm
    echo "created system user nsm"
fi
# The analyst reads the sensor output through the nsm group
id -nG "$OWNER" | grep -qw nsm || usermod -aG nsm "$OWNER"

if ! lvs "$VG/$LV" >/dev/null 2>&1; then
    lvcreate -y -L "$SIZE" -n "$LV" "$VG"
    mkfs.ext4 -q -L cases "/dev/$VG/$LV"
    echo "created logical volume $VG/$LV ($SIZE)"
fi

mkdir -p "$MNT"
if ! grep -q "^/dev/$VG/$LV " /etc/fstab; then
    echo "/dev/$VG/$LV $MNT ext4 noexec,nosuid,nodev 0 2" >> /etc/fstab
    systemctl daemon-reload
fi
mountpoint -q "$MNT" || mount "$MNT"
rm -rf "$MNT/lost+found"

# setgid: new case folders inherit group nsm
chown "$OWNER:nsm" "$MNT"
chmod 2750 "$MNT"

install -d -o nsm -g nsm -m 2750 /var/log/nsm /var/log/nsm/cases

echo "--- result"
findmnt -no SOURCE,TARGET,OPTIONS "$MNT"
ls -ld "$MNT" /var/log/nsm /var/log/nsm/cases
id nsm
