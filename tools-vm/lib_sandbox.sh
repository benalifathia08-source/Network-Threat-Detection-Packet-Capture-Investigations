# Shared helpers for the analysis scripts. Source it, don't run it.
#
# sandbox_run <workdir> <writable-dir> <command...>
#   Runs a command as the unprivileged user "nsm" inside a transient systemd unit:
#   - PrivateNetwork=yes  : the process has no network at all (only its own loopback),
#                           so analysing a capture can never contact a real server
#   - ProtectSystem=strict: the whole file system is read-only, except <writable-dir>
#   - ProtectHome=yes     : home folders are invisible
#   - no capabilities, no privilege escalation, no devices, private /tmp
#   - limits: 3 GB memory, 30 minutes
# Needs root (call the scripts with sudo).

CASE_ROOT=/srv/cases
NSM_ROOT=/var/log/nsm/cases

check_case_id() {
    [[ ${1:-} =~ ^[a-z0-9][a-z0-9-]{0,39}$ ]] || { echo "error: case id must be lowercase letters, digits and dashes (got '${1:-}')" >&2; exit 2; }
}

need_root() {
    [[ $EUID -eq 0 ]] || { echo "error: run with sudo" >&2; exit 2; }
}

# Prints the single capture of a case, or fails
case_pcap() {
    local dir="$CASE_ROOT/$1/pcap"
    local files=()
    mapfile -t files < <(find "$dir" -maxdepth 1 -type f \( -name '*.pcap' -o -name '*.pcapng' \) 2>/dev/null | sort)
    [[ ${#files[@]} -eq 1 ]] || { echo "error: need exactly one .pcap/.pcapng in $dir (found ${#files[@]})" >&2; exit 2; }
    printf '%s\n' "${files[0]}"
}

sandbox_run() {
    local workdir=$1 writable=$2
    shift 2
    systemd-run --quiet --wait --pipe --collect \
        --uid=nsm --gid=nsm \
        -p WorkingDirectory="$workdir" \
        -p PrivateNetwork=yes \
        -p ProtectSystem=strict -p ReadWritePaths="$writable" \
        -p ProtectHome=yes -p PrivateTmp=yes -p PrivateDevices=yes \
        -p NoNewPrivileges=yes -p CapabilityBoundingSet= \
        -p ProtectKernelTunables=yes -p ProtectKernelModules=yes -p ProtectControlGroups=yes \
        -p UMask=0027 -p MemoryMax=3G -p RuntimeMaxSec=1800 \
        "$@"
}
