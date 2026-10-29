#!/usr/bin/env bash
# ntshark.sh <case-id> [tshark options...]
#
# tshark on a case capture, run sandboxed like the sensors (no network, user nsm).
# Wireshark's dissectors parse hostile input; this keeps a parser bug away from the
# analyst's account, which has sudo. Output goes to the terminal.
#
# Examples:
#   sudo bash ntshark.sh case-1 -Y 'dhcp' -T fields -e frame.time_utc -e dhcp.option.hostname
#   sudo bash ntshark.sh case-1 -q -z conv,ip
#   sudo bash ntshark.sh case-1 --capinfos        (summary of the capture)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/lib_sandbox.sh"

need_root
CASE=${1:-}
check_case_id "$CASE"
shift
PCAP=$(case_pcap "$CASE")

if [[ ${1:-} == --capinfos ]]; then
    sandbox_run / /tmp /usr/bin/capinfos "$PCAP"
else
    sandbox_run / /tmp /usr/bin/tshark -n -r "$PCAP" "$@"
fi
