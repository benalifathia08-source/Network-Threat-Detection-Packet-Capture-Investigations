#!/usr/bin/env bash
# Run from Git Bash on the laptop, in the repo folder: bash scripts/deploy.sh [tools|wazuh|all]
# Copies the repo's tools-vm/ and detections/ to the tools VM and installs the agent block,
# and/or installs the Wazuh rules on the server.
# Uses Windows OpenSSH because the lab key's passphrase is held by the Windows ssh-agent.
set -euo pipefail
cd "$(dirname "$0")/.."
SSH=/c/Windows/System32/OpenSSH/ssh.exe
SCP=/c/Windows/System32/OpenSSH/scp.exe
TOOLS=fathia@192.168.145.20
WAZUH=fathia@192.168.145.128
WHAT=${1:-all}

if [[ $WHAT == tools || $WHAT == all ]]; then
    "$SSH" -o BatchMode=yes "$TOOLS" 'rm -rf ~/ntd/tools-vm ~/ntd/detections && mkdir -p ~/ntd'
    "$SCP" -q -r tools-vm detections "$TOOLS:ntd/"
    "$SSH" -o BatchMode=yes "$TOOLS" 'sudo bash ~/ntd/tools-vm/install_agent_config.sh'
fi

if [[ $WHAT == wazuh || $WHAT == all ]]; then
    "$SSH" -o BatchMode=yes "$WAZUH" 'mkdir -p ~/ntd'
    "$SCP" -q detections/wazuh/nsm_rules.xml wazuh/install_rules.sh "$WAZUH:ntd/"
    "$SSH" -o BatchMode=yes "$WAZUH" 'sudo bash ~/ntd/install_rules.sh ~/ntd/nsm_rules.xml'
fi
