#!/usr/bin/env python3
"""Move finished sensor output into the folder the Wazuh agent watches, without losing lines.

Why this exists (found 2026-10-21): the agent's logcollector starts reading a file it
discovers *from the end*. A log that is already complete when the agent first sees it is
skipped entirely. Its internal queue is also small (1024 lines), so dumping a big file at
once can drop lines.

So, for every file the agent watches:
  1. create it EMPTY in the final folder,
  2. wait until the agent's own log says it found it ("(1957): New file that matches"),
  3. append the real lines at a limited rate (default 300 lines/second).
Files the agent doesn't watch are copied straight away.

Usage (root, called by analyze_pcap.sh):
    publish_logs.py <finished-temp-dir> <final-dir> [lines-per-second]
"""
import os
import shutil
import sys
import time

AGENT_LOG = "/var/ossec/logs/ossec.log"
# Must match tools-vm/wazuh-agent-localfile.xml
WATCHED = {"suricata/alerts.json"} | {
    f"zeek/{name}.log"
    for name in ("conn", "dns", "http", "ssl", "files", "notice", "dhcp", "kerberos", "software", "dce_rpc")
}
WAIT_SECONDS = 240


def chown_nsm(path):
    shutil.chown(path, "nsm", "nsm")


def main():
    src, dst = sys.argv[1], sys.argv[2]
    rate = int(sys.argv[3]) if len(sys.argv) > 3 else 300
    if os.path.exists(dst):
        sys.exit(f"error: {dst} already exists")

    log_start = os.path.getsize(AGENT_LOG)
    watched_here = []
    for root, dirs, files in os.walk(src):
        rel_root = os.path.relpath(root, src)
        out_root = os.path.normpath(os.path.join(dst, rel_root))
        os.makedirs(out_root, mode=0o2750, exist_ok=True)
        chown_nsm(out_root)
        for name in files:
            rel = os.path.normpath(os.path.join(rel_root, name)).replace(os.sep, "/")
            target = os.path.join(out_root, name)
            if rel in WATCHED:
                open(target, "w").close()          # step 1: empty file
                os.chmod(target, 0o640)
                watched_here.append(rel)
            else:
                shutil.copy2(os.path.join(root, name), target)
            chown_nsm(target)

    # step 2: wait for the agent to report each watched file
    pending = {os.path.join(dst, rel) for rel in watched_here}
    deadline = time.time() + WAIT_SECONDS
    print(f"  waiting for the Wazuh agent to pick up {len(pending)} files (checks about once a minute)...", flush=True)
    while pending and time.time() < deadline:
        with open(AGENT_LOG, errors="replace") as f:
            f.seek(log_start)
            new = f.read()
        pending = {p for p in pending if f"'{p}'" not in new}
        if pending:
            time.sleep(3)
    if pending:
        sys.exit("error: the agent did not pick up: " + ", ".join(sorted(pending))
                 + f"\n       (temp output kept in {src})")

    # step 3: fill them at a limited rate
    total = 0
    for rel in sorted(watched_here):
        with open(os.path.join(src, rel), "rb") as fin, open(os.path.join(dst, rel), "ab") as fout:
            sent, t0 = 0, time.time()
            for line in fin:
                fout.write(line)
                sent += 1
                if sent % 50 == 0:
                    fout.flush()
                    ahead = sent / rate - (time.time() - t0)
                    if ahead > 0:
                        time.sleep(ahead)
            fout.flush()
        print(f"  shipped {sent:>6} lines  {rel}", flush=True)
        total += sent
    shutil.rmtree(src)
    print(f"  total {total} lines sent to Wazuh", flush=True)


if __name__ == "__main__":
    main()
