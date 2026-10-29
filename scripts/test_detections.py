#!/usr/bin/env python3
"""Detection tests: does every case rule fire where it must, and stay silent everywhere else?

For each capture in detections/tests/expected.json it takes the LATEST analysis run
(/var/log/nsm/latest/<capture> on the tools VM) and counts:
  - suricata:<sid>  lines with that signature id in the run's suricata/alerts.json
  - wazuh:<id>      Wazuh alerts with that rule id whose location is inside the run folder
A rule passes when it meets its "fire" expectation on the listed captures and has
0 hits on every other capture (the clean baseline and the other cases).

Run from Git Bash on the laptop, in the repo folder:
    python -I scripts/test_detections.py            (prints a Markdown table; exit 1 on failure)
"""
import json
import subprocess
import sys
from pathlib import Path

SSH = "/c/Windows/System32/OpenSSH/ssh.exe" if Path("/c/Windows").exists() else r"C:\Windows\System32\OpenSSH\ssh.exe"
TOOLS, WAZUH = "fathia@192.168.145.20", "fathia@192.168.145.128"
SPEC = Path(__file__).resolve().parents[1] / "detections" / "tests" / "expected.json"


def ssh(host, command):
    return subprocess.run([SSH, "-o", "BatchMode=yes", host, command], capture_output=True, text=True, check=True).stdout


def main():
    spec = json.loads(SPEC.read_text(encoding="utf-8"))
    captures = spec["captures"]

    # Which run folder is "latest" for each capture, and its Suricata SID counts
    runs, suricata = {}, {}
    for cap in captures:
        out = ssh(TOOLS, f"readlink /var/log/nsm/latest/{cap} && jq -r '.alert.signature_id' /var/log/nsm/latest/{cap}/suricata/alerts.json | sort | uniq -c")
        lines = out.splitlines()
        runs[cap] = Path(lines[0]).name
        suricata[cap] = {sid: int(n) for n, sid in (l.split() for l in lines[1:])}

    # Wazuh alert counts per run folder and rule id
    jq = r"""fromjson? | select(.location|startswith("/var/log/nsm/cases/")) | [(.location|split("/")[5]), .rule.id] | @tsv"""
    out = ssh(WAZUH, f"sudo cat /var/ossec/logs/alerts/alerts.json | jq -rR '{jq}' | sort | uniq -c")
    wazuh = {}
    for line in out.splitlines():
        n, run, rid = line.split()
        wazuh.setdefault(run, {})[rid] = int(n)

    def count(rule, cap):
        kind, rid = rule.split(":")
        return suricata[cap].get(rid, 0) if kind == "suricata" else wazuh.get(runs[cap], {}).get(rid, 0)

    print("| Rule | Detects | " + " | ".join(captures) + " | Result |")
    print("|---|---|" + "---|" * len(captures) + "---|")
    failed = 0
    for r in spec["rules"]:
        cells, ok = [], True
        for cap in captures:
            n = count(r["rule"], cap)
            want = r["fire"].get(cap)
            if want is None:
                good = n == 0
            elif "exactly" in want:
                good = n == want["exactly"]
            else:
                good = n >= want["at_least"]
            ok &= good
            cells.append(f"{n}" + ("" if good else " (x)"))
        failed += not ok
        print(f"| `{r['rule']}` | {r['name']} | " + " | ".join(cells) + f" | {'PASS' if ok else 'FAIL'} |")
    print()
    print("Runs: " + ", ".join(f"{c} = `{runs[c]}`" for c in captures))
    print(f"{len(spec['rules']) - failed}/{len(spec['rules'])} rules pass")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
