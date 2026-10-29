#!/usr/bin/env python3
"""Reputation lookups for a case's indicators, by NAME or HASH only (docs/SAFETY.md).

Reuses Project 2's lookup code (AI-Phishing-Triage-Assistant/phishtriage/enrich): VirusTotal
and AbuseIPDB with the API keys from that project's .env (read by Project 2's own Settings
class; this script never prints or stores them) and RDAP for domain registration dates.
urlscan.io is never used: it visits the URL, which our safety rules forbid.

Input: a text file, one indicator per line, "domain <name>", "ip <address>" or
"sha256 <hash>". Defanged forms (example[.]com) are accepted. Lines starting with # are
ignored.

Output: a table, and JSON lines with the time of each lookup (for the report's IOC table).

Run with Project 2's virtual environment, from the Network-Threat-Detection folder:
    ../AI-Phishing-Triage-Assistant/.venv/Scripts/python.exe -I scripts/lookup_iocs.py \
        investigations/case-1/lookups.txt investigations/case-1/lookups.jsonl
"""
import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

P2 = Path(__file__).resolve().parents[2] / "AI-Phishing-Triage-Assistant"
sys.path.insert(0, str(P2))

from phishtriage.config import Settings  # noqa: E402
from phishtriage.enrich import Enricher  # noqa: E402
from phishtriage.enrich.cache import Cache  # noqa: E402


def refang(value: str) -> str:
    return value.replace("[.]", ".").replace("[:]", ":").replace("hxxp", "http").strip()


def defang(value: str) -> str:
    return value.replace("http", "hxxp").replace(".", "[.]")


def main():
    src, out = Path(sys.argv[1]), Path(sys.argv[2])
    settings = Settings.load(env_file=P2 / ".env")
    enricher = Enricher(settings, cache=Cache(":memory:"), scan_urls=False)
    results = []
    for raw in src.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        kind, value = raw.split(None, 1)
        value = refang(value)
        if kind == "domain":
            reps = [enricher.virustotal.lookup("domain", value), enricher.rdap.domain(value)]
        elif kind == "ip":
            reps = [enricher.virustotal.lookup("ip", value), enricher.abuseipdb.check(value)]
        elif kind == "sha256":
            reps = [enricher.virustotal.lookup("file", value)]
        else:
            sys.exit(f"error: unknown kind {kind!r}")
        checked = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        for rep in reps:
            # the repo never holds live indicators: defang the looked-up value wherever it
            # appears in the row (target, the VirusTotal / AbuseIPDB link, extra details)
            row = json.loads(json.dumps(asdict(rep)).replace(rep.target, defang(rep.target)))
            row["checked_utc"] = checked
            results.append(row)
            if rep.service == "virustotal" and rep.status == "ok":
                summary = f"{rep.malicious}/{rep.engines} malicious, {rep.suspicious} suspicious {rep.labels or ''}"
            elif rep.service == "abuseipdb" and rep.status == "ok":
                summary = f"confidence {rep.score}%, {rep.extra.get('reports')} reports, {rep.extra.get('isp')} ({rep.extra.get('country')})"
            elif rep.service == "rdap" and rep.status == "ok":
                summary = f"registered {rep.extra.get('registered', '?')} ({rep.extra.get('age_days', '?')} days ago) {rep.extra.get('registrar', '')}"
            else:
                summary = f"{rep.status}: {rep.detail}"
            print(f"{rep.service:<10} {kind:<6} {value.replace('.', '[.]'):<42} {summary}", flush=True)
    with out.open("w", encoding="utf-8", newline="\n") as f:
        for row in results:
            f.write(json.dumps(row) + "\n")
    print(f"saved {len(results)} results to {out}")


if __name__ == "__main__":
    main()
