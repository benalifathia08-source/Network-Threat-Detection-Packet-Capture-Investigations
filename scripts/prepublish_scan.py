#!/usr/bin/env python3
"""Pre-publish scan: nothing live, nothing secret, nothing personal in the files to publish.

Checks every file git tracks (or every file under a folder given as argument):
  1. live indicators: every domain / IP / URL from investigations/*/iocs.csv, refanged,
     must not appear anywhere in clickable form (defanged forms are fine);
  2. URLs: every http(s) URL must point to an allowlisted reference site;
  3. secrets: private keys, API-key assignments, passwords, bearer tokens;
  4. personal data: e-mail addresses (only noreply addresses are allowed);
  5. private material: the working log and the draft folder must not be in the files, and
     no file may mention the AI assistant or its vendor (the private notes stay private).
Exit 1 on any finding, with file:line for each.

Usage: python -I scripts/prepublish_scan.py [folder]   (default: the git-tracked files)
"""
import csv
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_URL_HOSTS = {
    "www.malware-traffic-analysis.net", "malware-traffic-analysis.net", "github.com", "suricata.io",
    "zeek.org", "docs.zeek.org", "www.wireshark.org", "wazuh.com", "rules.emergingthreats.net",
    "www.virustotal.com", "www.abuseipdb.com", "rdap.org", "download.opensuse.org",
    "launchpad.net", "ppa.launchpadcontent.net", "attack.mitre.org", "isc.sans.edu",
    "www.w3.org",
    # benign sites the clean-baseline script visits
    "ubuntu.com", "www.wikipedia.org", "www.debian.org", "example.com", "neverssl.com",
}
SECRET_PATTERNS = [
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key"),
    (r"(?i)(?<![&?])\b(api[_-]?key|apikey|secret|password|passwd|token)\s*[:=]\s*['\"]?[A-Za-z0-9/+_\-]{12,}", "secret assignment"),
    (r"(?i)authorization:\s*bearer\s+[A-Za-z0-9._\-]{10,}", "bearer token"),
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS key"),
]
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# Words are split so this file doesn't match itself.
PRIVATE_WORDS = re.compile("|".join(["cla" + "ude", "anth" + "ropic", "PROJECT" + "_LOG", "docs/" + "port" + "folio"]), re.I)
PRIVATE_PATHS = ("PROJECT" + "_LOG.md", "docs/" + "port" + "folio/")


def refang(value):
    return value.replace("hxxp", "http").replace("[.]", ".").replace("[:]", ":").strip()


def files_to_scan(folder):
    if folder:
        base = Path(folder)
        return [p for p in base.rglob("*") if p.is_file() and ".git" not in p.parts]
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return [ROOT / line for line in out.splitlines()]


def live_indicators(base):
    found = set()
    for path in base.glob("investigations/*/iocs.csv"):
        for row in csv.DictReader(open(path, encoding="utf-8")):
            if row["type"] in ("domain", "ip", "url"):
                value = refang(row["indicator_defanged"])
                if row["type"] == "url":
                    value = value.split("<")[0]  # templated URLs: keep the fixed prefix
                found.add(value)
    # context services (legitimate) are allowed in clear text
    return {v for v in found if v not in {"drive.google.com", "nodejs.org", "registry.npmjs.org", "dns.google"}}


def main():
    folder = sys.argv[1] if len(sys.argv) > 1 else None
    base = Path(folder) if folder else ROOT
    indicators = live_indicators(base)
    findings = []
    for path in files_to_scan(folder):
        if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".pcap", ".bundle"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        rel = path.relative_to(base) if folder else path.relative_to(ROOT)
        if str(rel).replace("\\", "/").startswith(PRIVATE_PATHS):
            if folder:
                findings.append(f"{rel}: private file in the upload")
            continue
        for n, line in enumerate(text.splitlines(), 1):
            for ind in indicators:
                # a live indicator: the exact text, not followed/preceded by more host characters
                if re.search(r"(?<![\w.\-])" + re.escape(ind) + r"(?![\w\-]|\.[a-z])", line):
                    findings.append(f"{rel}:{n}: live indicator {ind!r}")
            for url in re.findall(r"https?://[^\s)\"'<>|`\]]+", line):
                host = url.split("/")[2].split(":")[0].lower()
                if "\\" in host:  # a regex in a script, not a link
                    continue
                if host not in ALLOWED_URL_HOSTS:
                    findings.append(f"{rel}:{n}: URL to a non-allowlisted host: {url}")
            for pattern, label in SECRET_PATTERNS:
                if re.search(pattern, line):
                    findings.append(f"{rel}:{n}: possible {label}")
            if PRIVATE_WORDS.search(line):
                findings.append(f"{rel}:{n}: private reference: {PRIVATE_WORDS.search(line).group(0)!r}")
            for email in EMAIL.findall(line):
                if "noreply" not in email.lower():
                    findings.append(f"{rel}:{n}: e-mail address {email}")
    for f in findings:
        print(f)
    print(f"scanned {len(files_to_scan(folder))} files, {len(indicators)} indicators: {len(findings)} findings")
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
