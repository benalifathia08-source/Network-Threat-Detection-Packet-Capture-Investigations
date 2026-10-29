#!/usr/bin/env bash
# fetch_answers.sh <case-id> <answers-zip-url>
#
# Downloads a case's official answer PDF (only AFTER the report is final, METHODOLOGY
# step 9) into /srv/cases/<case-id>/answers/. Same safety rules as the captures: HTTPS
# from this one site only, list the zip first, refuse it unless it holds exactly one PDF,
# write it under our own name. Runs as fathia.
set -euo pipefail
CASE=${1:?usage: fetch_answers.sh <case-id> <answers-zip-url>}
URL=${2:?}
[[ $CASE =~ ^[a-z0-9][a-z0-9-]{0,39}$ ]] || { echo "error: bad case id" >&2; exit 2; }
[[ $URL =~ ^https://www\.malware-traffic-analysis\.net/[0-9]{4}/[0-9]{2}/[0-9]{2}/[A-Za-z0-9._-]+-answers\.pdf\.zip$ ]] \
    || { echo "error: only https answer zips from malware-traffic-analysis.net" >&2; exit 2; }
ZIP=$(basename "$URL")
DATE=$(echo "$ZIP" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2}' | tr -d -)
DIR=/srv/cases/$CASE/answers
mkdir -p "$DIR"; chmod 2750 "$DIR"
[[ -f $DIR/$ZIP ]] || { curl -fsSL --proto '=https' --max-time 300 -o "$DIR/$ZIP.part" "$URL" && mv "$DIR/$ZIP.part" "$DIR/$ZIP"; }
chmod 0440 "$DIR/$ZIP"
python3 -I - "$DIR/$ZIP" "$DIR/answers.pdf" "${PASSWORD:-infected_$DATE}" <<'PY'
import os, sys, zipfile
zpath, target, password = sys.argv[1], sys.argv[2], sys.argv[3].encode()
with zipfile.ZipFile(zpath) as z:
    members = [m for m in z.infolist() if not m.is_dir()]
    for m in members:
        print(f"zip contents: {m.filename}  {m.file_size:,} bytes")
    if len(members) != 1 or not members[0].filename.lower().endswith(".pdf") or members[0].file_size > 50 * 1024**2:
        sys.exit("error: refused: the zip must hold exactly one PDF under 50 MB")
    if not os.path.exists(target):
        with z.open(members[0], pwd=password) as src, open(target, "xb") as dst:
            dst.write(src.read())
    os.chmod(target, 0o440)
print(f"extracted: {target}")
PY
sha256sum "$DIR/$ZIP" "$DIR/answers.pdf"
