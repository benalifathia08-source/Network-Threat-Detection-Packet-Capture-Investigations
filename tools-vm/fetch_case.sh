#!/usr/bin/env bash
# fetch_case.sh <case-id> <zip-url> <expected-bytes>
#
# Downloads one case zip from malware-traffic-analysis.net INTO THE TOOLS VM, checks its
# size, records its SHA-256, and extracts only the capture (extract_pcap.py).
# Runs as fathia (no sudo needed). Files land on the noexec disk:
#   /srv/cases/<case-id>/download/<zip>        the original zip, kept for the record
#   /srv/cases/<case-id>/pcap/<name>.pcap      read-only capture
#   /srv/cases/<case-id>/case-info.json        URL, sizes, hashes, time
#
# The zip password follows the site's scheme (its About page): infected_<date of the post>.
# Set PASSWORD=... to override.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
CASE=${1:?usage: fetch_case.sh <case-id> <zip-url> <expected-bytes>}
URL=${2:?}
EXPECT=${3:?}
[[ $CASE =~ ^[a-z0-9][a-z0-9-]{0,39}$ ]] || { echo "error: bad case id" >&2; exit 2; }
[[ $URL =~ ^https://www\.malware-traffic-analysis\.net/[0-9]{4}/[0-9]{2}/[0-9]{2}/[A-Za-z0-9._-]+\.pcap\.zip$ ]] \
    || { echo "error: only https capture zips from malware-traffic-analysis.net" >&2; exit 2; }

ZIP=$(basename "$URL")
DATE=$(echo "$ZIP" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2}' | tr -d -)
PASSWORD=${PASSWORD:-infected_$DATE}
DIR=/srv/cases/$CASE
mkdir -p "$DIR/download" "$DIR/pcap"
chmod 2750 "$DIR" "$DIR/download" "$DIR/pcap"

if [[ ! -f $DIR/download/$ZIP ]]; then
    curl -fsSL --proto '=https' --max-time 600 -o "$DIR/download/$ZIP.part" "$URL"
    mv "$DIR/download/$ZIP.part" "$DIR/download/$ZIP"
    chmod 0440 "$DIR/download/$ZIP"
fi
SIZE=$(stat -c %s "$DIR/download/$ZIP")
[[ $SIZE == "$EXPECT" ]] || { echo "error: size $SIZE, expected $EXPECT" >&2; exit 1; }
ZIP_SHA=$(sha256sum "$DIR/download/$ZIP" | cut -d' ' -f1)
echo "downloaded $ZIP: $SIZE bytes, sha256 $ZIP_SHA"

OUTPUT=$(python3 -I "$HERE/extract_pcap.py" "$DIR/download/$ZIP" "$DIR/pcap" "$PASSWORD")
echo "$OUTPUT"
PCAP=$(echo "$OUTPUT" | sed -n 's/^extracted: \(.*\)  [0-9,]* bytes$/\1/p')
PCAP_SHA=$(echo "$OUTPUT" | sed -n 's/^sha256: //p')

jq -n --arg case "$CASE" --arg url "$URL" --arg zip "$ZIP" --argjson zip_bytes "$SIZE" \
      --arg zip_sha256 "$ZIP_SHA" --arg pcap "$(basename "$PCAP")" \
      --argjson pcap_bytes "$(stat -c %s "$PCAP")" --arg pcap_sha256 "$PCAP_SHA" \
      --arg fetched_utc "$(date -u +%FT%TZ)" \
      '{case:$case, url:$url, zip:$zip, zip_bytes:$zip_bytes, zip_sha256:$zip_sha256,
        pcap:$pcap, pcap_bytes:$pcap_bytes, pcap_sha256:$pcap_sha256, fetched_utc:$fetched_utc}' \
    > "$DIR/case-info.json"
chmod 0440 "$DIR/case-info.json"
cat "$DIR/case-info.json"
