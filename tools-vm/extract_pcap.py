#!/usr/bin/env python3
"""Safely take the capture out of a password-protected case zip.

Rules (docs/SAFETY.md):
  - list the zip first; refuse it unless it holds exactly ONE member ending in .pcap or
    .pcapng (a zip with a program or document inside is never opened)
  - write the capture under a name WE choose (never the path stored in the zip, which
    could point outside the folder: "zip slip")
  - refuse members larger than 2 GB uncompressed (zip bomb guard)
  - make the capture read-only and print its SHA-256

Usage (as fathia):
    python3 -I extract_pcap.py <zip> <output-dir> <password>
"""
import hashlib
import os
import sys
import zipfile

MAX_BYTES = 2 * 1024**3


def main():
    zpath, outdir, password = sys.argv[1], sys.argv[2], sys.argv[3].encode()
    with zipfile.ZipFile(zpath) as z:
        members = [m for m in z.infolist() if not m.is_dir()]
        print("zip contents:")
        for m in members:
            enc = "encrypted" if m.flag_bits & 0x1 else "not encrypted"
            print(f"  {m.filename}  {m.file_size:,} bytes  ({enc})")
        if len(members) != 1 or not members[0].filename.lower().endswith((".pcap", ".pcapng")):
            sys.exit("error: refused: the zip must hold exactly one .pcap/.pcapng file")
        m = members[0]
        if m.file_size > MAX_BYTES:
            sys.exit("error: refused: capture larger than 2 GB")
        ext = ".pcapng" if m.filename.lower().endswith(".pcapng") else ".pcap"
        name = os.path.basename(zpath)[: -len(".pcap.zip")] if zpath.endswith(".pcap.zip") else "capture"
        target = os.path.join(outdir, name + ext)
        if os.path.exists(target):
            sys.exit(f"error: {target} already exists")
        h = hashlib.sha256()
        written = 0
        with z.open(m, pwd=password) as src, open(target, "xb") as dst:
            while chunk := src.read(1024 * 1024):
                written += len(chunk)
                if written > MAX_BYTES:
                    dst.close()
                    os.remove(target)
                    sys.exit("error: refused: capture grew past 2 GB while extracting")
                h.update(chunk)
                dst.write(chunk)
    os.chmod(target, 0o440)
    print(f"extracted: {target}  {written:,} bytes")
    print(f"sha256: {h.hexdigest()}")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as e:  # wrong password
        sys.exit(f"error: {e}")
    except NotImplementedError as e:  # AES-encrypted zip: needs 7-Zip
        sys.exit(f"error: {e} (AES zip: needs 7-Zip)")
