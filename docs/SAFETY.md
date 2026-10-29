# Safety rules for handling malware traffic

These captures record real infections. The traffic inside them points to real criminal servers, and some download zips on the source site also contain the malware itself. These rules apply to everyone working on this project. If a rule gets in the way, change the rule here first and write down why. Don't quietly work around it.

## 1. Where files live

| What | Where | Never |
|---|---|---|
| Downloaded zips | Tools VM, `/srv/cases/<case>/download/` (owner `fathia`, group `nsm`, no access for anyone else) | On the Windows host, in git, in a shared folder between host and VM |
| Unzipped captures (`.pcap`) | Tools VM, `/srv/cases/<case>/pcap/` (read-only after unzip: `chmod 0400`) | In git, on a USB stick, in a cloud drive |
| Sensor output (Suricata, Zeek JSON) | Tools VM, `/var/log/nsm/cases/<case>/` | In git as full files (excerpts in reports only) |
| Reports, IOC lists, rules | This repo | Live (clickable) indicators: everything is defanged |

`/srv/cases` is a separate 10 GB disk mounted `noexec,nosuid,nodev`, so nothing in it can be run (tested 2026-10-21). Suricata, Zeek and tshark read the captures as the unprivileged user `nsm` inside a sandbox with no network at all. Details and test results are in `PIPELINE.md`.

## 2. What we do with a capture

- **Analyse offline only.** `suricata -r`, `zeek -r`, `tshark -r`, Wireshark "Open". Never `tcpreplay` or any tool that sends the packets onto a network.
- **Never extract files as runnable files.** No Wireshark "Export Objects", no Zeek file extraction to disk, no `binwalk`/`foremost` carving. When a file hash is needed, take it from Zeek's `files.log` (which hashes in memory) or from the report on the case page.
- **Never upload a file anywhere.** VirusTotal and similar services get the **hash** only, as in Projects 2 and 3.
- **Never visit an indicator.** Do not open a URL, domain or IP from a capture in a browser, with `curl`, or with an online "URL checker" that fetches it. Look them up only in services that answer from their own data (for example, a VirusTotal or AbuseIPDB search by name).
- **Never run anything from a capture.** No scripts, no documents, no "let's see what it does". This project is about traffic, not malware analysis.

## 3. Writing about it

- **Defang every indicator** in reports, CSVs, commit messages and chat: `hxxp://`, `example[.]com`, `203.0.113[.]5`. Hashes need no defanging.
- **Victim details in the captures are fake lab data** created by the site's author, but treat them as if they were real: report them because the exercise asks for them, and don't add more than the report needs.
- **Credit and link** the case page. Don't copy the site's text, re-host its captures, or reproduce its answer keys.

## 4. Wireshark GUI (decision F)

| Option | Risk | Effort |
|---|---|---|
| **a. Wireshark inside the tools VM** (if it has a desktop) | Lowest: the capture never leaves the VM | Install `wireshark` from the Ubuntu archive |
| **b. Wireshark on Windows, `.pcap` only** | Low: a `.pcap` is data, not a program. The risk is a mistake (an "Export Objects", or a zip that contains malware). Copy only the unzipped `.pcap` with `scp`, keep it in one folder, delete it after the case | One Wireshark download on the host (needs approval) |
| **c. No GUI, `tshark` only** | None extra | Harder to learn from; no Wireshark screenshots for the README |

Recommendation: **a** if the VM has a desktop, otherwise **b** with the rules above.

**Checked 2026-10-21:** the tools VM is a server install with no desktop, so option **a** is out. Chosen: **b**. Wireshark 4.6.9 is installed on Windows with **Npcap unticked** in the installer: Npcap is a network driver needed only for live capture, and we only open files. Copy only the unzipped `.pcap` to `C:\Users\Fathia\Documents\ntd-pcaps\` (outside the repo and outside OneDrive), never "Export Objects", delete the file when the case is closed. Analysis that doesn't need the GUI stays in the VM with `ntshark.sh`.

## 5. If something goes wrong

- A zip turns out to contain an executable: leave it zipped, note it in the log, delete it from the VM after the case.
- Windows Defender flags anything on the host: stop, don't restore the file, and write down what happened.
- Something was clicked or opened by mistake: stop, note the time, revert the tools VM to its last snapshot.
