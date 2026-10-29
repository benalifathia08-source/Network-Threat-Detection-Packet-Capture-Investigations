# Choosing the three cases (decision D)

Source: the training exercises at <https://www.malware-traffic-analysis.net/training-exercises.html>. Each exercise has a scenario, a password-protected zip with the capture, and answers published separately. Read **only the scenario** when choosing. Never open the answers until the report is final (see `METHODOLOGY.md` step 9).

## What makes a good set of three

1. **Different stories.** One infection type per case (for example an information stealer, a loader or backdoor, a remote access tool), so the reports don't repeat each other.
2. **Recent.** 2024–2026 malware families are what job interviews ask about.
3. **Active Directory victim if possible.** Ties into Project 1 and shows the Kerberos/LDAP steps of the method.
4. **A capture of reasonable size.** Under about 50 MB keeps Suricata and Zeek fast on a 4–6 GB VM.
5. **An answer key exists**, so the reports can be measured.

## Shortlist (from the exercise list on 2026-10-20)

Families come from the titles only. The scenario page is read at M2 to confirm what each case is about and its size.

| Date | Title | Family (from title) | Note |
|---|---|---|---|
| 2026-10-01 | "Natureforce" | Not named | Newest; read the scenario to see what it is |
| 2026-09-11 | "Kongtuke rebuke!" | KongTuke (web inject leading to malware) | Recent initial-access technique |
| 2026-01-31 | "Lumma in the Room-ah!" | Lumma Stealer | Information stealer, very common in 2024–2026 |
| 2025-01-22 | "Download from fake software site" | Not named | Fake-installer initial access |
| 2024-08-15 | "WarmCookie" | WarmCookie | Backdoor / loader |
| 2024-07-30 | "You dirty rat!" | Not named (a RAT, by the title) | Remote access tool |

## Choice (2026-10-21, after reading the scenario pages only)

All three are Active Directory networks, all from 2026, and each tells a different story.

| Case | Exercise | Story | Scenario asks for | Download (only this file) |
|---|---|---|---|---|
| **case-1** | [2026-01-31 "Lumma in the Room-ah!"](https://www.malware-traffic-analysis.net/2026/01/31/index.html) | **Information stealer.** Starts from a real-looking SOC situation: an ET alert "Lumma Stealer Victim Fingerprinting Activity" fired; find the host and user | Victim IP, MAC, host name, user account, the user's full name, the domain that triggered the alert | `2026-01-31-traffic-analysis-exercise.pcap.zip`, 21.7 MB |
| **case-2** | [2026-09-11 "Kongtuke rebuke!"](https://www.malware-traffic-analysis.net/2026/09/11/index.html) | **Compromised website → ClickFix** (a fake "verify you are human" page that tricks the user into pasting a command) | Victim IP, MAC, host name, user account, full name | `2026-09-11-traffic-analysis-exercise.pcap.zip`, 54.6 MB. **Not** the bonus `forensic-analysis-files.zip`: the page says it holds the malware itself |
| **case-3** | [2026-10-01 "Natureforce"](https://www.malware-traffic-analysis.net/2026/10/01/index.html) | **Remote access tool.** Two alerts: a Windows program sent over an unusual port (TCP 9000), then CNCmachineRMS RAT command-and-control | Victim IP, MAC, host name, user account, SHA-256 of the program sent over port 9000 | `2026-10-01-traffic-analysis-exercise.pcap.zip`, 33.1 MB |

Why Natureforce over WarmCookie and "You dirty rat!": it is the newest, and it asks for the hash of a program sent over an unusual port. The plan was to rebuild that hash from the stream **in memory**, without ever writing the program to disk. That is a good interview story about doing forensics safely.

*Correction after the investigation:* the program came over **HTTP** on port 9000, so Zeek recognised and hashed it, but only MD5 and SHA-1 (Zeek 8.0's default). The SHA-256 was rebuilt in memory, the pipeline now makes Zeek compute SHA-256 too, and both agree with the answer key.

Total download: 109.4 MB for the three zips.

**Outcome (2026-10-22):** all three investigated; answer keys 7/7, 5/5 and 5/5.
