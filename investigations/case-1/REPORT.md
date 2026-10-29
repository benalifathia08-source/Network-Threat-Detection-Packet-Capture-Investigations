# Case 1 — Lumma Stealer infection from a fake file download (2026-01-27)

| | |
|---|---|
| **Source** | [2026-01-31 traffic analysis exercise "Lumma in the Room-ah!"](https://www.malware-traffic-analysis.net/2026/01/31/index.html) (malware-traffic-analysis.net, by Brad Duncan) |
| **Capture** | `2026-01-31-traffic-analysis-exercise.pcap` (27,242,609 bytes), SHA-256 `f755444d0b6eac847e07b73dea0774084b232d8577f536547a12f39b959d7833`; from zip SHA-256 `754b777a5cabe079b86b93663ad9d71e1767174d7ce513f19bc7710f8b0aa573` |
| **Time span** | 2026-01-27 23:04:03 – 23:14:27 UTC (10 min 24 s, 51,181 packets) |
| **Analysed** | 2026-10-21; Wireshark walkthrough of the key findings: [REPRODUCE.md](REPRODUCE.md) |
| **Tools** | Suricata 8.0.7 + ET Open (2026-10-20, 53,222 active rules), Zeek 8.0.10, tshark 4.2.2, Wazuh 4.14 |
| **Verdict** | Windows client DESKTOP-ES9F3ML (user gwyatt) downloaded and ran Lumma Stealer. Within 30 seconds the malware sent about 2 MB to its server, most likely saved browser passwords and cookies. Possible domain group discovery followed. No further contact after 23:06:15. |

> All indicators in this report are defanged. Do not visit them.

## 1. Executive summary

On 27 January 2026 at 23:04 UTC, a user on the WIN11OFFICE network, Gabriel Wyatt (account `gwyatt`), followed a Google Drive link that led to a chain of file-hosting sites. One of them sent the computer a 15.9 MB file. About 20 seconds after the download finished, the computer began talking to two servers used by **Lumma Stealer**, malware that steals saved passwords, browser cookies and other data. Over the next 30 seconds it uploaded about 2 MB to the attacker's server and contacted two more recently registered domains. It then resolved the name of every group in the domain, which looks like the attacker mapping the network. **Treat the computer as compromised:** isolate it, reset every password the user saved in a browser and their domain password, end their active web sessions, and check other hosts for the indicators below.

## 2. Victim

| Field | Value | Evidence |
|---|---|---|
| IP address | 10.1.21.58 | DHCP ACK at 23:04:03.9 (`dhcp.log`); the only internal client in the capture (320 of 325 connections; the rest are the gateway and DHCP broadcasts) |
| MAC address | 00:21:5d:c8:0e:f2 | DHCP (`dhcp.log`), every connection in `conn.log` (Zeek MAC logging), NetBIOS frames |
| Host name | DESKTOP-ES9F3ML | DHCP option 12, NetBIOS name registration, the client FQDN `DESKTOP-ES9F3ML.win11office[.]com` |
| User account | gwyatt | Kerberos AS-REQ/AS-REP at 23:04:24.1 (`kerberos.log`, client `gwyatt/WIN11OFFICE.COM`) |
| Full name | Gabriel Wyatt | SAMR `QueryUserInfo` response from the DC, frame 358, 23:04:24.28 (readable because SAMR over SMB was not encrypted) |
| Domain / DC | win11office[.]com (WIN11OFFICE), DC WIN-LU4L24X3UB7 at 10.1.21.2 | Kerberos, LDAP, SMB tree connect to `\\WIN-LU4L24X3UB7\IPC$` |

## 3. Timeline (UTC, 2026-01-27)

| Time | Event | Evidence |
|---|---|---|
| 23:04:03.9 | DESKTOP-ES9F3ML gets 10.1.21.58 by DHCP | `dhcp.log` |
| 23:04:24.1 | User `gwyatt` logs on to the domain (Kerberos) | `kerberos.log` |
| 23:04:44.6 | Browser opens **drive[.]google[.]com** | `ssl.log` SNI |
| 23:04:49.2 | Within 8 seconds: hiyter[.]com, media[.]megafilehub4[.]lat, arch[.]filemegahab4[.]sbs | `dns.log`, `ssl.log` |
| 23:04:52 – ~23:05:14 | **15.9 MB downloaded** from arch[.]filemegahab4[.]sbs (104.21.46.67, Cloudflare) over TLS. The content is encrypted, so no file name or hash | `conn.log`: 15,892,883 bytes received in 22 s |
| 23:05:34.2 | First Lumma C2: **whooptm[.]cyou** → 62.72.32[.]156, one TLS session. About 20 s after the download ended: the user probably opened the file | `dns.log`, `ssl.log`; ET "Lumma Stealer Related CnC Domain" |
| 23:05:36.2 | Second Lumma C2: **whitepepper[.]su** → 153.92.1[.]49; 17 TLS sessions in 30 s | `ssl.log`; ET Lumma SNI/DNS alerts (26) |
| 23:05:39.3 | Chrome opens `hxxp://whitepepper[.]su/api/set_agent?id=3BF67EC0…&agent=Chrome`: **the malware drives the victim's browser** | `http.log` (real Chrome 144 user agent); ET 2066606 "Lumma Stealer Victim Fingerprinting Activity" at 23:05:39.58 |
| 23:05:40.2 | Chrome POSTs an 8,023-byte browser fingerprint (`act=log`: platform, user agent, languages, cookie support…) | `http.log`, frame 24601 body |
| 23:05:44 | **253 KB uploaded** to 153.92.1[.]49 over TLS (2,245 bytes back) | `conn.log` |
| 23:05:47.1 | Same again with **Edge** (`agent=Edge`, Edge 144 user agent), 7,975-byte fingerprint | `http.log` |
| 23:05:54 | **388 KB uploaded** (2,245 bytes back) | `conn.log` |
| 23:06:02 | **1.42 MB uploaded** (2,245 bytes back) | `conn.log` |
| 23:06:06.7 | holiday-forever[.]cc → 80.97.160[.]24: 118 KB received | `dns.log`, `conn.log` |
| 23:06:10.4 | communicationfirewall-security[.]cc → 104.21.9.36 (Cloudflare): two sessions, 134 KB received | `dns.log`, `conn.log` |
| 23:06:12.7 – 23:06:15 | **748 LSA name lookups** to the DC: every domain and built-in group name, 12 times each (up to 302 per second), plus 30 group-membership queries | `dce_rpc.log`, tshark `lsarpc` |
| 23:06:15 – 23:14:27 | Only Microsoft services; no further contact with any malicious host | `ssl.log`, `conn.log` |

## 4. Findings

### 4.1 Initial access
The chain starts with **drive[.]google[.]com** and moves within 8 seconds to three file-hosting lookalikes (`megafilehub4`, `filemegahab4`). That is the common pattern of a shared link leading to a "download your file" page. The 15.9 MB transfer from `arch[.]filemegahab4[.]sbs` ends about 20 seconds before the first C2 contact, so it is very likely the malware (or an archive containing it).

**What the traffic cannot show:** how the user got the link (e-mail, chat, search), the file's name, or its hash. Everything was HTTPS. Initial access is therefore recorded as *suspected* user execution of a downloaded file. Finding the file needs the endpoint (browser history, the Downloads folder, Sysmon events).

### 4.2 Command and control
Two C2 domains in sequence: `whooptm[.]cyou` (one short session, likely a check-in or the first entry of a fallback list) and then `whitepepper[.]su` (17 TLS sessions plus 4 plain-HTTP requests). ET Open identifies both as Lumma C2.

The plain-HTTP part is unusual and is the best evidence in the capture. The request goes to `/api/set_agent?id=<victim id>&token=…&agent=Chrome` with a **genuine Chrome user agent**, then the same with **Edge**. The malware opened the user's real browsers on its own page, and each browser posted a fingerprint of itself. A plausible reason, which the traffic does not prove, is to collect data that is only available inside a running browser.

### 4.3 Actions on the victim
- **Data theft:** three TLS uploads to the C2 of 253 KB, 388 KB and 1.42 MB, about **2.06 MB** in total, each answered with exactly 2,245 bytes. That is the pattern of a server receiving files. Lumma is known to steal browser passwords, cookies, crypto wallets and documents. The traffic proves the upload, not its content.
- **Follow-up:** two `.cc` domains, registered 5 and 42 days before the infection, sent about 250 KB right after the theft. This could be a second-stage payload or configuration. Not confirmed.
- **Domain group discovery (suspected):** at 23:06:12, one second after the `.cc` downloads, the client resolved every group name in the domain 12 times and asked for group members, all in 3 seconds. That fits automated enumeration of who the administrators are. An admin console can do something similar, but nothing else in the capture suggests a person was doing admin work.

## 5. Indicators of compromise

Full list with reputation details: [`iocs.csv`](iocs.csv). Lookups on 2026-10-21 by name/address only ([`lookups.jsonl`](lookups.jsonl)).

| Type | Indicator (defanged) | Role | Status | Reputation (2026-10-21) |
|---|---|---|---|---|
| domain | whitepepper[.]su | Lumma C2, data upload | confirmed malicious | VT 20/92; ET Lumma rules |
| ip | 153.92.1[.]49 | whitepepper[.]su | confirmed malicious | VT 2/92; AbuseIPDB 0 % (Hostinger, LT) |
| url | hxxp://whitepepper[.]su/api/set_agent?id=3BF67EC05320C5729578BE4C0ADF174C&… | fingerprint check-in | confirmed malicious | — |
| domain | whooptm[.]cyou | Lumma C2 | confirmed malicious | VT 17/92; registered 2026-01-13 (14 days before) |
| ip | 62.72.32[.]156 | whooptm[.]cyou | confirmed malicious | VT 9/92; AbuseIPDB 0 % (Hostinger, LT) |
| domain | arch[.]filemegahab4[.]sbs | 15.9 MB download before infection | suspicious (likely payload host) | **VT 1/92** |
| domain | media[.]megafilehub4[.]lat | lure chain | suspicious | VT 10/92 |
| domain | hiyter[.]com | lure chain (same second) | suspicious | VT 0/92; registered 2025-05-15 |
| domain | holiday-forever[.]cc | contacted right after the theft | suspicious | VT 16/92; registered 2026-01-22 (5 days before) |
| ip | 80.97.160[.]24 | holiday-forever[.]cc | suspicious | VT 3/92; AbuseIPDB 0 % (AlexHost, MD) |
| domain | communicationfirewall-security[.]cc | contacted right after the theft | suspicious | VT 13/92; registered 2025-12-16 |
| domain | drive[.]google[.]com | start of the chain | **context, do not block** | legitimate service |

No file hashes: every file transfer was encrypted.

**Lesson:** reputation alone would have missed the payload host (1/92) and all three server IPs (0 AbuseIPDB reports). The signals that worked were **behaviour** (upload-heavy sessions, the browser fingerprint) and **domain age** (C2 domains 5–42 days old).

## 6. MITRE ATT&CK mapping

| Tactic | Technique | Evidence in this capture |
|---|---|---|
| Execution | T1204.002 User Execution: Malicious File (*suspected*) | 15.9 MB download, then C2 20 s later |
| Command and Control | T1105 Ingress Tool Transfer | 15.9 MB download from arch[.]filemegahab4[.]sbs |
| Command and Control | T1071.001 Application Layer Protocol: Web Protocols | HTTP and HTTPS to whitepepper[.]su, `/api/set_agent` |
| Discovery | T1082 System Information Discovery | Fingerprint POST body (platform, user agent, languages) |
| Discovery | T1069.002 Permission Groups Discovery: Domain Groups (*suspected*) | 748 LSA lookups of every group name, 30 group-member queries |
| Credential Access | T1555.003 Credentials from Web Browsers (*suspected*: Lumma's known behaviour, consistent with the uploads) | 2.06 MB uploaded right after browser activity |
| Exfiltration | T1041 Exfiltration Over C2 Channel | Uploads of 253 KB, 388 KB, 1.42 MB to the C2 |

## 7. Detections

| Rule | Type | Detects | This capture | Clean baseline | Case 2 | Case 3 |
|---|---|---|---|---|---|---|
| SID 1004001 | Suricata | Lumma-style browser fingerprint upload: `POST /api/set_agent?…&act=log` with a `timestamp=…&system=` body | **2** (Chrome, Edge) | 0 | 0 | 0 |
| 100801 | Wazuh (Zeek conn) | Upload-heavy TLS session: ≥ 200 KB sent to an outside host, < 100 KB back | **3** (the three uploads) | 0 | 0 | 0 |
| 100803 | Wazuh (Zeek DCE-RPC) | 100+ LSA name lookups from one host in 10 s (group discovery) | **1** | 0 | 0 | 0 |

Live test 2026-10-21 (`scripts/test_detections.py`, runs `case-1-20261021T213022Z`, `baseline-20261021T213153Z`, `case-2-20261021T213245Z`, `case-3-20261021T213350Z`): **3/3 pass**. Every count matches the evidence exactly, with no false alarms on the other captures. The sample is small: four captures are not proof of a low false-positive rate in a real network (see the "False alarms" notes in each rule).

ET Open rules that already fired: Lumma C2 domain in DNS (12) and TLS SNI (17), the victim fingerprinting GET (1), `.su` and `.cc` TLD queries (14), `.su` HTTP request (6). **What the custom rules add:** all three are about **behaviour, not names**. They keep working when the attacker changes domains, which Lumma does constantly. Rule definitions and reasoning: [`detections/`](../../detections/).

## 8. Recommendations

1. **Contain:** isolate DESKTOP-ES9F3ML from the network.
2. **Credentials:** treat everything saved in the user's browsers as stolen. Reset the domain password of `gwyatt`, reset passwords saved in Chrome and Edge, revoke active web sessions (cookies were likely taken), and enable MFA where possible.
3. **Endpoint:** collect the downloaded file (browser download history around 23:04:52–23:05:14), hash it, and re-image the machine. Stealers often drop a second stage.
4. **Block** (confirmed only): whitepepper[.]su, whooptm[.]cyou, 153.92.1[.]49, 62.72.32[.]156. **Watch** the suspicious ones (DNS sinkhole or alert-only). Never block drive[.]google[.]com.
5. **Hunt:** search DNS and proxy logs of all hosts for the indicators in section 5, and for the behaviours in section 7 (large uploads with small replies, bursts of LSA lookups).
6. **Follow up on the discovery burst:** review the DC's logs for gwyatt's activity after 23:06, and check whether any admin account was used from this host afterwards.

## 9. What I missed (written after reading the answer key)

Answer key opened on 2026-10-22, after sections 1–8 were final. They were not changed afterwards.

| Answer-key item | Found? | Notes |
|---|---|---|
| Victim IP address | ✅ 10.1.21.58 | The key's answer line has a typo (10.1.**28**.58); its own screenshots and hints show 10.1.21.58 |
| MAC address | ✅ 00:21:5d:c8:0e:f2 | |
| Host name | ✅ DESKTOP-ES9F3ML | The key uses NetBIOS; we used DHCP option 12 and NetBIOS. Same answer |
| User account | ✅ gwyatt | Kerberos `CNameString`, same method |
| Full name | ✅ Gabriel Wyatt | Same source (SAMR `QueryUserInfo`). The key finds it with a case-sensitive text search for "Wyatt"; we filtered on the SAMR operation (`samr.opnum == 36`), which also works when the account name doesn't contain the surname |
| Trigger domain | ✅ whitepepper[.]su | |
| Follow-up: two suspicious `.cc` domains | ✅ holiday-forever[.]cc, communicationfirewall-security[.]cc | The key links them to known follow-up malware patterns; we called them a possible second stage. Same conclusion, now with a source |

**Score: 7 of 7, nothing missed.**

**Beyond the key** (not asked for, but useful to a responder): the lure chain and the 15.9 MB download, the malware driving Chrome and Edge for fingerprints, the measured uploads (2.06 MB), the suspected group-discovery burst, the domain ages, and three tested detections.

**Method check:** no gap found. One improvement taken from the key: the case-sensitive "Find Packet" search for a surname is a fast fallback when the SAMR field filter doesn't work.

## 10. Credits

Capture and exercise by Brad Duncan, malware-traffic-analysis.net. This report is our own analysis; it does not reproduce the site's text or answers.
