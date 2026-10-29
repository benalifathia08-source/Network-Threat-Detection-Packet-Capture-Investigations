# Case 2 — KongTuke web inject, ClickFix, and a Node.js backdoor (2026-09-11)

| | |
|---|---|
| **Source** | [2026-09-11 traffic analysis exercise "Kongtuke rebuke!"](https://www.malware-traffic-analysis.net/2026/09/11/index.html) (malware-traffic-analysis.net, by Brad Duncan) |
| **Capture** | `2026-09-11-traffic-analysis-exercise.pcap` (59,484,402 bytes), SHA-256 `21bb800849459709a7ceb5513573b2b20f090ffccd00eb89b9886feedd47a2df`; from zip SHA-256 `2406e67624b3c86e73929d552f472e157c496ee56bdde6e2299a481b90210ab0`. Only the capture zip was downloaded, never the bonus zip that contains the malware |
| **Time span** | 2026-09-11 20:05:55 – 20:27:05 UTC (21 min 10 s, 73,779 packets) |
| **Analysed** | 2026-10-22 |
| **Tools** | Suricata 8.0.7 + ET Open (2026-10-20, 53,222 active rules), Zeek 8.0.10, tshark 4.2.2, Wazuh 4.14 |
| **Verdict** | Windows client DESKTOP-6T17ZFM (user gmcdowell) visited a compromised website carrying a KongTuke / LandUpdate808 inject. Within 40 seconds it downloaded about 45 MB of tools, including the genuine Node.js runtime, and started a backdoor with **two C2 channels** (HTTP every ~10 s, TLS every ~16 s). The backdoor sent **4.47 MB** out, survived a new logon, and then tried seven fallback servers, all of which refused it. |

> All indicators in this report are defanged. Do not visit them.

## 1. Executive summary

On 11 September 2026 at 20:05 UTC, user Gabriel McDowell (`gmcdowell`) opened a legitimate-looking website, quadcinema[.]com, that had been tampered with. A hidden script loaded from aatthews[.]cfd, a domain registered that same day and known to security vendors as part of the **KongTuke / LandUpdate808** campaign. These campaigns show a fake "verify you are human" page that tells the user to paste a command into Windows (**ClickFix**). Thirty-four seconds later, the computer started downloading about 45 MB of files from freshly registered domains, plus the official Node.js software, and a **backdoor** began calling its server every 10 seconds. Over the next 13 minutes the attacker could run commands on the machine and received **4.47 MB of data** from it. After the user signed in again at 20:22, the backdoor restarted on its own and tried seven backup servers, all of which rejected it. **Treat the computer as fully compromised:** isolate it, reset the user's passwords, re-image it, and block the indicators below. Almost none of them were known to reputation services, so behaviour-based detection is what catches this.

## 2. Victim

| Field | Value | Evidence |
|---|---|---|
| IP address | 10.9.11.135 | The only internal client (362 of 368 connections; the rest are the DC) |
| MAC address | 08:d4:0c:7a:29:1e | All 362 connections in `conn.log` (Zeek MAC logging) |
| Host name | DESKTOP-6T17ZFM | Kerberos TGS for `host/desktop-6t17zfm.overhands[.]org` at 20:22:07; LDAP DC-locator queries |
| User account | gmcdowell | Kerberos AS-REQ/AS-REP at 20:22:07 (`kerberos.log`) |
| Full name | Gabriel McDowell | SAMR `QueryUserInfo` response from the DC, frame 70694 (20:15:33) |
| Domain / DC | overhands[.]org (OVERHANDS), DC WIN-GTWXC9UYSE4 at 10.9.11.2 | Kerberos, LDAP SRV lookups |

## 3. Timeline (UTC, 2026-09-11)

| Time | Event | Evidence |
|---|---|---|
| 20:05:55 | Capture starts: the victim is loading **quadcinema[.]com** (2.1 MB page) | `dns.log`, `ssl.log`, `conn.log` |
| 20:05:56 | Same second: **aatthews[.]cfd**, the injected script (83 KB + 19 KB over TLS) | ET "LandUpdate808 Domain in DNS Lookup" ×2; `ssl.log` |
| 20:05:59 – 20:06:32 | **33-second gap.** Most likely the fake check page and the user pasting the command (ClickFix). The content is encrypted, so this is *suspected* | timing |
| 20:06:33 | **winrun2915[.]com**: 1.7 MB received | `conn.log`, `ssl.log` |
| 20:06:36 – 20:06:38 | **logincrypt8338[.]com**, then **opscast3707[.]net**: 7.1 MB received | `conn.log` |
| 20:06:42 – 20:06:52 | **xos-aploq[.]com** (www, jaw, soft): small files, the largest 86 KB | `ssl.log`, `conn.log` |
| 20:06:47 | **nodejs[.]org**: **35.7 MB** received, the genuine Node.js runtime, used to run JavaScript malware | `conn.log` |
| 20:06:57 | **HTTP C2 starts**: `hxxp://know.mom-nower[.]com/<random>&<64-hex token>` (86.106.87[.]134), every ~10 s, fake Firefox 137 user agent | `http.log` |
| 20:06:33 – 20:19:08 | **TLS C2 in parallel**: 50 short sessions (~3.9 KB) rotating over winrun2915 / logincrypt8338 / opscast3707, median gap 15.7 s. Three more names in the rotation **don't exist** (NXDOMAIN, 15–16 tries each) | `ssl.log`, `dns.log` |
| 20:07:16 | First result upload over HTTP (12,896 bytes) | `http.log` |
| 20:08:59 | **registry.npmjs[.]org**: about 20 package downloads (the backdoor installs its dependencies) | `ssl.log`, `conn.log` |
| 20:09:55 | **4,447,024 bytes POSTed** to the HTTP C2 (reply: empty 204). Right after it, the victim token in the URL changes from `4a0fd955…` to `99099296…` | `http.log` |
| 20:10 – 20:19:10 | Beacon continues: 52 empty (204) replies in total, occasional small tasks (200) and results (POST) | `http.log` |
| 20:19:08 – 20:19:10 | Both C2 channels stop | `ssl.log`, `http.log` |
| 20:22:07 | **New logon by gmcdowell** (Kerberos AS/TGS burst; no DHCP, so the machine probably did not restart) | `kerberos.log` |
| 20:22:17 – 20:26:47 | **Backdoor restarts by itself** and tries seven fallback servers (comonto-rsr, fif-lost, bert-hits, and mom-nower again) with the same token. Each gets a 75-byte and a ~26.6 KB gzip POST, and **every one is refused** (400 / 406) | `http.log`; Suricata "excessive header repetition" on the replies |
| 20:27:05 | Capture ends | capinfos |

## 4. Findings

### 4.1 Initial access: compromised website, then ClickFix (suspected)
quadcinema[.]com is a domain registered in 1998. Its site loaded a script from aatthews[.]cfd, registered **the same day** as the infection and identified by ET Open as LandUpdate808, the web-inject framework used in KongTuke campaigns. These campaigns show a fake CAPTCHA that tells the user to press Win+R and paste a command. The traffic fits that picture: a 33-second pause, then downloads that start with no browser navigation in between. The page content and the command are inside TLS, so the ClickFix step is *suspected*, not seen.

### 4.2 Execution: a JavaScript backdoor on a borrowed runtime
The 35.7 MB download from **nodejs[.]org** and the npm package installs two minutes later are unusual for an office workstation. The likely reading: the stages from winrun2915 / opscast3707 (1.7 MB, 7.1 MB) set up a script, and the attacker brought the **official Node.js runtime** to run it. Abusing a trusted vendor's download site means a domain blocklist would never stop this step.

### 4.3 Command and control: two channels and a fallback plan
- **HTTP channel** (`know.mom-nower[.]com`, 86.106.87[.]134), every ~10 s: random lowercase path, then `&`, then a **64-hex victim token**. Mostly 204 "nothing to do" replies, with a task (200) and a result (POST) every few minutes. The user agent claims Firefox 137, but this machine browses with Edge.
- **TLS channel**: short sessions every ~16 s, rotating over three live and three dead domains.
- **Fallback:** after the new logon the same implant (same token) cycled through seven servers on four domains. stream.fif-lost[.]com sits on the **same IP** as the main C2, so these are one operator's infrastructure.

### 4.4 Data sent out
4.47 MB left over the HTTP channel before 20:20: one 4,447,024-byte POST at 20:09:55, plus about 25 KB of small results. Zeek saw the POST bodies as gzip archives. The content isn't visible here, and that file type is the attacker's packing, not proof of what was inside.

### 4.5 Why nothing stopped it
| Control | What it saw |
|---|---|
| Domain reputation | **know.mom-nower[.]com 0/92**, comonto-rsr / fif-lost / bert-hits 0/92, opscast3707 0/92, xos-aploq 0/92 |
| IP reputation | 86.106.87[.]134, 62.3.53[.]87, 146.70.139[.]165: **0 AbuseIPDB reports** |
| ET Open | Only the inject domain (LandUpdate808, ×2) and protocol anomalies. **No alert on the backdoor's C2** |
| What did stand out | Domain age (0–3 days for the inject and stage domains), the 10-second rhythm, 52 empty replies, the fixed URL layout, a 4.4 MB upload, repeated failures for the same dead names |

## 5. Indicators of compromise

Full list: [`iocs.csv`](iocs.csv); reputation lookups on 2026-10-22, by name/address only ([`lookups.jsonl`](lookups.jsonl)).

| Type | Indicator (defanged) | Role | Status | Reputation (2026-10-22) |
|---|---|---|---|---|
| domain | aatthews[.]cfd | KongTuke / LandUpdate808 inject | confirmed malicious | VT 22/92; registered 2026-09-11 (same day) |
| domain | know.mom-nower[.]com | HTTP C2, 4.47 MB upload | confirmed malicious (behaviour) | **VT 0/92**; registered 2026-06-30 |
| ip | 86.106.87[.]134 | know.mom-nower / stream.fif-lost | confirmed malicious (behaviour) | VT 0/92; AbuseIPDB 0 % (M247, US) |
| url | hxxp://know.mom-nower[.]com/…&4a0fd955c05d43841a9a8d921ceec63b0dc5b431a9fb54b33ad7848707bc16e9 | C2 URL with victim token (also token 99099296646b5ffb8188092fb5030b7890c1de2d6a058cab178d4548c4dca1ab) | confirmed malicious | — |
| domain | winrun2915[.]com | stage download (1.7 MB) + TLS C2 rotation | confirmed malicious (behaviour) | VT 6/92; registered 2026-09-08 |
| domain | logincrypt8338[.]com | TLS C2 rotation | confirmed malicious (behaviour) | VT 18/92; registered 2026-09-10 |
| domain | opscast3707[.]net | stage download (7.1 MB) + TLS C2 rotation | confirmed malicious (behaviour) | VT 0/92; registered 2026-09-11 |
| domain | xos-aploq[.]com (www, jaw, soft) | stage files | suspicious | VT 0/92 ("newly registered"); registered 2026-09-11 |
| domain | comonto-rsr[.]com (now, firt, start) | fallback C2 | confirmed malicious (same token) | VT 0/92; registered 2026-07-22 |
| domain | fif-lost[.]com (stream, hyko) | fallback C2 | confirmed malicious (same token) | VT 0/92; registered 2026-06-30 |
| domain | bert-hits[.]com (second, gets, www) | fallback C2 | confirmed malicious (same token) | VT 0/92; registered 2026-07-22 |
| ip | 62.3.53[.]87 | now / start.comonto-rsr | confirmed malicious (same token) | AbuseIPDB 0 % (RoyaleHosting, NL) |
| ip | 146.70.139[.]165 | second.bert-hits | confirmed malicious (same token) | AbuseIPDB 0 % (M247, DE) |
| domain | globalcert8618[.]net, hostjob3862[.]net, opsbox8097[.]com | dead fallback names (NXDOMAIN) | suspicious | not registered |
| domain | quadcinema[.]com | compromised website (start of chain) | **context, do not block blindly**; notify the owner | VT 0/92; registered 1998 |
| domain | nodejs[.]org, registry.npmjs[.]org | legitimate services abused | **context, never block** | legitimate |

## 6. MITRE ATT&CK mapping

| Tactic | Technique | Evidence in this capture |
|---|---|---|
| Initial Access | T1189 Drive-by Compromise | compromised site → aatthews[.]cfd inject (ET LandUpdate808) |
| Execution | T1204.004 User Execution: Malicious Copy and Paste (*suspected*, ClickFix) | 33 s pause, then downloads without browsing |
| Execution | T1059.007 Command and Scripting Interpreter: JavaScript (*suspected*) | Node.js runtime + npm packages downloaded |
| Command and Control | T1105 Ingress Tool Transfer | 1.7 MB, 7.1 MB, 35.7 MB, npm packages |
| Command and Control | T1071.001 Application Layer Protocol: Web Protocols | HTTP beacon every ~10 s; TLS beacon every ~16 s |
| Command and Control | T1008 Fallback Channels | three dead names in rotation; seven fallback servers after the logon |
| Persistence | T1547 Boot or Logon Autostart Execution (*suspected*) | the implant restarted with the same token after the 20:22 logon |
| Exfiltration | T1041 Exfiltration Over C2 Channel | 4,447,024-byte POST to the HTTP C2 |

## 7. Detections

| Rule | Type | Detects | This capture | Clean baseline | Case 1 | Case 3 |
|---|---|---|---|---|---|---|
| SID 1004101 | Suricata | Backdoor C2 path: random path + `&` + 64-hex token | **99** (every implant request) | 0 | 0 | 0 |
| 100821 (+100820) | Wazuh (Zeek HTTP) | 20+ empty (204) replies from one host in 5 min (beacon) | **1** | 0 | 0 | 0 |
| 100822 | Wazuh (Zeek HTTP) | POST ≥ 1 MB to an outside host | **1** (the 4.4 MB upload) | 0 | 0 | 0 |
| 100824 (+100823) | Wazuh (Zeek DNS) | Same name fails 10+ times in 5 min (dead fallback C2), excluding wpad and SRV lookups | **1** | 0 | 0 | 0 |

Live test 2026-10-22 (`scripts/test_detections.py`, runs `case-1-20261022T224613Z`, `case-2-20261022T224732Z`, `case-3-20261022T224420Z`, `baseline-20261022T224511Z`): **4/4 pass**, no false alarms on the other captures. The frequency rules fire once: Wazuh's `ignore` timer silences a rule for 5 minutes after it fires, for all hosts and names together.

ET Open rules that fired: LandUpdate808 inject domain (2), `.cfd` TLD (2), protocol anomalies (12). **What the custom rules add:** coverage of the backdoor itself (beacon, URL layout, upload, fallback behaviour), none of it based on a domain or an IP. **Measured before written:** a plain "repeated NXDOMAIN" rule would have fired in every capture on Windows' own `wpad` lookups (13–20 per capture). The exclusion is in the rule, with its reason.

## 8. Recommendations

1. **Contain:** isolate DESKTOP-6T17ZFM. The backdoor gives the attacker remote command execution and survived a logon.
2. **Credentials:** reset gmcdowell's domain password, and any passwords used or saved on that machine; revoke web sessions.
3. **Endpoint:** look for a `node.exe` outside Program Files, scheduled tasks or Run keys pointing to it, and a recent `.js` file in the user's profile. Re-image after collection.
4. **Block:** all domains and IPs marked confirmed above, at DNS and the proxy. **Do not block** nodejs[.]org or registry.npmjs[.]org. Instead, alert when a non-developer workstation downloads the Node.js runtime.
5. **User awareness:** ClickFix only works if the user pastes a command. Teach "a website will never ask you to press Win+R". Where possible, restrict the Run dialog and PowerShell for standard users.
6. **Tell the site owner:** quadcinema[.]com is compromised and will infect other visitors.
7. **Hunt:** other hosts with the 64-hex URL layout, 204-polling, or DNS failures for the three dead names.

## 9. What I missed (written after reading the answer key)

Answer key opened on 2026-10-22, after sections 1–8 were final. They were not changed afterwards.

| Answer-key item | Found? | Notes |
|---|---|---|
| Victim IP address | ✅ 10.9.11.135 | |
| MAC address | ✅ 08:d4:0c:7a:29:1e | |
| Host name | ✅ DESKTOP-6T17ZFM | The key's shortcut is `browser.response_computer_name` (Windows browser announcements); we used the Kerberos host ticket. Same answer |
| User account | ✅ gmcdowell | |
| Full name | ✅ Gabriel McDowell | Same source (SAMR); the key's filter `samr.samr_UserInfo21.full_name` is a faster shortcut |

**Score: 5 of 5, nothing missed.**

**Beyond the key:** the key only asks for the victim. This report adds the full chain (inject → stages → Node.js → two C2 channels → upload → fallback after logon), 20 indicators with reputation and domain ages, and four tested detections. The key confirms the "Kongtuke ClickFix" framing, which the report could only call *suspected* from traffic alone.

**Method check:** two shortcuts added to METHODOLOGY.md (`browser.response_computer_name`, `samr.samr_UserInfo21.full_name`).

## 10. Credits

Capture and exercise by Brad Duncan, malware-traffic-analysis.net. This report is our own analysis; it does not reproduce the site's text or answers.
