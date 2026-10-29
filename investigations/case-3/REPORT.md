# Case 3 — A command-line download chain and a remote access trojan over a fake HTTPS port (2026-10-01)

| | |
|---|---|
| **Source** | [2026-10-01 traffic analysis exercise "Natureforce"](https://www.malware-traffic-analysis.net/2026/10/01/index.html) (malware-traffic-analysis.net, by Brad Duncan) |
| **Capture** | `2026-10-01-traffic-analysis-exercise.pcap` (36,838,132 bytes), SHA-256 `287d6dee90cfef71f98a97c42e30444608de2cf59d2f7392a0a6df8dbbc8274b`; from zip SHA-256 `ffc811c2d1e990ee6e008caf2df926ecb9e3aeed3dd0032e6e03ed085a6647bc` |
| **Time span** | 2026-10-01 19:27:27 – 20:07:58 UTC (40 min 31 s, 42,497 packets) |
| **Analysed** | 2026-10-22 |
| **Tools** | Suricata 8.0.7 + ET Open (2026-10-20, 53,222 active rules), Zeek 8.0.10, tshark 4.2.2, Wazuh 4.14 |
| **Verdict** | Windows client DESKTOP-4VGYQX7 (user bdiaz) was led from a Google search to a site carrying an inject. Twenty-nine seconds later **curl** fetched two script stages from a same-day domain, then a Windows program (`runner_ilove.exe`, VirusTotal 45/70) from a bare IP on port 9000. The program resolved its server by **DNS-over-HTTPS** and held a **37-minute remote-access connection on port 443 that is not TLS**. |

> All indicators in this report are defanged. Do not visit them.

## 1. Executive summary

On 1 October 2026 at 19:28 UTC, user `bdiaz` searched Google and opened a website, ars-soar[.]com, that pulled content from sorrelapse[.]best, a domain registered that day. Half a minute later, a **command-line tool (curl)**, not the web browser, began downloading files on the computer. This pattern matches "ClickFix"-style tricks, where a web page persuades the user to paste and run a command. curl fetched two script stages and then a Windows program, `runner_ilove.exe`, from a server addressed only by its IP number, on an unusual port (9000). Security vendors identify this program as a **remote access trojan** (45 of 70 VirusTotal engines). It then looked up its server through Google's encrypted DNS service, which the company's DNS server cannot see. Next it opened a connection that stayed up for 37 minutes, received 13.4 MB in the first 18 seconds (most likely additional tools), and then kept the line open with a one-byte heartbeat every 20 seconds, waiting for orders. **The attacker had remote control of the machine during the whole capture.** Isolate it, reset the user's credentials, re-image it, and block the indicators below.

## 2. Victim

| Field | Value | Evidence |
|---|---|---|
| IP address | 10.10.1.128 | DHCP ACK at 19:27:27 (`dhcp.log`); the only internal client (344 of 345 connections) |
| MAC address | 00:22:fb:ec:7e:e7 | DHCP (`dhcp.log`), every connection in `conn.log` |
| Host name | DESKTOP-4VGYQX7 | DHCP option 12, NetBIOS registrations, Kerberos machine account `desktop-4vgyqx7$` |
| User account | bdiaz | Kerberos AS-REQ/AS-REP at 19:27:46 (`kerberos.log`) |
| Domain / DC | natureforce[.]com (NATUREFORCE), DC WIN-LEKBU2OY51N at 10.10.1.10 | Kerberos, LDAP |

The scenario doesn't ask for the full name, and the capture holds no SAMR user query that would carry it.

## 3. Timeline (UTC, 2026-10-01)

| Time | Event | Evidence |
|---|---|---|
| 19:27:27 | DESKTOP-4VGYQX7 gets 10.10.1.128; machine account logs on | `dhcp.log`, `kerberos.log` |
| 19:27:46 | User **bdiaz** logs on | `kerberos.log` |
| 19:28:09 | Google search (google, youtube, ads domains) | `dns.log` |
| 19:28:30 | **www.ars-soar[.]com** (registered 2019): 510 KB page | `ssl.log`, `conn.log` |
| 19:28:31 | **sorrelapse[.]best** (registered **2026-10-01**): 1.74 MB | `ssl.log`, `conn.log` |
| 19:28:31 – 19:29:00 | **29-second gap**: most likely the fake page and the user running a pasted command (*suspected*: page content is encrypted) | timing |
| 19:29:00 – 19:29:02 | **curl/8.21.0** → `hxxp://holtandberyl[.]com/prw` and `/crv` → redirects to HTTPS → 75 KB and **1.1 MB** received (holtandberyl[.]com also registered **2026-10-01**) | `http.log`, `ssl.log`, `conn.log` |
| 19:30:36 | **curl** → `hxxp://107.175.82[.]242:9000/wilow/runner_ilove.exe`: **1,646,592-byte Windows program** | `http.log`, `files.log`; ET "Executable Download from dotted-quad Host", "curl User-Agent to Dotted Quad", "Packed Executable Download" |
| 19:30:43 | **DNS-over-HTTPS** to dns.google (8.8.4.4). The server's name is resolved outside the company DNS | `ssl.log`; ET "Google DNS over HTTPS Domain in TLS SNI" |
| 19:30:44 | **RAT connection** to 195.63.128[.]106:443. **Not TLS** (Suricata `app_proto: failed`, Zeek: no service) | `conn.log`, Suricata flow |
| 19:30:44 – 19:31:02 | Victim sends ~84 KB first (likely system details), then **13.4 MB downloaded in 17.6 s** | tshark on the stream |
| 19:31 – 20:07:58 | **Heartbeat**: one `0x00` byte each way, about every 20 s (98 from the victim). The connection is still open when the capture ends (37 min) | tshark on the stream |
| 19:39:50, 19:40:53 | Normal Adobe and certificate checks; nothing else suspicious | `http.log` |

## 4. Findings

### 4.1 Initial access: search → site → inject → pasted command (suspected)
ars-soar[.]com has existed since 2019; sorrelapse[.]best was registered the day of the attack and is flagged by 16/92 VirusTotal engines. That points to an inject placed on a legitimate site. **curl** took over 29 seconds later. A person downloads with a browser; curl means a script or a pasted command. Same as case 2, the page itself is encrypted, so ClickFix is *suspected*, not seen.

### 4.2 Ingress: scripts over HTTPS, then a program from a bare IP
The two holtandberyl[.]com requests began in plain HTTP and were redirected to HTTPS, so only their size is visible (75 KB, 1.1 MB). The program came over **plain HTTP on port 9000**, from an IP with no domain name. ET Open fired five rules on this request. Zeek identified it as a Windows program and hashed it:

| Hash | Value | How we got it |
|---|---|---|
| SHA-256 | `b789adce70c028a6d17be45ec34667aa95586350ee0c4057e75b138b1ad35061` | Rebuilt from the HTTP stream **in memory** (tshark → hex → `sha256sum`, never written to disk) **and** computed by Zeek; both agree. VirusTotal: **45/70**, `trojan.capdoor/zusy` |
| SHA-1 | `425efc5636affb32f4a72f73b5b80c26c54b15bc` | Zeek `files.log`, matches the rebuild |
| MD5 | `cb50fe432a302b85845bc7ea98742c11` | Zeek `files.log`, matches the rebuild |

*Lesson:* Zeek's standard hashing in 8.0 stops at SHA-1. The pipeline now adds SHA-256 (`tools-vm/ntd.zeek`). A first attempt at the rebuild used a `tee` one-liner and produced a **wrong** SHA-256. Checking the rebuild's MD5 and SHA-1 against Zeek caught the error. Always verify a hash two ways.

### 4.3 Hiding the lookup: DNS-over-HTTPS
One second before connecting to its server, the victim opened TLS to dns.google. The RAT's server address therefore **never appears in the company's DNS logs**: `dns.log` has no lookup that returns 195.63.128[.]106. On an Active Directory network every client should use the domain's DNS, so DoH from a workstation is a signal in itself.

### 4.4 Command and control: a custom protocol on port 443
Port 443 is open outbound almost everywhere, because it carries HTTPS. This connection is not HTTPS: the victim speaks first, with a binary block that is not a TLS handshake, and neither Suricata nor Zeek can identify the protocol. After a burst (84 KB up, 13.4 MB down in 18 s), the line goes quiet except for a **one-byte keep-alive every ~20 s**. That is a RAT waiting for its operator.

The scenario's alert names the family (a "CNCmachineRMS RAT" signature). **No such signature fired with our ET Open ruleset (2026-10-20)**: the only Suricata event on this connection was a TCP anomaly ("excessive retransmissions"). That signature likely comes from a ruleset we don't have. It's the clearest case in this project for behaviour rules: ours catches the connection without knowing the family.

### 4.5 Reputation versus behaviour
| Indicator | Reputation (2026-10-22) | Behaviour that gave it away |
|---|---|---|
| runner_ilove.exe | VT **45/70** | program fetched by curl from a bare IP on port 9000 |
| 107.175.82[.]242 | VT 19/92, AbuseIPDB 0 % | serves a program on port 9000 |
| 195.63.128[.]106 (RAT server) | VT 7/92, AbuseIPDB 3 % (1 report) | non-TLS on 443, 37 min, 1-byte heartbeat |
| holtandberyl[.]com | **VT 0/92**, registered same day | contacted by curl, not a browser |
| sorrelapse[.]best | VT 16/92, registered same day | loaded right before the curl chain |

## 5. Indicators of compromise

Full list: [`iocs.csv`](iocs.csv); reputation lookups on 2026-10-22, by name / address / hash only ([`lookups.jsonl`](lookups.jsonl)).

| Type | Indicator (defanged) | Role | Status |
|---|---|---|---|
| sha256 | b789adce70c028a6d17be45ec34667aa95586350ee0c4057e75b138b1ad35061 | runner_ilove.exe (RAT) | confirmed malicious (VT 45/70) |
| url | hxxp://107.175.82[.]242:9000/wilow/runner_ilove.exe | program download | confirmed malicious |
| ip | 107.175.82[.]242 | program host, port 9000 | confirmed malicious |
| ip | 195.63.128[.]106 | RAT server, TCP 443 (not TLS) | confirmed malicious |
| domain | holtandberyl[.]com | script stages fetched by curl (`/prw`, `/crv`) | confirmed malicious (behaviour) |
| ip | 35.170.55[.]9 | holtandberyl[.]com (AWS) | suspicious (shared cloud address) |
| domain | sorrelapse[.]best | inject / redirect loaded before the chain | confirmed malicious (VT 16/92, same-day) |
| ip | 44.203.10[.]190 | sorrelapse[.]best (AWS) | suspicious (shared cloud address) |
| domain | ars-soar[.]com | likely compromised site (registered 2019) | **context**; notify the owner |
| domain | dns.google | DoH resolver used to hide the C2 lookup | **context, legitimate**; block DoH by policy, not by indicator |

## 6. MITRE ATT&CK mapping

| Tactic | Technique | Evidence in this capture |
|---|---|---|
| Initial Access | T1189 Drive-by Compromise | ars-soar[.]com → sorrelapse[.]best |
| Execution | T1204.004 User Execution: Malicious Copy and Paste (*suspected*) | 29 s gap, then curl instead of the browser |
| Command and Control | T1105 Ingress Tool Transfer | two script stages; `runner_ilove.exe`; 13.4 MB over the RAT channel |
| Command and Control | T1071.004 Application Layer Protocol: DNS (via DoH) | dns.google right before the C2 connection |
| Command and Control | T1571 Non-Standard Port | port 9000 for the download; a custom protocol on 443 |
| Command and Control | T1095 Non-Application Layer Protocol | RAT protocol is neither TLS nor HTTP |
| Command and Control | T1219 Remote Access Tools / RAT behaviour | 37-minute session, 20 s heartbeat |

## 7. Detections

| Rule | Type | Detects | This capture | Clean baseline | Case 1 | Case 2 |
|---|---|---|---|---|---|---|
| SID 1004201 | Suricata | Non-TLS traffic to TCP 443 (protocol detection failed), once per connection | **1** (the RAT connection) | 0 | 0 | 0 |
| 100840 | Wazuh (Zeek HTTP) | Command-line tool (curl / wget / PowerShell) downloads a Windows program | **1** (runner_ilove.exe) | 0 | 0 | 0 |
| 100841 | Wazuh (Zeek HTTP) | Command-line HTTP request (visibility) | **2** (the two script fetches) | 0 | 0 | 0 |
| 100842 | Wazuh (Zeek TLS) | DNS-over-HTTPS from a client | **1** (dns.google) | 0 | 0 | 0 |

Live test 2026-10-22 (`scripts/test_detections.py`, runs `case-1-20261022T224613Z`, `case-2-20261022T224732Z`, `case-3-20261022T224420Z`, `baseline-20261022T224511Z`): **4/4 pass**, exact counts, no false alarms on the other captures.

ET Open fired 9 alerts: 5 on the program download (dotted-quad executable, curl to dotted quad, PE download, MZ response from a dotted quad, packed executable), 1 on DoH, 1 Microsoft connectivity test, and 2 protocol anomalies. **No ET rule identified the RAT channel.** **Measured before written:** "connection longer than 30 minutes" was rejected, because two genuine Microsoft TLS connections in this capture also lasted over 30 minutes. "Not TLS on 443" separates the RAT cleanly.

## 8. Recommendations

1. **Contain now:** the RAT session was still open when the capture ended. Isolate DESKTOP-4VGYQX7 and block 195.63.128[.]106 and 107.175.82[.]242 at the firewall.
2. **Credentials:** an attacker with remote control can capture anything typed. Reset bdiaz's passwords and revoke sessions.
3. **Endpoint:** search for `runner_ilove.exe` (SHA-256 above) on all hosts, and for curl runs started from the Run dialog or by `explorer.exe`. Re-image the victim.
4. **Network policy:**
   - allow outbound 443 only for real TLS (most next-generation firewalls can enforce this);
   - block DoH resolvers for workstations, or force browsers to use the company DNS by policy;
   - block or alert on executables fetched from bare IP addresses.
5. **User awareness:** a website never needs you to paste a command into Windows.
6. **Hunt:** other hosts talking to these IPs, using DoH, or showing a long non-TLS session on 443.

## 9. What I missed (written after reading the answer key)

Answer key opened on 2026-10-22, after sections 1–8 were final. They were not changed afterwards.

| Answer-key item | Found? | Notes |
|---|---|---|
| Victim IP address | ✅ 10.10.1.128 | |
| MAC address | ✅ 00:22:fb:ec:7e:e7 | |
| Host name | ✅ DESKTOP-4VGYQX7 | |
| User account | ✅ bdiaz | Same filter idea as the key (Kerberos names without `$`) |
| SHA-256 of the program from 107.175.82[.]242:9000 | ✅ `b789adce…1ad35061` | **Exact match.** The key gets it with Wireshark *Export Objects*, which writes the live malware to disk; we rebuilt it in memory and had Zeek compute it, so the program never touched a disk |

**Score: 5 of 5, nothing missed.**

**One discrepancy in the key:** its scenario names the RAT server 195.**64**.128[.]106. In the capture the only connection of this kind goes to 195.**63**.128[.]106 (Zeek, Suricata and tshark agree), so we report the address seen in the traffic. The key confirms that no first and last name is available in this capture, as found in section 2.

**Beyond the key:** the curl chain before the download, DoH to hide the C2 lookup, the RAT protocol's shape (84 KB up, 13.4 MB down in 18 s, then a 1-byte heartbeat every 20 s), and four tested detections. These include one that catches the RAT channel without the family signature our ruleset lacked.

**Method check:** "verify a hash two ways" is now part of METHODOLOGY step 6. The first in-memory attempt produced a wrong SHA-256, caught only because we compared MD5 and SHA-1 with Zeek's.

## 10. Credits

Capture and exercise by Brad Duncan, malware-traffic-analysis.net. This report is our own analysis; it does not reproduce the site's text or answers.
