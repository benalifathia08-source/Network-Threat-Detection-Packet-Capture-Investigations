# Case N — <short title> (<capture date>)

| | |
|---|---|
| **Source** | <case page URL> (malware-traffic-analysis.net, by Brad Duncan) |
| **Capture** | `<zip name>`, SHA-256 `<hash of the .pcap>` |
| **Analysed by** | <name>, <date> |
| **Tools** | Suricata <version> + ET Open (<ruleset date>), Zeek <version>, Wireshark/tshark <version>, Wazuh 4.14 |
| **Verdict** | <one line: e.g. "Host X infected with Y; C2 active for Z minutes; credentials likely stolen"> |

> All indicators in this report are defanged. Do not visit them.

## 1. Executive summary

Three to five sentences a manager can read: what happened, to which host and user, how bad it is, and what to do now.

## 2. Victim

| Field | Value | Evidence |
|---|---|---|
| IP address | | |
| MAC address | | |
| Host name | | |
| User account | | |
| Domain / DC | | |

## 3. Timeline (UTC)

| Time | Event | Evidence |
|---|---|---|
| | First contact with <site> | frame N / `http.log` uid … |
| | | |

## 4. Findings

### 4.1 Initial access
What started it, with the evidence (filter used, frame numbers, log lines). A screenshot where it helps.

### 4.2 Command and control
Servers, protocol, interval, what the traffic looks like.

### 4.3 Actions on the victim
Data sent out, follow-up downloads, spread inside the network.

## 5. Indicators of compromise

Full list in `iocs.csv`. Summary:

| Type | Indicator (defanged) | Role | Status | Reputation (service, date) |
|---|---|---|---|---|
| domain | | initial access | confirmed malicious | |

## 6. MITRE ATT&CK mapping

| Tactic | Technique | Evidence in this capture |
|---|---|---|
| | | |

## 7. Detections

| Rule | Type | Detects | Fires on this capture | Alerts on clean baseline |
|---|---|---|---|---|
| SID 10040xx | Suricata | | yes / no | 0 |
| 1008xx | Wazuh (Zeek) | | | |

ET Open rules that already fired: <list>. What the custom rules add: <one or two sentences>.

## 8. Recommendations

What a SOC should do: contain the host, reset which credentials, block what (only confirmed malicious indicators), and what to hunt for on other hosts.

## 9. What I missed (written after reading the answer key)

| Answer-key item | Found? | If missed: why, and what in the method would have caught it |
|---|---|---|
| | | |

Score: <found> of <total>.

## 10. Credits

Capture and exercise by Brad Duncan, malware-traffic-analysis.net. This report is our own analysis; it does not reproduce the site's text or answers.
