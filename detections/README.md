# Detections

Rules written from the three investigations. Every rule has a test, and a rule without a passing test is not finished.

## Layout

| Path | Contents |
|---|---|
| `suricata/local.rules` | Custom Suricata rules, SIDs **1004001–1004999** |
| `wazuh/nsm_rules.xml` | Custom Wazuh rules on Zeek and Suricata JSON, IDs **100800–100899** (created in M1) |
| `tests/wazuh_pipeline_fixtures.jsonl` + `tests/wazuh_pipeline_expected.txt` | Sample events for the pipeline rules (100860–100880) and the case 1 rules (100801, 100802), including look-alikes that must NOT match, and the rule each must match. Run on the Wazuh server: `sudo python3 ~/ntd/logtest.py ~/ntd/wazuh_pipeline_fixtures.jsonl --expect ~/ntd/wazuh_pipeline_expected.txt` (18/18 on 2026-10-21) |
| `tests/expected.json` | For each case rule: where it must fire (exact or minimum count) and that it stays silent on every other capture. Run from the laptop: `python -I scripts/test_detections.py` (prints the Markdown table used in the reports and README) |

ID blocks: 1004001–1004099 and 100800–100819 for case 1, 1004100–1004199 and 100820–100839 for case 2, 1004200–1004299 and 100840–100859 for case 3. 100860–100899 is for pipeline rules (for example "case processed").

## Rule conventions

- `msg` starts with `FTOU7 NTD` and names the behaviour, not just the family: `FTOU7 NTD Lumma-style C2 POST to /api with short random body`.
- Every Suricata rule has `classtype`, `sid`, `rev` and a `metadata: case <n>, created <date>, author ftou7` field.
- Prefer behaviour (URL pattern, user agent, TLS details, interval) over a single IP or domain. A rule on a single indicator is allowed only with a comment that says so and why.
- A header comment above each rule explains: what it detects, why, and what could cause a false alarm.

## Tests (built in M3, extended in M6)

For each rule:

1. **True positive:** run Suricata (or replay the Zeek JSON through `wazuh-logtest`) on the case capture. The rule must fire at least the expected number of times.
2. **False positive:** run the same on the clean baseline capture made on the tools VM in M2. The rule must not fire.
3. **Syntax:** `suricata -T` loads the rules with no errors; Wazuh accepts the XML (`wazuh-logtest` and a manager restart without errors).

The test script prints a table that goes into the README unchanged.

## Current rules

Live test 2026-10-22 (`python -I scripts/test_detections.py`): **11/11 pass**, exact counts, 0 hits on every other capture.

| Rule | Case | Detects | ATT&CK | Baseline | Case 1 | Case 2 | Case 3 |
|---|---|---|---|---|---|---|---|
| Suricata 1004001 | 1 | Lumma-style browser fingerprint upload (`POST /api/set_agent?…&act=log`) | T1041 | 0 | **2** | 0 | 0 |
| Wazuh 100801 | 1 | Upload-heavy TLS session (≥ 200 KB up, < 100 KB down, outside host) | T1041 | 0 | **3** | 0 | 0 |
| Wazuh 100803 (+100802) | 1 | 100+ LSA name lookups from one host in 10 s | T1069.002 | 0 | **1** | 0 | 0 |
| Suricata 1004101 | 2 | Backdoor C2 path: random path + `&` + 64-hex token | T1071.001 | 0 | 0 | **99** | 0 |
| Wazuh 100822 | 2 | Plain-HTTP POST ≥ 1 MB to an outside host | T1041 | 0 | 0 | **1** | 0 |
| Wazuh 100821 (+100820) | 2 | 20+ empty (204) replies from one host in 5 min | T1071.001 | 0 | 0 | **1** | 0 |
| Wazuh 100824 (+100823) | 2 | Same name fails to resolve 10+ times in 5 min (excl. wpad, isatap, SRV) | T1008 | 0 | 0 | **1** | 0 |
| Suricata 1004201 | 3 | Non-TLS traffic to TCP 443 (protocol detection failed), once per connection | T1571 / T1095 | 0 | 0 | 0 | **1** |
| Wazuh 100840 | 3 | curl / wget / PowerShell downloads a Windows program over HTTP | T1105 | 0 | 0 | 0 | **1** |
| Wazuh 100841 | 3 | Command-line HTTP request from a workstation (visibility, level 5) | — | 0 | 0 | 0 | **2** |
| Wazuh 100842 | 3 | DNS-over-HTTPS from a client | T1071.004 | 0 | 0 | 0 | **1** |

Pipeline and visibility rules (not case detections): 100860 (our Suricata SIDs at level 10), 100870–100876 (Zeek events searchable in Wazuh), 100880 (a Windows program seen in Zeek, T1105).

**Rule order matters in Wazuh:** sibling rules are tried in the order they are written. 100822 (large upload) is placed before 100820 (empty reply) because the 4.4 MB upload was answered with a 204, and 100840 before 100841 for the same reason. Both are covered by the unit tests.

## Lessons (Wazuh)

- **Frequency rules don't count level-0 matches.** 100803 never fired while its parent 100802 was level 0; at level 1 it works. Level 1 stays below the alert log level, so nothing floods the dashboard.
- **Numbers can only be compared with regex.** 100801 uses PCRE2 patterns such as `^([2-9]\d{5}|\d{7,})$` (≥ 200,000) on Zeek's byte counts, and `negate="yes"` to exclude private address ranges.
- **The `ignore` timer is per rule, not per field value.** After 100824 fires for one dead domain, it stays silent for 5 minutes for all names; the tests therefore expect "at least 1" for frequency rules.
- **Use documentation addresses in test data.** The fixtures use 203.0.113.0/24 (RFC 5737), not the real attacker IPs, so the repository holds no live indicators.
- **Test data written through a Bash heredoc loses backslashes** (`\\pipe` became `\pipe`, invalid JSON). Write fixtures with Python.
