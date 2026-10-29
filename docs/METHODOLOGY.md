# How we investigate a capture

The same steps for every case, so the three reports can be compared and the method itself can be shown in an interview. Each step lists the question, where the answer usually is, and a starting filter or command. Record every finding with its **UTC time** and **the evidence** (frame number, log line or alert). The report is written from these notes.

Paths below assume the case was processed with `scripts/analyze_pcap.sh <case>` (built in M1): Zeek JSON logs and Suricata `eve.json` are in `/var/log/nsm/cases/<case>/`.

## Step 0 — Know what you have

- Capture time span, packet count, size: `capinfos <file>.pcap`
- Who talks the most: Wireshark *Statistics → Conversations* (IPv4 and TCP tabs), or Zeek `conn.log` grouped by `id.resp_h`.
- Read the case scenario on the site again: what does it ask you to find?

## Step 1 — Identify the victim

Questions: which internal IP is infected? Its MAC address, host name and Windows user account?

| Clue | Wireshark filter | Zeek log |
|---|---|---|
| Host name and MAC from DHCP | `dhcp` | `dhcp.log` (`host_name`, `mac`) |
| Host name from NetBIOS | `nbns` | — |
| User account from Kerberos | `kerberos.CNameString` (add it as a column; names ending in `$` are computers) | `kerberos.log` (`client`) |
| Domain and domain controller | `ldap` or `kerberos`; DC name: `browser.command == 0x0f` | `kerberos.log`, `ldap` logs if present |
| Host name (Windows browser announcements) | `browser.response_computer_name` | — |
| User's full name (SAMR, when not encrypted) | `samr.samr_UserInfo21.full_name`, or `samr.opnum == 36` and open the reply | `dce_rpc.log` shows the call, not the value |

## Step 2 — Find how the infection started

Questions: which first suspicious web request or download started it? Was it a fake website, a link in an e-mail, a fake software installer, a "fix this error" page?

- Web requests and encrypted connections, in time order:
  `(http.request or tls.handshake.type eq 1) and !(ssdp)`
- Add columns for `tls.handshake.extensions_server_name` (the site name inside encrypted traffic) and `http.host`.
- Zeek: `http.log` (method, host, uri, user_agent, resp_mime_types), `ssl.log` (`server_name`), `files.log` (mime type, hashes).
- Look for: a download whose MIME type is a program or script (`application/x-dosexec`, zip, `.js`, `.ps1`, `.msi`); an odd user agent (PowerShell, curl, a script engine); a domain registered recently or a site name that imitates a brand.

## Step 3 — Find the command-and-control (C2)

Questions: after infection, which servers does the victim keep contacting, how often, and over what?

- Suricata alerts first: `jq -r 'select(.event_type=="alert") | [.timestamp, .src_ip, .dest_ip, .dest_port, .alert.signature] | @tsv' eve.json`
- Repeating connections (beaconing): group Zeek `conn.log` by destination and look at the time between connections. A steady interval (every 60 s, every 5 min) with little variation is a strong sign.
- Connections straight to an IP address with no DNS lookup before them.
- TLS to unusual ports, or self-signed certificates: Zeek `ssl.log` and `x509.log`.
- DNS: many lookups for random-looking names, very long names, or lots of TXT records: `dns.log`.

## Step 4 — Find what was taken or done

Questions: was data sent out (stolen passwords, files, screenshots)? Was more malware downloaded? Did it spread inside the network?

- Large uploads: Zeek `conn.log` where `orig_bytes` is much bigger than `resp_bytes`.
- HTTP `POST` requests to the C2: `http.request.method == "POST"`.
- Follow-up downloads after the first infection: `files.log` in time order.
- Inside the network: SMB to other hosts (`smb2`), LDAP queries, Kerberos tickets for services (`kerberos.msg_type == 13`), or remote management traffic.

## Step 5 — Build the timeline

One table, UTC, in order: first contact → download → execution sign (first C2) → C2 pattern → data taken / follow-up. Each line points to its evidence. The timeline is the backbone of the report.

## Step 6 — Extract and check indicators

- Collect domains, IPs, URLs and file hashes into `iocs.csv`, **defanged** (see `SAFETY.md`).
- **File hashes:** take MD5 / SHA-1 / SHA-256 from Zeek's `files.log`. If a hash is missing, rebuild it from the stream **in memory** (`ntshark.sh … -T fields -e http.file_data | tr -d ':\n' | xxd -r -p | sha256sum`), never by exporting the file. **Verify every hash two ways**: in case 3 a clever one-liner gave a wrong SHA-256, and only the comparison with Zeek's MD5 / SHA-1 caught it.
- Check each one against reputation services **by name or hash only**. Record what each service said and when; an empty answer is "unknown", never "clean".
- Mark each indicator: *confirmed malicious*, *suspicious*, or *context* (for example, a legitimate site the malware abused, like a cloud storage host). Context indicators must not be turned into blocking rules.

## Step 7 — Map to MITRE ATT&CK

For each step of the timeline, the technique it shows (for example T1189 Drive-by Compromise, T1204 User Execution, T1071.001 Web Protocols, T1105 Ingress Tool Transfer, T1041 Exfiltration Over C2 Channel). Only map what the traffic actually shows; say "suspected" otherwise.

## Step 8 — Write detections

- Prefer behaviour over single indicators: a rule on the C2's URL pattern or user agent lasts longer than one on an IP address that changes next week.
- For each rule: what it detects, why, what could cause a false alarm, and its test (see `detections/README.md`).
- Note which ET Open rules already fired, so the custom rules add something new rather than duplicate them.

## Step 9 — Only now: the answer key

Open the official answers, compare item by item, and fill in "What I missed" in the report. Do not edit the earlier sections to hide a miss. If a miss shows a gap in this method, update this file and say so in the log.
