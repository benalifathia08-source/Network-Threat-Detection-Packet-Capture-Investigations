# Case 1: reproduce the key findings in Wireshark

Goal: be able to show and explain each finding in an interview, from the raw capture, without the scripts. About 45 minutes. Each step gives the Wireshark filter, where to look, what you should see, and the screenshot to save.

## Before you start

1. **Install Wireshark 4.6.9**: <https://www.wireshark.org/download.html>, Windows x64 installer. **Untick Npcap** during setup (it's only for live capture).
2. **Copy the capture (the `.pcap` only, never the zip)** from the tools VM. In Git Bash (start Wazuh and the tools VM first if they are off):
   ```bash
   mkdir -p /c/Users/Fathia/Documents/ntd-pcaps
   /c/Windows/System32/OpenSSH/scp.exe fathia@192.168.145.20:/srv/cases/case-1/pcap/2026-01-31-traffic-analysis-exercise.pcap /c/Users/Fathia/Documents/ntd-pcaps/
   ```
   That folder is outside the repo and outside OneDrive. Delete the file when case 1 is closed.
3. Open it in Wireshark. Then set **View → Time Display Format → UTC Date and Time of Day**, so the times match the report.
4. Never use **File → Export Objects** on this capture (docs/SAFETY.md). Never open any domain from it in a browser.

Save screenshots to `Network-Threat-Detection/docs/screenshots/case-1/` with the names given below. Blur nothing: everything in this capture is fake lab data. But never show a real IP of yours.

## 1. Victim host, IP and MAC (DHCP)

- Filter: `dhcp`
- Click the **ACK** packet (the 4th). In the middle pane, open *Dynamic Host Configuration Protocol*:
  - *Your (client) IP address*: **10.1.21.58**
  - *Option (12) Host Name*: **DESKTOP-ES9F3ML**
  - *Client MAC address*: **00:21:5d:c8:0e:f2**
- 📸 `01-dhcp-victim.png`

## 2. User account (Kerberos)

- Filter: `kerberos.CNameString and !(kerberos.CNameString contains "$")` (names ending in `$` are computer accounts)
- Right-click *CNameString* in the details → *Apply as Column*.
- You should see **gwyatt** in the AS-REQ/AS-REP at 23:04:24.
- 📸 `02-kerberos-user.png`

## 3. Full name (SAMR)

- Filter: `samr.opnum == 36` (QueryUserInfo)
- Click the **response**, **frame 358**. Open *SAMR → … → Info21* and find **Full Name: Gabriel Wyatt**.
- Why is this readable? SAMR over SMB to the DC wasn't encrypted here, while LDAP was (SASL-sealed). Worth saying in an interview.
- 📸 `03-samr-full-name.png`

## 4. The lure chain and the download

- Filter: `(http.request or tls.handshake.type eq 1) and !(ssdp)`
- Add a column: right-click *Server Name* (under TLS → Handshake → Extension: server_name) → *Apply as Column*.
- Between **23:04:44 and 23:04:52**: drive.google.com, then media.megafilehub4[.]lat, then arch.filemegahab4[.]sbs.
- **Statistics → Conversations → TCP**, sort by *Bytes B → A*: the top one is 10.1.21.58 ↔ **104.21.46.67:443, about 15.9 MB** to the victim. That's the download.
- 📸 `04-lure-chain.png`, `05-download-size.png`

## 5. The Lumma check-in and the browser fingerprint

- Filter: `http.request and http.host contains "whitepepper"`
- Four requests: GET `/api/set_agent?id=…&agent=Chrome`, POST `…&act=log`, then the same pair with `agent=Edge`. Look at the *User-Agent* lines: real Chrome, then real Edge. **The malware drove the user's own browsers.**
- Right-click the first POST (**frame 24601**) → *Follow → HTTP Stream*. The body starts with `timestamp=…&system=%7B%22platform%22…`, a URL-encoded fingerprint of the browser. (Text only, safe to view.)
- 📸 `06-c2-http.png`, `07-fingerprint-post.png`

## 6. The data theft (upload sizes)

- Filter `tls.handshake.extensions_server_name contains "whitepepper"`, then **Statistics → Conversations → TCP**, tick *Limit to display filter*, sort by *Bytes A → B* (victim to server).
- Three conversations stand out: about **253 KB, 388 KB and 1.42 MB sent by the victim**, with only a few KB back each. Encryption hides the content, not the direction or the size.
- 📸 `08-upload-sizes.png`

## 7. The LSA lookup burst (suspected discovery)

- Filter: `lsarpc.opnum == 68` (LookupNames3)
- Look at the times: hundreds of packets between **23:06:13 and 23:06:15**.
- Open a few requests: the names are domain groups (*Domain Admins*, *Enterprise Admins*, …).
- **Statistics → I/O Graphs** with that filter shows the spike nicely.
- 📸 `09-lsa-burst.png`

## 8. The same story in Wazuh

- Dashboard → *Threat Hunting* (or *Discover*), filter `location: *case-1*`, time range "Last 24 hours".
- Look for rule **86601** (ET Lumma alerts), **100801** (upload-heavy sessions, level 8), **100803** (LSA burst, level 10), and **100871/100873** (Zeek DNS/TLS) for the timeline.
- Remember: Wazuh's time column is when Wazuh read the line. The traffic time is in `data.ts` / `data.timestamp`.
- 📸 `10-wazuh-case1.png`

## Then

The report is final and the answer key has been checked (section 9 of `REPORT.md`: 7 of 7). This guide is for **you**: being able to show each finding live, from the raw capture, is what convinces an interviewer. Optional: rewrite the executive summary in your own words, so you can tell the story without notes.
