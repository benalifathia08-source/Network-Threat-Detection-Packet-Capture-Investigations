# NTD (Project 4) Zeek policy for offline case analysis. Used instead of Zeek's "local".
# Installed to /usr/local/share/ntd/ntd.zeek by install_agent_config.sh.
#
# Same as the packaged site/local.zeek (Zeek 8.0.10), except:
#   removed  frameworks/files/detect-MHR    sends every file hash to an outside DNS service
#                                            (Team Cymru); nothing leaves the lab
#   removed  protocols/ssh/geo-data          needs a GeoIP database we don't have
#   removed  frameworks/telemetry/log        Zeek's own performance metrics, not evidence
#   added    community-id-logging            same flow ID as Suricata's eve.json
#   added    mac-logging                     MAC addresses in conn.log (victim identification)
#   set      Site::local_nets                the private ranges the case networks use
#   set      JSON logs with ISO 8601 times   for Wazuh and jq
#   added    SHA-256 for every file          (see the event at the end)

@load misc/loaded-scripts
@load misc/capture-loss
@load misc/stats
@load frameworks/software/vulnerable
@load frameworks/software/version-changes
@load-sigs frameworks/signatures/detect-windows-shells
@load protocols/ftp/software
@load protocols/smtp/software
@load protocols/ssh/software
@load protocols/http/software
@load protocols/dns/detect-external-names
@load protocols/ftp/detect
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/ssl/known-certs
@load protocols/ssl/validate-certs
@load protocols/ssl/log-hostcerts-only
@load protocols/ssh/detect-bruteforcing
@load protocols/ssh/interesting-hostnames
@load protocols/http/detect-sql-injection
@load frameworks/files/hash-all-files
@load policy/frameworks/notice/extend-email/hostnames
@load policy/protocols/conn/community-id-logging
@load policy/protocols/conn/mac-logging

redef Site::local_nets += { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 };

# SHA-256 for every file, in memory (nothing is written to disk). hash-all-files only adds
# MD5 and SHA-1 in Zeek 8.0; threat intelligence and reports use SHA-256 (found in case 3,
# 2026-10-22: files.log had sha256 = null for the program sent over port 9000).
event file_sniff(f: fa_file, meta: fa_metadata)
	{
	Files::add_analyzer(f, Files::ANALYZER_SHA256);
	}

redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;
