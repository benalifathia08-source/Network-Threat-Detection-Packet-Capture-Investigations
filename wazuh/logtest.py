#!/usr/bin/env python3
"""Send JSON log lines to the Wazuh manager's logtest socket and print the rule that matched.

The interactive `wazuh-logtest` tool hangs when it reads from a pipe, so this talks to
its socket directly (the documented logtest API: 4-byte little-endian length + JSON).

Usage on the Wazuh server:
    sudo python3 logtest.py <events.jsonl> [--expect <expected.txt>] [--location <path>]
Each line may start with "LOCATION<TAB>" to set a different location for that event.
Prints: rule id, level, description, for each line.
With --expect (one rule id per line, same order as the events) it prints PASS/FAIL per
line and exits with 1 if any line fails.
"""
import json
import socket
import struct
import sys

SOCK = "/var/ossec/queue/sockets/logtest"


def call(payload):
    data = json.dumps(payload).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(SOCK)
        s.sendall(struct.pack("<I", len(data)) + data)
        size = struct.unpack("<I", s.recv(4))[0]
        buf = b""
        while len(buf) < size:
            chunk = s.recv(size - len(buf))
            if not chunk:
                break
            buf += chunk
    return json.loads(buf)


def main():
    args = sys.argv[1:]
    path = args.pop(0)
    expected, default_location = None, "/var/log/nsm/cases/test/zeek/test.log"
    while args:
        opt = args.pop(0)
        if opt == "--expect":
            expected = [l.strip() for l in open(args.pop(0)) if l.strip()]
        elif opt == "--location":
            default_location = args.pop(0)
    token, results = None, []
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if not line.strip():
            continue
        location = default_location
        if "\t" in line:
            location, line = line.split("\t", 1)
        params = {"event": line, "log_format": "json", "location": location}
        if token:
            params["token"] = token
        reply = call({"version": 1, "command": "log_processing", "parameters": params})
        if reply.get("error"):
            print("error:", reply.get("message"))
            continue
        token = reply["data"].get("token", token)
        rule = reply["data"]["output"].get("rule", {})
        results.append(str(rule.get("id", "-")))
        mark = ""
        if expected is not None:
            want = expected[len(results) - 1] if len(results) <= len(expected) else "?"
            mark = "PASS  " if want == results[-1] else f"FAIL (want {want})  "
        print(f'{mark}{rule.get("id", "-"):>7}  level {rule.get("level", "-"):>2}  {rule.get("description", "(no rule)")}')
    if expected is not None:
        failed = sum(1 for i, r in enumerate(results) if i >= len(expected) or expected[i] != r)
        failed += max(0, len(expected) - len(results))
        print(f"{len(results) - failed if failed <= len(results) else 0}/{len(expected)} passed")
        sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
