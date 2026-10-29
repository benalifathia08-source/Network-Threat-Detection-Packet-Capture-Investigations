#!/usr/bin/env python3
"""Draw docs/figures/case2-beacon.svg: the case 2 backdoor's activity on one time axis.

Input: a TSV exported from the case 2 Zeek logs on the tools VM (see the command in
docs/figures/README.md). Lines are:
    <ts> <status> <method> <request_body_len> <host>   HTTP requests with the C2 URL layout
    ---TLS, then one <ts> per TLS session to the rotating C2 domains
    ---NX,  then one <ts> per failed lookup of the dead fallback domains
Standard library only. Labels use roles, never domain names (nothing live in the image).

Usage: python -I scripts/make_figures.py <case2_beacon.tsv> docs/figures/case2-beacon.svg
"""
import sys
from datetime import datetime

W, H = 980, 380
LEFT, RIGHT = 170, 30
T0 = datetime.fromisoformat("2026-09-11T20:05:00+00:00")
T1 = datetime.fromisoformat("2026-09-11T20:28:00+00:00")
ROWS = {  # label, y
    "http": ("HTTP C2, every ~10 s", 120),
    "fallback": ("Refused by a C2 server", 180),
    "tls": ("TLS C2, every ~16 s", 240),
    "nx": ("Dead fallback names", 300),
}
INK, MUTED, GRID = "#1f2328", "#59636e", "#d1d9e0"
C_EMPTY, C_TASK, C_POST, C_BIG, C_REFUSED, C_TLS, C_NX = (
    "#8c959f", "#0969da", "#bf8700", "#cf222e", "#cf222e", "#1a7f37", "#8250df")


def ts(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def x(t):
    return LEFT + (t - T0).total_seconds() / (T1 - T0).total_seconds() * (W - LEFT - RIGHT)


def main():
    src, out = sys.argv[1], sys.argv[2]
    http, tls, nx, section = [], [], [], "http"
    for line in open(src, encoding="utf-8"):
        line = line.rstrip("\n")
        if line.startswith("---"):
            section = line[3:].lower()
            continue
        if not line:
            continue
        parts = line.split("\t")
        if section == "http":
            http.append((ts(parts[0]), parts[1], parts[2], int(parts[3] or 0)))
        elif section == "tls":
            tls.append(ts(parts[0]))
        else:
            nx.append(ts(parts[0]))

    s = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
         'font-family="Segoe UI, Helvetica, Arial, sans-serif" role="img" '
         'aria-label="Case 2: backdoor activity over time">',
         f'<rect width="{W}" height="{H}" fill="#ffffff"/>',
         f'<text x="20" y="32" font-size="18" font-weight="600" fill="{INK}">Case 2: the backdoor\'s rhythm '
         '(2026-09-11, UTC)</text>',
         f'<text x="20" y="54" font-size="13" fill="{MUTED}">Each mark is one connection or request. '
         'The domains changed; the rhythm and the URL layout did not.</text>']
    # minute grid
    for minute in range(5, 29):
        t = T0.replace(minute=minute)
        gx = x(t)
        s.append(f'<line x1="{gx:.1f}" y1="85" x2="{gx:.1f}" y2="325" stroke="{GRID}" stroke-width="1"/>')
        if minute % 5 == 0:
            s.append(f'<text x="{gx:.1f}" y="345" font-size="12" fill="{MUTED}" text-anchor="middle">20:{minute:02d}</text>')
    for label, y in ROWS.values():
        s.append(f'<text x="{LEFT - 12}" y="{y + 4}" font-size="13" fill="{INK}" text-anchor="end">{label}</text>')
    # events
    for t, status, method, body in http:
        cx = x(t)
        if status in ("400", "406"):
            y = ROWS["fallback"][1]
            s.append(f'<path d="M{cx-4:.1f},{y-4} l8,8 m0,-8 l-8,8" stroke="{C_REFUSED}" stroke-width="2"/>')
            continue
        y = ROWS["http"][1]
        if method == "POST" and body >= 1_000_000:
            s.append(f'<circle cx="{cx:.1f}" cy="{y}" r="9" fill="{C_BIG}"/>')
        elif method == "POST":
            s.append(f'<circle cx="{cx:.1f}" cy="{y}" r="5" fill="{C_POST}"/>')
        elif status == "200":
            s.append(f'<circle cx="{cx:.1f}" cy="{y}" r="5" fill="{C_TASK}"/>')
        else:
            s.append(f'<circle cx="{cx:.1f}" cy="{y}" r="3.5" fill="{C_EMPTY}"/>')
    for t in tls:
        s.append(f'<rect x="{x(t)-2:.1f}" y="{ROWS["tls"][1]-7}" width="4" height="14" fill="{C_TLS}"/>')
    for t in nx:
        s.append(f'<rect x="{x(t)-1.5:.1f}" y="{ROWS["nx"][1]-5}" width="3" height="10" fill="{C_NX}"/>')
    # annotations
    marks = [("2026-09-11T20:05:56Z", "inject"), ("2026-09-11T20:06:47Z", "Node.js"),
             ("2026-09-11T20:09:55Z", "4.4 MB upload"), ("2026-09-11T20:22:07Z", "user logs on again")]
    for i, (when, text) in enumerate(marks):
        ax = x(ts(when))
        ty = 80 if i % 2 else 66
        s.append(f'<line x1="{ax:.1f}" y1="{ty - 10}" x2="{ax:.1f}" y2="325" stroke="{INK}" stroke-width="1" stroke-dasharray="3,3"/>')
        s.append(f'<text x="{ax + 4:.1f}" y="{ty}" font-size="12" fill="{INK}">{text}</text>')
    # legend
    lx, ly = LEFT, 368
    legend = [(C_EMPTY, "empty reply (204)"), (C_TASK, "task (200)"), (C_POST, "result POST"),
              (C_BIG, "4.4 MB POST"), (C_REFUSED, "refused (400/406)"), (C_TLS, "TLS session"), (C_NX, "NXDOMAIN")]
    for color, text in legend:
        s.append(f'<circle cx="{lx}" cy="{ly - 4}" r="5" fill="{color}"/>')
        s.append(f'<text x="{lx + 9}" y="{ly}" font-size="12" fill="{INK}">{text}</text>')
        lx += 9 + 7 * len(text) + 22
    s.append("</svg>")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(s) + "\n")
    print(f"wrote {out}: {len(http)} HTTP, {len(tls)} TLS, {len(nx)} NXDOMAIN events")


if __name__ == "__main__":
    main()
