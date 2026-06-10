#!/usr/bin/env python3
"""
smartwall-viewer — Attack report generator for Corero SmartWall.

Generates beautiful HTML attack reports from Corero SmartWall CMS data.
Accepts JSON from the CMS REST API, manual export, or example data.

Usage:
    python3 smartwall-viewer.py attacks.json                    # Generate report
    python3 smartwall-viewer.py attacks.json -o report.html     # Custom output
    python3 smartwall-viewer.py --demo                          # Generate demo report
    python3 smartwall-viewer.py --serve                         # Serve live dashboard
    python3 smartwall-viewer.py --serve --port 8700             # Custom port

Built by Flowtriq Networks Inc. (https://flowtriq.com)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

VERSION = "1.0.0"
SCRIPT_DIR = Path(__file__).parent


def _demo_data() -> dict:
    """Generate realistic demo attack data."""
    return {
        "device": {
            "name": "SmartWall-01",
            "model": "SmartWall TDS",
            "firmware": "10.3.2",
            "deployment": "inline",
            "uptime": "47 days, 12:34:56",
        },
        "summary": {
            "total_attacks": 147,
            "attacks_mitigated": 143,
            "attacks_escalated": 4,
            "avg_duration_seconds": 342,
            "peak_attack_gbps": 12.4,
            "peak_attack_mpps": 8.7,
            "period": "Last 30 days",
        },
        "protection_profiles": [
            {"name": "web-servers", "managed_objects": 3, "rules": 5, "attacks_blocked": 89},
            {"name": "dns-infra", "managed_objects": 1, "rules": 3, "attacks_blocked": 41},
            {"name": "game-servers", "managed_objects": 2, "rules": 4, "attacks_blocked": 17},
        ],
        "top_attack_types": [
            {"type": "UDP Flood", "count": 52, "pct": 35.4},
            {"type": "DNS Amplification", "count": 34, "pct": 23.1},
            {"type": "SYN Flood", "count": 28, "pct": 19.0},
            {"type": "NTP Amplification", "count": 15, "pct": 10.2},
            {"type": "HTTP Flood", "count": 11, "pct": 7.5},
            {"type": "Other", "count": 7, "pct": 4.8},
        ],
        "recent_attacks": [
            {"time": "2026-06-09 14:23:01", "target": "10.0.0.50", "type": "UDP Flood", "peak_mbps": 4200, "peak_pps": 3100000, "duration": "4m 12s", "action": "Dropped", "profile": "web-servers"},
            {"time": "2026-06-09 08:11:44", "target": "10.0.1.10", "type": "DNS Amplification", "peak_mbps": 8900, "peak_pps": 2400000, "duration": "12m 05s", "action": "Dropped", "profile": "dns-infra"},
            {"time": "2026-06-08 22:45:12", "target": "10.0.0.51", "type": "SYN Flood", "peak_mbps": 1200, "peak_pps": 5600000, "duration": "2m 33s", "action": "Rate-limited", "profile": "web-servers"},
            {"time": "2026-06-08 16:02:55", "target": "10.0.2.20", "type": "UDP Flood", "peak_mbps": 3400, "peak_pps": 2800000, "duration": "7m 18s", "action": "Dropped", "profile": "game-servers"},
            {"time": "2026-06-07 11:30:22", "target": "10.0.0.52", "type": "NTP Amplification", "peak_mbps": 12400, "peak_pps": 8700000, "duration": "15m 41s", "action": "Escalated to RTBH", "profile": "web-servers"},
            {"time": "2026-06-07 03:18:09", "target": "10.0.1.11", "type": "DNS Amplification", "peak_mbps": 5600, "peak_pps": 1900000, "duration": "8m 22s", "action": "Dropped", "profile": "dns-infra"},
            {"time": "2026-06-06 19:55:33", "target": "10.0.2.21", "type": "HTTP Flood", "peak_mbps": 450, "peak_pps": 890000, "duration": "22m 14s", "action": "Rate-limited", "profile": "game-servers"},
            {"time": "2026-06-06 09:12:47", "target": "10.0.0.50", "type": "SYN Flood", "peak_mbps": 2100, "peak_pps": 4200000, "duration": "3m 56s", "action": "Dropped", "profile": "web-servers"},
        ],
        "managed_objects": [
            {"name": "Web Frontend", "prefixes": ["10.0.0.0/24"], "profile": "web-servers", "attacks_30d": 52},
            {"name": "API Servers", "prefixes": ["10.0.0.128/25", "10.0.3.0/24"], "profile": "web-servers", "attacks_30d": 23},
            {"name": "DNS Cluster", "prefixes": ["10.0.1.0/24"], "profile": "dns-infra", "attacks_30d": 41},
            {"name": "Game Cluster A", "prefixes": ["10.0.2.0/25"], "profile": "game-servers", "attacks_30d": 11},
            {"name": "Game Cluster B", "prefixes": ["10.0.2.128/25"], "profile": "game-servers", "attacks_30d": 6},
            {"name": "Mail Servers", "prefixes": ["10.0.4.0/24"], "profile": "web-servers", "attacks_30d": 14},
        ],
    }


def generate_report(data: dict, is_demo: bool = False) -> str:
    """Generate an HTML report from SmartWall data."""
    device = data.get("device", {})
    summary = data.get("summary", {})
    profiles = data.get("protection_profiles", [])
    attack_types = data.get("top_attack_types", [])
    recent = data.get("recent_attacks", [])
    managed = data.get("managed_objects", [])

    demo_banner = ""
    if is_demo:
        demo_banner = '<div class="demo-banner">Demo Report -- Generated with example data. Export your SmartWall CMS data to see real attack analytics.</div>'

    # Build attack type bars
    max_count = max((a["count"] for a in attack_types), default=1)
    attack_type_rows = ""
    colors = ["#4ab8e8", "#00d97e", "#ff3b52", "#fbbc05", "#c084fc", "#5a7fa6"]
    for i, at in enumerate(attack_types):
        color = colors[i % len(colors)]
        pct = at["count"] / max_count * 100
        attack_type_rows += f"""
        <div class="at-row">
          <div class="at-label">{at['type']}</div>
          <div class="at-bar-wrap"><div class="at-bar" style="width:{pct:.0f}%;background:{color}"></div></div>
          <div class="at-count">{at['count']}<span class="at-pct">{at['pct']:.1f}%</span></div>
        </div>"""

    # Build profile cards
    profile_cards = ""
    for p in profiles:
        profile_cards += f"""
        <div class="profile-card">
          <div class="pc-name">{p['name']}</div>
          <div class="pc-stats">
            <div class="pc-stat"><span class="pc-num">{p['rules']}</span>Rules</div>
            <div class="pc-stat"><span class="pc-num">{p['managed_objects']}</span>Objects</div>
            <div class="pc-stat"><span class="pc-num">{p['attacks_blocked']}</span>Blocked</div>
          </div>
        </div>"""

    # Build recent attacks table
    attack_rows = ""
    for a in recent:
        action_class = "act-drop" if "Drop" in a["action"] else "act-limit" if "limit" in a["action"].lower() else "act-escalate"
        attack_rows += f"""
        <tr>
          <td>{a['time']}</td>
          <td>{a['target']}</td>
          <td>{a['type']}</td>
          <td>{a['peak_mbps']:,}</td>
          <td>{a['peak_pps']:,}</td>
          <td>{a['duration']}</td>
          <td><span class="action-badge {action_class}">{a['action']}</span></td>
        </tr>"""

    # Build managed objects table
    mo_rows = ""
    for m in managed:
        pfx = ", ".join(m.get("prefixes", []))
        mo_rows += f"""
        <tr>
          <td>{m['name']}</td>
          <td><code>{pfx}</code></td>
          <td>{m.get('profile', '')}</td>
          <td>{m.get('attacks_30d', 0)}</td>
        </tr>"""

    generated = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SmartWall Attack Report — {device.get('name', 'Corero SmartWall')}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
:root{{--bg:#0a0e17;--ink:#0f1521;--ink-2:#141c2b;--ink-3:#1a2436;--border:#1e2d44;--text:#8fa4c4;--text-2:#b0c4de;--white:#e8f0fa;--blue:#4ab8e8;--green:#00d97e;--red:#ff3b52;--yellow:#fbbc05;--mono:'SF Mono',Consolas,'Liberation Mono',monospace;--body:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}}
body{{background:var(--bg);color:var(--text);font-family:var(--body);padding:0}}
a{{color:var(--blue);text-decoration:none}}
code{{font-family:var(--mono);font-size:.82rem;color:var(--blue)}}

.header{{background:var(--ink);border-bottom:1px solid var(--border);padding:18px 32px;display:flex;align-items:center;justify-content:space-between}}
.header-left{{display:flex;align-items:center;gap:14px}}
.logo{{font-size:1.1rem;font-weight:700;color:var(--white)}}
.logo span{{color:var(--blue);font-weight:400;font-size:.85rem}}
.header-right{{font-size:.75rem;color:var(--text);display:flex;align-items:center;gap:16px}}
.header-right .badge{{font-family:var(--mono);font-size:.68rem;padding:4px 10px;border-radius:4px;border:1px solid var(--border)}}
.powered-by strong{{color:var(--blue)}}

.wrap{{max-width:1200px;margin:0 auto;padding:24px 32px 60px}}

.demo-banner{{background:rgba(251,188,5,.08);border:1px solid rgba(251,188,5,.25);border-radius:8px;padding:12px 18px;margin-bottom:20px;font-size:.82rem;color:var(--yellow)}}

.device-info{{display:flex;gap:24px;margin-bottom:24px;flex-wrap:wrap}}
.device-info .di{{font-size:.78rem;color:var(--text)}}
.device-info .di strong{{color:var(--text-2)}}

.stats-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin-bottom:28px}}
.stat-card{{background:var(--ink-2);border:1px solid var(--border);border-radius:10px;padding:18px 20px}}
.stat-label{{font-family:var(--mono);font-size:.62rem;letter-spacing:.1em;text-transform:uppercase;color:var(--text);margin-bottom:8px}}
.stat-value{{font-family:var(--mono);font-size:1.6rem;font-weight:700;color:var(--white)}}
.stat-value.blue{{color:var(--blue)}}
.stat-value.green{{color:var(--green)}}
.stat-value.red{{color:var(--red)}}
.stat-unit{{font-size:.7rem;color:var(--text);font-weight:400;margin-left:2px}}

.section{{margin-bottom:28px}}
.section h2{{font-size:1rem;color:var(--white);margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px}}
.section h2 .dot{{width:6px;height:6px;border-radius:50%;flex-shrink:0}}

.panels{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:28px}}

.at-row{{display:flex;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid rgba(30,45,68,.3)}}
.at-label{{width:160px;font-size:.82rem;color:var(--text-2);flex-shrink:0}}
.at-bar-wrap{{flex:1;height:6px;background:var(--ink-3);border-radius:3px;overflow:hidden}}
.at-bar{{height:100%;border-radius:3px;transition:width .6s}}
.at-count{{font-family:var(--mono);font-size:.8rem;color:var(--white);width:80px;text-align:right;flex-shrink:0}}
.at-pct{{color:var(--text);font-size:.7rem;margin-left:6px}}

.profile-cards{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}}
.profile-card{{background:var(--ink-2);border:1px solid var(--border);border-radius:8px;padding:16px}}
.pc-name{{font-family:var(--mono);font-size:.82rem;color:var(--blue);font-weight:600;margin-bottom:10px}}
.pc-stats{{display:flex;gap:14px}}
.pc-stat{{font-size:.7rem;color:var(--text);text-align:center}}
.pc-num{{display:block;font-family:var(--mono);font-size:1.1rem;font-weight:700;color:var(--white);margin-bottom:2px}}

table{{width:100%;border-collapse:collapse}}
th{{font-family:var(--mono);font-size:.62rem;letter-spacing:.08em;text-transform:uppercase;color:var(--text);padding:10px 12px;text-align:left;background:var(--ink-3);border-bottom:1px solid var(--border)}}
td{{padding:10px 12px;font-size:.8rem;color:var(--text-2);border-bottom:1px solid rgba(30,45,68,.4);font-family:var(--mono)}}
tr:hover td{{background:rgba(74,184,232,.03)}}

.action-badge{{font-size:.68rem;padding:3px 8px;border-radius:4px;font-family:var(--mono)}}
.act-drop{{background:rgba(0,217,126,.1);color:var(--green)}}
.act-limit{{background:rgba(251,188,5,.08);color:var(--yellow)}}
.act-escalate{{background:rgba(255,59,82,.08);color:var(--red)}}

.footer{{padding:32px;text-align:center;border-top:1px solid var(--border);margin-top:40px}}
.footer-brand{{font-size:.88rem;color:var(--text-2)}}
.footer-brand strong{{color:var(--blue)}}
.footer-sub{{font-size:.75rem;color:var(--text);margin-top:6px}}
.footer-links{{margin-top:10px;display:flex;justify-content:center;gap:16px;font-size:.75rem}}

@media(max-width:900px){{.stats-grid{{grid-template-columns:repeat(2,1fr)}}.panels{{grid-template-columns:1fr}}.profile-cards{{grid-template-columns:1fr}}}}
@media print{{body{{background:#fff;color:#333}}th{{background:#f0f0f0;color:#555}}td{{color:#333}}.stat-card,.profile-card{{background:#f9f9f9;border-color:#ddd}}.stat-value,.pc-num{{color:#111}}.header,.footer{{display:none}}}}
</style>
</head>
<body>

<div class="header">
  <div class="header-left">
    <div class="logo">SmartWall Attack Report <span>v{VERSION}</span></div>
  </div>
  <div class="header-right">
    <span class="badge">{device.get('name', '--')}</span>
    <span class="badge">{summary.get('period', 'Last 30 days')}</span>
    <div class="powered-by">Built by <strong><a href="https://flowtriq.com?ref=smartwall-viewer">Flowtriq</a></strong></div>
  </div>
</div>

<div class="wrap">
{demo_banner}

<div class="device-info">
  <div class="di"><strong>Device:</strong> {device.get('name', '--')}</div>
  <div class="di"><strong>Model:</strong> {device.get('model', '--')}</div>
  <div class="di"><strong>Firmware:</strong> {device.get('firmware', '--')}</div>
  <div class="di"><strong>Mode:</strong> {device.get('deployment', '--')}</div>
  <div class="di"><strong>Uptime:</strong> {device.get('uptime', '--')}</div>
  <div class="di"><strong>Generated:</strong> {generated}</div>
</div>

<div class="stats-grid">
  <div class="stat-card"><div class="stat-label">Total Attacks</div><div class="stat-value blue">{summary.get('total_attacks', 0)}</div></div>
  <div class="stat-card"><div class="stat-label">Mitigated</div><div class="stat-value green">{summary.get('attacks_mitigated', 0)}</div></div>
  <div class="stat-card"><div class="stat-label">Escalated</div><div class="stat-value red">{summary.get('attacks_escalated', 0)}</div></div>
  <div class="stat-card"><div class="stat-label">Peak Attack</div><div class="stat-value">{summary.get('peak_attack_gbps', 0)}<span class="stat-unit">Gbps</span></div></div>
  <div class="stat-card"><div class="stat-label">Avg Duration</div><div class="stat-value">{summary.get('avg_duration_seconds', 0) // 60}<span class="stat-unit">min</span></div></div>
</div>

<div class="panels">
  <div class="section">
    <h2><span class="dot" style="background:var(--blue)"></span>Attack Types</h2>
    {attack_type_rows}
  </div>
  <div class="section">
    <h2><span class="dot" style="background:var(--green)"></span>Protection Profiles</h2>
    <div class="profile-cards">{profile_cards}</div>
  </div>
</div>

<div class="section">
  <h2><span class="dot" style="background:var(--red)"></span>Recent Attacks</h2>
  <table>
    <thead><tr><th>Time</th><th>Target</th><th>Type</th><th>Peak Mbps</th><th>Peak PPS</th><th>Duration</th><th>Action</th></tr></thead>
    <tbody>{attack_rows}</tbody>
  </table>
</div>

<div class="section">
  <h2><span class="dot" style="background:var(--blue)"></span>Managed Objects</h2>
  <table>
    <thead><tr><th>Name</th><th>Prefixes</th><th>Profile</th><th>Attacks (30d)</th></tr></thead>
    <tbody>{mo_rows}</tbody>
  </table>
</div>

</div>

<div class="footer">
  <div class="footer-brand">Generated by <strong><a href="https://flowtriq.com?ref=smartwall-viewer">Flowtriq</a></strong> SmartWall Viewer</div>
  <div class="footer-sub">Looking for sub-second detection, L7 protection, and PCAP forensics? <a href="https://flowtriq.com?ref=smartwall-viewer">flowtriq.com</a></div>
  <div class="footer-links">
    <a href="https://flowtriq.com?ref=smartwall-viewer">Flowtriq</a>
    <a href="https://flowtriq.com/pricing?ref=smartwall-viewer">Pricing</a>
    <a href="https://github.com/flowtriq/flowtriq-migrate">Migration Tool</a>
    <a href="https://github.com/flowtriq/smartwall-viewer">GitHub</a>
  </div>
</div>

</body>
</html>"""


class ViewerHandler(SimpleHTTPRequestHandler):
    """Serve the demo report."""

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            html = generate_report(_demo_data(), is_demo=True).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", len(html))
            self.end_headers()
            self.wfile.write(html)
        else:
            self.send_error(404)

    def log_message(self, format, *args):
        pass


def main():
    parser = argparse.ArgumentParser(
        description="SmartWall Viewer — Attack report generator for Corero SmartWall",
    )
    parser.add_argument("input_file", nargs="?", help="JSON file with SmartWall data")
    parser.add_argument("-o", "--output", default="report.html", help="Output HTML file (default: report.html)")
    parser.add_argument("--demo", action="store_true", help="Generate a demo report with example data")
    parser.add_argument("--serve", action="store_true", help="Serve the report as a live web page")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address for --serve (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8700, help="Port for --serve (default: 8700)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()

    if args.serve:
        print(f"\n  SmartWall Viewer v{VERSION}")
        print(f"  http://{args.host}:{args.port}")
        print(f"  Built by Flowtriq -- https://flowtriq.com\n")
        server = HTTPServer((args.host, args.port), ViewerHandler)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down.")
        return

    if args.demo:
        data = _demo_data()
        is_demo = True
    elif args.input_file:
        try:
            with open(args.input_file) as f:
                data = json.load(f)
            is_demo = False
        except FileNotFoundError:
            print(f"Error: File not found: {args.input_file}", file=sys.stderr)
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

    html = generate_report(data, is_demo=is_demo)
    with open(args.output, "w") as f:
        f.write(html)
    print(f"Report generated: {args.output}")


if __name__ == "__main__":
    main()
