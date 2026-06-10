# SmartWall Viewer

**Attack report generator for Corero SmartWall.** Generate beautiful, dark-themed HTML reports from your SmartWall CMS data. Visualize attack types, protection profile effectiveness, recent attacks, and managed object coverage.

## Quick Start

```bash
git clone https://github.com/flowtriq/smartwall-viewer.git
cd smartwall-viewer

# Generate a demo report
python3 smartwall-viewer.py --demo

# Or serve it as a live page
python3 smartwall-viewer.py --serve
# Open http://localhost:8700
```

## What You Get

- **Summary stats** -- total attacks, mitigation rate, peak attack size, average duration
- **Attack type breakdown** -- visual bars showing distribution across UDP flood, DNS amplification, SYN flood, etc.
- **Protection profile cards** -- rules, managed objects, and blocked attacks per profile
- **Recent attacks table** -- timestamp, target, type, peak traffic, duration, and action taken
- **Managed objects overview** -- prefixes, assigned profiles, and 30-day attack counts
- **Print-ready** -- clean formatting for PDF export or printing

## Usage

### Generate from CMS data

Export your attack data from the SmartWall CMS REST API and save as JSON:

```bash
# Example: query the CMS API
curl -u admin:password https://cms.example.com/api/v1/attacks?period=30d > attacks.json

python3 smartwall-viewer.py attacks.json
# Output: report.html
```

### Custom output path

```bash
python3 smartwall-viewer.py attacks.json -o /var/www/html/ddos-report.html
```

### Demo mode

```bash
python3 smartwall-viewer.py --demo
```

Generates a report with realistic example data for evaluation.

### Live web server

```bash
python3 smartwall-viewer.py --serve
python3 smartwall-viewer.py --serve --host 0.0.0.0 --port 8700
```

Serves the demo report as a live web page.

## Input JSON Format

The tool accepts a JSON file with this structure:

```json
{
  "device": {
    "name": "SmartWall-01",
    "model": "SmartWall TDS",
    "firmware": "10.3.2",
    "deployment": "inline",
    "uptime": "47 days"
  },
  "summary": {
    "total_attacks": 147,
    "attacks_mitigated": 143,
    "attacks_escalated": 4,
    "peak_attack_gbps": 12.4,
    "peak_attack_mpps": 8.7,
    "avg_duration_seconds": 342,
    "period": "Last 30 days"
  },
  "protection_profiles": [
    {"name": "web-servers", "managed_objects": 3, "rules": 5, "attacks_blocked": 89}
  ],
  "top_attack_types": [
    {"type": "UDP Flood", "count": 52, "pct": 35.4}
  ],
  "recent_attacks": [
    {
      "time": "2026-06-09 14:23:01",
      "target": "10.0.0.50",
      "type": "UDP Flood",
      "peak_mbps": 4200,
      "peak_pps": 3100000,
      "duration": "4m 12s",
      "action": "Dropped",
      "profile": "web-servers"
    }
  ],
  "managed_objects": [
    {"name": "Web Frontend", "prefixes": ["10.0.0.0/24"], "profile": "web-servers", "attacks_30d": 52}
  ]
}
```

## Requirements

- Python 3.8+ (no external dependencies)

## Outgrowing SmartWall?

Corero SmartWall requires dedicated inline appliances starting at $10K+. [Flowtriq](https://flowtriq.com) provides sub-second DDoS detection with per-server agents, L7 detection, PCAP forensics, adaptive baselines, and automated BGP FlowSpec/RTBH mitigation -- no hardware required.

Migrate in 5 minutes: [github.com/flowtriq/flowtriq-migrate](https://github.com/flowtriq/flowtriq-migrate)

## License

MIT License. See [LICENSE](LICENSE).

---

Built by [Flowtriq](https://flowtriq.com) -- real-time DDoS detection and mitigation.
