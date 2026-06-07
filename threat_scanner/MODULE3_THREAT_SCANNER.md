# Module 3 – Threat Scanner

## Overview

The **Threat Scanner** actively detects security issues in your environment and feeds the findings directly into the **Module 1 Graph Knowledge Base**. It runs lightweight checks on hosts, processes, and log files, then pushes structured **Event** nodes into the graph for immediate investigation.

- **No external database** – uses the existing Module 1 REST API (`POST /ingest/events`).
- **Extensible framework** – new scanners can be added by creating a single Python class.
- **Immediate integration** – after a scan, Module 2 (MITRE Mapper) or manual graph expansion will automatically include the new events.

## Architecture

threat_scanner/
├── scanner_framework.py         # Base scanner class, ingestion helper
├── scan.py                      # CLI entry point
├── scanner_config.json          # Central configuration
├── scanners/
│   ├── port_scanner.py          # TCP port scanner
│   ├── process_scanner.py       # Suspicious process detector
│   └── log_watcher.py           # Log file analyser
└── data/
└── sample_firewall.log      # Example log for testing

```

The scanner runs on the same Termux device (or any machine with Python) and communicates with the Graph Knowledge Base API at `http://localhost:8000`.

## Included Scanners (Prototype)

### 1. Port Scanner
- Connects to a configurable list of TCP ports on target hosts.
- Reports open ports with a severity based on the port number (e.g., SMB/445 → high).
- Uses Python’s `socket` module – no external tools required.

### 2. Suspicious Process Scanner
- Lists running processes using `ps aux` (Linux/Termux) or `tasklist` (Windows).
- Compares process names against a blacklist (`nc`, `netcat`, `mimikatz`, etc.).
- Generates a medium‑severity event when a match is found.

### 3. Log Watcher
- Reads a firewall/syslog file (configurable path).
- Scans each line for known malicious patterns (`DROP`, `Failed password`, specific IPs).
- Produces events with appropriate severity (medium for generic drops, high for known‑bad IPs).

## Setup

### Prerequisites
- **Module 1** must be installed and running on `http://localhost:8000`.
- Python packages: `requests` (already installed with Module 1).
- No other dependencies.

### Installation (Termux one‑liner)

Paste the entire block below to create the module:

```bash
mkdir -p ~/projects/cyber_platform/threat_scanner/scanners
mkdir -p ~/projects/cyber_platform/threat_scanner/data
cd ~/projects/cyber_platform/threat_scanner

# ... (all file creation commands as provided earlier) ...
```

If you haven't already run the full setup script, use the complete block from the Module 3 code answer. The block above is omitted here for brevity; you already have it saved from the previous message.

Usage

Run the scanner from the module’s directory.

Basic Command – Scan Everything

```bash
cd ~/projects/cyber_platform/threat_scanner
python scan.py --all
```

Run Specific Scanners

```bash
# Port scanner only (default targets from config)
python scan.py --port

# Port scanner with a custom target
python scan.py --port --target 192.168.1.100

# Process scanner only
python scan.py --process

# Log watcher (uses log file from config)
python scan.py --log

# Log watcher with a different log file
python scan.py --log /var/log/custom_firewall.log
```

All findings are printed to the terminal and automatically ingested into the graph.

Configuration

All scanner settings are in scanner_config.json. You can edit it at any time.

Example (scanner_config.json)

```json
{
  "port_scanner": {
    "targets": ["localhost", "SERVER-01"],
    "ports": [22, 80, 443, 445, 3389, 8080],
    "severity_by_port": {
      "445": "high",
      "3389": "medium"
    }
  },
  "process_scanner": {
    "suspicious_names": ["nc", "netcat", "mimikatz", "reverse_shell"]
  },
  "log_watcher": {
    "log_file": "data/sample_firewall.log",
    "patterns": {
      "DROP": "medium",
      "Failed password": "low"
    },
    "malicious_ips": ["185.130.5.10"]
  }
}
```

· port_scanner.targets – list of hostnames/IPs to scan.
· port_scanner.ports – TCP ports to check.
· port_scanner.severity_by_port – map port numbers to a severity (low, medium, high, critical).
· process_scanner.suspicious_names – case‑insensitive substrings to match in process lists.
· log_watcher.log_file – path to the log file.
· log_watcher.patterns – substrings to look for, each with a severity.
· log_watcher.malicious_ips – specific IP addresses that trigger a high‑severity alert.

Event Schema

Each finding becomes an Event node in the graph with these properties:

______________________________________________________________________________________
      Field      |			 Description                                 |
_________________|____________________________________________________________________|
 timestamp       | ISO‑8601 UTC time when the event was detected.                     | 
 source_host     |  Hostname or IP where the finding was observed.                    |
 user            | (optional) Username associated with the event.                     |
 event_type      | Category: PortScan, SuspiciousProcess, FirewallAlert, ThreatIntel. |
 alert_severity  | low, medium, high, or critical.                                    |
 details         | Human‑readable description.                                        |
_________________|____________________________________________________________________|

The ingestion endpoint (POST /ingest/events) automatically links the event to the corresponding asset via the OBSERVED_ON relationship (using source_host).

Example Output

```text
$ python scan.py --all
[*] Running Port Scanner...
[+] Open port 445/tcp on localhost - severity: high
[+] Open port 8080/tcp on localhost - severity: low
[*] Running Process Scanner...
[+] Suspicious process matching 'nc' detected on localhost
[*] Running Log Watcher...
[+] Log scan complete. Found 5 events.
[+] Ingested 8 event(s) into graph.
```

After the scan, you can immediately query the new data:

```bash
cd ~/projects/cyber_platform/graph_db
graphdb expand Asset:hostname=localhost
```

or run the MITRE Mapper to incorporate the fresh evidence:

```bash
cd ~/projects/cyber_platform/mitre_mapper
python mitre_mapper.py Asset:hostname=localhost
```

Integration with Other Modules

· Module 1 – Receives all events; the graph is automatically enriched.
· Module 2 – The mapper can use the new events to update attack paths, blast radius, and confidence scores.
· Module 4 (AI Analyst) – Will consume these events and the graph context to generate natural‑language explanations and recommended countermeasures.
· Module 5 (Investigation UI) – The graphical dashboard will display the latest events in real‑time.

Troubleshooting

_____________________________________________________________________________________________________________________________________________________________________________________________________________________________
		Problem				|		 Solution
________________________________________________|____________________________________________________________________________________________________________________________________________________________________________|
  Connection refused when ingesting             | Module 1 backend is not running. Start it: cd ~/projects/cyber_platform/graph_db/backend && python -m uvicorn main:app --host 0.0.0.0 --port 8000 &                        |
  Log file not found                            | Edit scanner_config.json and set the correct log_file path, or pass a custom path with --log <file>.                                                                       |
  Port scanner shows nothing                    | The target host may be unreachable or firewalled. Try scanning localhost first.                                                                                            |
  Process scanner finds no suspicious processes | The blacklist may not match anything on your system. Add more entries to suspicious_names in the config, or run a harmless test by temporarily adding a known process name.|
  Python import errors                          | Ensure you run the script from the threat_scanner/ directory, or add the directory to PYTHONPATH.                                                                          |
________________________________________________|____________________________________________________________________________________________________________________________________________________________________________|


Extending the Module

To add a new scanner (e.g., vulnerability checker):

1. Create a new file in scanners/ (e.g., vuln_scanner.py).
2. Subclass Scanner and implement the run() method, returning a list of event dicts.
3. Import it in scan.py and add a new CLI flag (--vuln).
4. Add its configuration section to scanner_config.json.

The ingestion framework handles everything else – no changes to Module 1 required.

---

End of Module 3 documentation.
