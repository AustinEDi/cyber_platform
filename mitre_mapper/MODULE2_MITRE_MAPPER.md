# Module 2 – MITRE Attack Mapper

## Overview

The MITRE Attack Mapper automatically traverses the **Module 1 Graph Knowledge Base** to reconstruct an attacker’s path through your environment. Given a single starting point (an asset, IP, malware, CVE, etc.), it:

- Walks the graph up to a configurable depth
- Identifies MITRE ATT&CK techniques and their tactics
- Maps the attack flow (initial access → impact)
- Lists affected assets (blast radius)
- Collects supporting evidence (events, indicators)
- Suggests mitigations based on known ATT&CK mitigations
- Calculates a confidence score

The output is a **human‑readable report** (printed to the terminal) and a **JSON file** for further processing.

## Architecture

mitre_mapper/
└── mitre_mapper.py   ← standalone script (zero dependencies beyond requests)


The mapper is a **stateless client** – it does not have its own database. It communicates with the Module 1 REST API (`http://localhost:8000`) to expand nodes and search the graph.

### How It Works

1. **BFS Graph Walker** – Starting from the user‑provided node, the mapper repeatedly calls `GET /graph/expand?node_id=…`. It collects all nodes and edges into a local sub‑graph, respecting a user‑definable depth limit (default 4 hops).

2. **Node & Edge Classification** – The sub‑graph is analysed to identify:
   - **Techniques** (MITRE ATT&CK)
   - **Malware**
   - **CVEs** (vulnerabilities)
   - **IPs / Domains** (infrastructure)
   - **Assets** (affected hosts)
   - **Events** (logs, alerts)
   - **Threat Actors**

3. **Attack Flow Construction** – Techniques are sorted by MITRE tactic order (Reconnaissance → Impact) to produce a logical kill chain.

4. **Blast Radius** – All assets found in the sub‑graph are listed as potentially affected.

5. **Evidence Collection** – Events and indicators are formatted as evidence items.

6. **Mitigation Lookup** – A built‑in table provides best‑practice mitigations for common techniques (e.g., PowerShell logging, backups). This will later be replaced by dynamic queries to ATT&CK data or an LLM.

7. **Confidence Scoring** – Based on the presence of concrete events and the path length. Starting at 90% when events exist, reducing by 10% for every extra hop beyond the first.

## Setup

### Prerequisites

- **Module 1** must be installed and the backend must be running on `http://localhost:8000`.
- Sample data ingested (MITRE, CVEs, threat intel, assets, events).  
  *Refer to Module 1 documentation for setup steps.*

### Install the Mapper

1. Create a folder for the mapper:
   ```bash
   mkdir -p ~/projects/cyber_platform/mitre_mapper
   cd ~/projects/cyber_platform/mitre_mapper

2. Copy mitre_mapper.py (provided below) into this folder.
3. Make sure the required Python package is available (it should already be installed from Module 1):
   ```bash
   pip install requests
   ```

Usage

Run the mapper from the mitre_mapper/ directory (or specify the full path to the script).

Basic Command

```bash
python mitre_mapper.py <node_id>
```

Where <node_id> follows the format Label:property=value, for example:

· Asset:hostname=SERVER-01
· IP:address=185.130.5.10
· Malware:name=Emotet
· Technique:technique_id=T1059.001
· CVE:cve_id=CVE-2025-1234
· ThreatActor:name=APT29

Optional Arguments

· --depth N – maximum number of hops from the starting node (default 4).

Examples

```bash
python mitre_mapper.py Asset:hostname=SERVER-01
python mitre_mapper.py IP:address=185.130.5.10 --depth 5
python mitre_mapper.py Malware:name=Emotet
```

Output

The mapper prints a report directly to the terminal and saves a detailed JSON file (report.json) in the current directory.

Example Report (Terminal)

```
============================================================
MITRE ATT&CK MAPPING REPORT
============================================================

Finding:
Malware Emotet detected affecting SERVER-01, WORKSTATION-15. Exploits CVE-2025-1234 (Critical severity).

Attack Flow:
  [execution] PowerShell (T1059.001)
  [impact] Data Encrypted for Impact (T1486)

Affected Assets:
  - SERVER-01
  - WORKSTATION-15

Evidence:
  - [Event] Firewall Block on SERVER-01: Connection to 185.130.5.10 blocked
  - [IP] IP address: 185.130.5.10
  - [Malware] Malware: Emotet

Relationships Used:
  asset:SERVER-01 -[OBSERVED_ON]-> event:da9e6b46...
  IP:185.130.5.10 -[LINKED_TO]-> Malware:Emotet
  Malware:Emotet -[USES]-> Technique:T1059.001
  Malware:Emotet -[EXPLOITS]-> CVE:CVE-2025-1234

Mitigations:
  1. Enable PowerShell logging, script block logging, constrained language mode.
  2. Maintain offline backups, implement application whitelisting, use behaviour-based anti-ransomware.

Confidence: 80%
============================================================

Understanding the Report

Finding

A concise summary of what the graph tells you.
Example: “Malware Emotet detected affecting SERVER-01. Exploits CVE-2025-1234 (Critical severity).”

Attack Flow

A chronological ordering of MITRE techniques based on their tactic (initial-access, execution, persistence, impact, etc.).
This shows the likely progression of the attack.

Affected Assets

Hostnames of all assets that appear in the sub‑graph.
In a real investigation, these are the machines you need to triage first.

Evidence

Concrete logs, indicators, or intelligence that support the finding.
Each item includes a type (Event, IP, Malware, etc.) and a brief description.

Relationships Used

The graph edges that were traversed to build the report.
These provide traceability – you can verify each step by querying the graph directly.

Mitigations

Recommended countermeasures for the techniques found.
Currently uses a hard‑coded table; future versions will pull live data from the ATT&CK framework.

Confidence

A percentage indicating how certain the mapper is about the full attack chain.

· High confidence (90‑100%) when concrete events are directly linked.
· Drops by ~10% for every additional hop beyond the first.

JSON Report (report.json)

The JSON file contains the same data in a structured format, ready for consumption by other modules (e.g., Module 4 – AI Analyst). Example snippet:

```json
{
  "finding": "Malware Emotet detected affecting SERVER-01...",
  "attack_chain": [
    {"tactic": "execution", "technique_id": "T1059.001", "name": "PowerShell", "description": "..."}
  ],
  "affected_assets": ["SERVER-01"],
  "evidence": [...],
  "relationships_used": [...],
  "mitigations": [...],
  "confidence": 80
}
```

Troubleshooting

         Problem 	     |			Solution
_____________________________|_________________________________________________________________________________________________________________________________________________|
No data found 		     | Make sure the Module 1 backend is running and that data has been ingested.
Connection refused 	     | Start the backend: cd ~/projects/cyber_platform/graph_db/backend && python -m uvicorn main:app --host 0.0.0.0 --port 8000 &
Report shows zero techniques | The starting node may not be connected to any MITRE techniques. Try expanding with the CLI first (graphdb expand ...) to verify the path exists.
Missing Python modules 	     | pip install requests
_____________________________|__________________________________________________________________________________________________________________________________________________

Integration with Other Modules

· Module 1 – Provides the graph data via REST API.
· Module 3 (Threat Scanner) – Will inject new events into the graph; the mapper can then be re‑run to see updated attack paths.
· Module 4 (AI Analyst) – Will consume the JSON report and produce natural‑language explanations, as well as replace the hard‑coded mitigations with dynamic, LLM‑generated advice.
· Module 5 (Investigation UI) – Will display the mapper’s report in a graphical dashboard.

Full Source Code (mitre_mapper.py)

The complete Python script is listed below for reference. You can copy it directly into your project.

#!/usr/bin/env python3
"""
MITRE Attack Mapper – Module 2
==============================
Traverses the security knowledge graph (Module 1) to reconstruct
attack paths, identify affected assets, and generate an explainable report.

Usage:
    python mitre_mapper.py Asset:hostname=SERVER-01
    python mitre_mapper.py IP:address=185.130.5.10 --depth 5
"""

import sys
import json
from collections import deque
import requests

API_BASE = "http://localhost:8000"
AUTH = ("analyst", "password")  # auth disabled, but token still works

# ----------------------------------------------------------------------
# 1.  Token & API Helpers
# ----------------------------------------------------------------------
def get_token():
    resp = requests.post(f"{API_BASE}/token", data={"username": AUTH[0], "password": AUTH[1]})
    if resp.status_code == 200:
        return resp.json()["access_token"]
    return None

def api_headers():
    token = get_token()
    return {"Authorization": f"Bearer {token}"} if token else {}

def expand_node(node_id):
    """Call /graph/expand and return nodes + edges."""
    resp = requests.get(
        f"{API_BASE}/graph/expand",
        params={"node_id": node_id},
        headers=api_headers()
    )
    if resp.status_code == 200:
        return resp.json()
    return {"nodes": [], "edges": []}

def search_graph(keyword):
    """Call /graph/search for full-text lookup."""
    resp = requests.get(
        f"{API_BASE}/graph/search",
        params={"q": keyword},
        headers=api_headers()
    )
    if resp.status_code == 200:
        return resp.json()
    return []

# ----------------------------------------------------------------------
# 2.  Recursive Graph Walker (BFS)
# ----------------------------------------------------------------------
def walk_graph(start_node_id, max_depth=4):
    visited = set()
    queue = deque()
    queue.append((start_node_id, 0))

    all_nodes = {}
    all_edges = []

    while queue:
        current, depth = queue.popleft()
        if current in visited or depth > max_depth:
            continue
        visited.add(current)

        result = expand_node(current)
        for node in result.get("nodes", []):
            nid = node["id"]
            if nid not in all_nodes:
                all_nodes[nid] = node
        for edge in result.get("edges", []):
            if (edge["from"], edge["to"], edge["label"]) not in [(e["from"], e["to"], e["label"]) for e in all_edges]:
                all_edges.append(edge)
        for edge in result.get("edges", []):
            neighbor = edge["to"] if edge["from"] == current else edge["from"]
            if neighbor not in visited:
                queue.append((neighbor, depth + 1))

    return {"nodes": all_nodes, "edges": all_edges}

# ----------------------------------------------------------------------
# 3.  Analysis
# ----------------------------------------------------------------------
TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access",
    "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact"
]

MITIGATIONS = {
    "T1059.001": "Enable PowerShell logging, script block logging, constrained language mode.",
    "T1486": "Maintain offline backups, implement application whitelisting, use behaviour-based anti-ransomware.",
    "T1566.001": "User training on phishing, email filtering, attachment sandboxing.",
}

def analyze_subgraph(subgraph, start_node_id):
    nodes = subgraph["nodes"]
    edges = subgraph["edges"]

    techniques = []
    malware_list = []
    cves = []
    ips = []
    assets = []
    events = []
    threat_actors = []

    for nid, ndata in nodes.items():
        label = ndata.get("label", "")
        props = ndata.get("properties", {})
        if label == "Technique":
            techniques.append(props)
        elif label == "Malware":
            malware_list.append(props)
        elif label == "CVE":
            cves.append(props)
        elif label == "IP":
            ips.append(props)
        elif label == "Asset":
            assets.append(props)
        elif label == "Event":
            events.append(props)
        elif label == "ThreatActor":
            threat_actors.append(props)

    # Sort techniques by tactic order
    def tactic_index(props):
        tactics = props.get("tactics", [])
        if tactics:
            for t in tactics:
                if t in TACTIC_ORDER:
                    return TACTIC_ORDER.index(t)
        return 999
    techniques.sort(key=tactic_index)

    attack_flow = []
    for t in techniques:
        attack_flow.append({
            "tactic": t.get("tactics", ["unknown"])[0],
            "technique_id": t.get("technique_id", ""),
            "name": t.get("name", ""),
            "description": t.get("description", "")
        })

    affected_assets = [a.get("hostname","") for a in assets]

    evidence = []
    for evt in events:
        evidence.append({
            "type": "Event",
            "details": f"{evt.get('event_type','')} on {evt.get('source_host','')}: {evt.get('details','')}"
        })
    for ip in ips:
        evidence.append({"type": "IP", "details": f"IP address: {ip.get('address','')}"})
    for mw in malware_list:
        evidence.append({"type": "Malware", "details": f"Malware: {mw.get('name','')}"})

    rels = [f"{e['from']} -[{e['label']}]-> {e['to']}" for e in edges]

    mitigations = []
    for t in techniques:
        tid = t.get("technique_id","")
        if tid in MITIGATIONS:
            mitigations.append(MITIGATIONS[tid])

    confidence = 90 if events else 70
    if len(edges) > 3:
        confidence -= 10
    if len(edges) > 6:
        confidence -= 10
    confidence = max(confidence, 30)

    finding = "Attack path identified."
    if malware_list:
        finding = f"Malware {malware_list[0].get('name','')} detected"
        if assets:
            finding += f" affecting {', '.join(affected_assets)}."
    elif ips:
        finding = f"Suspicious communication to {ips[0].get('address','')} observed."
    if cves:
        finding += f" Exploits {cves[0].get('cve_id','')} ({cves[0].get('severity','')} severity)."

    return {
        "finding": finding,
        "attack_chain": attack_flow,
        "affected_assets": affected_assets,
        "evidence": evidence,
        "relationships_used": rels,
        "mitigations": mitigations,
        "confidence": confidence
    }

# ----------------------------------------------------------------------
# 4.  Report Generation
# ----------------------------------------------------------------------
def print_report(report):
    print("=" * 60)
    print("MITRE ATT&CK MAPPING REPORT")
    print("=" * 60)
    print(f"\nFinding:\n{report['finding']}\n")

    print("Attack Flow:")
    if report["attack_chain"]:
        for step in report["attack_chain"]:
            print(f"  [{step['tactic']}] {step['name']} ({step['technique_id']})")
    else:
        print("  No techniques identified.")

    print(f"\nAffected Assets:")
    for a in report["affected_assets"]:
        print(f"  - {a}")

    print(f"\nEvidence:")
    for e in report["evidence"]:
        print(f"  - [{e['type']}] {e['details']}")

    print(f"\nRelationships Used:")
    for r in report["relationships_used"]:
        print(f"  {r}")

    print(f"\nMitigations:")
    if report["mitigations"]:
        for i, m in enumerate(report["mitigations"], 1):
            print(f"  {i}. {m}")
    else:
        print("  None found.")

    print(f"\nConfidence: {report['confidence']}%")
    print("=" * 60)

def main():
    if len(sys.argv) < 2:
        print("Usage: python mitre_mapper.py <node_id> [--depth 4]")
        print("Example: python mitre_mapper.py Asset:hostname=SERVER-01")
        sys.exit(1)

    start_node = sys.argv[1]
    depth = 4
    if "--depth" in sys.argv:
        idx = sys.argv.index("--depth")
        if idx + 1 < len(sys.argv):
            depth = int(sys.argv[idx + 1])

    print(f"[*] Walking graph from {start_node} with max depth {depth}...")
    sub = walk_graph(start_node, depth)
    if not sub["nodes"]:
        print("[-] No data found. Is the backend running and data ingested?")
        sys.exit(1)

    print(f"[*] Analyzing {len(sub['nodes'])} nodes and {len(sub['edges'])} edges...")
    report = analyze_subgraph(sub, start_node)
    print_report(report)

    with open("report.json", "w") as f:
        json.dump(report, f, indent=2)
    print("\n[+] JSON report saved to report.json")

if __name__ == "__main__":
    main()



Quick Start (Copy & Paste)

1. Start Module 1 backend (skip if already running):
 
   cd ~/projects/cyber_platform/graph_db/backend

   pkill -f uvicorn
   python -m uvicorn main:app --host 0.0.0.0 --port 8000 &
   disown
   sleep 5
   
2. Ingest sample data (skip if already ingested):
   
   cd ~/projects/cyber_platform/graph_db
   graphdb ingest mitre data/mitre_attack.json
   graphdb ingest cve data/cves.json
   graphdb ingest threat data/threat_intel.json
   graphdb ingest assets data/assets.json
   graphdb ingest events data/events.json
   
3. Run the mapper:
   
   cd ~/projects/cyber_platform/mitre_mapper
   python mitre_mapper.py Asset:hostname=SERVER-01
   
4. View the JSON report:
   
   cat report.json
   

---

End of Module 2 documentation.
