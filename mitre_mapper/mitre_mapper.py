#!/usr/bin/env python3
"""
MITRE Attack Mapper – Module 2
==============================
Traverses the security knowledge graph (Module 1) to reconstruct
attack paths, identify affected assets, and generate an explainable report.

Usage:
    python mitre_mapper.py Asset:hostname=SERVER-01
    python mitre_mapper.py IP:address=185.130.5.10 --depth 5 --case 42
"""

import sys
import json
import os
from collections import deque
from datetime import datetime
import requests

API_BASE = "http://localhost:8000"
AUTH = ("analyst", "password")
REPORTS_DIR = "reports"

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
    resp = requests.get(
        f"{API_BASE}/graph/expand",
        params={"node_id": node_id},
        headers=api_headers()
    )
    if resp.status_code == 200:
        return resp.json()
    return {"nodes": [], "edges": []}

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
# 4.  Report Generation (text + file)
# ----------------------------------------------------------------------
def format_report(report):
    lines = []
    lines.append("=" * 60)
    lines.append("MITRE ATT&CK MAPPING REPORT")
    lines.append("=" * 60)
    lines.append(f"\nFinding:\n{report['finding']}\n")

    lines.append("Attack Flow:")
    if report["attack_chain"]:
        for step in report["attack_chain"]:
            lines.append(f"  [{step['tactic']}] {step['name']} ({step['technique_id']})")
    else:
        lines.append("  No techniques identified.")

    lines.append(f"\nAffected Assets:")
    for a in report["affected_assets"]:
        lines.append(f"  - {a}")

    lines.append(f"\nEvidence:")
    for e in report["evidence"]:
        lines.append(f"  - [{e['type']}] {e['details']}")

    lines.append(f"\nRelationships Used:")
    for r in report["relationships_used"]:
        lines.append(f"  {r}")

    lines.append(f"\nMitigations:")
    if report["mitigations"]:
        for i, m in enumerate(report["mitigations"], 1):
            lines.append(f"  {i}. {m}")
    else:
        lines.append("  None found.")

    lines.append(f"\nConfidence: {report['confidence']}%")
    lines.append("=" * 60)
    return "\n".join(lines)

def print_report(report):
    print(format_report(report))

def save_report(report, case_number=None):
    """Save report as .txt and .json inside REPORTS_DIR."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    now = datetime.now()
    date_str = now.strftime("%Y%m%d")
    time_str = now.strftime("%H%M%S")

    # Determine case number
    if case_number is None:
        # Auto-increment based on existing files for today
        existing = [f for f in os.listdir(REPORTS_DIR)
                    if f.startswith(f"report_{date_str}-") and f.endswith(".txt")]
        nums = []
        for f in existing:
            try:
                # file format: report_YYYYMMDD-HHMMSS-NNNN.txt
                # extract NNNN from the part after the second '-'
                parts = f[len(f"report_{date_str}-"):-4].split("-")
                if len(parts) >= 2:
                    num = int(parts[-1])
                    nums.append(num)
            except ValueError:
                pass
        case_number = max(nums, default=0) + 1

    case_str = f"{case_number:04d}"
    txt_filename = f"report_{date_str}-{time_str}-{case_str}.txt"
    json_filename = f"report_{date_str}-{time_str}-{case_str}.json"

    txt_path = os.path.join(REPORTS_DIR, txt_filename)
    with open(txt_path, "w") as f:
        f.write(format_report(report))

    json_path = os.path.join(REPORTS_DIR, json_filename)
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[+] Report saved as:")
    print(f"    {txt_path}")
    print(f"    {json_path}")

# ----------------------------------------------------------------------
# 5.  Main CLI
# ----------------------------------------------------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: python mitre_mapper.py <node_id> [--depth 4] [--case N]")
        print("Example: python mitre_mapper.py Asset:hostname=SERVER-01")
        sys.exit(1)

    start_node = sys.argv[1]
    depth = 4
    case_number = None

    if "--depth" in sys.argv:
        idx = sys.argv.index("--depth")
        if idx + 1 < len(sys.argv):
            depth = int(sys.argv[idx + 1])
    if "--case" in sys.argv:
        idx = sys.argv.index("--case")
        if idx + 1 < len(sys.argv):
            case_number = int(sys.argv[idx + 1])

    print(f"[*] Walking graph from {start_node} with max depth {depth}...")
    sub = walk_graph(start_node, depth)
    if not sub["nodes"]:
        print("[-] No data found. Is the backend running and data ingested?")
        sys.exit(1)

    print(f"[*] Analyzing {len(sub['nodes'])} nodes and {len(sub['edges'])} edges...")
    report = analyze_subgraph(sub, start_node)
    print_report(report)

    save_report(report, case_number)

if __name__ == "__main__":
    main()
