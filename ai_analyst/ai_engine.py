import requests
import json
import re

API_BASE = "http://localhost:8000"
AUTH = ("analyst", "password")

def get_token():
    resp = requests.post(f"{API_BASE}/token", data={"username": AUTH[0], "password": AUTH[1]})
    if resp.status_code == 200:
        return resp.json()["access_token"]
    return None

def graph_query(node_id):
    """Expand a node (1-hop) from the knowledge graph."""
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    resp = requests.get(f"{API_BASE}/graph/expand", params={"node_id": node_id}, headers=headers)
    if resp.status_code == 200:
        return resp.json()
    return {"nodes": [], "edges": []}

def search_graph(keyword):
    """Full-text search in the graph."""
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    resp = requests.get(f"{API_BASE}/graph/search", params={"q": keyword}, headers=headers)
    if resp.status_code == 200:
        return resp.json()
    return []

def build_context(question):
    """
    Heuristically extract key terms and fetch relevant graph context.
    Returns (context_text, nodes_dict, edges_list).
    """
    # Extract known patterns
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', question)
    cves = re.findall(r'CVE-\d{4}-\d{4,7}', question, re.IGNORECASE)
    techniques = re.findall(r'T\d{4}(?:\.\d{3})?', question)
    malware_keywords = re.findall(r'(?i)\b(emotet|wannacry|trickbot|zeus)\b', question)

    # Extract possible hostnames: alphabetic strings, min 3 chars, exclude common words
    common = {"the","is","a","an","and","or","for","of","to","in","on","with",
              "from","by","this","that","show","me","all","linked","affected",
              "assets","techniques","related","mitre","attack","malware","what",
              "are","any","which","how","many","list","find","give","you","your"}
    words = re.findall(r'\b([A-Za-z][A-Za-z0-9-]*)\b', question)
    hostnames = []
    for w in words:
        # skip if purely numeric, IP-like, or common word, or too short
        if w.isdigit() or re.match(r'\d{1,3}\.\d{1,3}', w):
            continue
        if w.lower() in common or len(w) < 3:
            continue
        # skip if it's part of an IP address (e.g., "185" or "130")
        if any(w in ip.split('.') for ip in ips):
            continue
        hostnames.append(w)

    all_nodes = {}
    all_edges = []

    def merge_expand_result(result):
        for node in result.get("nodes", []):
            nid = node["id"]
            if nid not in all_nodes:
                all_nodes[nid] = node
        for edge in result.get("edges", []):
            if (edge["from"], edge["to"], edge["label"]) not in [(e["from"], e["to"], e["label"]) for e in all_edges]:
                all_edges.append(edge)

    def merge_search_result(search_list):
        for item in search_list:
            lbl = item["label"]
            props = item["properties"]
            key_field = {
                "Asset": "hostname",
                "IP": "address",
                "Domain": "name",
                "CVE": "cve_id",
                "ThreatActor": "name",
                "Malware": "name",
                "Technique": "technique_id",
                "Event": "event_id"
            }.get(lbl, "hostname")
            val = props.get(key_field, list(props.values())[0] if props else "unknown")
            node_id = f"{lbl}:{val}"
            if node_id not in all_nodes:
                all_nodes[node_id] = {"id": node_id, "label": lbl, "properties": props}

    # Search / expand for each detected indicator
    for ip in ips:
        merge_search_result(search_graph(ip))
        merge_expand_result(graph_query(f"IP:address={ip}"))
    for host in hostnames:
        merge_expand_result(graph_query(f"Asset:hostname={host}"))
    for cve in cves:
        merge_expand_result(graph_query(f"CVE:cve_id={cve}"))
    for tid in techniques:
        merge_expand_result(graph_query(f"Technique:technique_id={tid}"))
    for mw in malware_keywords:
        merge_search_result(search_graph(mw))
        merge_expand_result(graph_query(f"Malware:name={mw.capitalize()}"))

    # Build text context
    lines = []
    lines.append("Nodes found:")
    for nid, nd in all_nodes.items():
        lines.append(f"  [{nd.get('label','')}] {json.dumps(nd.get('properties',{}))}")
    lines.append("Edges found:")
    for e in all_edges:
        lines.append(f"  {e['from']} -[{e['label']}]-> {e['to']}")
    return "\n".join(lines), all_nodes, all_edges
