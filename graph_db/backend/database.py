import json
import uuid
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data" / "graph_storage"
DATA_DIR.mkdir(parents=True, exist_ok=True)

NODES_FILE = DATA_DIR / "nodes.json"
EDGES_FILE = DATA_DIR / "edges.json"

def _migrate_node(node):
    """Upgrade an old node (with 'id') to new format (with 'key')."""
    if "key" in node:
        return node  # already migrated
    label = node.get("label", "Unknown")
    props = node.get("properties", {})
    # Compute key using the same logic as _node_key
    key = _node_key(label, props)
    node["key"] = key
    # Keep the old 'id' in a field 'old_id' for edge migration reference
    if "id" in node:
        node["old_id"] = node["id"]
    return node

def _load_nodes():
    if NODES_FILE.exists():
        data = json.loads(NODES_FILE.read_text())
        migrated = [_migrate_node(n) for n in data]
        if migrated != data:
            _save_nodes(migrated)  # persist the migrated data
        return migrated
    return []

def _save_nodes(nodes):
    NODES_FILE.write_text(json.dumps(nodes, indent=2))

def _migrate_edges(edges, nodes):
    """Convert edges referencing old node 'id' to new node 'key'."""
    # Build mapping from old_id -> new_key
    id_to_key = {}
    for n in nodes:
        if "old_id" in n:
            id_to_key[n["old_id"]] = n["key"]
    migrated = []
    for e in edges:
        # If the edge uses old IDs, replace them
        new_from = id_to_key.get(e["from"], e["from"])
        new_to = id_to_key.get(e["to"], e["to"])
        if new_from != e["from"] or new_to != e["to"]:
            e = {"from": new_from, "to": new_to, "label": e["label"]}
        migrated.append(e)
    return migrated

def _load_edges():
    if EDGES_FILE.exists():
        edges = json.loads(EDGES_FILE.read_text())
        nodes = _load_nodes()  # ensures nodes are migrated first
        migrated = _migrate_edges(edges, nodes)
        if migrated != edges:
            _save_edges(migrated)
        return migrated
    return []

def _save_edges(edges):
    EDGES_FILE.write_text(json.dumps(edges, indent=2))

def _node_key(label, props):
    """Create a stable key for a node based on its unique property."""
    if label == "Asset":
        return f"asset:{props.get('hostname','')}"
    if label == "User":
        return f"user:{props.get('username','')}"
    if label == "IP":
        return f"ip:{props.get('address','')}"
    if label == "Domain":
        return f"domain:{props.get('name','')}"
    if label == "CVE":
        return f"cve:{props.get('cve_id','')}"
    if label == "ThreatActor":
        return f"threat_actor:{props.get('name','')}"
    if label == "Malware":
        return f"malware:{props.get('name','')}"
    if label == "Technique":
        return f"technique:{props.get('technique_id','')}"
    if label == "Event":
        return f"event:{props.get('event_id', str(uuid.uuid4()))}"
    if label == "Alert":
        return f"alert:{props.get('alert_id', str(uuid.uuid4()))}"
    return str(uuid.uuid4())

def _get_node(key):
    nodes = _load_nodes()
    for n in nodes:
        if n.get("key") == key:
            return n
    return None

def merge_node(label, props):
    """Create or update a node. Returns the node key."""
    key = _node_key(label, props)
    nodes = _load_nodes()
    # check if exists
    existing = None
    for n in nodes:
        if n.get("key") == key:
            existing = n
            break
    if existing:
        # update properties
        existing["properties"].update(props)
        _save_nodes(nodes)
        return key
    else:
        node = {"key": key, "label": label, "properties": props}
        nodes.append(node)
        _save_nodes(nodes)
        return key

def add_edge(from_key, to_key, rel_type):
    """Add a relationship edge between two node keys."""
    edges = _load_edges()
    # avoid duplicates
    if not any(e["from"] == from_key and e["to"] == to_key and e["label"] == rel_type for e in edges):
        edges.append({"from": from_key, "to": to_key, "label": rel_type})
        _save_edges(edges)

# Ingest helper functions
def ingest_technique(tech):
    props = {
        "technique_id": tech["technique_id"],
        "name": tech["name"],
        "description": tech.get("description", ""),
        "tactics": tech.get("tactics", [])
    }
    merge_node("Technique", props)

def ingest_cve(cve):
    props = {
        "cve_id": cve["cve_id"],
        "description": cve.get("description", ""),
        "cvss_score": cve.get("cvss_score", 0),
        "severity": cve.get("severity", ""),
        "vendor": cve.get("vendor", ""),
        "published_date": cve.get("published_date", "")
    }
    merge_node("CVE", props)

def ingest_threat_item(item):
    t = item["type"]
    val = item["value"]
    if t == "ip":
        key = merge_node("IP", {"address": val})
    elif t == "domain":
        key = merge_node("Domain", {"name": val})
    elif t == "malware":
        key = merge_node("Malware", {"name": val})
    elif t == "threat_actor":
        key = merge_node("ThreatActor", {"name": val})
    else:
        return
    # relationships
    for rel in item.get("relationships", []):
        target = rel["target"]
        rel_type = rel["type"]
        # determine target label based on target name (heuristic)
        target_label = "Malware" if target in ["Emotet","WannaCry"] else "Technique" if target.startswith("T") else "CVE" if target.startswith("CVE") else "IP" if "." in target else "Domain" if "." in target else "ThreatActor"
        # We need the key of the target node. Since we already merged it, get its key.
        target_key = None
        nodes = _load_nodes()
        for n in nodes:
            if n["label"] == target_label and target in n["properties"].values():
                target_key = n["key"]
                break
        if not target_key:
            # If target not yet in graph, create a placeholder
            if target_label == "Malware":
                target_key = merge_node("Malware", {"name": target})
            elif target_label == "Technique":
                target_key = merge_node("Technique", {"technique_id": target, "name": target, "description": "", "tactics": []})
            elif target_label == "CVE":
                target_key = merge_node("CVE", {"cve_id": target, "description": "", "cvss_score": 0, "severity": "", "vendor": "", "published_date": ""})
            elif target_label == "IP":
                target_key = merge_node("IP", {"address": target})
            elif target_label == "Domain":
                target_key = merge_node("Domain", {"name": target})
            elif target_label == "ThreatActor":
                target_key = merge_node("ThreatActor", {"name": target})
            else:
                continue
        add_edge(key, target_key, rel_type)

def ingest_asset(asset):
    props = {
        "hostname": asset["hostname"],
        "os": asset.get("os", ""),
        "owner": asset.get("owner", ""),
        "department": asset.get("department", ""),
        "criticality": asset.get("criticality", "")
    }
    merge_node("Asset", props)

def ingest_event(evt):
    event_id = evt.get("event_id", str(uuid.uuid4()))
    props = {
        "event_id": event_id,
        "timestamp": evt["timestamp"],
        "source_host": evt["source_host"],
        "user": evt.get("user", ""),
        "event_type": evt["event_type"],
        "details": evt.get("details", "")
    }
    event_key = merge_node("Event", props)
    # Link to Asset by hostname
    asset_key = f"asset:{evt['source_host']}"
    if _get_node(asset_key):
        add_edge(event_key, asset_key, "OBSERVED_ON")
    else:
        # If asset not yet in graph, create a minimal one
        merge_node("Asset", {"hostname": evt["source_host"]})
        add_edge(event_key, f"asset:{evt['source_host']}", "OBSERVED_ON")

# Query helpers
def expand_node(label, prop, value):
    """Return nodes and edges connected to the specified node."""
    target_key = _node_key(label, {prop: value})
    target = _get_node(target_key)
    if not target:
        return {"nodes": [], "edges": []}
    edges = _load_edges()
    nodes_out = {}
    nodes_out[target_key] = {
        "id": target_key,
        "label": target["label"],
        "properties": target["properties"]
    }
    edges_out = []
    for e in edges:
        if e["from"] == target_key or e["to"] == target_key:
            other = e["to"] if e["from"] == target_key else e["from"]
            other_node = _get_node(other)
            if other_node:
                nodes_out[other] = {
                    "id": other,
                    "label": other_node["label"],
                    "properties": other_node["properties"]
                }
            edges_out.append({
                "from": e["from"],
                "to": e["to"],
                "label": e["label"]
            })
    return {"nodes": list(nodes_out.values()), "edges": edges_out}

def search_nodes(keyword):
    """Search across all node properties for a keyword."""
    nodes = _load_nodes()
    results = []
    for n in nodes:
        for v in n["properties"].values():
            if isinstance(v, str) and keyword.lower() in v.lower():
                results.append({"label": n["label"], "properties": n["properties"]})
                break
    return results[:20]
