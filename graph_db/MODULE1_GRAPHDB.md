# Module 1: Graph Knowledge Base (Graph DB)

## Overview

The **Graph Knowledge Base** is the foundational data layer of the Cybersecurity Decision Intelligence Platform. It stores all security entities (assets, IPs, domains, malware, CVEs, ATT&CK techniques, threat actors, events) and the relationships between them in a searchable, expandable graph.

- **Storage:** JSON file‑based (no external database required) – portable and easy to run on Termux.
- **Access:** REST API (FastAPI) and a command‑line interface (`graphdb`).
- **Authentication:** Optional JWT token auth (currently disabled for local testing).

The graph is designed to be queried by other modules (MITRE Mapper, AI Analyst, Scanners) but can also be used directly by a human analyst via the CLI or API.

## Architecture

graph_db/
├── backend/
│   ├── main.py               # FastAPI app entry point
│   ├── config.py             # Neo4j (unused), auth secrets, feature flags
│   ├── database.py           # JSON storage, node/edge CRUD, query logic
│   ├── models.py             # Pydantic request/response models
│   ├── auth.py               # JWT authentication (disabled by default)
│   ├── routers/
│   │   ├── ingest.py         # /ingest endpoints (mitre, cve, threat, assets, events)
│   │   ├── graph.py          # /graph/expand, /graph/search endpoints
│   │   └── query.py          # (placeholder, raw Cypher not supported)
│   └── requirements.txt      # Python dependencies
├── data/
│   ├── mitre_attack.json     # Sample MITRE ATT&CK data
│   ├── cves.json             # Sample CVE data
│   ├── threat_intel.json     # Sample threat intel (IPs, domains, malware)
│   ├── assets.json           # Sample asset inventory
│   ├── events.json           # Sample security events
│   └── graph_storage/        # Created automatically; holds nodes.json and edges.json
└── cli.py                    # Unified CLI tool (graphdb command)

Setup (Termux)

1. **Install dependencies**:
   ```bash
   pkg update && pkg upgrade -y
   pkg install python wget git curl -y
   # Java / Neo4j are NOT required (file‑based storage)

2. Create the project (if not already done):
   ```bash
   mkdir -p ~/projects/cyber_platform/graph_db/backend/routers
   mkdir -p ~/projects/cyber_platform/graph_db/data
   cd ~/projects/cyber_platform/graph_db
   ```
3. Install Python packages:
   ```bash
   cd backend
   pip install -r requirements.txt
   # Or manually:
   # pip install fastapi uvicorn python-jose passlib pydantic click requests
   ```

4. Set up the graphdb alias (if not already in .bashrc):
   ```bash
   echo "alias graphdb='python ~/projects/cyber_platform/graph_db/cli.py'" >> ~/.bashrc
   source ~/.bashrc
   ```
5. Start the backend:
   ```bash
   cd ~/projects/cyber_platform/graph_db/backend
   python -m uvicorn main:app --host 0.0.0.0 --port 8000 &
   disown
   ```
   The API is now running on http://localhost:8000.

Using the CLI

All commands are run from the project root (~/projects/cyber_platform/graph_db) to allow relative paths to the data/ folder.

	Command 	       |	Example				     |						Description
______________________________________________________________________________________________________________________________________________________________________
graphdb init-schema            | graphdb init-schema                         | (Legacy – no longer required; does nothing in file mode)
graphdb start                  | graphdb start        			     | Launches the FastAPI server in the background (if not already running).
graphdb ingest <source> <file> | graphdb ingest mitre data/mitre_attack.json | Loads data from a JSON file. Source must be one of: mitre, cve, threat, assets, events.
graphdb expand <node_id>       | graphdb expand Asset:hostname=SERVER-01     | Shows all nodes and edges directly connected to the specified node.
graphdb search <keyword>       | graphdb search Emotet                       | Full‑text search across all entity properties.
______________________________________________________________________________________________________________________________________________________________________


Node ID format for expand

```
Label:property=value
```

Examples:

· Asset:hostname=SERVER-01
· IP:address=185.130.5.10
· Malware:name=Emotet
· Technique:technique_id=T1059.001

The CLI prints the number of nodes and edges found, then lists each node’s key and label.

Using the REST API

Get an access token (auth is disabled, but the endpoint works)

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/token -d 'username=analyst&password=password' | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

Expand a node

```bash
curl -H "Authorization: Bearer $TOKEN" "http://localhost:8000/graph/expand?node_id=Asset:hostname=SERVER-01"
```

Search

```bash
curl -H "Authorization: Bearer $TOKEN" "http://localhost:8000/graph/search?q=Emotet"
```

Ingest data via API

```bash
curl -X POST http://localhost:8000/ingest/assets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"data":[{"hostname":"DB-01","os":"Linux","owner":"dba","department":"IT","criticality":"high"}]}'
```

Data Formats

MITRE ATT&CK (mitre_attack.json)

```json
{
  "data": [
    {
      "technique_id": "T1059.001",
      "name": "PowerShell",
      "description": "Adversaries may abuse PowerShell...",
      "tactics": ["execution"]
    }
  ]
}
```

CVEs (cves.json)

```json
{
  "data": [
    {
      "cve_id": "CVE-2025-1234",
      "description": "Remote code execution...",
      "cvss_score": 9.8,
      "severity": "Critical",
      "vendor": "Microsoft",
      "published_date": "2025-05-15"
    }
  ]
}
```

Threat Intel (threat_intel.json)

```json
{
  "data": [
    {
      "type": "ip",
      "value": "185.130.5.10",
      "relationships": [
        {"target": "Emotet", "type": "LINKED_TO"}
      ]
    },
    {
      "type": "malware",
      "value": "Emotet",
      "relationships": [
        {"target": "CVE-2025-1234", "type": "EXPLOITS"},
        {"target": "T1059.001", "type": "USES"}
      ]
    }
  ]
}
```

Assets (assets.json)

```json
{
  "data": [
    {
      "hostname": "SERVER-01",
      "os": "Windows Server 2019",
      "owner": "ops",
      "department": "IT",
      "criticality": "high"
    }
  ]
}
```

Events (events.json)

```json
{
  "data": [
    {
      "timestamp": "2026-06-05T08:30:00Z",
      "source_host": "SERVER-01",
      "user": "SYSTEM",
      "event_type": "Firewall Block",
      "details": "Connection to 185.130.5.10 blocked"
    }
  ]
}
```

How an Analyst Interprets the Data

1. Start with an entity of interest – maybe a server that triggered an alert.
   ```bash
   graphdb expand Asset:hostname=SERVER-01
   ```
   Output:
   ```
   Nodes: 2, Edges: 1
     asset:SERVER-01 (Asset)
     event:72d1dfd1-... (Event)
   ```
   This tells you the server has at least one event attached.
2. Drill into the event (you can search for the event ID or expand it):
   ```bash
   graphdb search 72d1dfd1
   ```
   The returned event properties will show details like "details": "Connection to 185.130.5.10 blocked".
3. Pivot to the IP:
   ```bash
   graphdb expand IP:address=185.130.5.10
   ```
   If threat intel was loaded, you’ll see edges like LINKED_TO -> Emotet.
4. Follow the malware:
   ```bash
   graphdb expand Malware:name=Emotet
   ```
   This reveals techniques (USES T1059.001) and vulnerabilities (EXPLOITS CVE-2025-1234).

By chaining these commands, the analyst manually traverses the attack path. Later modules (MITRE Mapper, AI Analyst) will automate this process and generate a natural‑language report.

Data Persistence and Migration

· All data is stored in data/graph_storage/nodes.json and edges.json.
· The storage engine automatically migrates old‑format nodes (from earlier prototype versions) to the new format when the backend starts – no data is ever lost.
· To reset the graph completely, delete the graph_storage/ folder:
  ```bash
  rm -rf data/graph_storage
  ```

Troubleshooting

	Problem			   |				 Solution
___________________________________|____________________________________________________________________________________________________|
Connection refused on CLI commands |  Backend is not running. Start it with graphdb start or manually with uvicorn.			|
File not found for ingest 	   | Run commands from graph_db/ directory, not from backend/.						|
KeyError: 'key' 		   | Old data format detected. Restart the backend; migration happens automatically.			|
Missing Python modules		   | Run pip install fastapi uvicorn click requests (plus python-jose, passlib, pydantic if needed).	|
________________________________________________________________________________________________________________________________________|

Next Modules

· Module 2 – MITRE Attack Mapper: Automatically walks the graph to build an attack chain report.
· Module 3 – Threat Scanner: Generates new events and alerts from active scans.
· Module 4 – AI Analyst: Answers natural language questions using the graph.
· Module 5 – Investigation UI: Visual graph explorer with AI query panel.
