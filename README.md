We’ll create a comprehensive PLATFORM_README.md file that covers every module, how they connect, and the exact commands to operate the platform via Termux and the web UI.

```markdown
# Cyber Decision Intelligence Platform — Complete Documentation

## Overview

The **Cyber Decision Intelligence Platform** is a modular, AI‑powered cybersecurity investigation workspace that runs entirely on **Termux (Android)**. It consists of five integrated modules:

| Module | Name | Purpose |
|--------|------|---------|
| 1 | Graph Knowledge Base | JSON‑based graph storage with REST API |
| 2 | MITRE Attack Mapper | Automated attack‑path walking & reporting |
| 3 | Threat Scanner | On‑demand scanners (port, process, log) |
| 4 | AI Analyst | Natural language queries via local LLM (Ollama) or rule‑based fallback |
| 5 | Investigation UI | Web‑based SOC dashboard (graph, mapper, scanner, AI) |

All modules communicate through the **Graph Knowledge Base API** (`http://localhost:8000`). The platform uses **no external database** – all data is stored in JSON files.

---

## Architecture & Module Connections

```

┌─────────────────────────────┐
│   Investigation UI (Web)    │   Module 5 (browser)
│   http://localhost:8000      │
└──────────┬──────────────────┘
│ REST API
▼
┌─────────────────────────────┐
│  Graph Knowledge Base (API) │   Module 1 (FastAPI)
│  /ingest, /graph/expand,    │
│  /ui/mapper, /ui/scanner,   │
│  /ui/ai                     │
└──────────┬──────────────────┘
│
┌──────┼──────┐
│      │      │
┌───▼──┐ ┌▼───┐ ┌▼───────┐
│MITRE │ │AI   │ │Threat  │
│Mapper│ │Analyst│Scanner │
│Mod.2 │ │Mod.4 │ │Mod.3   │
└──────┘ └─────┘ └────────┘

```

- **Module 2** reads graph data via `/graph/expand` and generates attack‑path reports.
- **Module 3** pushes new `Event` nodes into the graph via `/ingest/events`.
- **Module 4** queries the graph (`/graph/search`, `/graph/expand`) and uses an LLM to answer questions.
- **Module 5** is a single‑page web app served by Module 1’s FastAPI; it calls all the above endpoints.

---

## Directory Structure (Termux)

```

~/projects/cyber_platform/
├── graph_db/                    # Module 1
│   ├── backend/
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── database.py
│   │   ├── auth.py
│   │   ├── routers/...
│   │   ├── static/              # Module 5 UI files
│   │   │   ├── index.html
│   │   │   ├── style.css
│   │   │   └── vis-network.min.js
│   │   └── requirements.txt
│   ├── data/                    # JSON sample datasets
│   │   ├── mitre_attack.json
│   │   ├── cves.json
│   │   ├── threat_intel.json
│   │   ├── assets.json
│   │   ├── events.json
│   │   └── graph_storage/       # auto‑created runtime storage
│   └── cli.py                   # graphdb CLI
├── mitre_mapper/                # Module 2
│   └── mitre_mapper.py
├── threat_scanner/              # Module 3
│   ├── scan.py
│   ├── scanner_framework.py
│   ├── scanner_config.json
│   ├── scanners/
│   │   ├── port_scanner.py
│   │   ├── process_scanner.py
│   │   └── log_watcher.py
│   └── data/
│       └── sample_firewall.log
└── ai_analyst/                  # Module 4
├── ai_analyst.py
├── ai_engine.py
├── llm_client.py
└── countermeasures.py

```

---

## Installation (Termux)

1. **Install system dependencies**
   ```bash
   pkg update && pkg upgrade -y
   pkg install python wget curl -y
```

2. Create project folder and clone/files (if not already present)
   Ensure the directory structure above exists. All code has been previously provided as copy‑paste blocks.
3. Install Python packages (from Module 1’s requirements.txt)
   ```bash
   cd ~/projects/cyber_platform/graph_db/backend
   pip install fastapi uvicorn python-jose passlib pydantic click requests
   ```
4. (Optional) Install Ollama for Module 4 LLM
   ```bash
   pkg install ollama
   ollama serve &          # start in background
   ollama pull tinyllama   # lightweight model
   ```
   If you skip this, the AI Analyst will use the built‑in rule‑based fallback.

---

Starting the Platform

1. Start the Graph Knowledge Base (Module 1)

This is the core service – all other modules depend on it.

```bash
cd ~/projects/cyber_platform/graph_db/backend
pkill -f uvicorn
python -m uvicorn main:app --host 0.0.0.0 --port 8000 &
disown
sleep 5
```

Verify it’s running:

```bash
curl -s http://localhost:8000/token -d "username=analyst&password=password"
```

You should see {"access_token":"...","token_type":"bearer"}.

2. Ingest sample data (only needed once)

```bash
cd ~/projects/cyber_platform/graph_db
source ~/.bashrc   # if `graphdb` alias not set
graphdb ingest mitre data/mitre_attack.json
graphdb ingest cve data/cves.json
graphdb ingest threat data/threat_intel.json
graphdb ingest assets data/assets.json
graphdb ingest events data/events.json
```

---

Module CLI Commands

All commands assume the backend is running.

Module 1 – Graph Knowledge Base (CLI: graphdb)

```bash
# Expand a node
graphdb expand Asset:hostname=SERVER-01

# Search for a keyword
graphdb search Emotet

# Ingest a specific dataset
graphdb ingest mitre data/mitre_attack.json
```

Note: The graphdb alias is defined as python ~/projects/cyber_platform/graph_db/cli.py.

Module 2 – MITRE Attack Mapper

```bash
cd ~/projects/cyber_platform/mitre_mapper
python mitre_mapper.py Asset:hostname=SERVER-01
python mitre_mapper.py IP:address=185.130.5.10 --depth 5
```

Reports are saved in mitre_mapper/reports/ as report_YYYYMMDD-HHMMSS-NNNN.txt.

Module 3 – Threat Scanner

```bash
cd ~/projects/cyber_platform/threat_scanner
python scan.py --all          # run all scanners
python scan.py --port --target 192.168.1.10
python scan.py --process
python scan.py --log data/sample_firewall.log
```

Module 4 – AI Analyst

```bash
cd ~/projects/cyber_platform/ai_analyst
python ai_analyst.py ask "What malware is linked to 185.130.5.10?" --model tinyllama
python ai_analyst.py ask "Show all affected assets" --no-llm   # rule‑based fallback
```

---

Web Investigation UI (Module 5)

Once the backend is running, open your Android browser to:
http://localhost:8000

First use

1. Log in – click Login (top right), use analyst / password.
2. Search – type firewall or Emotet in the top search bar and click the magnifying glass.
3. Expand – double‑click any node in the centre panel to see its relationships.
4. AI Query – type a question in the right panel and click Ask AI.
5. Map Attack Path – click a node on the graph, then click Map Attack Path.
6. Scanners – click Port Scan, Process Scan, or Log Watch in the left panel.

Centre Panel Tabs

· Graph – interactive vis‑network graph.
· MITRE Map – visual attack chain generated by the mapper.
· Timeline – chronologically sorted events.

Reports

· Export JSON – downloads all investigation notebook cards.
· Export Evidence – downloads the event timeline.

---

Data Flow Example

1. Analyst runs a scan (python scan.py --log ...) → 7 new Event nodes are created in the graph.
2. In the UI, analyst searches for firewall → sees the asset with connected events.
3. Analyst double‑clicks the asset → all events expand.
4. Analyst clicks a node and presses Map Attack Path → the mapper walks the graph and produces a report.
5. Analyst asks the AI: “What malware is linked to this IP?” → the AI retrieves graph context and answers.

---

Troubleshooting

Symptom Solution
Connection refused on CLI commands Backend not running. Start Module 1.
Port 8000 already in use Run pkill -9 -f uvicorn and restart.
Graph canvas blank in UI 1. Check status bar (top of page). If red, vis-network.min.js missing. Run: cd ~/projects/cyber_platform/graph_db/backend/static && curl -L -o vis-network.min.js https://cdn.jsdelivr.net/npm/vis-network@9.1.2/dist/vis-network.min.js. 2. Hard‑refresh browser.
Buttons do nothing Browser cached old script. Hard‑refresh or use incognito mode.
AI query returns fallback message Ollama not installed/running. Either install tinyllama or use --no-llm.
Ingest fails with 401 Auth is disabled; just login via the CLI or set AUTH_ENABLED=False in config.py.

---

Environment Variables (optional)

Set in ~/.bashrc or before running:

```bash
export OPENAI_API_KEY="sk-..."   # if using OpenAI instead of Ollama
export OLLAMA_HOST="http://localhost:11434"
```

---

Shutting Down

```bash
pkill -f uvicorn          # stop backend
ollama stop               # stop Ollama (if used)
```

---

That’s the complete platform documentation. Save this file as PLATFORM_README.md in your project root.

```

This Markdown file can be copied directly into your project and serves as the definitive guide for running and connecting all modules.
