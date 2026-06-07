from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pathlib import Path
from auth import authenticate_user, create_access_token, get_current_user
from routers import ingest, graph, query
import uvicorn

app = FastAPI(title="Cyber Decision Intelligence")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ingest.router)
app.include_router(graph.router)
app.include_router(query.router)

# Auth endpoint
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    token = create_access_token(data={"sub": user["username"], "role": user["role"]})
    return {"access_token": token, "token_type": "bearer"}

# Module 5 UI endpoints
class MapperRequest(BaseModel):
    node_id: str
    depth: int = 4

class ScannerRequest(BaseModel):
    scanner: str
    target: str = None

class AIRequest(BaseModel):
    question: str
    no_llm: bool = False
    model: str = "tinyllama"

@app.post("/ui/mapper")
async def run_mapper(req: MapperRequest, user=Depends(get_current_user)):
    import sys, json
    sys.path.insert(0, str(Path(__file__).parent.parent.parent / "mitre_mapper"))
    from mitre_mapper import walk_graph, analyze_subgraph
    sub = walk_graph(req.node_id, req.depth)
    if not sub["nodes"]:
        return {"error": "No data found"}
    report = analyze_subgraph(sub, req.node_id)
    return report

@app.post("/ui/scanner")
async def run_scanner(req: ScannerRequest, user=Depends(get_current_user)):
    import sys, json
    sys.path.insert(0, str(Path(__file__).parent.parent.parent / "threat_scanner"))
    from scanners.port_scanner import PortScanner
    from scanners.process_scanner import ProcessScanner
    from scanners.log_watcher import LogWatcher

    config_path = str(Path(__file__).parent.parent.parent / "threat_scanner" / "scanner_config.json")
    with open(config_path) as f:
        config = json.load(f)

    events = []
    if req.scanner == "port":
        cfg = config.get("port_scanner", {})
        if req.target:
            cfg["targets"] = [req.target]
        events = PortScanner(cfg).run()
    elif req.scanner == "process":
        cfg = config.get("process_scanner", {})
        events = ProcessScanner(cfg).run()
    elif req.scanner == "log":
        cfg = config.get("log_watcher", {})
        if req.target:
            cfg["log_file"] = req.target
        events = LogWatcher(cfg).run()
    else:
        return {"error": "Invalid scanner type"}

    if events:
        from database import ingest_event
        for evt in events:
            ingest_event(evt)
    return {"status": "ok", "events": events}

@app.post("/ui/ai")
async def run_ai(req: AIRequest, user=Depends(get_current_user)):
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent / "ai_analyst"))
    from ai_engine import build_context
    from llm_client import ask_llm
    context, nodes, edges = build_context(req.question)
    if not nodes:
        return {"findings": "No graph data found for this query.", "confidence": 0}
    if req.no_llm:
        assets = set()
        malware = set()
        for n in nodes.values():
            p = n.get("properties", {})
            if n["label"] == "Asset": assets.add(p.get("hostname", ""))
            if n["label"] == "Malware": malware.add(p.get("name", ""))
        findings = f"Graph contains {len(nodes)} nodes and {len(edges)} edges."
        if malware: findings += f" Malware: {', '.join(malware)}."
        if assets: findings += f" Affected assets: {', '.join(assets)}."
        return {"findings": findings, "evidence": "", "relationships": "", "confidence": 60 if malware else 50}
    else:
        prompt = f"""You are a cybersecurity analyst assistant. Based on the graph context, answer:
        Question: {req.question}
        Context: {context}
        Provide: Findings, Evidence, Relationships Used, Confidence (0-100%), Countermeasures."""
        response = ask_llm(prompt, mode="ollama", model=req.model)
        return {"findings": response, "confidence": 70}

# Serve static files under /static
app.mount("/static", StaticFiles(directory="static", html=True), name="static")

# Serve index.html at root
from fastapi.responses import FileResponse

@app.get("/")
async def index():
    return FileResponse("static/index.html")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
