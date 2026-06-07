#!/usr/bin/env python3
import sys
import os
from pathlib import Path

# Ensure the backend directory is on the Python path
BACKEND_DIR = Path(__file__).parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))

import click
import requests
import subprocess
import time

API_URL = "http://localhost:8000"

@click.group()
def cli():
    pass

@cli.command()
def init_schema():
    """Initialize Neo4j constraints (unique nodes)."""
    from database import run_query
    stmts = [
        "CREATE CONSTRAINT asset_hostname IF NOT EXISTS FOR (a:Asset) REQUIRE a.hostname IS UNIQUE;",
        "CREATE CONSTRAINT user_username IF NOT EXISTS FOR (u:User) REQUIRE u.username IS UNIQUE;",
        "CREATE CONSTRAINT ip_address IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE;",
        "CREATE CONSTRAINT domain_name IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE;",
        "CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (c:CVE) REQUIRE c.cve_id IS UNIQUE;",
        "CREATE CONSTRAINT technique_id IF NOT EXISTS FOR (t:Technique) REQUIRE t.technique_id IS UNIQUE;",
        "CREATE CONSTRAINT threatactor_name IF NOT EXISTS FOR (ta:ThreatActor) REQUIRE ta.name IS UNIQUE;",
        "CREATE CONSTRAINT malware_name IF NOT EXISTS FOR (m:Malware) REQUIRE m.name IS UNIQUE;",
    ]
    for s in stmts:
        run_query(s)
    print("[+] Schema initialized.")

@cli.command()
def start():
    """Start Neo4j and the FastAPI server."""
    # Check if Neo4j is already accepting connections
    bolt_check = subprocess.run(["curl", "-s", "http://localhost:7474"], capture_output=True)
    if bolt_check.returncode != 0:
        print("[*] Starting Neo4j...")
        neo4j_path = os.path.expanduser("~/neo4j/bin/neo4j")
        subprocess.Popen([neo4j_path, "console"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(12)
    print("[*] Starting backend on http://localhost:8000 ...")
    subprocess.Popen(["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"],
                     cwd=str(BACKEND_DIR), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[+] Backend running. Use 'graphdb expand ...' or 'curl' to test.")

def get_token():
    r = requests.post(f"{API_URL}/token", data={"username": "analyst", "password": "password"})
    return r.json().get("access_token") if r.status_code == 200 else None

def auth_headers():
    token = get_token()
    return {"Authorization": f"Bearer {token}"} if token else {}

@cli.command()
@click.argument("source", type=click.Choice(["mitre", "cve", "threat", "assets", "events"]))
@click.argument("file", type=click.Path(exists=True))
def ingest(source, file):
    """Load data from a JSON file."""
    with open(file) as f:
        import json
        payload = json.load(f)
    r = requests.post(f"{API_URL}/ingest/{source}", json={"data": payload["data"]}, headers=auth_headers())
    if r.status_code == 200:
        print(f"[+] Ingested {len(payload['data'])} {source} records.")
    else:
        print(f"[-] Error: {r.status_code} - {r.text}")

@cli.command()
@click.argument("node_id")
def expand(node_id):
    """Expand a node: Label:property=value"""
    r = requests.get(f"{API_URL}/graph/expand?node_id={node_id}", headers=auth_headers())
    if r.status_code == 200:
        data = r.json()
        print(f"Nodes: {len(data['nodes'])}, Edges: {len(data['edges'])}")
        for n in data['nodes']:
            print(f"  {n['id']} ({n['label']})")
    else:
        print("Error:", r.text)

@cli.command()
@click.argument("word")
def search(word):
    """Search for entities containing a keyword."""
    r = requests.get(f"{API_URL}/graph/search?q={word}", headers=auth_headers())
    if r.status_code == 200:
        results = r.json()
        for item in results:
            print(f"{item['label']}: {item['properties']}")
    else:
        print("Error:", r.text)

if __name__ == "__main__":
    cli()
