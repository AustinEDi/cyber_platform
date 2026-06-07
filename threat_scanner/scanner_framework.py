import requests
from datetime import datetime, timezone

API_BASE = "http://localhost:8000"
AUTH = ("analyst", "password")

def get_token():
    resp = requests.post(f"{API_BASE}/token", data={"username": AUTH[0], "password": AUTH[1]})
    return resp.json().get("access_token") if resp.status_code == 200 else None

def ingest_events(events):
    if not events:
        return
    token = get_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    resp = requests.post(f"{API_BASE}/ingest/events", json={"data": events}, headers=headers)
    if resp.status_code == 200:
        print(f"[+] Ingested {len(events)} event(s) into graph.")
    else:
        print(f"[-] Ingestion failed: {resp.status_code} {resp.text}")

class Scanner:
    def __init__(self, config=None):
        self.config = config or {}
    def run(self):
        return []
