from fastapi import APIRouter, Depends
from models import IngestPayload
from database import (
    ingest_technique, ingest_cve, ingest_threat_item,
    ingest_asset, ingest_event
)
from auth import get_current_user

router = APIRouter(prefix="/ingest", tags=["ingest"])

@router.post("/mitre")
async def ingest_mitre(payload: IngestPayload, user=Depends(get_current_user)):
    for tech in payload.data:
        ingest_technique(tech)
    return {"status": "ingested", "count": len(payload.data)}

@router.post("/cve")
async def ingest_cves(payload: IngestPayload, user=Depends(get_current_user)):
    for cve in payload.data:
        ingest_cve(cve)
    return {"status": "ingested", "count": len(payload.data)}

@router.post("/threat")
async def ingest_threat(payload: IngestPayload, user=Depends(get_current_user)):
    for item in payload.data:
        ingest_threat_item(item)
    return {"status": "ok"}

@router.post("/assets")
async def ingest_assets(payload: IngestPayload, user=Depends(get_current_user)):
    for asset in payload.data:
        ingest_asset(asset)
    return {"status": "ingested", "count": len(payload.data)}

@router.post("/events")
async def ingest_events(payload: IngestPayload, user=Depends(get_current_user)):
    for evt in payload.data:
        ingest_event(evt)
    return {"status": "ingested", "count": len(payload.data)}
