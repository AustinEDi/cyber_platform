from fastapi import APIRouter, Depends, Query
from database import expand_node, search_nodes
from auth import get_current_user

router = APIRouter(prefix="/graph", tags=["graph"])

@router.get("/expand")
async def expand(node_id: str = Query(...), user=Depends(get_current_user)):
    try:
        label, rest = node_id.split(":", 1)
        prop, val = rest.split("=", 1)
    except ValueError:
        return {"error": "Invalid format. Use Label:property=value"}
    return expand_node(label, prop, val)

@router.get("/search")
async def search(q: str = Query(...), user=Depends(get_current_user)):
    return search_nodes(q)
