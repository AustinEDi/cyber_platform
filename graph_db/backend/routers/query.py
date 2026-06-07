from fastapi import APIRouter, Depends
from pydantic import BaseModel
from auth import get_current_user

router = APIRouter(prefix="/query", tags=["query"])

class CypherQuery(BaseModel):
    cypher: str
    params: dict = {}

@router.post("/cypher")
async def run_cypher(payload: CypherQuery, user=Depends(get_current_user)):
    # Raw Cypher not supported in file-based mode
    return {"error": "Cypher queries are not supported in this storage mode"}
