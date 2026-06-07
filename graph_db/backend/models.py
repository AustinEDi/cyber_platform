from pydantic import BaseModel
from typing import List, Dict, Optional

class IngestPayload(BaseModel):
    data: List[Dict]

class NLQuery(BaseModel):
    question: str
    context_filter: Optional[Dict] = None
