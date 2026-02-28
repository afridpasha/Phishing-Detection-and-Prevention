from pydantic import BaseModel, Field
from typing import Optional, List, Dict
from .common_schema import DetectionResult

class SMSAnalysisRequest(BaseModel):
    message: str
    sender: Optional[str] = None
    carrier: Optional[str] = None
    language: str = "auto"

class SMSMetadata(BaseModel):
    detected_language: str
    urls_found: List[str]
    url_analysis: Dict
    brands_mentioned: List[str]
    urgency_score: float
    sender_reputation: str

class SMSAnalysisResponse(DetectionResult):
    metadata: SMSMetadata
