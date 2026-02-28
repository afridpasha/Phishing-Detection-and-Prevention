from pydantic import BaseModel, HttpUrl, Field
from typing import Optional
from .common_schema import DetectionResult

class URLAnalysisRequest(BaseModel):
    url: str
    include_screenshot: bool = False
    follow_redirects: bool = True
    context: Optional[str] = Field(default="unknown", pattern="^(email|sms|web|unknown)$")

class URLMetadata(BaseModel):
    original_url: str
    normalized_url: str
    final_destination: str
    redirect_hops: int
    domain_age_days: float
    ssl_valid: bool
    ssl_age_days: float

class URLAnalysisResponse(DetectionResult):
    metadata: URLMetadata
