from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict
from .common_schema import DetectionResult

class EmailAttachment(BaseModel):
    filename: str
    content_b64: str
    mime_type: str

class EmailAnalysisRequest(BaseModel):
    subject: str
    body_text: str
    body_html: Optional[str] = None
    sender_email: EmailStr
    sender_display_name: Optional[str] = None
    recipient_email: Optional[EmailStr] = None
    headers_raw: Optional[str] = None
    attachments: Optional[List[EmailAttachment]] = None

class AttachmentResult(BaseModel):
    filename: str
    verdict: str
    malware_family: Optional[str] = None

class EmailMetadata(BaseModel):
    spf_result: str
    dkim_result: str
    dmarc_result: str
    display_name_mismatch: bool
    is_ai_generated: bool
    ai_generated_probability: float
    attachment_results: List[AttachmentResult]
    bec_risk: float
    urls_found: List[str]

class EmailAnalysisResponse(DetectionResult):
    metadata: EmailMetadata
