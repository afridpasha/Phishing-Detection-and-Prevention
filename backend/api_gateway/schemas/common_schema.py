from pydantic import BaseModel, Field
from typing import Dict, List, Optional
from datetime import datetime
from enum import Enum

class RiskLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Action(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    EMERGENCY_BLOCK = "emergency_block"

class Explanation(BaseModel):
    summary: str
    top_indicators: List[str]
    shap_values: Dict[str, float]
    recommendation: str

class DetectionResult(BaseModel):
    request_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    input_type: str
    final_score: float = Field(ge=0.0, le=1.0)
    risk_level: RiskLevel
    action: Action
    confidence: float = Field(ge=0.0, le=1.0)
    latency_ms: float
    model_scores: Dict[str, float]
    explanation: Explanation
    metadata: Dict
