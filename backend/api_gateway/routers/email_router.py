from fastapi import APIRouter, HTTPException
from ..schemas.email_schema import EmailAnalysisRequest, EmailAnalysisResponse, EmailMetadata
from ..schemas.common_schema import RiskLevel, Action, Explanation
from backend.email_service.service import analyze_email
from backend.ensemble_engine.decision_maker import make_final_decision
import uuid
from datetime import datetime

router = APIRouter(tags=["Email Analysis"])

@router.post("/analyze/email", response_model=EmailAnalysisResponse)
async def analyze_email_endpoint(request: EmailAnalysisRequest):
    """Analyze email for phishing threats"""
    try:
        result = await analyze_email(
            request.subject,
            request.body_text,
            request.body_html,
            request.sender_email,
            request.sender_display_name,
            request.recipient_email,
            request.headers_raw,
            request.attachments
        )
        
        decision = await make_final_decision(
            input_type="email",
            model_scores=result['model_scores'],
            metadata=result['metadata'],
            indicators=result['indicators']
        )
        
        response = EmailAnalysisResponse(
            request_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            input_type="email",
            final_score=decision['final_score'],
            risk_level=RiskLevel(decision['risk_level']),
            action=Action(decision['action']),
            confidence=decision['confidence'],
            latency_ms=result['latency_ms'],
            model_scores=result['model_scores'],
            explanation=Explanation(
                summary=decision['summary'],
                top_indicators=result['indicators'][:5],
                shap_values={},
                recommendation=decision['recommendation']
            ),
            metadata=EmailMetadata(**result['metadata'])
        )
        
        return response
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
