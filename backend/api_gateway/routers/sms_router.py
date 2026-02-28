from fastapi import APIRouter, HTTPException
from ..schemas.sms_schema import SMSAnalysisRequest, SMSAnalysisResponse, SMSMetadata
from ..schemas.common_schema import RiskLevel, Action, Explanation
from backend.sms_service.service import analyze_sms
from backend.ensemble_engine.decision_maker import make_final_decision
import uuid
from datetime import datetime

router = APIRouter(tags=["SMS Analysis"])

@router.post("/analyze/sms", response_model=SMSAnalysisResponse)
async def analyze_sms_endpoint(request: SMSAnalysisRequest):
    """Analyze SMS/text message for smishing"""
    try:
        result = await analyze_sms(
            request.message,
            request.sender,
            request.carrier,
            request.language
        )
        
        decision = await make_final_decision(
            input_type="sms",
            model_scores=result['model_scores'],
            metadata=result['metadata'],
            indicators=result['indicators']
        )
        
        response = SMSAnalysisResponse(
            request_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            input_type="sms",
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
            metadata=SMSMetadata(**result['metadata'])
        )
        
        return response
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
