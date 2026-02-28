from fastapi import APIRouter, HTTPException
from ..schemas.url_schema import URLAnalysisRequest, URLAnalysisResponse, URLMetadata
from ..schemas.common_schema import RiskLevel, Action, Explanation
from backend.url_service.service import analyze_url
from backend.ensemble_engine.decision_maker import make_final_decision
import uuid
from datetime import datetime

router = APIRouter(tags=["URL Analysis"])

@router.post("/analyze/url", response_model=URLAnalysisResponse)
async def analyze_url_endpoint(request: URLAnalysisRequest):
    """Analyze URL for phishing threats"""
    try:
        # Run URL analysis
        result = await analyze_url(
            request.url,
            request.include_screenshot,
            request.follow_redirects,
            request.context
        )
        
        # Make final decision
        decision = await make_final_decision(
            input_type="url",
            model_scores=result['model_scores'],
            metadata=result['metadata'],
            indicators=result['indicators']
        )
        
        # Build response
        response = URLAnalysisResponse(
            request_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            input_type="url",
            final_score=decision['final_score'],
            risk_level=RiskLevel(decision['risk_level']),
            action=Action(decision['action']),
            confidence=decision['confidence'],
            latency_ms=result['latency_ms'],
            model_scores=result['model_scores'],
            explanation=Explanation(
                summary=decision['summary'],
                top_indicators=result['indicators'][:5],
                shap_values=result.get('shap_values', {}),
                recommendation=decision['recommendation']
            ),
            metadata=URLMetadata(**result['metadata'])
        )
        
        return response
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
