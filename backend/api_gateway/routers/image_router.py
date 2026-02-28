from fastapi import APIRouter, HTTPException, File, UploadFile, Form
from ..schemas.image_schema import ImageAnalysisResponse, ImageMetadata
from ..schemas.common_schema import RiskLevel, Action, Explanation
from backend.image_service.service import analyze_image
from backend.ensemble_engine.decision_maker import make_final_decision
import uuid
from datetime import datetime
from typing import Optional

router = APIRouter(tags=["Image Analysis"])

@router.post("/analyze/image", response_model=ImageAnalysisResponse)
async def analyze_image_endpoint(
    image: UploadFile = File(...),
    context: Optional[str] = Form("unknown"),
    run_sandbox: Optional[bool] = Form(False)
):
    """Analyze image for QR phishing, RAT payloads, steganography"""
    try:
        image_bytes = await image.read()
        
        result = await analyze_image(image_bytes, context, run_sandbox)
        
        decision = await make_final_decision(
            input_type="image",
            model_scores=result['model_scores'],
            metadata=result['metadata'],
            indicators=result['indicators']
        )
        
        response = ImageAnalysisResponse(
            request_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            input_type="image",
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
            metadata=ImageMetadata(**result['metadata'])
        )
        
        return response
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
