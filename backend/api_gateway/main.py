"""
API Gateway - FastAPI Application
Real-Time Phishing Detection System

RESTful API for phishing detection services
"""

from fastapi import FastAPI, HTTPException, Depends, status, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Dict, Any
from datetime import datetime
import logging
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.detection_engine.main_engine import PhishingDetectionEngine, get_engine

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Phishing Detection API",
    description="Real-Time AI/ML-Based Phishing Detection and Prevention System",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Pydantic models for request/response
class EmailAnalysisRequest(BaseModel):
    subject: str = Field(..., description="Email subject line")
    body: str = Field(..., description="Email body content")
    sender: Optional[EmailStr] = Field(None, description="Sender email address")
    html_content: Optional[str] = Field(None, description="HTML content of email")
    attachments: Optional[List[str]] = Field(None, description="Attachment filenames")
    
    class Config:
        schema_extra = {
            "example": {
                "subject": "URGENT: Verify your account",
                "body": "Click here to verify your account immediately...",
                "sender": "security@suspicious.com",
                "attachments": ["invoice.pdf"]
            }
        }


class URLAnalysisRequest(BaseModel):
    url: str = Field(..., description="URL to analyze")
    include_screenshot: Optional[bool] = Field(False, description="Include screenshot analysis")
    
    class Config:
        schema_extra = {
            "example": {
                "url": "https://example.com/login",
                "include_screenshot": False
            }
        }


class SMSAnalysisRequest(BaseModel):
    message: str = Field(..., description="SMS message content")
    sender: Optional[str] = Field(None, description="Sender phone number")
    
    class Config:
        schema_extra = {
            "example": {
                "message": "Your package is waiting. Click to track: http://bit.ly/abc123",
                "sender": "+1234567890"
            }
        }


class AnalysisResponse(BaseModel):
    timestamp: str
    final_score: float
    risk_level: str
    action: str
    confidence: float
    latency_ms: float
    explanation: Dict[str, Any]
    metadata: Dict[str, Any]


class HealthResponse(BaseModel):
    status: str
    timestamp: str
    version: str
    models_loaded: bool


class StatisticsResponse(BaseModel):
    total_requests: int
    average_latency_ms: float
    decision_statistics: Dict[str, Any]


# Dependency to get detection engine
async def get_detection_engine() -> PhishingDetectionEngine:
    """Dependency to get detection engine instance"""
    return get_engine()


# API Endpoints

@app.get("/", response_model=Dict[str, str])
async def root():
    """Root endpoint"""
    return {
        "message": "Phishing Detection API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }


@app.get("/health", response_model=HealthResponse)
async def health_check(engine: PhishingDetectionEngine = Depends(get_detection_engine)):
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now().isoformat(),
        version="1.0.0",
        models_loaded=engine.nlp_model is not None
    )


@app.post("/api/v1/analyze/email", response_model=AnalysisResponse)
async def analyze_email(
    request: EmailAnalysisRequest,
    engine: PhishingDetectionEngine = Depends(get_detection_engine)
):
    """
    Analyze email for phishing indicators
    
    - **subject**: Email subject line
    - **body**: Email body content
    - **sender**: Sender email address (optional)
    - **html_content**: HTML source (optional)
    - **attachments**: List of attachments (optional)
    """
    try:
        result = await engine.analyze_email(
            subject=request.subject,
            body=request.body,
            sender=request.sender,
            html_content=request.html_content,
            attachments=request.attachments
        )
        
        return AnalysisResponse(**result)
    
    except Exception as e:
        logger.error(f"Email analysis error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}"
        )


@app.post("/api/v1/analyze/url", response_model=AnalysisResponse)
async def analyze_url(
    request: URLAnalysisRequest,
    engine: PhishingDetectionEngine = Depends(get_detection_engine)
):
    """
    Analyze URL for phishing indicators
    
    - **url**: URL to analyze
    - **include_screenshot**: Whether to capture and analyze screenshot
    """
    try:
        result = await engine.analyze_url(
            url=request.url,
            screenshot=None,  # TODO: Implement screenshot capture
            html_content=None
        )
        
        return AnalysisResponse(**result)
    
    except Exception as e:
        logger.error(f"URL analysis error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}"
        )


@app.post("/api/v1/analyze/sms", response_model=AnalysisResponse)
async def analyze_sms(
    request: SMSAnalysisRequest,
    engine: PhishingDetectionEngine = Depends(get_detection_engine)
):
    """
    Analyze SMS message for phishing (smishing) indicators
    
    - **message**: SMS message content
    - **sender**: Sender phone number (optional)
    """
    try:
        result = await engine.analyze_sms(
            message=request.message,
            sender=request.sender
        )
        
        return AnalysisResponse(**result)
    
    except Exception as e:
        logger.error(f"SMS analysis error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}"
        )


@app.get("/api/v1/statistics", response_model=StatisticsResponse)
async def get_statistics(engine: PhishingDetectionEngine = Depends(get_detection_engine)):
    """Get system statistics"""
    try:
        stats = engine.get_statistics()
        return StatisticsResponse(**stats)
    
    except Exception as e:
        logger.error(f"Statistics error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve statistics: {str(e)}"
        )


@app.post("/api/v1/feedback")
async def submit_feedback(
    decision_id: str,
    is_correct: bool,
    comments: Optional[str] = None
):
    """
    Submit user feedback on a detection decision
    
    - **decision_id**: ID of the decision
    - **is_correct**: Whether the decision was correct
    - **comments**: Additional comments
    """
    # TODO: Implement feedback storage for retraining
    return {
        "status": "success",
        "message": "Feedback recorded",
        "decision_id": decision_id
    }


@app.post("/api/v1/models/reload")
async def reload_models(engine: PhishingDetectionEngine = Depends(get_detection_engine)):
    """Reload ML models (admin endpoint)"""
    try:
        engine.reload_models()
        return {"status": "success", "message": "Models reloaded successfully"}
    
    except Exception as e:
        logger.error(f"Model reload error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to reload models: {str(e)}"
        )


@app.put("/api/v1/config/weights")
async def update_weights(
    weights: Dict[str, float],
    engine: PhishingDetectionEngine = Depends(get_detection_engine)
):
    """Update ensemble model weights (admin endpoint)"""
    try:
        engine.update_ensemble_weights(weights)
        return {
            "status": "success",
            "message": "Weights updated",
            "new_weights": weights
        }
    
    except Exception as e:
        logger.error(f"Weight update error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update weights: {str(e)}"
        )


# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "timestamp": datetime.now().isoformat()
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal server error",
            "timestamp": datetime.now().isoformat()
        }
    )


# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    logger.info("Starting Phishing Detection API...")
    logger.info("API Documentation available at /docs")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("Shutting down Phishing Detection API...")
    engine = get_engine()
    engine.shutdown()


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
