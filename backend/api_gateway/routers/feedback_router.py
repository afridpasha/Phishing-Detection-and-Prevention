from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel

from backend.learning_pipeline.feedback_processor import feedback_processor

router = APIRouter(tags=['Feedback'])


class FeedbackRequest(BaseModel):
    request_id: str
    is_correct: bool
    actual_label: Optional[str] = None
    comments: Optional[str] = None


@router.post('/feedback')
async def submit_feedback(feedback: FeedbackRequest):
    result = await feedback_processor.process_feedback(feedback.model_dump())
    return {
        'status': 'success',
        'message': 'Feedback received and processed',
        'result': result,
    }
