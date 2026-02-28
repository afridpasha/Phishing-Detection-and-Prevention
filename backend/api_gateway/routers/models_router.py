from fastapi import APIRouter

from backend.email_service.service import get_email_model_status
from backend.ensemble_engine.meta_learner import get_meta_learner_status
from backend.image_service.service import get_image_model_status
from backend.sms_service.service import get_sms_model_status
from backend.url_service.service import get_url_model_status

router = APIRouter(tags=['Model Status'])


@router.get('/models/status')
async def get_models_status() -> dict:
    return {
        'url': get_url_model_status(),
        'sms': get_sms_model_status(),
        'email': get_email_model_status(),
        'image': get_image_model_status(),
        'ensemble': get_meta_learner_status(),
    }
