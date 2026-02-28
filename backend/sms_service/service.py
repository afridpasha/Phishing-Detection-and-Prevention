import os
import re
import time
from typing import Dict, Optional

try:
    from langdetect import detect
except Exception:  # pragma: no cover
    detect = None

from backend.api_gateway.config import settings
from backend.sms_service.models.mdeberta_model import MDeBERTaSMSClassifier
from backend.sms_service.models.securebert_model import SecureBERTClassifier
from backend.sms_service.models.setfit_model import SetFitSMSClassifier
from backend.sms_service.ner_engine import BrandNER
from backend.sms_service.sender_reputation import SenderReputationEngine

# Global model instances
securebert_model: Optional[SecureBERTClassifier] = None
mdeberta_model: Optional[MDeBERTaSMSClassifier] = None
setfit_model: Optional[SetFitSMSClassifier] = None
brand_ner: Optional[BrandNER] = None
sender_engine: Optional[SenderReputationEngine] = None


async def load_sms_models():
    global securebert_model, mdeberta_model, setfit_model, brand_ner, sender_engine

    device = 'cuda' if settings.ENABLE_GPU else 'cpu'
    base = settings.MODELS_BASE_PATH

    securebert_model = SecureBERTClassifier(os.path.join(base, 'sms', 'securebert_sms'), device)
    mdeberta_model = MDeBERTaSMSClassifier(os.path.join(base, 'sms', 'mdeberta_sms'), device)
    setfit_model = SetFitSMSClassifier(os.path.join(base, 'sms', 'setfit_sms'))
    brand_ner = BrandNER()
    sender_engine = SenderReputationEngine()


def get_sms_model_status() -> Dict[str, bool]:
    return {
        'securebert': securebert_model is not None,
        'mdeberta': mdeberta_model is not None,
        'setfit': setfit_model is not None,
        'brand_ner': brand_ner is not None,
        'sender_reputation': sender_engine is not None,
    }


async def analyze_sms(message: str, sender: Optional[str], carrier: Optional[str], language: str) -> Dict:
    start = time.time()
    lang = language if language and language != 'auto' else _safe_langdetect(message)

    secure_score = securebert_model.predict(message) if securebert_model else 0.5
    mdeberta_score = mdeberta_model.predict(message) if mdeberta_model else 0.5
    setfit_score = setfit_model.predict(message) if setfit_model else 0.5

    urls = re.findall(r'https?://[^\s]+', message)
    urgency_terms = ['urgent', 'immediately', 'now', 'suspended', 'verify', 'action required']
    urgency_score = min(1.0, 0.18 * sum(1 for t in urgency_terms if t in message.lower()))
    brands = brand_ner.extract_brands(message) if brand_ner else []
    sender_rep = sender_engine.score_sender(sender, carrier) if sender_engine else {'label': 'unknown', 'score': 0.5}

    primary = secure_score if lang == 'en' else mdeberta_score

    model_scores = {
        'securebert': float(secure_score),
        'mdeberta': float(mdeberta_score),
        'setfit': float(setfit_score),
        'language_router': float(primary),
    }

    indicators = []
    if urls:
        indicators.append(f'Embedded URLs found: {len(urls)}')
    if brands:
        indicators.append(f'Brand mentions detected: {", ".join(brands[:3])}')
    if sender_rep['score'] > 0.6:
        indicators.append('Sender reputation appears suspicious')

    return {
        'model_scores': model_scores,
        'final_score': sum(model_scores.values()) / len(model_scores),
        'indicators': indicators,
        'metadata': {
            'detected_language': lang,
            'urls_found': urls,
            'url_analysis': {},
            'brands_mentioned': brands,
            'urgency_score': urgency_score,
            'sender_reputation': sender_rep['label'],
        },
        'latency_ms': (time.time() - start) * 1000,
    }


def _safe_langdetect(message: str) -> str:
    if detect is None:
        return 'en'
    try:
        return detect(message)
    except Exception:
        return 'en'
