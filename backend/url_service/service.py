import os
import time
from typing import Dict, Optional

from backend.api_gateway.config import settings
from backend.threat_intel.intel_aggregator import ThreatIntelAggregator

from .feature_extractor import URLFeatureExtractor
from .models.deberta_url import DeBERTaURLClassifier
from .models.tgt_model import TGTInference
from .models.urlnet_model import URLNetInference
from .models.xgboost_url import XGBoostURLClassifier
from .preprocessor import URLPreprocessor

# Global model instances
urlnet_model: Optional[URLNetInference] = None
deberta_model: Optional[DeBERTaURLClassifier] = None
xgboost_model: Optional[XGBoostURLClassifier] = None
tgt_model: Optional[TGTInference] = None
preprocessor: Optional[URLPreprocessor] = None
feature_extractor: Optional[URLFeatureExtractor] = None
threat_intel: Optional[ThreatIntelAggregator] = None


async def load_url_models():
    global urlnet_model, deberta_model, xgboost_model, tgt_model, preprocessor, feature_extractor, threat_intel

    base_path = settings.MODELS_BASE_PATH
    device = 'cuda' if settings.ENABLE_GPU else 'cpu'

    preprocessor = URLPreprocessor()
    feature_extractor = URLFeatureExtractor()
    threat_intel = ThreatIntelAggregator()

    urlnet_path = os.path.join(base_path, 'url', 'urlnet_model.pt')
    if os.path.exists(urlnet_path):
        urlnet_model = URLNetInference(urlnet_path, device)

    deberta_path = os.path.join(base_path, 'url', 'deberta_url')
    if os.path.exists(deberta_path):
        deberta_model = DeBERTaURLClassifier(deberta_path, device)

    xgboost_path = os.path.join(base_path, 'url', 'xgboost_url.joblib')
    if os.path.exists(xgboost_path):
        xgboost_model = XGBoostURLClassifier(xgboost_path)

    tgt_path = os.path.join(base_path, 'url', 'tgt_model.pt')
    if os.path.exists(tgt_path):
        tgt_model = TGTInference(tgt_path, device)


def get_url_model_status() -> Dict[str, bool]:
    return {
        'urlnet': urlnet_model is not None,
        'deberta_url': deberta_model is not None,
        'xgboost': xgboost_model is not None,
        'tgt_graph': tgt_model is not None,
        'threat_intel': threat_intel is not None,
    }


async def analyze_url(url: str, include_screenshot: bool = False, follow_redirects: bool = True, context: str = 'unknown') -> Dict:
    start_time = time.time()

    normalized_url = preprocessor.normalize_url(url)
    has_homoglyph, brand, homoglyph_conf = preprocessor.detect_homoglyphs(normalized_url)

    final_url, redirect_count, chain = normalized_url, 0, [normalized_url]
    if follow_redirects:
        final_url, redirect_count, chain = await preprocessor.unwind_redirects(normalized_url)

    features = feature_extractor.extract_features(final_url)
    features['has_homoglyph'] = 1.0 if has_homoglyph else 0.0
    features['homoglyph_brand'] = float(len(brand))
    features['homoglyph_confidence'] = float(homoglyph_conf)
    features['redirect_count'] = float(redirect_count)
    features['redirect_chain_length'] = float(len(chain) - 1)

    model_scores = {}
    shap_values = {}

    model_scores['urlnet'] = urlnet_model.predict(final_url) if urlnet_model else 0.5
    model_scores['deberta_url'] = deberta_model.predict(final_url) if deberta_model else 0.5

    if xgboost_model:
        xgb_score, shap_vals = xgboost_model.predict(features)
        model_scores['xgboost'] = xgb_score
        shap_values = shap_vals
    else:
        model_scores['xgboost'] = 0.5

    if tgt_model:
        model_scores['tgt_graph'] = await tgt_model.predict(final_url)
    else:
        model_scores['tgt_graph'] = 0.5

    intel_score = 0.0
    vt_ratio = 0.0
    in_vt = False
    if threat_intel:
        intel = await threat_intel.check_url(final_url)
        intel_score = float(intel.get('threat_score', 0.0))
        vt = intel.get('virustotal', {})
        vt_ratio = float(vt.get('detection_ratio', 0.0))
        in_vt = bool(vt.get('in_virustotal', False))

    model_scores['threat_intel'] = intel_score
    features['in_virustotal'] = 1.0 if in_vt else 0.0
    features['vt_detection_ratio'] = vt_ratio

    indicators = []
    if has_homoglyph:
        indicators.append(f'Homoglyph detected: impersonating {brand}')
    if redirect_count > 1:
        indicators.append(f'Suspicious redirect chain: {redirect_count} hops')
    if features['has_ip_address']:
        indicators.append('IP address used instead of domain name')
    if features['is_suspicious_tld']:
        indicators.append('Suspicious top-level domain')
    if in_vt and vt_ratio > 0.2:
        indicators.append(f'VirusTotal detection ratio elevated: {vt_ratio:.2f}')

    latency_ms = (time.time() - start_time) * 1000

    return {
        'model_scores': model_scores,
        'final_score': sum(model_scores.values()) / max(1, len(model_scores)),
        'shap_values': shap_values,
        'indicators': indicators,
        'metadata': {
            'original_url': url,
            'normalized_url': normalized_url,
            'final_destination': final_url,
            'redirect_hops': redirect_count,
            'domain_age_days': float(features.get('domain_age_days', 0.0)),
            'ssl_valid': bool(features.get('ssl_age_days', 0.0) >= 0),
            'ssl_age_days': float(features.get('ssl_age_days', 0.0)),
        },
        'latency_ms': latency_ms,
    }
