from typing import Dict, Optional, Tuple

import joblib
import lightgbm as lgb
import os

from backend.api_gateway.config import settings
from backend.ensemble_engine.shap_explainer import SHAPExplainer

meta_learner_model: Optional[lgb.LGBMClassifier] = None
meta_shap: Optional[SHAPExplainer] = None


async def load_meta_learner():
    global meta_learner_model, meta_shap
    model_path = os.path.join(settings.MODELS_BASE_PATH, 'ensemble', 'meta_learner.joblib')
    if os.path.exists(model_path):
        try:
            meta_learner_model = joblib.load(model_path)
            meta_shap = SHAPExplainer(meta_learner_model)
        except Exception:
            meta_learner_model = None
            meta_shap = None


def get_meta_learner_status() -> Dict[str, bool]:
    return {'loaded': meta_learner_model is not None}


def build_feature_vector(input_type: str, model_scores: Dict[str, float], metadata: Dict) -> Tuple[list[float], list[str]]:
    items = sorted((k, float(v)) for k, v in model_scores.items())
    values = [v for _, v in items]
    names = [k for k, _ in items]

    values.extend([
        float(metadata.get('urgency_score', 0.0)),
        float(metadata.get('redirect_hops', metadata.get('redirect_count', 0.0))),
        float(metadata.get('domain_age_days', 0.0)),
    ])
    names.extend(['urgency_score', 'redirect_count', 'domain_age_days'])

    one_hot = {
        'url': [1.0, 0.0, 0.0, 0.0],
        'sms': [0.0, 1.0, 0.0, 0.0],
        'email': [0.0, 0.0, 1.0, 0.0],
        'image': [0.0, 0.0, 0.0, 1.0],
    }.get(input_type, [0.0, 0.0, 0.0, 0.0])
    values.extend(one_hot)
    names.extend(['input_type_url', 'input_type_sms', 'input_type_email', 'input_type_image'])

    return values, names


def predict_meta_score(input_type: str, model_scores: Dict[str, float], metadata: Dict) -> Tuple[float, Dict[str, float]]:
    values, names = build_feature_vector(input_type, model_scores, metadata)

    if meta_learner_model is not None:
        try:
            score = float(meta_learner_model.predict_proba([values])[0][1])
            shap_values = meta_shap.explain(values, names) if meta_shap else {}
            return score, shap_values
        except Exception:
            pass

    if not model_scores:
        return 0.5, {}
    score = sum(float(v) for v in model_scores.values()) / len(model_scores)
    return float(score), {}
