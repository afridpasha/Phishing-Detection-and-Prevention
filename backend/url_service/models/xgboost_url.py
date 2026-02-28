try:
    import xgboost as xgb  # noqa: F401
except Exception:  # pragma: no cover
    xgb = None
import joblib
try:
    import shap
except Exception:  # pragma: no cover
    shap = None
import pandas as pd
from typing import Dict, Tuple

class XGBoostURLClassifier:
    def __init__(self, model_path: str):
        self.model = joblib.load(model_path)
        self.explainer = shap.TreeExplainer(self.model) if shap is not None else None
    
    def predict(self, features: Dict[str, float]) -> Tuple[float, Dict[str, float]]:
        """Predict phishing probability and return SHAP values"""
        features_df = pd.DataFrame([features])
        
        # Predict
        score = self.model.predict_proba(features_df)[0][1]
        
        # Get SHAP values
        if self.explainer is not None:
            shap_values = self.explainer.shap_values(features_df)
        else:
            shap_values = [[0.0 for _ in features.keys()]]
        
        # Get top 5 contributing features
        if isinstance(shap_values, list):
            shap_values = shap_values[1]  # Positive class
        
        feature_importance = dict(zip(features.keys(), shap_values[0]))
        top_features = dict(sorted(feature_importance.items(), 
                                  key=lambda x: abs(x[1]), 
                                  reverse=True)[:5])
        
        return score, top_features
