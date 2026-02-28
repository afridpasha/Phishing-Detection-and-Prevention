from typing import Dict, List

import numpy as np


class SHAPExplainer:
    def __init__(self, model=None):
        self.model = model
        self._explainer = None
        if model is not None:
            try:
                import shap
                self._explainer = shap.TreeExplainer(model)
            except Exception:
                self._explainer = None

    def explain(self, feature_vector, feature_names: List[str]) -> Dict[str, float]:
        if self._explainer is not None:
            try:
                values = self._explainer.shap_values([feature_vector])
                if isinstance(values, list):
                    values = values[-1]
                vals = np.array(values)[0]
                pairs = sorted(zip(feature_names, vals), key=lambda x: abs(float(x[1])), reverse=True)[:5]
                return {k: float(v) for k, v in pairs}
            except Exception:
                pass
        pairs = sorted(zip(feature_names, feature_vector), key=lambda x: abs(float(x[1])), reverse=True)[:5]
        return {k: float(v) for k, v in pairs}
