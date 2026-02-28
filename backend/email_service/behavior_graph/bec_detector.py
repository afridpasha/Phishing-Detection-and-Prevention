from typing import Dict

from backend.email_service.models.gat_model import GATBECDetector


class BECDetector:
    def __init__(self, model_path: str | None = None):
        self.model = GATBECDetector(model_path)

    def predict(self, features: Dict[str, float]) -> float:
        return self.model.predict(features)
