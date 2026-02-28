from typing import Dict


class GATBECDetector:
    def __init__(self, model_path: str | None = None):
        self.model_path = model_path

    def predict(self, features: Dict[str, float]) -> float:
        cold_contact = features.get('cold_contact_flag', 0.0)
        display_mismatch = features.get('display_name_mismatch_flag', 0.0)
        reply_to_mismatch = features.get('reply_to_mismatch_flag', 0.0)
        finance_terms = features.get('financial_keywords_ratio', 0.0)
        score = 0.35 * cold_contact + 0.25 * display_mismatch + 0.2 * reply_to_mismatch + 0.2 * finance_terms
        return max(0.0, min(1.0, float(score)))
