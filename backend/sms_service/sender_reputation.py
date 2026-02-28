import re
from typing import Dict, Optional


class SenderReputationEngine:
    def score_sender(self, sender: Optional[str], carrier: Optional[str] = None) -> Dict[str, float | str]:
        if not sender:
            return {'label': 'unknown', 'score': 0.5}

        value = sender.strip().lower()
        short_code = bool(re.fullmatch(r'\d{5,6}', value))
        phone_like = bool(re.fullmatch(r'[+0-9\-\s]{7,20}', value))
        alpha_sender = bool(re.fullmatch(r'[a-z0-9_-]{3,20}', value)) and not phone_like

        score = 0.5
        if short_code:
            score = 0.2
        elif phone_like:
            score = 0.45
        elif alpha_sender:
            score = 0.65

        if carrier and carrier.lower() in {'unknown', 'unverified'}:
            score = min(0.95, score + 0.2)

        label = 'trusted' if score < 0.35 else 'suspicious' if score > 0.6 else 'unknown'
        return {'label': label, 'score': score}
