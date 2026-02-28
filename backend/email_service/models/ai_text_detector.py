import re

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer


class AITextDetector:
    def __init__(self, model_path: str, device: str = 'cpu'):
        self.device = device
        self.loaded = False
        self.model = None
        self.tokenizer = None
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_path)
            self.model = AutoModelForSequenceClassification.from_pretrained(model_path).to(device)
            self.model.eval()
            self.loaded = True
        except Exception:
            self.loaded = False

    def predict(self, text: str) -> float:
        if self.loaded and self.model and self.tokenizer:
            with torch.no_grad():
                inputs = self.tokenizer(text, return_tensors='pt', truncation=True, padding=True, max_length=512)
                inputs = {k: v.to(self.device) for k, v in inputs.items()}
                logits = self.model(**inputs).logits
                return float(torch.softmax(logits, dim=1)[0][1].item())

        sentences = [s.strip() for s in re.split(r'[.!?]+', text) if s.strip()]
        if not sentences:
            return 0.0
        lengths = [len(s.split()) for s in sentences]
        avg_len = sum(lengths) / len(lengths)
        variance = sum((l - avg_len) ** 2 for l in lengths) / len(lengths)
        low_variance_flag = 1.0 if variance < 12 else 0.0
        return min(0.9, 0.35 * low_variance_flag + 0.002 * avg_len)
