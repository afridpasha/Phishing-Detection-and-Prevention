import re

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer


class CodeBERTHTMLDetector:
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

    def predict(self, html: str | None) -> float:
        html = html or ''
        if self.loaded and self.model and self.tokenizer:
            with torch.no_grad():
                inputs = self.tokenizer(html, return_tensors='pt', truncation=True, padding=True, max_length=512)
                inputs = {k: v.to(self.device) for k, v in inputs.items()}
                logits = self.model(**inputs).logits
                return float(torch.softmax(logits, dim=1)[0][1].item())
        suspicious = [r'eval\(', r'fromCharCode', r'base64', r'atob\(', r'document\.write', r'javascript:']
        hits = sum(1 for p in suspicious if re.search(p, html, flags=re.IGNORECASE))
        return min(0.95, hits * 0.14)
