import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer


class SecureBERTClassifier:
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
        self.keywords = {'otp', 'verify', 'suspended', 'delivery', 'urgent', 'click', 'bank', 'account', 'reset', 'gift'}

    def predict(self, message: str) -> float:
        if self.loaded and self.model and self.tokenizer:
            with torch.no_grad():
                inputs = self.tokenizer(message, return_tensors='pt', truncation=True, padding=True, max_length=512)
                inputs = {k: v.to(self.device) for k, v in inputs.items()}
                logits = self.model(**inputs).logits
                return float(torch.softmax(logits, dim=1)[0][1].item())
        lower = message.lower()
        hits = sum(1 for k in self.keywords if k in lower)
        has_link = 1 if 'http://' in lower or 'https://' in lower else 0
        return min(0.98, 0.08 * hits + 0.25 * has_link)
