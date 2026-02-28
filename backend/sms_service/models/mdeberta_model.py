import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer


class MDeBERTaSMSClassifier:
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

    def predict(self, message: str) -> float:
        if self.loaded and self.model and self.tokenizer:
            with torch.no_grad():
                inputs = self.tokenizer(message, return_tensors='pt', truncation=True, padding=True, max_length=512)
                inputs = {k: v.to(self.device) for k, v in inputs.items()}
                logits = self.model(**inputs).logits
                return float(torch.softmax(logits, dim=1)[0][1].item())
        lower = message.lower()
        suspicious = ['urgent', 'premio', 'verifica', 'entrega', 'bank', 'otp', 'click']
        hits = sum(1 for x in suspicious if x in lower)
        return min(0.95, 0.07 * hits + (0.2 if 'http' in lower else 0.0))
