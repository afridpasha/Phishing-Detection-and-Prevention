from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

class DeBERTaURLClassifier:
    def __init__(self, model_path: str, device='cpu'):
        self.device = device
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_path)
        self.model.to(device)
        self.model.eval()
    
    def predict(self, url: str) -> float:
        """Predict phishing probability using DeBERTa"""
        inputs = self.tokenizer(url, return_tensors='pt', max_length=128, 
                               truncation=True, padding=True)
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        
        with torch.no_grad():
            logits = self.model(**inputs).logits
            probs = torch.softmax(logits, dim=1)
            score = probs[0][1].item()  # Phishing class probability
        
        return score
