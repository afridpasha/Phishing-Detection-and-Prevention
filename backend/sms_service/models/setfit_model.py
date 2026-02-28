class SetFitSMSClassifier:
    def __init__(self, model_path: str):
        self.model_path = model_path
        self.loaded = False
        self.model = None
        try:
            from setfit import SetFitModel
            self.model = SetFitModel.from_pretrained(model_path)
            self.loaded = True
        except Exception:
            self.loaded = False

    def predict(self, message: str) -> float:
        if self.loaded and self.model:
            pred = self.model.predict([message])
            try:
                return float(pred[0])
            except Exception:
                return 0.5
        lower = message.lower()
        indicators = ['limited time', 'click now', 'claim', 'verify', 'account']
        return min(0.9, 0.09 * sum(1 for i in indicators if i in lower))
