from typing import Dict
import pickle
import os

class RiverOnlineLearner:
    def __init__(self):
        self._river_available = True
        try:
            from river import compose, linear_model, preprocessing

            self.model = compose.Pipeline(
                preprocessing.StandardScaler(),
                linear_model.LogisticRegression()
            )
        except Exception:
            self._river_available = False
            self.model = None
        self.model_path = 'models/ensemble/river_online.pkl'
        self.load_model()
    
    def load_model(self):
        """Load existing model if available"""
        if os.path.exists(self.model_path):
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
    
    def save_model(self):
        """Save model to disk"""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)
    
    def update(self, features: Dict, true_label: int):
        """Update model with new example"""
        if self._river_available and self.model is not None:
            self.model.learn_one(features, true_label)
            self.save_model()
    
    def predict(self, features: Dict) -> float:
        """Predict probability"""
        try:
            if self._river_available and self.model is not None:
                proba = self.model.predict_proba_one(features)
                return proba.get(1, 0.5)
            return 0.5
        except:
            return 0.5

# Global instance
online_learner = RiverOnlineLearner()
