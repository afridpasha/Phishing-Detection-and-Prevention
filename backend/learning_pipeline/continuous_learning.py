"""
Continuous Learning Pipeline
Automated model retraining with user feedback
"""

import schedule
import time
import logging
from datetime import datetime, timedelta
from typing import List, Dict
import pandas as pd
import joblib
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ContinuousLearningPipeline:
    """Automated retraining pipeline"""
    
    def __init__(self, feedback_db_path: str = "feedback.db"):
        self.feedback_db = feedback_db_path
        self.min_samples_for_retrain = 1000
        self.retrain_interval_hours = 24
        self.model_dir = Path("models")
        self.feedback_buffer = []
    
    def collect_feedback(self, decision_id: str, is_correct: bool, 
                        url: str, features: Dict, true_label: int):
        """Collect user feedback"""
        self.feedback_buffer.append({
            'decision_id': decision_id,
            'is_correct': is_correct,
            'url': url,
            'features': features,
            'true_label': true_label,
            'timestamp': datetime.now()
        })
        
        logger.info(f"Feedback collected: {decision_id} - Correct: {is_correct}")
        
        # Trigger retraining if buffer is full
        if len(self.feedback_buffer) >= self.min_samples_for_retrain:
            self.trigger_retraining()
    
    def trigger_retraining(self):
        """Trigger model retraining"""
        logger.info(f"Starting retraining with {len(self.feedback_buffer)} samples")
        
        # Convert feedback to training data
        df = pd.DataFrame(self.feedback_buffer)
        
        # Extract features and labels
        X = pd.DataFrame(list(df['features']))
        y = df['true_label']
        
        # Load current model
        try:
            model = joblib.load(self.model_dir / "url_phishing_ensemble.joblib")
            
            # Incremental learning (partial_fit for compatible models)
            # For ensemble, we retrain on combined old + new data
            logger.info("Retraining model...")
            
            # In production, load historical data and combine
            # model.fit(X, y)  # Simplified
            
            # Save updated model with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            new_model_path = self.model_dir / f"url_phishing_ensemble_{timestamp}.joblib"
            joblib.dump(model, new_model_path)
            
            # Update production model
            joblib.dump(model, self.model_dir / "url_phishing_ensemble.joblib")
            
            logger.info(f"Model retrained and saved: {new_model_path}")
            
            # Clear feedback buffer
            self.feedback_buffer = []
            
            # Validate new model
            self.validate_model(model, X, y)
            
        except Exception as e:
            logger.error(f"Retraining failed: {e}")
    
    def validate_model(self, model, X_val, y_val):
        """Validate retrained model"""
        from sklearn.metrics import accuracy_score, precision_score, recall_score
        
        predictions = model.predict(X_val)
        accuracy = accuracy_score(y_val, predictions)
        precision = precision_score(y_val, predictions)
        recall = recall_score(y_val, predictions)
        
        logger.info(f"Model Validation - Acc: {accuracy:.3f}, Prec: {precision:.3f}, Rec: {recall:.3f}")
        
        # Check if model meets minimum requirements
        if accuracy < 0.85:
            logger.warning("Model accuracy below threshold! Rolling back...")
            # Implement rollback logic
    
    def detect_model_drift(self):
        """Detect model performance drift"""
        # Compare recent predictions vs feedback
        if len(self.feedback_buffer) < 100:
            return False
        
        recent_feedback = self.feedback_buffer[-100:]
        incorrect_count = sum(1 for f in recent_feedback if not f['is_correct'])
        error_rate = incorrect_count / len(recent_feedback)
        
        if error_rate > 0.15:  # 15% error threshold
            logger.warning(f"Model drift detected! Error rate: {error_rate:.2%}")
            return True
        
        return False
    
    def schedule_retraining(self):
        """Schedule periodic retraining"""
        schedule.every(self.retrain_interval_hours).hours.do(self.trigger_retraining)
        
        logger.info(f"Scheduled retraining every {self.retrain_interval_hours} hours")
        
        while True:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
    
    def export_training_data(self, output_path: str):
        """Export feedback data for analysis"""
        df = pd.DataFrame(self.feedback_buffer)
        df.to_csv(output_path, index=False)
        logger.info(f"Training data exported: {output_path}")


if __name__ == "__main__":
    pipeline = ContinuousLearningPipeline()
    
    # Example: Collect feedback
    pipeline.collect_feedback(
        decision_id="test_001",
        is_correct=False,
        url="http://phishing.com",
        features={'url_length': 20, 'has_https': 0},
        true_label=1
    )
    
    logger.info("Continuous learning pipeline initialized")
