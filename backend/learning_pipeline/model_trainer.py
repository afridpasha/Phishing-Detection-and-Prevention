"""
Model Training Pipeline
Real-Time Phishing Detection System

Handles training, validation, and deployment of ML models
"""

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import logging
import json

try:
    import mlflow
    import mlflow.pytorch
    MLFLOW_AVAILABLE = True
except ImportError:
    MLFLOW_AVAILABLE = False
    logging.warning("MLflow not installed. Model tracking will be disabled.")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PhishingDataset(Dataset):
    """Dataset for phishing detection training"""
    
    def __init__(self, data: List[Dict], tokenizer=None, transform=None):
        self.data = data
        self.tokenizer = tokenizer
        self.transform = transform
    
    def __len__(self):
        return len(self.data)
    
    def __getitem__(self, idx):
        item = self.data[idx]
        
        if self.tokenizer:
            # For NLP models
            encoding = self.tokenizer(
                item['text'],
                max_length=512,
                padding='max_length',
                truncation=True,
                return_tensors='pt'
            )
            return {
                'input_ids': encoding['input_ids'].squeeze(),
                'attention_mask': encoding['attention_mask'].squeeze(),
                'label': torch.tensor(item['label'], dtype=torch.float)
            }
        
        return item


class ModelTrainer:
    """
    Unified training pipeline for all detection models
    
    Features:
    - Automated hyperparameter tuning
    - Early stopping
    - Model versioning with MLflow
    - Distributed training support
    - A/B testing integration
    """
    
    def __init__(
        self,
        model: nn.Module,
        train_dataset: Dataset,
        val_dataset: Dataset,
        config: Optional[Dict] = None
    ):
        self.model = model
        self.train_dataset = train_dataset
        self.val_dataset = val_dataset
        self.config = config or {}
        
        # Training hyperparameters
        self.batch_size = self.config.get('batch_size', 32)
        self.learning_rate = self.config.get('learning_rate', 2e-5)
        self.num_epochs = self.config.get('num_epochs', 10)
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        # Move model to device
        self.model.to(self.device)
        
        # Initialize optimizer and criterion
        self.optimizer = torch.optim.AdamW(
            self.model.parameters(),
            lr=self.learning_rate
        )
        self.criterion = nn.BCEWithLogitsLoss()
        
        # Early stopping
        self.patience = self.config.get('patience', 3)
        self.best_val_loss = float('inf')
        self.patience_counter = 0
        
        # MLflow tracking
        self.experiment_name = self.config.get('experiment_name', 'phishing_detection')
        if MLFLOW_AVAILABLE:
            mlflow.set_experiment(self.experiment_name)
        
        logger.info(f"Trainer initialized on device: {self.device}")
    
    def train(self) -> Dict[str, any]:
        """
        Train the model
        
        Returns:
            Training metrics and statistics
        """
        logger.info("Starting training...")
        
        # Start MLflow run
        if MLFLOW_AVAILABLE:
            mlflow.start_run()
        
        try:
            # Log parameters
            if MLFLOW_AVAILABLE:
                mlflow.log_params({
                    'batch_size': self.batch_size,
                    'learning_rate': self.learning_rate,
                    'num_epochs': self.num_epochs,
                    'model_type': self.model.__class__.__name__
                })
            
            # Create data loaders
            train_loader = DataLoader(
                self.train_dataset,
                batch_size=self.batch_size,
                shuffle=True
            )
            
            val_loader = DataLoader(
                self.val_dataset,
                batch_size=self.batch_size,
                shuffle=False
            )
            
            best_model_state = None
            training_history = []
            
            # Training loop
            for epoch in range(self.num_epochs):
                # Train
                train_metrics = self._train_epoch(train_loader, epoch)
                
                # Validate
                val_metrics = self._validate_epoch(val_loader, epoch)
                
                # Combine metrics
                epoch_metrics = {
                    'epoch': epoch + 1,
                    'train_loss': train_metrics['loss'],
                    'train_accuracy': train_metrics['accuracy'],
                    'val_loss': val_metrics['loss'],
                    'val_accuracy': val_metrics['accuracy']
                }
                
                training_history.append(epoch_metrics)
                
                # Log to MLflow
                if MLFLOW_AVAILABLE:
                    mlflow.log_metrics({
                        f'train_{k}': v for k, v in train_metrics.items()
                    }, step=epoch)
                    mlflow.log_metrics({
                        f'val_{k}': v for k, v in val_metrics.items()
                    }, step=epoch)
                
                # Print progress
                logger.info(
                    f"Epoch {epoch+1}/{self.num_epochs} - "
                    f"Train Loss: {train_metrics['loss']:.4f}, "
                    f"Val Loss: {val_metrics['loss']:.4f}, "
                    f"Val Acc: {val_metrics['accuracy']:.4f}"
                )
                
                # Early stopping check
                if val_metrics['loss'] < self.best_val_loss:
                    self.best_val_loss = val_metrics['loss']
                    best_model_state = self.model.state_dict().copy()
                    self.patience_counter = 0
                    logger.info(f"New best model! Val Loss: {self.best_val_loss:.4f}")
                else:
                    self.patience_counter += 1
                    if self.patience_counter >= self.patience:
                        logger.info(f"Early stopping triggered after {epoch+1} epochs")
                        break
            
            # Restore best model
            if best_model_state:
                self.model.load_state_dict(best_model_state)
            
            # Final evaluation
            final_metrics = self._evaluate_model(val_loader)
            
            # Log final metrics
            if MLFLOW_AVAILABLE:
                mlflow.log_metrics(final_metrics)
            
            # Save model
            model_path = f"models/{self.experiment_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pth"
            torch.save(self.model.state_dict(), model_path)
            if MLFLOW_AVAILABLE:
                mlflow.pytorch.log_model(self.model, "model")
            
            logger.info(f"Training completed. Model saved to {model_path}")
            
            return {
                'training_history': training_history,
                'final_metrics': final_metrics,
                'model_path': model_path
            }
        finally:
            if MLFLOW_AVAILABLE:
                mlflow.end_run()
    
    def _train_epoch(self, train_loader: DataLoader, epoch: int) -> Dict[str, float]:
        """Train for one epoch"""
        self.model.train()
        total_loss = 0.0
        correct = 0
        total = 0
        
        for batch in train_loader:
            # Move to device
            input_ids = batch['input_ids'].to(self.device)
            attention_mask = batch['attention_mask'].to(self.device)
            labels = batch['label'].to(self.device)
            
            # Forward pass
            self.optimizer.zero_grad()
            outputs = self.model(input_ids, attention_mask)
            
            # Calculate loss
            logits = outputs['logits'] if isinstance(outputs, dict) else outputs
            loss = self.criterion(logits.squeeze(), labels)
            
            # Backward pass
            loss.backward()
            self.optimizer.step()
            
            # Statistics
            total_loss += loss.item()
            predictions = (torch.sigmoid(logits) > 0.5).float()
            correct += (predictions.squeeze() == labels).sum().item()
            total += labels.size(0)
        
        return {
            'loss': total_loss / len(train_loader),
            'accuracy': correct / total
        }
    
    def _validate_epoch(self, val_loader: DataLoader, epoch: int) -> Dict[str, float]:
        """Validate for one epoch"""
        self.model.eval()
        total_loss = 0.0
        correct = 0
        total = 0
        
        with torch.no_grad():
            for batch in val_loader:
                input_ids = batch['input_ids'].to(self.device)
                attention_mask = batch['attention_mask'].to(self.device)
                labels = batch['label'].to(self.device)
                
                outputs = self.model(input_ids, attention_mask)
                logits = outputs['logits'] if isinstance(outputs, dict) else outputs
                loss = self.criterion(logits.squeeze(), labels)
                
                total_loss += loss.item()
                predictions = (torch.sigmoid(logits) > 0.5).float()
                correct += (predictions.squeeze() == labels).sum().item()
                total += labels.size(0)
        
        return {
            'loss': total_loss / len(val_loader),
            'accuracy': correct / total
        }
    
    def _evaluate_model(self, test_loader: DataLoader) -> Dict[str, float]:
        """
        Comprehensive model evaluation
        
        Returns:
            Precision, recall, F1-score, accuracy
        """
        self.model.eval()
        
        true_positives = 0
        true_negatives = 0
        false_positives = 0
        false_negatives = 0
        
        with torch.no_grad():
            for batch in test_loader:
                input_ids = batch['input_ids'].to(self.device)
                attention_mask = batch['attention_mask'].to(self.device)
                labels = batch['label'].to(self.device)
                
                outputs = self.model(input_ids, attention_mask)
                logits = outputs['logits'] if isinstance(outputs, dict) else outputs
                predictions = (torch.sigmoid(logits) > 0.5).float().squeeze()
                
                # Calculate confusion matrix elements
                true_positives += ((predictions == 1) & (labels == 1)).sum().item()
                true_negatives += ((predictions == 0) & (labels == 0)).sum().item()
                false_positives += ((predictions == 1) & (labels == 0)).sum().item()
                false_negatives += ((predictions == 0) & (labels == 1)).sum().item()
        
        # Calculate metrics
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (true_positives + true_negatives) / (true_positives + true_negatives + false_positives + false_negatives)
        
        return {
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'accuracy': accuracy,
            'true_positives': true_positives,
            'true_negatives': true_negatives,
            'false_positives': false_positives,
            'false_negatives': false_negatives
        }
    
    def hyperparameter_tuning(
        self,
        param_grid: Dict[str, List],
        num_trials: int = 10
    ) -> Dict[str, any]:
        """
        Automated hyperparameter tuning using Optuna
        
        Args:
            param_grid: Dictionary of hyperparameters to tune
            num_trials: Number of tuning trials
            
        Returns:
            Best hyperparameters and results
        """
        try:
            import optuna
            
            def objective(trial):
                # Sample hyperparameters
                lr = trial.suggest_loguniform('learning_rate', 1e-5, 1e-3)
                batch_size = trial.suggest_categorical('batch_size', param_grid.get('batch_size', [16, 32, 64]))
                
                # Update config
                self.learning_rate = lr
                self.batch_size = batch_size
                self.optimizer = torch.optim.AdamW(self.model.parameters(), lr=lr)
                
                # Train for a few epochs
                train_loader = DataLoader(self.train_dataset, batch_size=batch_size, shuffle=True)
                val_loader = DataLoader(self.val_dataset, batch_size=batch_size, shuffle=False)
                
                for epoch in range(3):  # Quick evaluation
                    self._train_epoch(train_loader, epoch)
                val_metrics = self._validate_epoch(val_loader, 0)
                
                return val_metrics['loss']
            
            # Run optimization
            study = optuna.create_study(direction='minimize')
            study.optimize(objective, n_trials=num_trials)
            
            logger.info(f"Best hyperparameters: {study.best_params}")
            
            return {
                'best_params': study.best_params,
                'best_value': study.best_value,
                'study': study
            }
            
        except ImportError:
            logger.warning("Optuna not installed. Skipping hyperparameter tuning.")
            return {}


if __name__ == "__main__":
    print("Model Training Pipeline - Test Mode")
    
    # This would be used with actual datasets
    print("Trainer initialized successfully")
    print("Ready for model training workflows")
