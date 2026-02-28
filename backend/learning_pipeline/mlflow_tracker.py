import mlflow
from ..api_gateway.config import settings
from typing import Dict

mlflow.set_tracking_uri(settings.MLFLOW_TRACKING_URI)

class MLflowTracker:
    def log_training_run(self, model_name: str, params: Dict, metrics: Dict, model_path: str):
        """Log training run to MLflow"""
        with mlflow.start_run(run_name=f'{model_name}_training'):
            mlflow.log_params(params)
            mlflow.log_metrics(metrics)
            mlflow.log_artifact(model_path)
            mlflow.set_tag('model_name', model_name)
            run_id = mlflow.active_run().info.run_id
        return run_id
    
    def log_inference_metrics(self, model_name: str, metrics: Dict):
        """Log inference metrics"""
        with mlflow.start_run(run_name=f'{model_name}_inference'):
            mlflow.log_metrics(metrics)
    
    def register_production_model(self, run_id: str, model_name: str):
        """Register model for production"""
        client = mlflow.tracking.MlflowClient()
        model_uri = f'runs:/{run_id}/model'
        try:
            client.create_registered_model(model_name)
        except:
            pass
        client.create_model_version(model_name, model_uri, run_id)

# Global instance
mlflow_tracker = MLflowTracker()
