from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # API
    API_HOST: str = '0.0.0.0'
    API_PORT: int = 8000
    API_ENV: str = 'development'
    LOG_LEVEL: str = 'info'
    ENABLE_GPU: bool = False
    WORKERS: int = 4

    # Security
    JWT_SECRET: str
    JWT_ALGORITHM: str = 'HS256'
    JWT_EXPIRE_MINUTES: int = 15
    API_KEY_HEADER: str = 'X-API-Key'
    ENTERPRISE_API_KEYS: str = ''

    # PostgreSQL
    POSTGRES_HOST: str = 'localhost'
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = 'phishing_shield'
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str = 'phishing_shield_db'
    POSTGRES_POOL_SIZE: int = 20

    # Neo4j
    NEO4J_URI: str = 'bolt://localhost:7687'
    NEO4J_USER: str = 'neo4j'
    NEO4J_PASSWORD: str

    # Redis
    REDIS_HOST: str = 'localhost'
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: str
    REDIS_IOC_TTL_SECONDS: int = 3600
    REDIS_RATE_LIMIT_PER_MIN: int = 100

    # Kafka
    KAFKA_BOOTSTRAP_SERVERS: str = 'localhost:9092'
    KAFKA_TOPIC_URL: str = 'url.analysis'
    KAFKA_TOPIC_SMS: str = 'sms.analysis'
    KAFKA_TOPIC_EMAIL: str = 'email.analysis'
    KAFKA_TOPIC_IMAGE: str = 'img.analysis'
    KAFKA_CONSUMER_GROUP: str = 'phishing-shield-consumers'

    # MinIO
    MINIO_ENDPOINT: str = 'localhost:9000'
    MINIO_ACCESS_KEY: str = 'minioadmin'
    MINIO_SECRET_KEY: str
    MINIO_BUCKET_SCREENSHOTS: str = 'screenshots'
    MINIO_BUCKET_MODELS: str = 'model-artifacts'

    # Elasticsearch
    ELASTICSEARCH_HOST: str = 'localhost'
    ELASTICSEARCH_PORT: int = 9200

    # Threat Intelligence
    VIRUSTOTAL_API_KEY: Optional[str] = None
    MISP_URL: Optional[str] = None
    MISP_API_KEY: Optional[str] = None
    OTX_API_KEY: Optional[str] = None

    # CAPE Sandbox
    CAPE_URL: str = 'http://localhost:8090'
    CAPE_API_KEY: Optional[str] = None

    # MLflow
    MLFLOW_TRACKING_URI: str = 'http://localhost:5000'

    # Model Paths
    MODELS_BASE_PATH: str = './models'
    EDGE_MODELS_PATH: str = './models/edge'

    class Config:
        env_file = '.env'
        case_sensitive = True

    @property
    def enterprise_keys(self) -> set[str]:
        return {k.strip() for k in self.ENTERPRISE_API_KEYS.split(',') if k.strip()}


settings = Settings()
