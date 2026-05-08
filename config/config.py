"""
Phishing Shield 2.0 - Configuration
Centralized configuration for all modules
"""

import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).resolve().parent

# Model directories
MODELS_DIR = BASE_DIR / 'models'
URL_MODELS_DIR = MODELS_DIR / 'url'
SMS_MODELS_DIR = MODELS_DIR / 'sms'
EMAIL_MODELS_DIR = MODELS_DIR / 'email'
IMAGE_MODELS_DIR = MODELS_DIR / 'image'

# Upload configuration
UPLOAD_FOLDER = BASE_DIR / 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'svg'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

# Flask configuration
FLASK_CONFIG = {
    'DEBUG': False,
    'HOST': '0.0.0.0',
    'PORT': 5000,
    'THREADED': True
}

# Model weights (for advanced detectors)
MALCONV2_WEIGHTS_PATH = ""
BYTEFORMER_WEIGHTS_PATH = ""
EMBER_LGB_PATH = ""
VISUAL_MAL_WEIGHTS_PATH = ""
API_TRANSFORMER_PATH = ""
VIRUSTOTAL_API_KEY = ""

# Logging configuration
LOGGING_CONFIG = {
    'level': 'INFO',
    'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
}

# Create necessary directories
def init_directories():
    """Create all necessary directories"""
    UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
    for model_dir in [URL_MODELS_DIR, SMS_MODELS_DIR, EMAIL_MODELS_DIR, IMAGE_MODELS_DIR]:
        model_dir.mkdir(parents=True, exist_ok=True)
