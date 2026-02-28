# Phishing Shield 2.0

Real-Time AI/ML-Based Phishing Detection & Prevention System

## Overview

Phishing Shield 2.0 is a production-grade, cloud-native microservices system that detects and prevents phishing attacks across 4 categories:

1. **URL Phishing** - Homoglyphs, typosquatting, zero-day domains
2. **SMS/Smishing** - Fake delivery SMS, OTP fraud, multilingual attacks
3. **Email Phishing** - BEC, spear phishing, AI-generated text, malicious attachments
4. **Image/QR/RAT** - QR phishing, steganography, RAT payloads, fake login pages

## Performance Targets

- **TPR**: > 97.5% across all categories
- **FPR**: < 0.8%
- **Latency**: < 80ms (URL/SMS/Email), < 200ms (Image)
- **Throughput**: > 15,000 req/s
- **Availability**: > 99.95%

## Quick Start

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- 16GB RAM minimum
- GPU optional (CUDA for faster inference)

### Installation

1. **Clone and setup**:
```bash
cd phishing_shield_2
cp .env.example .env
# Edit .env with your configuration
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

3. **Start infrastructure**:
```bash
cd infrastructure/docker
docker-compose up -d
```

4. **Run API server**:
```bash
python run_api.py
```

API will be available at: http://localhost:8000
API docs: http://localhost:8000/docs

## API Endpoints

### URL Analysis
```bash
POST /api/v2/analyze/url
{
  "url": "https://suspicious-site.com",
  "follow_redirects": true,
  "context": "email"
}
```

### SMS Analysis
```bash
POST /api/v2/analyze/sms
{
  "message": "Your package is held. Click: http://bit.ly/abc",
  "sender": "+1-555-0123"
}
```

### Email Analysis
```bash
POST /api/v2/analyze/email
{
  "subject": "Urgent: Verify your account",
  "body_text": "Click here to verify...",
  "sender_email": "security@bank.com"
}
```

### Image Analysis
```bash
POST /api/v2/analyze/image
Content-Type: multipart/form-data
image: <file>
context: "email_attachment"
```

## Architecture

### Models Used

**Category 1 - URL**:
- URLNet (CNN+LSTM)
- DeBERTa-v3
- XGBoost + SHAP
- Temporal Graph Transformer

**Category 2 - SMS**:
- SecureBERT
- mDeBERTa-v3
- SetFit

**Category 3 - Email**:
- PhishBERT (RoBERTa)
- AI-Text Detector
- GAT (BEC detection)
- CodeBERT

**Category 4 - Image**:
- YOLOv8 (QR detection)
- CLIP ViT-L/14
- LayoutLMv3
- EfficientNetV2
- Steganography CNN
- Chi-square + RS analysis
- EXIF forensics + YARA

**Ensemble**:
- LightGBM meta-learner
- SHAP explainability

## Training Models

To train all models:
```bash
python model_training/train_all_models.py
```

Individual model training:
```bash
python model_training/train_urlnet.py
python model_training/train_deberta_url.py
python model_training/train_phishbert_email.py
# ... etc
```

## Testing

Run all tests:
```bash
pytest tests/ --cov=backend --cov-report=html --cov-fail-under=85
```

Unit tests:
```bash
pytest tests/unit/ -v
```

Integration tests:
```bash
pytest tests/integration/ -v
```

Adversarial tests:
```bash
pytest tests/adversarial/ -v
```

## Deployment

### Docker Compose (Development)
```bash
cd infrastructure/docker
docker-compose up -d
```

### Kubernetes (Production)
```bash
kubectl apply -f infrastructure/kubernetes/
```

## Monitoring

- **Prometheus**: Metrics collection
- **Grafana**: Dashboards
- **MLflow**: Model tracking
- **Evidently**: Model drift detection

## Security

- JWT authentication on all endpoints
- Rate limiting (100 req/min default)
- API key validation
- TLS/SSL encryption
- Non-root Docker containers

## Continuous Learning

- **River ML**: Online learning updates
- **Evidently**: Drift monitoring every 6 hours
- **Feedback loop**: User corrections improve models
- **Auto-retraining**: Triggered when TPR < 92%

## Edge Deployment

Browser extension with on-device inference:
- URLNet ONNX (< 4MB)
- DistilBERT ONNX (< 7MB)
- < 30ms latency

## License

Confidential - Cyber Security Cell 2026

## Support

For issues and questions, contact the Cyber Security Cell team.
