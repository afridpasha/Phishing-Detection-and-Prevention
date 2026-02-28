# Phishing Shield 2.0 - Quick Start Guide

## Prerequisites
- Python 3.11+
- Docker & Docker Compose
- 16GB RAM minimum
- Windows/Linux/macOS

## Installation (5 Minutes)

### Step 1: Setup Environment
```bash
cd phishing_shield_2
cp .env.example .env
```

Edit `.env` and set passwords:
```
POSTGRES_PASSWORD=your_secure_password
REDIS_PASSWORD=your_secure_password
NEO4J_PASSWORD=your_secure_password
MINIO_SECRET_KEY=your_secure_password
JWT_SECRET=your_64_character_random_string
```

### Step 2: Install Python Dependencies
```bash
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

### Step 3: Start Infrastructure
```bash
cd infrastructure/docker
docker-compose up -d
```

Wait 30 seconds for all services to start.

### Step 4: Run API Server
```bash
cd ../..
python run_api.py
```

## Test the API

### Health Check
```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "healthy",
  "version": "2.0.0",
  "models_loaded": true
}
```

### API Documentation
Open browser: http://localhost:8000/docs

### Test URL Analysis (No Auth Required for /health)
```bash
curl -X POST http://localhost:8000/api/v2/analyze/url \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer test_token" \
  -d '{
    "url": "https://google.com",
    "follow_redirects": true,
    "context": "web"
  }'
```

Note: Authentication is enabled. For testing, you'll need to:
1. Generate a JWT token, or
2. Temporarily disable auth in `backend/api_gateway/main.py`

## Running Tests

```bash
# All tests
pytest tests/ -v

# Unit tests only
pytest tests/unit/ -v

# Specific test
pytest tests/unit/test_url_preprocessor.py -v
```

## Training Models

### Train URLNet
```bash
# First, prepare dataset: datasets/url/combined_urls.csv
# Format: url,label (where label is 0=benign, 1=phishing)

python model_training/train_urlnet.py
```

### Train All Models
```bash
python model_training/train_all_models.py
```

## Infrastructure Services

After `docker-compose up -d`:

- **PostgreSQL**: localhost:5432
- **Redis**: localhost:6379
- **Neo4j Browser**: http://localhost:7474
- **MinIO Console**: http://localhost:9001
- **Elasticsearch**: http://localhost:9200
- **Kafka**: localhost:9092
- **MLflow**: http://localhost:5000

## Stopping Services

```bash
cd infrastructure/docker
docker-compose down
```

## Troubleshooting

### Port Already in Use
```bash
# Check what's using port 8000
netstat -ano | findstr :8000  # Windows
lsof -i :8000                 # Linux/Mac

# Kill the process or change API_PORT in .env
```

### Models Not Loading
- Models will show as "not loaded" until training is complete
- API will still work with placeholder scores
- Check `models/` directory for trained model files

### Docker Services Not Starting
```bash
# Check logs
docker-compose logs postgres
docker-compose logs redis

# Restart specific service
docker-compose restart postgres
```

### Import Errors
```bash
# Ensure you're in the project root
cd phishing_shield_2

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

## Development Workflow

1. **Make changes** to code
2. **Run tests**: `pytest tests/unit/ -v`
3. **Restart API**: `Ctrl+C` then `python run_api.py`
4. **Test endpoint**: Use Swagger UI at http://localhost:8000/docs

## Production Deployment

See `infrastructure/kubernetes/` for production deployment manifests.

```bash
# Deploy to Kubernetes
kubectl apply -f infrastructure/kubernetes/

# Check status
kubectl get pods -n phishing-shield
```

## Getting Help

- Check `README.md` for full documentation
- Check `IMPLEMENTATION_SUMMARY.md` for architecture details
- Review API docs at http://localhost:8000/docs
- Check logs: `docker-compose logs -f api-gateway`

## Next Steps

1. ✅ API is running
2. ⏳ Collect training datasets
3. ⏳ Train models
4. ⏳ Configure threat intelligence API keys
5. ⏳ Deploy to production

---
**You're ready to start developing!** 🚀
