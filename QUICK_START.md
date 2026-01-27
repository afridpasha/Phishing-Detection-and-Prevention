# Quick Reference Guide

## 🚀 Getting Started

### Prerequisites
- Python 3.9+
- Docker & Docker Compose
- Node.js 16+ (for admin dashboard)

### Installation
```bash
# 1. Clone and navigate
cd TBP

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Start infrastructure services
docker-compose up -d

# 4. Train models (if needed)
python model_training/train_all_models.py

# 5. Start API server
python run_api.py
```

## 📂 Project Structure

```
TBP/
├── backend/              # Core backend services
├── frontend/             # UI components
├── model_training/       # ML training scripts
├── models/               # Trained models
├── datasets/             # Training data
├── infrastructure/       # Deployment configs
├── tests/                # Test suites
├── docs/                 # Documentation
├── run_api.py           # 🎯 Main API launcher
├── run_tests.py         # 🧪 Test runner
└── requirements.txt     # Dependencies
```

## 🎯 Main Entry Points

### Start API Server
```bash
python run_api.py
```
- Starts FastAPI server on http://localhost:8000
- API docs: http://localhost:8000/docs
- Health check: http://localhost:8000/health

### Run Tests
```bash
python run_tests.py
```
- Runs unit tests
- Runs integration tests (if API is running)
- Code quality checks
- Security scans

### Train Models
```bash
# Train all models
python model_training/train_all_models.py

# Train specific model
python model_training/train_url_model.py
python model_training/train_nlp_model.py
python model_training/train_cnn_model.py
python model_training/train_gnn_model.py
```

## 🔌 API Endpoints

### Email Analysis
```bash
POST /api/v1/analyze/email
{
  "subject": "URGENT: Verify account",
  "body": "Click here...",
  "sender": "security@example.com"
}
```

### URL Analysis
```bash
POST /api/v1/analyze/url
{
  "url": "https://suspicious-site.com",
  "include_screenshot": false
}
```

### SMS Analysis
```bash
POST /api/v1/analyze/sms
{
  "message": "Your package is waiting...",
  "sender": "+1234567890"
}
```

### Statistics
```bash
GET /api/v1/statistics
```

## 🐳 Docker Commands

### Start All Services
```bash
docker-compose up -d
```

### Stop All Services
```bash
docker-compose down
```

### View Logs
```bash
docker-compose logs -f api-gateway
```

### Rebuild Containers
```bash
docker-compose up -d --build
```

## 🧪 Testing

### Unit Tests Only
```bash
pytest tests/unit/ -v
```

### Integration Tests Only
```bash
pytest tests/integration/ -v
```

### With Coverage
```bash
pytest tests/ --cov=backend --cov-report=html
```

## 🌐 Frontend

### Browser Extension
```bash
# Load in Chrome/Firefox
1. Open chrome://extensions/
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select: frontend/browser_extension/
```

### Admin Dashboard
```bash
cd frontend/admin_dashboard
npm install
npm start
# Opens on http://localhost:3000
```

## 📊 Services & Ports

| Service | Port | URL |
|---------|------|-----|
| API Gateway | 8000 | http://localhost:8000 |
| Admin Dashboard | 3000 | http://localhost:3000 |
| PostgreSQL | 5432 | localhost:5432 |
| Redis | 6379 | localhost:6379 |
| Neo4j Browser | 7474 | http://localhost:7474 |
| Neo4j Bolt | 7687 | bolt://localhost:7687 |

## 🔧 Configuration

### Environment Variables
Create `.env` file:
```env
API_URL=http://localhost:8000
LOG_LEVEL=info
ENABLE_GPU=false

POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=phishing_user
POSTGRES_PASSWORD=phishing_pass
POSTGRES_DB=phishing_db

REDIS_HOST=localhost
REDIS_PORT=6379

NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=phishing123
```

## 📝 Common Tasks

### Add New Detection Model
1. Create model in `backend/detection_engine/`
2. Add training script in `model_training/`
3. Update ensemble in `backend/detection_engine/ensemble.py`
4. Add tests in `tests/unit/`

### Update API Endpoint
1. Modify `backend/api_gateway/main.py`
2. Update Pydantic models
3. Add tests in `tests/integration/`
4. Update API docs

### Deploy to Production
1. Build Docker image: `docker build -t phishing-api .`
2. Push to registry: `docker push your-registry/phishing-api`
3. Apply K8s configs: `kubectl apply -f infrastructure/kubernetes/`
4. Or use Terraform: `cd infrastructure/terraform && terraform apply`

## 🐛 Troubleshooting

### API won't start
```bash
# Check if port 8000 is in use
netstat -ano | findstr :8000

# Check logs
python run_api.py
```

### Models not loading
```bash
# Retrain models
python model_training/train_all_models.py

# Check models directory
dir models\
```

### Database connection failed
```bash
# Restart services
docker-compose restart postgres redis neo4j

# Check service status
docker-compose ps
```

### Tests failing
```bash
# Ensure API is running for integration tests
python run_api.py

# Run in another terminal
python run_tests.py
```

## 📚 Documentation

- **API Docs**: `docs/api/API_DOCUMENTATION.md`
- **Architecture**: `docs/architecture/ARCHITECTURE.md`
- **Deployment**: `docs/deployment/DEPLOYMENT_GUIDE.md`
- **Cleanup Summary**: `CLEANUP_SUMMARY.md`

## 🔐 Security Notes

- Change default passwords in production
- Use environment variables for secrets
- Enable HTTPS/TLS in production
- Implement rate limiting
- Add authentication/authorization

## 📞 Support

For issues or questions:
1. Check documentation in `docs/`
2. Review `CLEANUP_SUMMARY.md`
3. Check API logs
4. Review test results

---

**Last Updated**: January 2026  
**Version**: 1.0  
**Status**: ✅ Production Ready
