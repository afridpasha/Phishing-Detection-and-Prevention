# Deployment Guide

## Quick Start (Docker)

```bash
# Clone repository
git clone <repository-url>
cd phishing-detection-system

# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f api-gateway

# Stop services
docker-compose down
```

## Kubernetes Deployment

```bash
# Apply configurations
kubectl apply -f infrastructure/kubernetes/config.yaml
kubectl apply -f infrastructure/kubernetes/redis.yaml
kubectl apply -f infrastructure/kubernetes/deployment.yaml

# Check status
kubectl get pods
kubectl get services

# Scale deployment
kubectl scale deployment phishing-api --replicas=5

# View logs
kubectl logs -f deployment/phishing-api
```

## AWS Deployment (Terraform)

```bash
cd infrastructure/terraform

# Initialize
terraform init

# Plan
terraform plan -var="db_password=SECURE_PASSWORD"

# Apply
terraform apply -var="db_password=SECURE_PASSWORD"

# Get outputs
terraform output eks_cluster_endpoint
```

## Environment Variables

```bash
# API Configuration
API_URL=http://localhost:8000
LOG_LEVEL=info
ENABLE_GPU=false

# Database
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=phishing_user
POSTGRES_PASSWORD=secure_password
POSTGRES_DB=phishing_db

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# Threat Intelligence APIs
MISP_API_KEY=your_key
OTX_API_KEY=your_key
VT_API_KEY=your_key
```

## Production Checklist

- [ ] Change all default passwords
- [ ] Configure SSL/TLS certificates
- [ ] Set up monitoring and alerting
- [ ] Configure backup strategy
- [ ] Enable rate limiting
- [ ] Set up log aggregation
- [ ] Configure auto-scaling
- [ ] Run security audit
- [ ] Load testing
- [ ] Disaster recovery plan

## Monitoring

Access dashboards:
- Grafana: http://localhost:3000 (admin/admin123)
- Prometheus: http://localhost:9090
- API Docs: http://localhost:8000/docs

## Troubleshooting

### API not responding
```bash
docker-compose logs api-gateway
kubectl logs deployment/phishing-api
```

### Database connection issues
```bash
docker-compose exec postgres psql -U phishing_user -d phishing_db
```

### High latency
- Check model loading
- Verify Redis cache
- Review resource limits
