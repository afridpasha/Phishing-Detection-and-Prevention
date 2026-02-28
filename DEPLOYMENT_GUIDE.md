# Phishing Shield 2.0 - Complete Deployment Guide

## 🚀 Production Deployment Steps

### Prerequisites
- Kubernetes cluster (1.29+)
- kubectl configured
- Docker registry access
- Domain name configured
- SSL certificates

### Step 1: Build Docker Images

```bash
# Build API Gateway
cd phishing_shield_2
docker build -t phishing-shield/api-gateway:2.0.0 -f infrastructure/docker/Dockerfile.api .

# Tag for registry
docker tag phishing-shield/api-gateway:2.0.0 your-registry.com/phishing-shield/api-gateway:2.0.0

# Push to registry
docker push your-registry.com/phishing-shield/api-gateway:2.0.0
```

### Step 2: Create Kubernetes Secrets

```bash
kubectl create namespace phishing-shield

kubectl create secret generic phishing-shield-secrets \
  --from-literal=POSTGRES_PASSWORD=your_secure_password \
  --from-literal=REDIS_PASSWORD=your_secure_password \
  --from-literal=NEO4J_PASSWORD=your_secure_password \
  --from-literal=JWT_SECRET=your_64_char_random_string \
  --from-literal=VIRUSTOTAL_API_KEY=your_vt_key \
  -n phishing-shield
```

### Step 3: Deploy Infrastructure Services

```bash
# Deploy PostgreSQL
kubectl apply -f infrastructure/kubernetes/postgres-deployment.yaml

# Deploy Redis
kubectl apply -f infrastructure/kubernetes/redis-deployment.yaml

# Deploy Neo4j
kubectl apply -f infrastructure/kubernetes/neo4j-deployment.yaml

# Deploy Kafka
kubectl apply -f infrastructure/kubernetes/kafka-deployment.yaml

# Wait for services to be ready
kubectl wait --for=condition=ready pod -l app=postgres -n phishing-shield --timeout=300s
```

### Step 4: Initialize Database

```bash
# Copy SQL script to postgres pod
kubectl cp infrastructure/database_init.sql phishing-shield/postgres-pod:/tmp/

# Execute initialization
kubectl exec -it postgres-pod -n phishing-shield -- psql -U phishing_shield -d phishing_shield_db -f /tmp/database_init.sql
```

### Step 5: Deploy Application Services

```bash
# Deploy API Gateway
kubectl apply -f infrastructure/kubernetes/api-gateway-deployment.yaml

# Deploy URL Service
kubectl apply -f infrastructure/kubernetes/url-service-deployment.yaml

# Deploy SMS Service
kubectl apply -f infrastructure/kubernetes/sms-service-deployment.yaml

# Deploy Email Service
kubectl apply -f infrastructure/kubernetes/email-service-deployment.yaml

# Deploy Image Service
kubectl apply -f infrastructure/kubernetes/image-service-deployment.yaml

# Deploy Ensemble Service
kubectl apply -f infrastructure/kubernetes/ensemble-service-deployment.yaml
```

### Step 6: Configure Autoscaling

```bash
kubectl apply -f infrastructure/kubernetes/hpa.yaml
```

### Step 7: Configure Ingress

```bash
# Install nginx ingress controller (if not already installed)
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.8.1/deploy/static/provider/cloud/deploy.yaml

# Apply ingress configuration
kubectl apply -f infrastructure/kubernetes/ingress.yaml
```

### Step 8: Verify Deployment

```bash
# Check all pods are running
kubectl get pods -n phishing-shield

# Check services
kubectl get svc -n phishing-shield

# Check ingress
kubectl get ingress -n phishing-shield

# Test health endpoint
curl https://api.phishingshield.com/health
```

### Step 9: Monitor Deployment

```bash
# View logs
kubectl logs -f deployment/api-gateway -n phishing-shield

# Check metrics
kubectl top pods -n phishing-shield

# Check HPA status
kubectl get hpa -n phishing-shield
```

## 📊 Performance Tuning

### Horizontal Scaling
```bash
# Scale API Gateway
kubectl scale deployment api-gateway --replicas=10 -n phishing-shield

# Scale URL Service
kubectl scale deployment url-service --replicas=5 -n phishing-shield
```

### Resource Limits
Edit deployment YAML files to adjust:
- CPU requests/limits
- Memory requests/limits
- HPA min/max replicas

## 🔒 Security Hardening

1. **Enable Network Policies**
```bash
kubectl apply -f infrastructure/kubernetes/network-policies.yaml
```

2. **Enable Pod Security Policies**
```bash
kubectl apply -f infrastructure/kubernetes/pod-security-policies.yaml
```

3. **Configure RBAC**
```bash
kubectl apply -f infrastructure/kubernetes/rbac.yaml
```

4. **Enable TLS**
- Configure cert-manager
- Update ingress with TLS certificates

## 🔄 Rolling Updates

```bash
# Update API Gateway
kubectl set image deployment/api-gateway api-gateway=phishing-shield/api-gateway:2.0.1 -n phishing-shield

# Check rollout status
kubectl rollout status deployment/api-gateway -n phishing-shield

# Rollback if needed
kubectl rollout undo deployment/api-gateway -n phishing-shield
```

## 📈 Monitoring Setup

### Prometheus
```bash
kubectl apply -f infrastructure/kubernetes/prometheus-deployment.yaml
```

### Grafana
```bash
kubectl apply -f infrastructure/kubernetes/grafana-deployment.yaml
```

## 🧪 Load Testing

```bash
# Install locust
pip install locust

# Run load test
locust -f tests/load/locustfile.py --host=https://api.phishingshield.com
```

## 🔧 Troubleshooting

### Pod Not Starting
```bash
kubectl describe pod <pod-name> -n phishing-shield
kubectl logs <pod-name> -n phishing-shield
```

### Service Not Accessible
```bash
kubectl get endpoints -n phishing-shield
kubectl describe service <service-name> -n phishing-shield
```

### Database Connection Issues
```bash
kubectl exec -it <api-pod> -n phishing-shield -- env | grep POSTGRES
kubectl exec -it postgres-pod -n phishing-shield -- psql -U phishing_shield -c "SELECT 1"
```

## 📝 Maintenance

### Backup Database
```bash
kubectl exec postgres-pod -n phishing-shield -- pg_dump -U phishing_shield phishing_shield_db > backup.sql
```

### Update Models
```bash
# Copy new models to pods
kubectl cp models/ phishing-shield/api-gateway-pod:/app/models/

# Restart pods to load new models
kubectl rollout restart deployment/api-gateway -n phishing-shield
```

## ✅ Production Checklist

- [ ] All secrets configured
- [ ] Database initialized
- [ ] All pods running
- [ ] Health checks passing
- [ ] Ingress configured
- [ ] TLS certificates valid
- [ ] Monitoring enabled
- [ ] Backups configured
- [ ] Autoscaling tested
- [ ] Load testing completed
- [ ] Security scan passed
- [ ] Documentation updated

---

**Deployment Status**: Ready for Production
**Target Uptime**: 99.95%
**Support**: 24/7 monitoring enabled
