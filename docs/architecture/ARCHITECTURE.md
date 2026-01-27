# System Architecture

## Overview

Multi-layer AI/ML-based phishing detection system with real-time analysis capabilities.

## Architecture Layers

### 1. Edge Layer
- Browser extensions (Chrome, Firefox, Edge)
- Email plugins (Outlook, Gmail)
- Mobile SDKs (iOS, Android)
- Local quick check (<50ms)

### 2. API Gateway
- FastAPI application
- Authentication (OAuth 2.0, JWT)
- Rate limiting
- Load balancing
- Request routing

### 3. Detection Engine
- **NLP Model**: BERT-based text analysis
- **CNN Model**: ResNet-50 visual analysis
- **GNN Model**: Graph neural network for domain relationships
- **URL Analyzer**: Pattern matching and ML-based detection
- **Ensemble Engine**: Weighted voting system

### 4. Analysis Layer
- Domain profiler
- WHOIS lookup
- DNS analysis
- SSL certificate validation
- Geolocation

### 5. Intelligence Layer
- Threat feed aggregation (MISP, OTX, VirusTotal)
- IOC database
- Blocklist management
- Reputation scoring

### 6. Learning Pipeline
- Model training
- Continuous learning
- Feedback integration
- Model versioning
- A/B testing

### 7. Storage Layer
- PostgreSQL (relational data)
- Redis (caching)
- Neo4j (graph data)
- S3 (model storage)

## Data Flow

```
User Request → Edge Layer → API Gateway → Detection Engine
                                              ↓
                                    Ensemble Decision
                                    ↙     ↓     ↘
                                NLP   CNN   GNN   URL
                                    ↓
                            Analysis Layer
                                    ↓
                        Intelligence Layer
                                    ↓
                            Final Decision
                                    ↓
                            User Response
                                    ↓
                            Feedback Loop
```

## Model Weights

- NLP: 0.35
- CNN: 0.25
- GNN: 0.20
- URL: 0.15
- Threat Intel: 0.05

## Decision Thresholds

- Safe: Score < 0.5
- Suspicious: Score 0.5-0.8
- Malicious: Score > 0.8

## Performance Targets

- Detection Latency: <100ms
- Edge Inference: <50ms
- Throughput: >10K req/sec
- Availability: >99.9%
- True Positive Rate: >95%
- False Positive Rate: <2%

## Security

- Encryption: AES-256 at rest, TLS 1.3 in transit
- Authentication: OAuth 2.0, JWT
- Compliance: GDPR, CCPA, SOC 2, ISO 27001

## Scalability

- Horizontal scaling with Kubernetes
- Auto-scaling based on CPU/memory
- Load balancing across replicas
- Caching with Redis
- CDN for static assets
