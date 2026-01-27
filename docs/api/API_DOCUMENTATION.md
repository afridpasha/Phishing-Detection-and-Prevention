# Phishing Detection API Documentation

## Base URL
```
http://localhost:8000/api/v1
```

## Authentication
Production uses JWT tokens:
```
Authorization: Bearer <token>
```

## Endpoints

### 1. Health Check
**GET** `/health`

Response:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00",
  "version": "1.0.0",
  "models_loaded": true
}
```

### 2. Analyze Email
**POST** `/analyze/email`

Request:
```json
{
  "subject": "URGENT: Verify your account",
  "body": "Click here to verify...",
  "sender": "security@suspicious.com"
}
```

Response:
```json
{
  "final_score": 0.85,
  "risk_level": "malicious",
  "action": "block",
  "confidence": 0.92,
  "latency_ms": 87.5
}
```

### 3. Analyze URL
**POST** `/analyze/url`

Request:
```json
{
  "url": "http://phishing-site.tk/login"
}
```

### 4. Get Statistics
**GET** `/statistics`

Response:
```json
{
  "total_requests": 15420,
  "average_latency_ms": 78.5
}
```

## Rate Limits
- 1000 requests/hour per IP
- 10000 requests/day per API key

## Response Times
- Target: <100ms
- Typical: 50-150ms
