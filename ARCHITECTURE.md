# PHISHING SHIELD 2.0 - SYSTEM ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PHISHING SHIELD 2.0 ARCHITECTURE                    │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLIENT LAYER                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│  Browser Extension  │  Mobile App  │  Web Dashboard  │  API Clients         │
│  (Edge Inference)   │  (TFLite)    │  (React)        │  (REST/gRPC)         │
└──────────────┬──────────────────────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           API GATEWAY (FastAPI)                              │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                      │
│  │ JWT Auth     │  │ Rate Limiter │  │ Logger       │  Middleware           │
│  └──────────────┘  └──────────────┘  └──────────────┘                      │
│                                                                               │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐             │
│  │ URL Router   │ SMS Router   │ Email Router │ Image Router │  Endpoints  │
│  └──────────────┴──────────────┴──────────────┴──────────────┘             │
└──────────────┬──────────────────────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DETECTION SERVICES LAYER                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  CATEGORY 1: URL PHISHING SERVICE                                    │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │  Preprocessor → Feature Extractor (87 features)                      │   │
│  │  ├─ URLNet (CNN+LSTM)          Score: 0.0-1.0                        │   │
│  │  ├─ DeBERTa-v3                 Score: 0.0-1.0                        │   │
│  │  ├─ XGBoost + SHAP             Score: 0.0-1.0 + Top-5 Features       │   │
│  │  └─ Temporal Graph Transformer Score: 0.0-1.0                        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  CATEGORY 2: SMS/SMISHING SERVICE                                    │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │  ├─ SecureBERT                 Score: 0.0-1.0                        │   │
│  │  ├─ mDeBERTa-v3 (Multilingual) Score: 0.0-1.0                        │   │
│  │  ├─ SetFit (Few-shot)          Score: 0.0-1.0                        │   │
│  │  └─ spaCy NER (Brand Detection)                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  CATEGORY 3: EMAIL PHISHING SERVICE                                  │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │  MIME Parser → Header Analyzer (SPF/DKIM/DMARC)                      │   │
│  │  ├─ PhishBERT (RoBERTa)        Score: 0.0-1.0                        │   │
│  │  ├─ AI-Text Detector           Score: 0.0-1.0                        │   │
│  │  ├─ GAT (BEC Detection)        Score: 0.0-1.0                        │   │
│  │  ├─ CodeBERT (HTML/JS)         Score: 0.0-1.0                        │   │
│  │  └─ CAPE Sandbox (Attachments) Malware: Yes/No                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  CATEGORY 4: IMAGE/QR/RAT SERVICE ⭐ MOST ADVANCED                   │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │  RAT/STEGANOGRAPHY PIPELINE:                                         │   │
│  │  ├─ LSB Analyzer (Chi-square + RS)      ✅ OPERATIONAL               │   │
│  │  ├─ DCT/DWT Frequency Analysis          ✅ OPERATIONAL               │   │
│  │  ├─ Polyglot Detector (JPEG+ZIP/PNG+PE) ✅ OPERATIONAL               │   │
│  │  ├─ SVG XSS Detector                    ✅ OPERATIONAL               │   │
│  │  ├─ EXIF Forensics + YARA               ✅ OPERATIONAL               │   │
│  │  ├─ Entropy Analyzer                    ✅ OPERATIONAL               │   │
│  │  └─ Steganography CNN                   Score: 0.0-1.0               │   │
│  │                                                                       │   │
│  │  QR PIPELINE:                                                         │   │
│  │  ├─ YOLOv8 QR Detector                  Bounding boxes               │   │
│  │  └─ ZXing Decoder → URL Analysis        Decoded content              │   │
│  │                                                                       │   │
│  │  VISUAL PIPELINE:                                                     │   │
│  │  ├─ CLIP ViT-L/14 (Brand Detection)     Similarity: 0.0-1.0         │   │
│  │  ├─ LayoutLMv3 (Fake Login Pages)       Score: 0.0-1.0              │   │
│  │  ├─ EfficientNetV2 (Visual Similarity)  Score: 0.0-1.0              │   │
│  │  ├─ TrOCR (Text Extraction)             Extracted text               │   │
│  │  └─ pHash + SSIM (Brand Comparison)     Similarity scores            │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
└──────────────┬──────────────────────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      ENSEMBLE & DECISION LAYER                               │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  LightGBM Meta-Learner                                               │   │
│  │  ├─ Input: All model scores + metadata                              │   │
│  │  ├─ Output: Final score (0.0-1.0)                                   │   │
│  │  └─ SHAP Explainer → Top-5 contributing features                    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Decision Maker                                                      │   │
│  │  ├─ Score < 0.35  → ALLOW  (safe/low)                               │   │
│  │  ├─ Score 0.55-0.70 → WARN   (medium)                               │   │
│  │  ├─ Score > 0.70  → BLOCK  (high/critical)                          │   │
│  │  └─ RAT detected  → EMERGENCY_BLOCK                                 │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└──────────────┬──────────────────────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      SUPPORTING SERVICES LAYER                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐          │
│  │ Threat Intel     │  │ Continuous       │  │ Kafka Streaming  │          │
│  │ ├─ VirusTotal    │  │ Learning         │  │ ├─ url.analysis  │          │
│  │ ├─ MISP          │  │ ├─ River ML      │  │ ├─ sms.analysis  │          │
│  │ ├─ OTX           │  │ ├─ Evidently     │  │ ├─ email.analysis│          │
│  │ ├─ URLhaus       │  │ ├─ MLflow        │  │ └─ img.analysis  │          │
│  │ └─ PhishTank     │  │ └─ Feedback Loop │  │                  │          │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘          │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          DATA STORAGE LAYER                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ PostgreSQL   │  │ Neo4j        │  │ Redis        │  │ MinIO        │   │
│  │ (TimescaleDB)│  │ (Graph DB)   │  │ (Cache)      │  │ (Objects)    │   │
│  │              │  │              │  │              │  │              │   │
│  │ • Detection  │  │ • Domain     │  │ • IOC Cache  │  │ • Screenshots│   │
│  │   Results    │  │   Graph      │  │ • Rate Limit │  │ • Models     │   │
│  │ • IOCs       │  │ • Email      │  │ • Sessions   │  │ • Artifacts  │   │
│  │ • Metrics    │  │   Behavior   │  │              │  │              │   │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘   │
│                                                                               │
│  ┌──────────────┐  ┌──────────────┐                                         │
│  │ Elasticsearch│  │ MongoDB      │                                         │
│  │ (Search)     │  │ (Audit Logs) │                                         │
│  └──────────────┘  └──────────────┘                                         │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                          DEPLOYMENT LAYER                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Kubernetes Cluster                                                  │   │
│  │  ├─ API Gateway Pods (HPA: 2-20 replicas)                           │   │
│  │  ├─ URL Service Pods (HPA: 2-10 replicas)                           │   │
│  │  ├─ SMS Service Pods (HPA: 2-10 replicas)                           │   │
│  │  ├─ Email Service Pods (HPA: 2-10 replicas)                         │   │
│  │  ├─ Image Service Pods (HPA: 2-10 replicas)                         │   │
│  │  ├─ Ensemble Service Pods (HPA: 2-10 replicas)                      │   │
│  │  └─ Ingress Controller (Nginx)                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                       MONITORING & OBSERVABILITY                             │
├─────────────────────────────────────────────────────────────────────────────┤
│  Prometheus → Grafana → Alerts                                              │
│  Structured Logging (JSON) → Elasticsearch → Kibana                         │
│  Distributed Tracing → Jaeger                                               │
│  Model Drift Detection → Evidently → Alerts                                 │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                            DATA FLOW EXAMPLE                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  1. User clicks suspicious link                                              │
│  2. Browser extension intercepts (Edge inference: <30ms)                     │
│  3. If uncertain → Send to cloud API                                         │
│  4. API Gateway → JWT auth → Rate limit → Route to URL Service              │
│  5. URL Service:                                                             │
│     ├─ Preprocess (normalize, detect homoglyphs)                            │
│     ├─ Extract 87 features                                                   │
│     ├─ Run 4 models in parallel                                              │
│     └─ Query threat intel                                                    │
│  6. Ensemble → Aggregate scores → SHAP explanation                           │
│  7. Decision Maker → Risk level + Action                                     │
│  8. Response → Browser extension                                             │
│  9. If BLOCK → Show warning page                                             │
│  10. Log to PostgreSQL + Kafka → Continuous learning                         │
│                                                                               │
│  Total latency: <80ms (P99)                                                  │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                         PERFORMANCE CHARACTERISTICS                          │
├─────────────────────────────────────────────────────────────────────────────┤
│  • Throughput: >15,000 requests/second (horizontally scaled)                │
│  • Latency (P99): <80ms (URL/SMS/Email), <200ms (Image)                     │
│  • Availability: >99.95% (multi-zone Kubernetes)                             │
│  • True Positive Rate: >97.5% (target)                                       │
│  • False Positive Rate: <0.8% (target)                                       │
│  • Edge Model Size: <15MB (URLNet + DistilBERT ONNX)                        │
│  • Model Update Latency: <5 seconds (River ML online learning)              │
└─────────────────────────────────────────────────────────────────────────────┘

Legend:
  ✅ = Fully Operational
  ⭐ = Advanced/Unique Feature
  → = Data Flow
  ├─ = Component
  └─ = Sub-component
```
