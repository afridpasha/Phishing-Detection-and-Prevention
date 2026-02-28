-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- DETECTION RESULTS (hypertable for time-series queries)
CREATE TABLE IF NOT EXISTS detection_results (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id      UUID NOT NULL UNIQUE,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    input_type      VARCHAR(10) NOT NULL,
    final_score     FLOAT NOT NULL,
    risk_level      VARCHAR(10) NOT NULL,
    action          VARCHAR(20) NOT NULL,
    confidence      FLOAT NOT NULL,
    latency_ms      FLOAT NOT NULL,
    model_scores    JSONB,
    shap_values     JSONB,
    indicators      TEXT[],
    metadata        JSONB,
    is_correct      BOOLEAN,
    feedback_text   TEXT
);

SELECT create_hypertable('detection_results', 'timestamp', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_detection_input_type ON detection_results (input_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_detection_risk_level ON detection_results (risk_level, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_detection_action ON detection_results (action, timestamp DESC);

-- IOC DATABASE
CREATE TABLE IF NOT EXISTS iocs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ioc_type        VARCHAR(20) NOT NULL,
    value           TEXT NOT NULL UNIQUE,
    confidence      FLOAT NOT NULL,
    first_seen      TIMESTAMPTZ DEFAULT NOW(),
    last_seen       TIMESTAMPTZ DEFAULT NOW(),
    source          VARCHAR(50),
    tags            TEXT[],
    raw_intel       JSONB
);

CREATE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs (ioc_type, value);
CREATE INDEX IF NOT EXISTS idx_iocs_confidence ON iocs (confidence DESC);

-- MODEL PERFORMANCE TRACKING
CREATE TABLE IF NOT EXISTS model_metrics (
    id              SERIAL PRIMARY KEY,
    timestamp       TIMESTAMPTZ DEFAULT NOW(),
    model_name      VARCHAR(50) NOT NULL,
    metric_name     VARCHAR(30) NOT NULL,
    metric_value    FLOAT NOT NULL,
    sample_count    INTEGER
);

SELECT create_hypertable('model_metrics', 'timestamp', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_model_metrics_name ON model_metrics (model_name, timestamp DESC);

-- Insert sample data
INSERT INTO model_metrics (model_name, metric_name, metric_value, sample_count)
VALUES 
    ('urlnet', 'accuracy', 0.975, 1000),
    ('deberta_url', 'accuracy', 0.982, 1000),
    ('xgboost', 'accuracy', 0.968, 1000)
ON CONFLICT DO NOTHING;
