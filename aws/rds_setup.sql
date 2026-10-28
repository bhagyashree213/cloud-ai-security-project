-- =====================================================================
-- CloudSentinel — Amazon RDS Production Relational Database Schema
-- Compatible with PostgreSQL and MySQL / Amazon Aurora engines.
-- =====================================================================

-- 1. Users & Role-Based Access Control Table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'Security Analyst',
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 2. Security Logs (Telemetry Ingestion) Table
CREATE TABLE IF NOT EXISTS security_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    login_attempts INTEGER NOT NULL,
    failed_attempts INTEGER NOT NULL,
    request_count INTEGER NOT NULL,
    file_access_count INTEGER NOT NULL,
    data_transfer_mb REAL NOT NULL,
    unusual_location INTEGER NOT NULL,
    unusual_time INTEGER NOT NULL,
    privilege_level INTEGER NOT NULL,
    source VARCHAR(255) DEFAULT 'System Telemetry',
    ip_address VARCHAR(100) DEFAULT '127.0.0.1',
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 3. Threat Evaluations (AI Engine Output) Table
CREATE TABLE IF NOT EXISTS threats (
    id SERIAL PRIMARY KEY,
    log_id INTEGER NOT NULL REFERENCES security_logs(id) ON DELETE CASCADE,
    threat_probability REAL NOT NULL,
    anomaly INTEGER NOT NULL,
    risk_score INTEGER NOT NULL,
    severity VARCHAR(20) NOT NULL,
    threat_type VARCHAR(100) NOT NULL,
    model_used VARCHAR(100) NOT NULL,
    anomaly_model_used VARCHAR(100) NOT NULL,
    contributing_factors TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 4. Alerts (Incident Management) Table
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    threat_id INTEGER NOT NULL REFERENCES threats(id) ON DELETE CASCADE,
    log_id INTEGER NOT NULL REFERENCES security_logs(id) ON DELETE CASCADE,
    message TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'OPEN',
    assigned_to VARCHAR(100) DEFAULT 'Unassigned',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 5. Alert History (Lifecycle & Triage Audit Trail) Table
CREATE TABLE IF NOT EXISTS alert_history (
    id SERIAL PRIMARY KEY,
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    changed_by VARCHAR(100) NOT NULL,
    old_status VARCHAR(20) NOT NULL,
    new_status VARCHAR(20) NOT NULL,
    notes TEXT,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 6. System Audit Logs (Security & Compliance Trail) Table
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,
    username VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    details TEXT,
    ip_address VARCHAR(100) DEFAULT '127.0.0.1',
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 7. Model Evaluations & Benchmark Tracking Table
CREATE TABLE IF NOT EXISTS model_evaluations (
    id SERIAL PRIMARY KEY,
    model_name VARCHAR(100) NOT NULL,
    model_type VARCHAR(100) NOT NULL,
    algorithm VARCHAR(100) NOT NULL,
    accuracy REAL,
    precision_score REAL,
    recall_score REAL,
    f1_score REAL,
    roc_auc REAL,
    training_time_sec REAL,
    confusion_matrix TEXT,
    hyperparameters TEXT,
    is_active INTEGER NOT NULL DEFAULT 0,
    evaluated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 8. Performance Indexes
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON security_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
CREATE INDEX IF NOT EXISTS idx_threats_log_id ON threats(log_id);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_threat_id ON alerts(threat_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
