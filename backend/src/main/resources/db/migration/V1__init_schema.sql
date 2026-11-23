CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL UNIQUE,
    email_hash VARCHAR(64) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    preferred_lang VARCHAR(10) NOT NULL DEFAULT 'en',
    role VARCHAR(20) NOT NULL DEFAULT 'STANDARD_USER',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE scan_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    input_type VARCHAR(20) NOT NULL,
    payload_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_scan_history_user ON scan_history(user_id);
CREATE INDEX idx_scan_history_created ON scan_history(created_at);

CREATE TABLE risk_assessments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scan_history(id) ON DELETE CASCADE,
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    risk_tier VARCHAR(20) NOT NULL,
    indicators_json JSONB NOT NULL DEFAULT '[]',
    context_answers_json JSONB,
    recommendation TEXT,
    latency_ms INTEGER,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_risk_assessment_scan ON risk_assessments(scan_id);

CREATE TABLE threat_indicators (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    indicator_type VARCHAR(20) NOT NULL,
    indicator_hash VARCHAR(64) NOT NULL UNIQUE,
    display_masked VARCHAR(255),
    status VARCHAR(20) NOT NULL DEFAULT 'UNVERIFIED',
    confidence_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    report_count INTEGER NOT NULL DEFAULT 0,
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_threat_type_hash ON threat_indicators(indicator_type, indicator_hash);

CREATE TABLE indicator_relationships (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_indicator_id UUID NOT NULL REFERENCES threat_indicators(id) ON DELETE CASCADE,
    target_indicator_id UUID NOT NULL REFERENCES threat_indicators(id) ON DELETE CASCADE,
    relation_type VARCHAR(30) NOT NULL,
    weight DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(source_indicator_id, target_indicator_id, relation_type)
);

CREATE TABLE incident_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    reporter_id UUID NOT NULL REFERENCES users(id),
    indicator_id UUID REFERENCES threat_indicators(id),
    scam_category VARCHAR(50),
    redacted_summary TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    moderator_id UUID REFERENCES users(id),
    dispute_reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_incident_status ON incident_reports(status);
CREATE INDEX idx_incident_reporter ON incident_reports(reporter_id);

CREATE TABLE trusted_contacts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    contact_name VARCHAR(100) NOT NULL,
    contact_channel_encrypted TEXT NOT NULL,
    consent_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    actor_id UUID REFERENCES users(id),
    action_type VARCHAR(50) NOT NULL,
    target_entity VARCHAR(255),
    metadata_json JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_audit_actor ON audit_logs(actor_id);
CREATE INDEX idx_audit_created ON audit_logs(created_at);

