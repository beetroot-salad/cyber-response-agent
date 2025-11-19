-- init-db.sql
-- PostgreSQL initialization script for Cyber Response Agent
-- Defines schema for ticket management from Wazuh alerts

-- Enable pgvector extension for future semantic search capabilities
CREATE EXTENSION IF NOT EXISTS vector;

-- ==========================================
-- TICKETS TABLE
-- Stores alert metadata from Wazuh/Falco events
-- ==========================================
CREATE TABLE tickets (
    -- Primary identification
    id SERIAL PRIMARY KEY,
    alert_id VARCHAR(255) UNIQUE NOT NULL,

    -- Alert classification
    alert_signature VARCHAR(255) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(50) DEFAULT 'open',

    -- Disposition and closure
    disposition VARCHAR(50),
    confidence_score NUMERIC(5,2),
    closure_reason TEXT,

    -- Timestamps
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP,
    closed_by VARCHAR(100) DEFAULT 'agent',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Raw alert data (JSONB for flexibility)
    raw_alert JSONB NOT NULL,

    -- Investigation tracking
    investigation_context JSONB
);

-- ==========================================
-- INDEXES
-- ==========================================
CREATE INDEX idx_tickets_status ON tickets(status);
CREATE INDEX idx_tickets_signature ON tickets(alert_signature);
CREATE INDEX idx_tickets_timestamp ON tickets(timestamp DESC);
CREATE INDEX idx_tickets_severity ON tickets(severity);
CREATE INDEX idx_tickets_disposition ON tickets(disposition);

-- ==========================================
-- COMMENTS (Documentation)
-- ==========================================
COMMENT ON TABLE tickets IS 'Stores security alerts from Wazuh for investigation and tracking';
COMMENT ON COLUMN tickets.alert_id IS 'Unique identifier from Wazuh alert';
COMMENT ON COLUMN tickets.alert_signature IS 'Rule name or signature that triggered the alert';
COMMENT ON COLUMN tickets.severity IS 'Alert severity level (critical, high, medium, low, info)';
COMMENT ON COLUMN tickets.status IS 'Ticket status (open, investigating, closed)';
COMMENT ON COLUMN tickets.disposition IS 'Investigation outcome (true_positive, false_positive, benign, escalated, inconclusive)';
COMMENT ON COLUMN tickets.raw_alert IS 'Complete alert JSON from Wazuh';
COMMENT ON COLUMN tickets.investigation_context IS 'Agent investigation steps, queries, and findings';
