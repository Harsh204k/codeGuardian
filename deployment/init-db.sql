-- Initialize CodeGuardian Database
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create main tables for vulnerability scanning
CREATE TABLE IF NOT EXISTS scan_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_name VARCHAR(255) NOT NULL,
    scan_type VARCHAR(50) NOT NULL DEFAULT 'full',
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    total_files INTEGER DEFAULT 0,
    total_vulnerabilities INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID REFERENCES scan_sessions(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    column_number INTEGER DEFAULT 1,
    vulnerability_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    confidence DECIMAL(3,2) DEFAULT 0.5,
    description TEXT,
    recommendation TEXT,
    rule_id VARCHAR(100),
    cwe_id VARCHAR(20),
    owasp_category VARCHAR(50),
    code_snippet TEXT,
    fix_suggestion TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS ml_predictions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    vulnerability_id UUID REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    model_name VARCHAR(100) NOT NULL,
    model_version VARCHAR(50),
    prediction_score DECIMAL(5,4) NOT NULL,
    confidence_score DECIMAL(5,4),
    features JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_scan_sessions_status ON scan_sessions(status);
CREATE INDEX IF NOT EXISTS idx_scan_sessions_started_at ON scan_sessions(started_at);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_session_id ON vulnerabilities(session_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_type ON vulnerabilities(vulnerability_type);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_file_path ON vulnerabilities(file_path);
CREATE INDEX IF NOT EXISTS idx_ml_predictions_vulnerability_id ON ml_predictions(vulnerability_id);

-- Insert sample data for testing (optional)
INSERT INTO scan_sessions (project_name, scan_type, status, total_files, total_vulnerabilities) 
VALUES ('sample_project', 'demo', 'completed', 10, 5) 
ON CONFLICT DO NOTHING;