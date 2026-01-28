-- Add scam detection tables to existing Dex database
-- Run this migration against the Dex database

-- Table: scam_flags (stores individual scam detections)
CREATE TABLE IF NOT EXISTS scam_flags (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sms_id UUID NOT NULL,
    account_id UUID NOT NULL,

    -- Classification
    is_scam BOOLEAN NOT NULL DEFAULT true,
    risk_level VARCHAR(10) NOT NULL CHECK (risk_level IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    risk_score DECIMAL(5,2) NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),

    -- Detection details
    detection_method VARCHAR(50) NOT NULL,
    detection_category VARCHAR(50),
    pattern_matched TEXT,
    behavioral_flags JSONB DEFAULT '{}',

    -- Message details (denormalized for quick access)
    message_text TEXT NOT NULL,
    from_number VARCHAR(20) NOT NULL,
    to_number VARCHAR(20) NOT NULL,
    sent_at TIMESTAMP NOT NULL,

    -- Review tracking
    reviewed BOOLEAN DEFAULT false,
    review_status VARCHAR(20) CHECK (review_status IN ('pending', 'confirmed_scam', 'false_positive')),
    review_notes TEXT,
    reviewed_by VARCHAR(100),
    reviewed_at TIMESTAMP,

    -- Metadata
    flagged_at TIMESTAMP NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),

    -- Foreign key to smses table (assumes smses table exists in Dex)
    CONSTRAINT fk_sms FOREIGN KEY (sms_id) REFERENCES smses(id) ON DELETE CASCADE,
    CONSTRAINT unique_sms_flag UNIQUE (sms_id)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_scam_flags_risk_level ON scam_flags(risk_level);
CREATE INDEX IF NOT EXISTS idx_scam_flags_review_status ON scam_flags(review_status);
CREATE INDEX IF NOT EXISTS idx_scam_flags_flagged_at ON scam_flags(flagged_at DESC);
CREATE INDEX IF NOT EXISTS idx_scam_flags_account_id ON scam_flags(account_id);
CREATE INDEX IF NOT EXISTS idx_scam_flags_from_number ON scam_flags(from_number);

-- Table: scam_detection_runs (logs each job execution)
CREATE TABLE IF NOT EXISTS scam_detection_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_type VARCHAR(20) NOT NULL CHECK (run_type IN ('periodic', 'nightly', 'manual')),
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP,
    status VARCHAR(20) NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
    messages_scanned INTEGER DEFAULT 0,
    scams_detected INTEGER DEFAULT 0,
    detection_breakdown JSONB DEFAULT '{}',
    error_message TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scam_detection_runs_start_time ON scam_detection_runs(start_time DESC);
CREATE INDEX IF NOT EXISTS idx_scam_detection_runs_status ON scam_detection_runs(status);

-- Table: nightly_scam_reports (daily summaries)
CREATE TABLE IF NOT EXISTS nightly_scam_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_date DATE NOT NULL UNIQUE,
    total_scams_detected INTEGER NOT NULL,
    scams_by_risk_level JSONB NOT NULL,
    scams_by_category JSONB NOT NULL,
    detection_methods JSONB NOT NULL,
    false_positive_rate DECIMAL(5,2),
    new_patterns_learned JSONB DEFAULT '[]',
    ai_summary TEXT,
    action_items JSONB DEFAULT '[]',
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nightly_scam_reports_date ON nightly_scam_reports(report_date DESC);

-- Add comment to document this migration
COMMENT ON TABLE scam_flags IS 'Stores individual scam detection flags for SMS messages';
COMMENT ON TABLE scam_detection_runs IS 'Logs execution of scam detection jobs';
COMMENT ON TABLE nightly_scam_reports IS 'Daily summary reports of scam detection activity';
