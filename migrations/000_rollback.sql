-- Rollback script for scam detection tables
-- Run this to remove all scam detection tables and data

-- Drop indexes first
DROP INDEX IF EXISTS idx_scam_flags_risk_level;
DROP INDEX IF EXISTS idx_scam_flags_review_status;
DROP INDEX IF EXISTS idx_scam_flags_flagged_at;
DROP INDEX IF EXISTS idx_scam_flags_account_id;
DROP INDEX IF EXISTS idx_scam_flags_from_number;
DROP INDEX IF EXISTS idx_scam_detection_runs_start_time;
DROP INDEX IF EXISTS idx_scam_detection_runs_status;
DROP INDEX IF EXISTS idx_nightly_scam_reports_date;

-- Drop tables (in reverse order due to foreign keys)
DROP TABLE IF EXISTS nightly_scam_reports CASCADE;
DROP TABLE IF EXISTS scam_detection_runs CASCADE;
DROP TABLE IF EXISTS scam_flags CASCADE;
