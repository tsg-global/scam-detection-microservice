# Scam Detection Microservice

Automated scam detection service for TSG Global SMS messages.

## Overview

This microservice runs background jobs to detect scam messages using:
- Pattern matching (regex-based detection)
- Behavioral analysis (sender patterns, message characteristics)
- AI-powered review (Claude Haiku for complex cases)

## Features

- **Periodic Scanning**: Every 15 minutes, scans recent outbound SMS messages
- **Nightly Summaries**: Daily at 2 AM, generates reports and learns new patterns
- **Risk Classification**: CRITICAL, HIGH, MEDIUM, LOW risk levels with scores (0-100)
- **Review Queue**: Flagged messages appear in admin portal for human review

## Architecture

```
FastAPI + APScheduler
├── CRON Jobs
│   ├── Periodic Scan (15 min)
│   └── Nightly Summary (2 AM)
├── Detection Engine
│   ├── Pattern Matcher
│   ├── Behavioral Detector
│   └── AI Reviewer (Claude)
└── Database (Dex PostgreSQL)
    ├── scam_flags
    ├── scam_detection_runs
    └── nightly_scam_reports
```

## Setup

### Prerequisites

- Python 3.11+
- PostgreSQL (existing Dex database)
- Docker & Docker Compose (for deployment)
- Anthropic API key

### Local Development

1. **Clone and install dependencies:**
   ```bash
   cd /Users/alex/tsgglobal/scam-detection-microservice
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Configure environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your actual credentials
   ```

3. **Run database migrations:**
   ```bash
   psql -U user -d dex -f migrations/001_create_scam_tables.sql
   ```

4. **Run the service:**
   ```bash
   python -m app.main
   ```

   The service will start on http://localhost:8000

### Docker Deployment

1. **Build and run:**
   ```bash
   docker-compose up -d
   ```

2. **Check logs:**
   ```bash
   docker-compose logs -f scam-detector
   ```

3. **Stop service:**
   ```bash
   docker-compose down
   ```

## Configuration

All settings are configured via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | - | PostgreSQL connection string |
| `PORTAL_API_URL` | - | Admin portal API base URL |
| `PORTAL_API_KEY` | - | API authentication key |
| `ANTHROPIC_API_KEY` | - | Claude API key |
| `PERIODIC_SCAN_INTERVAL_MINUTES` | 15 | Scan frequency |
| `NIGHTLY_SUMMARY_HOUR` | 2 | Summary job hour (24h format) |
| `RISK_THRESHOLD_CRITICAL` | 0.9 | Critical risk threshold (0-1) |
| `RISK_THRESHOLD_HIGH` | 0.7 | High risk threshold (0-1) |
| `RISK_THRESHOLD_MEDIUM` | 0.4 | Medium risk threshold (0-1) |

## Detection Methods

### Pattern Matching
- Phishing (account verification, suspicious links)
- Financial fraud (prize scams, urgent payments)
- Social engineering (urgency tactics, fake offers)
- Authentication theft (OTP/2FA requests)
- Package delivery (fake courier notifications)

### Behavioral Analysis
- Known scam numbers
- Short messages with links
- Excessive capitalization
- Multiple suspicious keywords
- International numbers

### AI Review
- Analyzes high-risk unreviewed messages
- Learns new patterns
- Generates daily summaries

## API Endpoints

- `GET /` - Service info
- `GET /health` - Health check

## Database Schema

### `scam_flags`
Stores individual scam detections with risk assessment and review status.

### `scam_detection_runs`
Logs each job execution with metrics.

### `nightly_scam_reports`
Daily summary reports with AI insights.

## Monitoring

### Health Check
```bash
curl http://localhost:8000/health
```

### View Recent Runs
```sql
SELECT * FROM scam_detection_runs ORDER BY start_time DESC LIMIT 10;
```

### Check Flagged Messages
```sql
SELECT risk_level, COUNT(*)
FROM scam_flags
WHERE flagged_at >= NOW() - INTERVAL '24 hours'
GROUP BY risk_level;
```

## Cost Estimate

- **Claude Haiku API**: ~$0.08-$10/month (based on volume)
- **Infrastructure**: $10-20/month (VM/container)
- **Total**: ~$20-40/month

## Rollback

To remove all scam detection tables:
```bash
psql -U user -d dex -f migrations/000_rollback.sql
```

## Support

For issues or questions, contact the development team.
