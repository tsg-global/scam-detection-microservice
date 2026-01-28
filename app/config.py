from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # Database
    database_url: str

    # Portal API
    portal_api_url: str
    portal_api_key: str

    # Anthropic API
    anthropic_api_key: str
    anthropic_model: str = "claude-haiku-20250306"

    # Job Settings
    periodic_scan_interval_minutes: int = 15
    nightly_summary_hour: int = 2
    nightly_summary_minute: int = 0

    # Detection Settings
    risk_threshold_critical: float = 0.9
    risk_threshold_high: float = 0.7
    risk_threshold_medium: float = 0.4
    max_ai_reviews_per_run: int = 100
    max_ai_reviews_daily: int = 20

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
