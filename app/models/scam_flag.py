from sqlalchemy import (
    Column,
    String,
    Boolean,
    DateTime,
    Numeric,
    Text,
    CheckConstraint,
    Integer,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func
from app.database import Base
import uuid


class ScamFlag(Base):
    __tablename__ = "scam_flags"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sms_id = Column(UUID(as_uuid=True), nullable=False, unique=True)
    account_id = Column(UUID(as_uuid=True), nullable=False)

    # Classification
    is_scam = Column(Boolean, nullable=False, default=True)
    risk_level = Column(String(10), nullable=False)
    risk_score = Column(Numeric(5, 2), nullable=False)

    # Detection details
    detection_method = Column(String(50), nullable=False)
    detection_category = Column(String(50), nullable=True)
    pattern_matched = Column(Text, nullable=True)
    behavioral_flags = Column(JSONB, nullable=False, default={})

    # Message details (denormalized)
    message_text = Column(Text, nullable=False)
    from_number = Column(String(20), nullable=False)
    to_number = Column(String(20), nullable=False)
    sent_at = Column(DateTime, nullable=False)

    # Review tracking
    reviewed = Column(Boolean, nullable=False, default=False)
    review_status = Column(String(20), nullable=True)
    review_notes = Column(Text, nullable=True)
    reviewed_by = Column(String(100), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)

    # Metadata
    flagged_at = Column(DateTime, nullable=False, server_default=func.now())
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(
        DateTime, nullable=False, server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "risk_level IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')",
            name="check_risk_level",
        ),
        CheckConstraint(
            "review_status IN ('pending', 'confirmed_scam', 'false_positive')",
            name="check_review_status",
        ),
        CheckConstraint(
            "risk_score >= 0 AND risk_score <= 100", name="check_risk_score"
        ),
    )


class ScamDetectionRun(Base):
    __tablename__ = "scam_detection_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    run_type = Column(String(20), nullable=False)
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=True)
    status = Column(String(20), nullable=False)
    messages_scanned = Column(Integer, nullable=False, default=0)
    scams_detected = Column(Integer, nullable=False, default=0)
    detection_breakdown = Column(JSONB, nullable=False, default={})
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    __table_args__ = (
        CheckConstraint(
            "run_type IN ('periodic', 'nightly', 'manual')", name="check_run_type"
        ),
        CheckConstraint(
            "status IN ('running', 'completed', 'failed')", name="check_status"
        ),
    )


class NightlyScamReport(Base):
    __tablename__ = "nightly_scam_reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    report_date = Column(DateTime, nullable=False, unique=True)
    total_scams_detected = Column(Integer, nullable=False)
    scams_by_risk_level = Column(JSONB, nullable=False)
    scams_by_category = Column(JSONB, nullable=False)
    detection_methods = Column(JSONB, nullable=False)
    false_positive_rate = Column(Numeric(5, 2), nullable=True)
    new_patterns_learned = Column(JSONB, nullable=False, default=[])
    ai_summary = Column(Text, nullable=True)
    action_items = Column(JSONB, nullable=False, default=[])
    created_at = Column(DateTime, nullable=False, server_default=func.now())
