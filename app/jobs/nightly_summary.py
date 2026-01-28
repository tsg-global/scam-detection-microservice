from datetime import datetime, timedelta, date
import logging
from sqlalchemy import func
from app.clients.anthropic_client import AnthropicClient
from app.models import ScamFlag, NightlyScamReport
from app.database import SessionLocal
from app.config import settings

logger = logging.getLogger(__name__)


async def nightly_summary_job():
    """
    Nightly summary job - runs daily at 2 AM
    Generates daily summary and learns new patterns with Claude
    """
    logger.info("Starting nightly scam summary...")

    report_date = date.today() - timedelta(days=1)
    db = SessionLocal()

    try:
        # 1. Query yesterday's scam flags
        start_datetime = datetime.combine(report_date, datetime.min.time())
        end_datetime = datetime.combine(
            report_date, datetime.max.time().replace(microsecond=0)
        )

        scam_flags = (
            db.query(ScamFlag)
            .filter(ScamFlag.flagged_at >= start_datetime)
            .filter(ScamFlag.flagged_at <= end_datetime)
            .all()
        )

        logger.info(f"Found {len(scam_flags)} scam flags for {report_date}")

        # 2. Calculate metrics
        total_scams = len(scam_flags)
        scams_by_risk = _count_by_field(scam_flags, "risk_level")
        scams_by_category = _count_by_field(scam_flags, "detection_category")
        detection_methods = _count_by_field(scam_flags, "detection_method")

        # Calculate false positive rate
        reviewed_flags = [f for f in scam_flags if f.reviewed]
        false_positives = [
            f for f in reviewed_flags if f.review_status == "false_positive"
        ]
        false_positive_rate = (
            (len(false_positives) / len(reviewed_flags) * 100)
            if reviewed_flags
            else 0.0
        )

        logger.info(
            f"Metrics: {total_scams} total, "
            f"{len(reviewed_flags)} reviewed, "
            f"{false_positive_rate:.2f}% false positive rate"
        )

        # 3. AI analysis of high-risk unreviewed messages
        high_risk_unreviewed = [
            f
            for f in scam_flags
            if f.risk_level in ["CRITICAL", "HIGH"] and not f.reviewed
        ][: settings.max_ai_reviews_daily]

        anthropic_client = AnthropicClient()
        new_patterns = []

        logger.info(
            f"Analyzing {len(high_risk_unreviewed)} high-risk messages with Claude"
        )

        for flag in high_risk_unreviewed:
            try:
                insight = await anthropic_client.analyze_scam(
                    message_text=flag.message_text,
                    current_detection=flag.detection_category,
                )

                if (
                    insight.get("new_pattern_detected")
                    and insight.get("confidence", 0) > 0.8
                ):
                    pattern_info = {
                        "pattern": insight.get("pattern_regex"),
                        "scam_type": insight.get("scam_type"),
                        "confidence": insight.get("confidence"),
                        "example_message": flag.message_text[:100],
                    }
                    new_patterns.append(pattern_info)
                    logger.info(f"New pattern detected: {insight.get('scam_type')}")

            except Exception as e:
                logger.error(f"Error analyzing message {flag.id} with Claude: {e}")
                continue

        # 4. Generate AI summary
        ai_summary = await anthropic_client.generate_summary(
            total_scams=total_scams,
            scams_by_risk=scams_by_risk,
            false_positive_rate=false_positive_rate,
        )

        # 5. Generate action items
        action_items = _generate_action_items(
            total_scams, false_positive_rate, new_patterns
        )

        # 6. Save report
        report = NightlyScamReport(
            report_date=report_date,
            total_scams_detected=total_scams,
            scams_by_risk_level=scams_by_risk,
            scams_by_category=scams_by_category,
            detection_methods=detection_methods,
            false_positive_rate=false_positive_rate,
            new_patterns_learned=new_patterns,
            ai_summary=ai_summary,
            action_items=action_items,
        )

        db.add(report)
        db.commit()

        logger.info(
            f"Nightly summary completed for {report_date}: "
            f"{total_scams} scams, {len(new_patterns)} new patterns"
        )

    except Exception as e:
        logger.error(f"Nightly summary failed: {e}")
        raise
    finally:
        db.close()


def _count_by_field(items, field):
    """Count items grouped by a field"""
    counts = {}
    for item in items:
        value = getattr(item, field, "unknown")
        if value:
            counts[str(value)] = counts.get(str(value), 0) + 1
    return counts


def _generate_action_items(
    total_scams: int, false_positive_rate: float, new_patterns: list
) -> list:
    """Generate recommended action items based on metrics"""
    actions = []

    if total_scams > 100:
        actions.append(
            {
                "priority": "high",
                "action": "High volume of scams detected",
                "recommendation": "Review detection patterns and consider additional filters",
            }
        )

    if false_positive_rate > 0.5:
        actions.append(
            {
                "priority": "high",
                "action": "High false positive rate",
                "recommendation": "Review and tune detection thresholds",
            }
        )

    if len(new_patterns) > 0:
        actions.append(
            {
                "priority": "medium",
                "action": f"{len(new_patterns)} new patterns identified",
                "recommendation": "Review and integrate new patterns into detector",
            }
        )

    return actions
