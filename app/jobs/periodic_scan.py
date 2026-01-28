from datetime import datetime, timedelta
import logging
from app.clients.portal_api import PortalAPIClient
from app.detection.integrated_detector import IntegratedScamDetector
from app.models import ScamFlag, ScamDetectionRun
from app.database import SessionLocal

logger = logging.getLogger(__name__)


async def periodic_scan_job():
    """
    Periodic scan job - runs every 15 minutes
    Scans recent outbound messages for scam indicators
    """
    logger.info("Starting periodic scam scan...")

    # Create detection run record
    run = ScamDetectionRun(
        run_type="periodic",
        start_time=datetime.utcnow(),
        status="running",
    )

    db = SessionLocal()
    try:
        db.add(run)
        db.commit()
        db.refresh(run)

        # 1. Fetch messages from last 15 minutes
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(minutes=15)

        portal_client = PortalAPIClient()
        messages = await portal_client.get_all_messages_in_range(
            start_datetime=start_time.isoformat(),
            end_datetime=end_time.isoformat(),
        )

        logger.info(f"Fetched {len(messages)} messages for scanning")

        # 2. Run scam detection on each message
        detector = IntegratedScamDetector()
        detection_results = []

        for msg in messages:
            try:
                result = detector.analyze_message(**msg)
                if result:  # Only include if scam detected
                    detection_results.append(result)
            except Exception as e:
                logger.error(f"Error analyzing message {msg.get('id')}: {e}")
                continue

        logger.info(f"Detected {len(detection_results)} potential scams")

        # 3. Write scam flags to database
        for result in detection_results:
            try:
                # Check if already flagged
                existing = (
                    db.query(ScamFlag)
                    .filter(ScamFlag.sms_id == result["sms_id"])
                    .first()
                )
                if existing:
                    logger.info(f"Message {result['sms_id']} already flagged, skipping")
                    continue

                scam_flag = ScamFlag(
                    sms_id=result["sms_id"],
                    account_id=result["account_id"],
                    is_scam=result["is_scam"],
                    risk_level=result["risk_level"],
                    risk_score=result["risk_score"],
                    detection_method=result["detection_method"],
                    detection_category=result.get("detection_category"),
                    pattern_matched=result.get("pattern_matched"),
                    behavioral_flags=result.get("behavioral_flags", {}),
                    message_text=result["message_text"],
                    from_number=result["from_number"],
                    to_number=result["to_number"],
                    sent_at=result["sent_at"],
                    review_status="pending",
                )
                db.add(scam_flag)
            except Exception as e:
                logger.error(f"Error saving scam flag: {e}")
                continue

        db.commit()

        # 4. Update run status
        run.status = "completed"
        run.end_time = datetime.utcnow()
        run.messages_scanned = len(messages)
        run.scams_detected = len(detection_results)
        run.detection_breakdown = {
            "by_risk_level": _count_by_field(detection_results, "risk_level"),
            "by_method": _count_by_field(detection_results, "detection_method"),
        }
        db.commit()

        logger.info(
            f"Periodic scan completed: {len(messages)} scanned, "
            f"{len(detection_results)} flagged"
        )

    except Exception as e:
        logger.error(f"Periodic scan failed: {e}")
        run.status = "failed"
        run.end_time = datetime.utcnow()
        run.error_message = str(e)
        db.commit()
        raise
    finally:
        db.close()


def _count_by_field(items, field):
    """Count items grouped by a field"""
    counts = {}
    for item in items:
        value = item.get(field, "unknown")
        counts[value] = counts.get(value, 0) + 1
    return counts
