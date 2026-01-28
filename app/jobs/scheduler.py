from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger
import logging
from app.config import settings
from app.jobs.periodic_scan import periodic_scan_job
from app.jobs.nightly_summary import nightly_summary_job

logger = logging.getLogger(__name__)


def setup_scheduler() -> AsyncIOScheduler:
    """
    Set up and configure the APScheduler

    Returns:
        Configured scheduler instance
    """
    scheduler = AsyncIOScheduler()

    # Periodic scan job - runs every 15 minutes
    scheduler.add_job(
        periodic_scan_job,
        trigger=IntervalTrigger(minutes=settings.periodic_scan_interval_minutes),
        id="periodic_scan",
        name="Periodic Scam Scan (15 min)",
        replace_existing=True,
        max_instances=1,  # Prevent overlapping runs
    )
    logger.info(
        f"Scheduled periodic scan job: every {settings.periodic_scan_interval_minutes} minutes"
    )

    # Nightly summary job - runs daily at 2:00 AM
    scheduler.add_job(
        nightly_summary_job,
        trigger=CronTrigger(
            hour=settings.nightly_summary_hour, minute=settings.nightly_summary_minute
        ),
        id="nightly_summary",
        name="Nightly Scam Summary",
        replace_existing=True,
        max_instances=1,
    )
    logger.info(
        f"Scheduled nightly summary job: daily at "
        f"{settings.nightly_summary_hour:02d}:{settings.nightly_summary_minute:02d}"
    )

    scheduler.start()
    logger.info("Scheduler started successfully")

    return scheduler
