from fastapi import FastAPI
from contextlib import asynccontextmanager
import logging
from app.jobs.scheduler import setup_scheduler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for FastAPI
    Handles startup and shutdown of the scheduler
    """
    logger.info("Starting scam detection microservice...")

    # Start the scheduler
    scheduler = setup_scheduler()
    logger.info("Scheduler started successfully")

    yield

    # Shutdown
    logger.info("Shutting down scam detection microservice...")
    scheduler.shutdown()
    logger.info("Scheduler stopped")


app = FastAPI(
    title="Scam Detection Microservice",
    description="Automated scam detection service for TSG Global SMS messages",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/")
async def root():
    return {
        "service": "Scam Detection Microservice",
        "version": "1.0.0",
        "status": "running",
    }


@app.get("/health")
async def health():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
