"""Celery application configuration."""

import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env from backend directory
_env_path = Path(__file__).parent / ".env"
if _env_path.exists():
    load_dotenv(_env_path)
else:
    # Also try .env.example as fallback
    _env_example = Path(__file__).parent / ".env.example"
    if _env_example.exists():
        load_dotenv(_env_example)

from celery import Celery

REDIS_URL = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/1")

celery_app = Celery(
    "scanner_worker",
    broker=REDIS_URL,
    backend=RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    result_expires=3600,  # 1 hour
    task_soft_time_limit=300,  # 5 min soft limit
    task_time_limit=360,  # 6 min hard limit
    task_default_queue="scans",
    task_routes={
        "backend.worker.tasks.run_scan_task": {"queue": "scans"},
        "backend.worker.tasks.generate_report_task": {"queue": "reports"},
    },
)

celery_app.autodiscover_tasks(["backend.worker"])
