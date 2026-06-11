"""Scan API endpoints using Celery for background task processing."""

import asyncio
import json
import logging
import os
import uuid

import redis as sync_redis
import redis.asyncio as aioredis
from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import Response, StreamingResponse

from ...models.sarif import generate_sarif
from ...models.scan import ScanStatus
from ...worker.tasks import run_scan_task

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["scan"])

REDIS_URL = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")

# Redis-backed result cache (survives restarts, shared across workers)
_blob_redis = sync_redis.Redis.from_url(REDIS_URL)
ZIP_BLOB_TTL = 600  # 10 minutes TTL for ZIP blobs
RESULT_CACHE_TTL = 3600  # 1 hour TTL for scan results
RESULT_KEY_PREFIX = "scan:result:"


def _cache_result(scan_id: str, result_data: dict) -> None:
    """Store scan result in Redis with TTL."""
    try:
        _blob_redis.set(
            f"{RESULT_KEY_PREFIX}{scan_id}",
            json.dumps(result_data),
            ex=RESULT_CACHE_TTL,
        )
    except Exception as e:
        logger.warning("Failed to cache result in Redis: %s", e)


def _get_cached_result(scan_id: str) -> dict | None:
    """Retrieve cached scan result from Redis."""
    try:
        data = _blob_redis.get(f"{RESULT_KEY_PREFIX}{scan_id}")
        if data:
            return json.loads(data)
    except Exception as e:
        logger.warning("Failed to read cached result: %s", e)
    return None


@router.post("/scan")
async def create_scan(file: UploadFile = File(...)):
    """
    Upload a ZIP file for vulnerability scanning.

    Stores ZIP in Redis blob store and dispatches scan task with reference.
    """
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only ZIP files are accepted")

    zip_bytes = await file.read()
    if len(zip_bytes) == 0:
        raise HTTPException(status_code=400, detail="Empty file uploaded")
    if len(zip_bytes) > 200 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File exceeds 200MB limit")

    scan_id = str(uuid.uuid4())

    # Store ZIP blob in Redis with TTL (avoids hex-encoding memory doubling)
    blob_key = f"scan:{scan_id}:zip"
    _blob_redis.set(blob_key, zip_bytes, ex=ZIP_BLOB_TTL)

    # Dispatch to Celery worker with blob reference
    run_scan_task.apply_async(
        args=[scan_id, blob_key, file.filename],
        task_id=scan_id,
    )

    return {"scan_id": scan_id, "status": "QUEUED", "filename": file.filename}


@router.get("/scan/{scan_id}/stream")
async def stream_scan(scan_id: str):
    """
    Stream scan progress via Server-Sent Events.

    Subscribes to the Redis pub/sub channel for this scan_id
    and forwards events to the client.
    """
    async def event_generator():
        r = aioredis.from_url(REDIS_URL, decode_responses=True)
        pubsub = r.pubsub()
        await pubsub.subscribe(f"scan:{scan_id}:progress")

        try:
            while True:
                msg = await pubsub.get_message(
                    ignore_subscribe_messages=True, timeout=120.0,
                )
                if msg is None:
                    yield f"data: {json.dumps({'type': 'keepalive'})}\n\n"
                    continue

                if msg["type"] == "message":
                    data = msg["data"]
                    yield f"data: {data}\n\n"

                    event = json.loads(data)
                    event_type = event.get("type")

                    if event_type == "complete":
                        if "result" in event:
                            _cache_result(scan_id, event["result"])
                        break
                    elif event_type == "error":
                        if "result" in event:
                            _cache_result(scan_id, event["result"])
                        break
        finally:
            await pubsub.unsubscribe(f"scan:{scan_id}:progress")
            await pubsub.aclose()
            await r.aclose()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/scan/{scan_id}/result")
async def get_result(scan_id: str):
    """Get the complete scan result."""
    cached = _get_cached_result(scan_id)
    if cached and cached.get("status") == "COMPLETED":
        return cached

    result = run_scan_task.AsyncResult(scan_id)

    if result.state == "SUCCESS":
        result_data = result.result
        _cache_result(scan_id, result_data)
        return result_data
    elif result.state == "FAILURE":
        raise HTTPException(status_code=500, detail=f"Scan failed: {result.info}")

    # Fall back to SQLite — Celery result backend TTL (1 hr) may have expired
    from ...models.database import get_scan_by_id
    db_result = get_scan_by_id(scan_id)
    if db_result:
        _cache_result(scan_id, db_result)
        return db_result

    if result.state == "PENDING":
        return {"scan_id": scan_id, "status": "QUEUED", "message": "Scan is queued"}
    elif result.state == "STARTED":
        return {"scan_id": scan_id, "status": "SCANNING", "message": "Scan in progress"}
    else:
        return {"scan_id": scan_id, "status": result.state}


@router.get("/scan/{scan_id}/sarif")
async def get_sarif(scan_id: str):
    """Get scan results in SARIF 2.1.0 format."""
    result_data = _get_cached_result(scan_id)
    if not result_data:
        result = run_scan_task.AsyncResult(scan_id)
        if result.state != "SUCCESS":
            raise HTTPException(status_code=409, detail="Scan not yet completed")
        result_data = result.result
        _cache_result(scan_id, result_data)

    if result_data.get("status") != "COMPLETED":
        raise HTTPException(status_code=409, detail="Scan not yet completed")

    from ...models.finding import Finding
    findings = [Finding(**f) for f in result_data.get("findings", [])]
    sarif = generate_sarif(findings)
    return sarif.model_dump(mode="json", by_alias=True)


@router.get("/scan/{scan_id}/pdf")
async def get_pdf(scan_id: str):
    """Get scan results as a PDF report."""
    result_data = _get_cached_result(scan_id)
    if not result_data:
        result = run_scan_task.AsyncResult(scan_id)
        if result.state != "SUCCESS":
            raise HTTPException(status_code=409, detail="Scan not yet completed")
        result_data = result.result
        _cache_result(scan_id, result_data)

    if result_data.get("status") != "COMPLETED":
        raise HTTPException(status_code=409, detail="Scan not yet completed")

    from ...llm.pdf_report import generate_pdf_report
    pdf_bytes = generate_pdf_report(result_data)

    if not pdf_bytes:
        raise HTTPException(
            status_code=503,
            detail="PDF generation unavailable. Install weasyprint or fpdf2.",
        )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="scan-{scan_id[:8]}.pdf"'
        },
    )
