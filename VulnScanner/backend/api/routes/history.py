"""Scan history and trend API endpoints."""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from ...models.database import (
    compare_scans,
    get_scan_by_id,
    get_scan_history,
    get_trend_data,
    suppress_finding,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["history"])


class SuppressRequest(BaseModel):
    scan_id: str
    rule_id: str
    file_path: str
    line_number: int
    reason: str


@router.get("/scans")
async def list_scans(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    """Get scan history ordered by most recent."""
    return get_scan_history(limit=limit, offset=offset)


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    """Get a full scan result from history."""
    result = get_scan_by_id(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result


@router.get("/scans/{scan_id_a}/compare/{scan_id_b}")
async def compare(scan_id_a: str, scan_id_b: str):
    """Compare two scans and return the diff."""
    return compare_scans(scan_id_a, scan_id_b)


@router.get("/trends")
async def trends(limit: int = Query(default=20, ge=1, le=100)):
    """Get vulnerability trend data across recent scans."""
    return get_trend_data(limit=limit)


@router.post("/findings/suppress")
async def suppress(req: SuppressRequest):
    """Mark a finding as false positive (suppress)."""
    success = suppress_finding(
        scan_id=req.scan_id,
        rule_id=req.rule_id,
        file_path=req.file_path,
        line_number=req.line_number,
        reason=req.reason,
    )
    if not success:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"status": "suppressed", "message": "Finding marked as false positive"}
