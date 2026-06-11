"""Scan request, result, and status models."""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

from .finding import Finding


class ScanStatus(str, Enum):
    QUEUED = "QUEUED"
    EXTRACTING = "EXTRACTING"
    SCANNING = "SCANNING"
    GENERATING_REPORT = "GENERATING_REPORT"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ScanResult(BaseModel):
    scan_id: str = Field(..., min_length=36, max_length=36)
    status: ScanStatus
    total_files: int = Field(default=0, ge=0)
    files_scanned: int = Field(default=0, ge=0)
    lines_scanned: int = Field(default=0, ge=0)
    total_findings: int = Field(default=0, ge=0)
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    findings_by_category: dict[str, int] = Field(default_factory=dict)
    findings_by_language: dict[str, int] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    llm_report: Optional[str] = None
    scan_duration_ms: int = Field(default=0, ge=0)
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
