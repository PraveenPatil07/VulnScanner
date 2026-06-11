"""Assembles the final vulnerability report from LLM output and scan data."""

import json
from datetime import datetime, timezone

from ..models.finding import Finding
from ..models.scan import ScanResult, ScanStatus


class ReportAssembler:
    """Assembles the final report combining static findings with LLM analysis."""

    def assemble(
        self,
        scan_id: str,
        findings: list[Finding],
        llm_report: str,
        scan_duration_ms: int,
        files_scanned: int,
        lines_scanned: int,
    ) -> ScanResult:
        """
        Assemble a complete ScanResult from scan data and LLM report.
        """
        # Build severity/category/language breakdowns
        findings_by_severity: dict[str, int] = {}
        findings_by_category: dict[str, int] = {}
        findings_by_language: dict[str, int] = {}

        for f in findings:
            sev = f.severity.value
            findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1
            cat = f.category.value
            findings_by_category[cat] = findings_by_category.get(cat, 0) + 1
            lang = f.language
            findings_by_language[lang] = findings_by_language.get(lang, 0) + 1

        return ScanResult(
            scan_id=scan_id,
            status=ScanStatus.COMPLETED,
            findings=findings,
            total_findings=len(findings),
            findings_by_severity=findings_by_severity,
            findings_by_category=findings_by_category,
            findings_by_language=findings_by_language,
            llm_report=llm_report,
            scan_duration_ms=scan_duration_ms,
            files_scanned=files_scanned,
            lines_scanned=lines_scanned,
            completed_at=datetime.now(timezone.utc),
        )

    def assemble_error(
        self,
        scan_id: str,
        error_message: str,
        scan_duration_ms: int = 0,
    ) -> ScanResult:
        """Assemble a failed scan result."""
        return ScanResult(
            scan_id=scan_id,
            status=ScanStatus.FAILED,
            findings=[],
            total_findings=0,
            findings_by_severity={},
            findings_by_category={},
            findings_by_language={},
            llm_report=None,
            scan_duration_ms=scan_duration_ms,
            files_scanned=0,
            lines_scanned=0,
            error=error_message,
        )

    def to_json(self, result: ScanResult) -> str:
        """Serialize ScanResult to JSON string."""
        return result.model_dump_json(indent=2)
