"""Database models and persistence layer using SQLite + SQLAlchemy."""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    JSON,
    create_engine,
    event,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

# Database location
DB_DIR = Path(__file__).parent.parent / "storage"
DB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = os.environ.get("CVS_DATABASE_URL", f"sqlite:///{DB_DIR / 'scanner.db'}")


class Base(DeclarativeBase):
    pass


class ScanRecord(Base):
    """Persistent record of a completed scan."""
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True)  # UUID
    status = Column(String(20), nullable=False, default="COMPLETED")
    filename = Column(String(500), nullable=True)
    total_files = Column(Integer, default=0)
    files_scanned = Column(Integer, default=0)
    lines_scanned = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    findings_by_severity = Column(JSON, default=dict)
    findings_by_category = Column(JSON, default=dict)
    findings_by_language = Column(JSON, default=dict)
    scan_duration_ms = Column(Integer, default=0)
    llm_report = Column(Text, nullable=True)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)


class FindingRecord(Base):
    """Persistent record of a single finding."""
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(36), nullable=False, index=True)
    rule_id = Column(String(50), nullable=False)
    category = Column(String(50), nullable=False)
    severity = Column(String(10), nullable=False)
    confidence = Column(String(10), nullable=False, default="MEDIUM")
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    file_path = Column(String(500), nullable=False)
    line_number = Column(Integer, nullable=False)
    column_start = Column(Integer, default=0)
    column_end = Column(Integer, default=0)
    code_snippet = Column(Text, default="")
    match_text = Column(Text, default="")
    cwe_id = Column(String(20), nullable=False)
    cvss_score = Column(Float, default=0.0)
    cvss_vector = Column(String(100), default="")
    mitre_attack_id = Column(String(50), nullable=True)
    owasp_top10 = Column(String(20), nullable=True)
    remediation = Column(Text, default="")
    language = Column(String(20), nullable=False)
    false_positive_risk = Column(String(10), default="MEDIUM")
    suppressed = Column(Integer, default=0)  # 0=active, 1=suppressed as FP
    suppressed_reason = Column(Text, nullable=True)


class SuppressionRule(Base):
    """User-created suppression rules for false positives."""
    __tablename__ = "suppressions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_id = Column(String(50), nullable=True)  # Match specific rule
    file_pattern = Column(String(500), nullable=True)  # Glob pattern
    category = Column(String(50), nullable=True)  # Match category
    reason = Column(Text, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    created_by = Column(String(100), default="user")


# Engine and session factory
_engine = create_engine(DB_PATH, echo=False, pool_pre_ping=True)


@event.listens_for(_engine, "connect")
def _set_sqlite_pragma(dbapi_conn, connection_record):
    """Enable WAL mode and foreign keys for SQLite."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)


def init_db() -> None:
    """Create all tables if they don't exist."""
    Base.metadata.create_all(_engine)


def get_db() -> Session:
    """Get a database session."""
    return SessionLocal()


def save_scan_result(scan_id: str, result_dict: dict, filename: str | None = None) -> None:
    """Persist a completed scan result to the database."""
    init_db()
    db = get_db()
    try:
        record = ScanRecord(
            id=scan_id,
            status=result_dict.get("status", "COMPLETED"),
            filename=filename,
            total_files=result_dict.get("total_files", 0),
            files_scanned=result_dict.get("files_scanned", 0),
            lines_scanned=result_dict.get("lines_scanned", 0),
            total_findings=result_dict.get("total_findings", 0),
            findings_by_severity=result_dict.get("findings_by_severity", {}),
            findings_by_category=result_dict.get("findings_by_category", {}),
            findings_by_language=result_dict.get("findings_by_language", {}),
            scan_duration_ms=result_dict.get("scan_duration_ms", 0),
            llm_report=result_dict.get("llm_report"),
            error=result_dict.get("error"),
            completed_at=datetime.now(timezone.utc),
        )
        db.merge(record)  # Upsert

        # Save findings
        for f in result_dict.get("findings", []):
            finding_rec = FindingRecord(
                scan_id=scan_id,
                rule_id=f.get("rule_id", ""),
                category=f.get("category", ""),
                severity=f.get("severity", ""),
                confidence=f.get("confidence", "MEDIUM"),
                title=f.get("title", ""),
                description=f.get("description", ""),
                file_path=f.get("file_path", ""),
                line_number=f.get("line_number", 0),
                column_start=f.get("column_start", 0),
                column_end=f.get("column_end", 0),
                code_snippet=f.get("code_snippet", ""),
                match_text=f.get("match_text", ""),
                cwe_id=f.get("cwe_id", ""),
                cvss_score=f.get("cvss_score", 0.0),
                cvss_vector=f.get("cvss_vector", ""),
                mitre_attack_id=f.get("mitre_attack_id"),
                owasp_top10=f.get("owasp_top10"),
                remediation=f.get("remediation", ""),
                language=f.get("language", ""),
                false_positive_risk=f.get("false_positive_risk", "MEDIUM"),
            )
            db.add(finding_rec)

        db.commit()
    except Exception as e:
        db.rollback()
        raise
    finally:
        db.close()


def get_scan_history(limit: int = 50, offset: int = 0) -> list[dict]:
    """Get scan history ordered by most recent first."""
    init_db()
    db = get_db()
    try:
        records = (
            db.query(ScanRecord)
            .order_by(ScanRecord.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [
            {
                "scan_id": r.id,
                "status": r.status,
                "filename": r.filename,
                "total_findings": r.total_findings,
                "findings_by_severity": r.findings_by_severity,
                "scan_duration_ms": r.scan_duration_ms,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in records
        ]
    finally:
        db.close()


def get_scan_by_id(scan_id: str) -> dict | None:
    """Retrieve a full scan record by ID."""
    init_db()
    db = get_db()
    try:
        record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
        if not record:
            return None

        findings = (
            db.query(FindingRecord)
            .filter(FindingRecord.scan_id == scan_id)
            .filter(FindingRecord.suppressed == 0)
            .all()
        )

        return {
            "scan_id": record.id,
            "status": record.status,
            "filename": record.filename,
            "total_files": record.total_files,
            "files_scanned": record.files_scanned,
            "lines_scanned": record.lines_scanned,
            "total_findings": record.total_findings,
            "findings_by_severity": record.findings_by_severity,
            "findings_by_category": record.findings_by_category,
            "findings_by_language": record.findings_by_language,
            "scan_duration_ms": record.scan_duration_ms,
            "llm_report": record.llm_report,
            "error": record.error,
            "created_at": record.created_at.isoformat() if record.created_at else None,
            "completed_at": record.completed_at.isoformat() if record.completed_at else None,
            "findings": [
                {
                    "scan_id": f.scan_id,
                    "rule_id": f.rule_id,
                    "category": f.category,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "title": f.title,
                    "description": f.description,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "column_start": f.column_start,
                    "column_end": f.column_end,
                    "code_snippet": f.code_snippet,
                    "match_text": f.match_text,
                    "cwe_id": f.cwe_id,
                    "cvss_score": f.cvss_score,
                    "cvss_vector": f.cvss_vector,
                    "mitre_attack_id": f.mitre_attack_id,
                    "owasp_top10": f.owasp_top10,
                    "remediation": f.remediation,
                    "language": f.language,
                    "false_positive_risk": f.false_positive_risk,
                    "nist_csf": [],
                    "references": [],
                }
                for f in findings
            ],
        }
    finally:
        db.close()


def compare_scans(scan_id_a: str, scan_id_b: str) -> dict:
    """Compare two scans and return diff of findings."""
    init_db()
    db = get_db()
    try:
        findings_a = (
            db.query(FindingRecord)
            .filter(FindingRecord.scan_id == scan_id_a)
            .filter(FindingRecord.suppressed == 0)
            .all()
        )
        findings_b = (
            db.query(FindingRecord)
            .filter(FindingRecord.scan_id == scan_id_b)
            .filter(FindingRecord.suppressed == 0)
            .all()
        )

        # Fingerprint: (rule_id, file_path, line_number)
        set_a = {(f.rule_id, f.file_path, f.line_number) for f in findings_a}
        set_b = {(f.rule_id, f.file_path, f.line_number) for f in findings_b}

        new_findings = set_b - set_a
        fixed_findings = set_a - set_b
        unchanged = set_a & set_b

        # Severity comparison
        sev_a = {}
        sev_b = {}
        for f in findings_a:
            sev_a[f.severity] = sev_a.get(f.severity, 0) + 1
        for f in findings_b:
            sev_b[f.severity] = sev_b.get(f.severity, 0) + 1

        return {
            "scan_a": scan_id_a,
            "scan_b": scan_id_b,
            "total_a": len(findings_a),
            "total_b": len(findings_b),
            "new_findings": len(new_findings),
            "fixed_findings": len(fixed_findings),
            "unchanged": len(unchanged),
            "severity_a": sev_a,
            "severity_b": sev_b,
            "delta": len(findings_b) - len(findings_a),
        }
    finally:
        db.close()


def suppress_finding(scan_id: str, rule_id: str, file_path: str, line_number: int, reason: str) -> bool:
    """Mark a specific finding as a false positive (suppressed)."""
    init_db()
    db = get_db()
    try:
        finding = (
            db.query(FindingRecord)
            .filter(
                FindingRecord.scan_id == scan_id,
                FindingRecord.rule_id == rule_id,
                FindingRecord.file_path == file_path,
                FindingRecord.line_number == line_number,
            )
            .first()
        )
        if finding:
            finding.suppressed = 1
            finding.suppressed_reason = reason
            db.commit()
            return True
        return False
    finally:
        db.close()


def get_trend_data(limit: int = 20) -> list[dict]:
    """Get severity trend data across recent scans."""
    init_db()
    db = get_db()
    try:
        records = (
            db.query(ScanRecord)
            .filter(ScanRecord.status == "COMPLETED")
            .order_by(ScanRecord.created_at.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "scan_id": r.id,
                "filename": r.filename,
                "total_findings": r.total_findings,
                "findings_by_severity": r.findings_by_severity,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "scan_duration_ms": r.scan_duration_ms,
            }
            for r in reversed(records)  # Chronological order
        ]
    finally:
        db.close()
