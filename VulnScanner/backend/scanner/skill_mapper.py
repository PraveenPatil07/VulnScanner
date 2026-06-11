"""Maps RawMatch objects to Finding models using skill metadata."""

import json
import logging
from pathlib import Path

from ..models.finding import Finding, Severity, VulnCategory
from .rule_engine import RawMatch

logger = logging.getLogger(__name__)

SKILL_METADATA_PATH = Path(__file__).parent.parent / "skills" / "skill_metadata.json"


class SkillMapper:
    """Maps raw scanner matches to structured Finding objects with enriched metadata."""

    def __init__(self, metadata_path: Path | None = None):
        self._metadata_path = metadata_path or SKILL_METADATA_PATH
        self._metadata: dict = {}
        self._loaded = False

    def load_metadata(self) -> None:
        """Load skill metadata from JSON."""
        try:
            with open(self._metadata_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._metadata = {cat["category"]: cat for cat in data.get("categories", [])}
            self._loaded = True
            logger.info("Loaded skill metadata for %d categories", len(self._metadata))
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error("Failed to load skill metadata: %s", e)
            self._metadata = {}
            self._loaded = True

    def map_match(self, match: RawMatch, scan_id: str) -> Finding:
        """
        Convert a RawMatch into a Finding model.

        Enriches with metadata from skill_metadata.json where available.
        """
        if not self._loaded:
            self.load_metadata()

        # Map severity string to enum
        severity = self._map_severity(match.rule.severity)

        # Map category string to enum
        category = self._map_category(match.rule.category)

        # Get enrichment from metadata
        meta = self._metadata.get(match.rule.category, {})

        # Build context snippet
        context_lines = (
            match.context_before
            + [f">>> {match.line_content}"]
            + match.context_after
        )
        code_snippet = "\n".join(context_lines)

        return Finding(
            scan_id=scan_id,
            rule_id=match.rule.id,
            title=match.rule.name,
            description=match.rule.description,
            severity=severity,
            category=category,
            cwe_id=match.rule.cwe,
            cvss_score=match.rule.cvss_score,
            cvss_vector=match.rule.cvss_vector,
            mitre_attack_id=match.rule.mitre_attack or meta.get("mitre_attack", ""),
            nist_csf=match.rule.nist_csf or meta.get("nist_csf", []),
            owasp_top10=meta.get("owasp_top10", ""),
            file_path=match.file_path,
            line_number=match.line_number,
            column_start=match.column_start,
            column_end=match.column_end,
            code_snippet=code_snippet,
            match_text=match.match_text,
            confidence=match.rule.confidence,
            false_positive_risk=match.rule.false_positive_risk,
            remediation=match.rule.remediation or meta.get("remediation", ""),
            references=match.rule.references or meta.get("references", []),
            language=match.rule.language,
        )

    def map_matches(self, matches: list[RawMatch], scan_id: str) -> list[Finding]:
        """Convert a list of RawMatch into Finding objects."""
        return [self.map_match(m, scan_id) for m in matches]

    def _map_severity(self, severity_str: str) -> Severity:
        """Map severity string to Severity enum."""
        mapping = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFO": Severity.INFO,
        }
        return mapping.get(severity_str.upper(), Severity.MEDIUM)

    def _map_category(self, category_str: str) -> VulnCategory:
        """Map category string to VulnCategory enum."""
        try:
            return VulnCategory(category_str)
        except ValueError:
            logger.warning("Unknown vulnerability category: %s", category_str)
            return VulnCategory.MISCONFIG
