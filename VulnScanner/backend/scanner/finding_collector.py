"""Finding collector: deduplication, severity sorting, and token budget management."""

import hashlib
import logging

from ..models.finding import Finding, Severity

logger = logging.getLogger(__name__)

# Token estimates (rough: 1 token ≈ 4 chars for code)
CHARS_PER_TOKEN = 4
DEFAULT_TOKEN_BUDGET = 100_000  # Max tokens for LLM context


class FindingCollector:
    """
    Collects, deduplicates, sorts, and manages findings within token budget.

    Responsibilities:
    - Deduplicate findings by (file, line, rule_id) fingerprint
    - Merge overlapping detections at same (file, line, category)
    - Sort by severity (CRITICAL first) then by confidence
    - Trim findings to stay within token budget for LLM prompt
    - Provide summary statistics
    """

    def __init__(self, token_budget: int = DEFAULT_TOKEN_BUDGET):
        self._findings: list[Finding] = []
        self._fingerprints: set[str] = set()
        self._location_map: dict[str, Finding] = {}  # file:line:category -> best finding
        self._token_budget = token_budget
        self._total_before_dedup = 0
        self._trimmed_count = 0
        self._merged_count = 0

    def add(self, finding: Finding) -> bool:
        """
        Add a finding if not duplicate. Merges overlapping detections
        at the same location+category, keeping the higher-quality one.
        Returns True if added (or replaced existing).
        """
        self._total_before_dedup += 1

        # Exact duplicate check (same file, line, rule)
        fingerprint = self._compute_fingerprint(finding)
        if fingerprint in self._fingerprints:
            return False

        # Location-based merge: same file + line + category from different detectors
        location_key = f"{finding.file_path}:{finding.line_number}:{finding.category.value}"
        if location_key in self._location_map:
            existing = self._location_map[location_key]
            if self._is_better_finding(finding, existing):
                # Replace existing with better detection
                self._findings.remove(existing)
                self._findings.append(finding)
                self._location_map[location_key] = finding
                self._fingerprints.add(fingerprint)
            self._merged_count += 1
            return False

        self._fingerprints.add(fingerprint)
        self._location_map[location_key] = finding
        self._findings.append(finding)
        return True

    def _is_better_finding(self, new: Finding, existing: Finding) -> bool:
        """Determine if new finding is higher quality than existing."""
        conf_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        new_conf = conf_order.get(new.confidence, 3)
        existing_conf = conf_order.get(existing.confidence, 3)
        if new_conf != existing_conf:
            return new_conf < existing_conf
        if new.cvss_score != existing.cvss_score:
            return new.cvss_score > existing.cvss_score
        # Prefer findings with longer descriptions (more informative)
        return len(new.description or "") > len(existing.description or "")

    def add_many(self, findings: list[Finding]) -> int:
        """Add multiple findings. Returns count of newly added (non-duplicate)."""
        added = 0
        for f in findings:
            if self.add(f):
                added += 1
        return added

    def get_findings(self, sort: bool = True) -> list[Finding]:
        """Get all collected findings, optionally sorted by severity."""
        if sort:
            return self._sort_findings(self._findings)
        return list(self._findings)

    def get_findings_within_budget(self) -> list[Finding]:
        """
        Get findings trimmed to stay within token budget.
        Prioritizes CRITICAL/HIGH severity findings.
        """
        sorted_findings = self._sort_findings(self._findings)
        result = []
        used_tokens = 0

        for finding in sorted_findings:
            finding_tokens = self._estimate_tokens(finding)
            if used_tokens + finding_tokens > self._token_budget:
                self._trimmed_count += 1
                continue
            result.append(finding)
            used_tokens += finding_tokens

        if self._trimmed_count > 0:
            logger.info(
                "Trimmed %d findings to stay within %d token budget",
                self._trimmed_count, self._token_budget,
            )

        return result

    def get_stats(self) -> dict:
        """Get collection statistics."""
        severity_counts = {}
        category_counts = {}
        language_counts = {}

        for f in self._findings:
            sev = f.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            cat = f.category.value
            category_counts[cat] = category_counts.get(cat, 0) + 1
            lang = f.language
            language_counts[lang] = language_counts.get(lang, 0) + 1

        return {
            "total_findings": len(self._findings),
            "duplicates_removed": self._total_before_dedup - len(self._findings) - self._merged_count,
            "merged_overlapping": self._merged_count,
            "trimmed_for_budget": self._trimmed_count,
            "by_severity": severity_counts,
            "by_category": category_counts,
            "by_language": language_counts,
        }

    def clear(self) -> None:
        """Reset the collector."""
        self._findings.clear()
        self._fingerprints.clear()
        self._location_map.clear()
        self._total_before_dedup = 0
        self._trimmed_count = 0
        self._merged_count = 0

    def _compute_fingerprint(self, finding: Finding) -> str:
        """Compute dedup fingerprint from file path, line, and rule ID."""
        raw = f"{finding.file_path}:{finding.line_number}:{finding.rule_id}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _sort_findings(self, findings: list[Finding]) -> list[Finding]:
        """Sort findings by severity (CRITICAL first), then confidence."""
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        confidence_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

        return sorted(
            findings,
            key=lambda f: (
                severity_order.get(f.severity, 5),
                confidence_order.get(f.confidence, 3),
            ),
        )

    def _estimate_tokens(self, finding: Finding) -> int:
        """Estimate token count for a finding in LLM context."""
        text_parts = [
            finding.title,
            finding.description,
            finding.code_snippet or "",
            finding.remediation or "",
            finding.file_path,
        ]
        total_chars = sum(len(p) for p in text_parts)
        return max(1, total_chars // CHARS_PER_TOKEN)
