"""Tests for the finding collector."""

import pytest

from backend.models.finding import Finding, Severity, VulnCategory
from backend.scanner.finding_collector import FindingCollector


def _make_finding(
    rule_id: str = "test-001",
    severity: Severity = Severity.HIGH,
    file_path: str = "app.py",
    line_number: int = 10,
    category: VulnCategory = VulnCategory.SQL_INJECTION,
) -> Finding:
    """Create a test finding."""
    return Finding(
        scan_id="test-scan-id",
        rule_id=rule_id,
        title=f"Test finding {rule_id}",
        description="Test description",
        severity=severity,
        category=category,
        cwe_id="CWE-89",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        file_path=file_path,
        line_number=line_number,
        column_start=0,
        column_end=20,
        code_snippet="vulnerable code here",
        match_text="vulnerable",
        confidence="HIGH",
        false_positive_risk="LOW",
        remediation="Fix it",
        references=[],
        language="python",
    )


class TestDeduplication:
    """Test finding deduplication."""

    def test_dedup_identical(self):
        """Test that identical findings are deduplicated."""
        collector = FindingCollector()
        f1 = _make_finding(rule_id="R1", file_path="a.py", line_number=5)
        f2 = _make_finding(rule_id="R1", file_path="a.py", line_number=5)

        assert collector.add(f1) is True
        assert collector.add(f2) is False
        assert len(collector.get_findings()) == 1

    def test_different_lines_not_deduped(self):
        """Test that same rule on different lines are separate."""
        collector = FindingCollector()
        f1 = _make_finding(rule_id="R1", file_path="a.py", line_number=5)
        f2 = _make_finding(rule_id="R1", file_path="a.py", line_number=10)

        collector.add(f1)
        collector.add(f2)
        assert len(collector.get_findings()) == 2

    def test_different_files_not_deduped(self):
        """Test that same rule in different files are separate."""
        collector = FindingCollector()
        f1 = _make_finding(rule_id="R1", file_path="a.py", line_number=5)
        f2 = _make_finding(rule_id="R1", file_path="b.py", line_number=5)

        collector.add(f1)
        collector.add(f2)
        assert len(collector.get_findings()) == 2


class TestSorting:
    """Test finding sorting by severity."""

    def test_sort_by_severity(self):
        """Test CRITICAL findings come first."""
        collector = FindingCollector()
        collector.add(_make_finding(rule_id="low", severity=Severity.LOW, line_number=1))
        collector.add(_make_finding(rule_id="crit", severity=Severity.CRITICAL, line_number=2))
        collector.add(_make_finding(rule_id="high", severity=Severity.HIGH, line_number=3))

        findings = collector.get_findings(sort=True)
        assert findings[0].severity == Severity.CRITICAL
        assert findings[1].severity == Severity.HIGH
        assert findings[2].severity == Severity.LOW


class TestTokenBudget:
    """Test token budget management."""

    def test_budget_limits_findings(self):
        """Test that token budget limits the number of findings returned."""
        collector = FindingCollector(token_budget=100)

        for i in range(50):
            collector.add(_make_finding(
                rule_id=f"R{i}",
                line_number=i + 1,
                severity=Severity.MEDIUM,
            ))

        budget_findings = collector.get_findings_within_budget()
        # Should be fewer than all findings
        assert len(budget_findings) < 50

    def test_budget_prioritizes_critical(self):
        """Test that critical findings are kept within budget."""
        collector = FindingCollector(token_budget=200)

        # Add many medium findings
        for i in range(20):
            collector.add(_make_finding(
                rule_id=f"med-{i}",
                line_number=i + 1,
                severity=Severity.MEDIUM,
            ))

        # Add one critical
        collector.add(_make_finding(
            rule_id="crit-1",
            line_number=100,
            severity=Severity.CRITICAL,
        ))

        budget_findings = collector.get_findings_within_budget()
        # Critical should be present
        critical_in_budget = [f for f in budget_findings if f.severity == Severity.CRITICAL]
        assert len(critical_in_budget) >= 1


class TestStats:
    """Test statistics generation."""

    def test_stats_accuracy(self):
        """Test that stats correctly count findings."""
        collector = FindingCollector()
        collector.add(_make_finding(rule_id="R1", severity=Severity.HIGH, line_number=1))
        collector.add(_make_finding(rule_id="R2", severity=Severity.CRITICAL, line_number=2))
        collector.add(_make_finding(rule_id="R1", line_number=1))  # duplicate

        stats = collector.get_stats()
        assert stats["total_findings"] == 2
        assert stats["duplicates_removed"] == 1
        assert stats["by_severity"]["HIGH"] == 1
        assert stats["by_severity"]["CRITICAL"] == 1
