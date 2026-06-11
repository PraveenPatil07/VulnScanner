"""Tests for the skill mapper."""

import pytest

from backend.models.finding import Finding, Severity, VulnCategory
from backend.scanner.rule_engine import RawMatch, Rule
from backend.scanner.skill_mapper import SkillMapper


@pytest.fixture
def mapper():
    """Create a configured SkillMapper."""
    m = SkillMapper()
    m.load_metadata()
    return m


@pytest.fixture
def sample_rule():
    """Create a sample rule for testing."""
    import re
    return Rule(
        id="PY-SQLI-001",
        name="SQL Injection via f-string",
        description="SQL query built with f-string interpolation",
        severity="HIGH",
        cwe="CWE-89",
        cvss_score=8.6,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        mitre_attack="T1190",
        nist_csf=["DE.CM-4", "PR.DS-5"],
        confidence="HIGH",
        false_positive_risk="LOW",
        remediation="Use parameterized queries",
        references=["https://cwe.mitre.org/data/definitions/89.html"],
        patterns=[re.compile(r"execute\(f\"")],
        false_positive_filters=[],
        language="python",
        category="SQL_INJECTION",
    )


@pytest.fixture
def sample_match(sample_rule):
    """Create a sample RawMatch."""
    return RawMatch(
        rule=sample_rule,
        file_path="app/db.py",
        line_number=42,
        line_content='cursor.execute(f"SELECT * FROM users WHERE id = {uid}")',
        context_before=["def get_user(uid):", "    conn = get_db()", "    cursor = conn.cursor()"],
        context_after=["    return cursor.fetchone()", "", "def list_users():"],
        match_text='execute(f"SELECT * FROM users WHERE id = {uid}")',
        column_start=11,
        column_end=58,
    )


class TestSkillMapper:
    """Tests for the SkillMapper."""

    def test_maps_severity(self, mapper, sample_match):
        """Test severity string maps to enum correctly."""
        finding = mapper.map_match(sample_match, "scan-123")
        assert finding.severity == Severity.HIGH

    def test_maps_category(self, mapper, sample_match):
        """Test category string maps to enum correctly."""
        finding = mapper.map_match(sample_match, "scan-123")
        assert finding.category == VulnCategory.SQL_INJECTION

    def test_preserves_rule_data(self, mapper, sample_match):
        """Test that rule metadata is preserved in finding."""
        finding = mapper.map_match(sample_match, "scan-123")
        assert finding.rule_id == "PY-SQLI-001"
        assert finding.cwe_id == "CWE-89"
        assert finding.cvss_score == 8.6
        assert finding.line_number == 42
        assert finding.file_path == "app/db.py"

    def test_builds_code_snippet(self, mapper, sample_match):
        """Test that code snippet includes context."""
        finding = mapper.map_match(sample_match, "scan-123")
        assert ">>>" in finding.code_snippet
        assert "cursor" in finding.code_snippet

    def test_maps_multiple(self, mapper, sample_match):
        """Test batch mapping."""
        findings = mapper.map_matches([sample_match, sample_match], "scan-123")
        assert len(findings) == 2
        assert all(isinstance(f, Finding) for f in findings)

    def test_unknown_category_fallback(self, mapper):
        """Test unknown category falls back to MISCONFIG."""
        import re
        rule = Rule(
            id="TEST-001", name="Test", description="Test",
            severity="MEDIUM", cwe="CWE-000", cvss_score=5.0,
            cvss_vector="", mitre_attack="", nist_csf=[],
            confidence="MEDIUM", false_positive_risk="LOW",
            remediation="Fix", references=[],
            patterns=[re.compile("x")], false_positive_filters=[],
            language="python", category="NONEXISTENT_CATEGORY",
        )
        match = RawMatch(
            rule=rule, file_path="test.py", line_number=1,
            line_content="x = 1", context_before=[], context_after=[],
            match_text="x",
        )
        finding = mapper.map_match(match, "scan-123")
        assert finding.category == VulnCategory.MISCONFIG
