"""Regression tests for false positive reduction.

These tests use known-safe code patterns that MUST NOT produce
high-confidence findings. If any test fails, the scanner is
generating false positives.
"""

import pytest

from backend.scanner.rule_engine import RuleEngine
from backend.scanner.ast_analyzers.python_ast import PythonASTAnalyzer


@pytest.fixture
def engine():
    e = RuleEngine()
    e.load_rules()
    return e


@pytest.fixture
def py_ast():
    return PythonASTAnalyzer()


class TestCredentialHelperFalsePositives:
    """Credential helper programs should NOT be flagged for hardcoded secrets."""

    def test_credential_helper_not_flagged(self, engine):
        """git-credential-libsecret.c pattern should not trigger HARDCODED_SECRETS."""
        code = '''
if (g_str_has_prefix(parts[i], "oauth_refresh_token=")) {
    g_free(c->oauth_refresh_token);
    c->oauth_refresh_token = g_strdup(&parts[i][20]);
}
'''
        matches = engine.scan_file(
            code,
            "contrib/credential/libsecret/git-credential-libsecret.c",
            "c",
        )
        secret_matches = [
            m for m in matches
            if m.rule.category == "HARDCODED_SECRETS" and m.rule.confidence == "HIGH"
        ]
        assert len(secret_matches) == 0

    def test_keychain_helper_not_flagged(self, engine):
        """Keychain helper files should not trigger secrets detection."""
        code = '''
CFDataAppendBytes(data,
    (const UInt8 *)STRING_WITH_LENGTH("\\noauth_refresh_token="));
'''
        matches = engine.scan_file(
            code,
            "contrib/credential/osxkeychain/git-credential-osxkeychain.c",
            "c",
        )
        secret_matches = [
            m for m in matches
            if m.rule.category == "HARDCODED_SECRETS" and m.rule.confidence == "HIGH"
        ]
        assert len(secret_matches) == 0


class TestSSTIFalsePositives:
    """string.Template should NOT be flagged as Jinja2 SSTI."""

    def test_string_template_not_flagged(self, engine):
        """string.Template usage should not trigger SSTI rules."""
        code = '''
from string import Template

class Module:
    class InfoTemplate(Template):
        pass

t = Module.InfoTemplate(module)
result = t.render()
'''
        matches = engine.scan_file(code, "generate.py", "python")
        ssti_matches = [m for m in matches if m.rule.category == "SSTI"]
        assert len(ssti_matches) == 0

    def test_jinja2_template_still_flagged(self, engine):
        """Jinja2 Template with user input SHOULD still be flagged."""
        code = '''
from jinja2 import Template

t = Template(request.form['template'])
result = t.render()
'''
        matches = engine.scan_file(code, "app.py", "python")
        ssti_matches = [m for m in matches if m.rule.category == "SSTI"]
        assert len(ssti_matches) >= 1


class TestCommandInjectionTaintAwareness:
    """Hardcoded string arguments should be LOW severity, not HIGH."""

    def test_hardcoded_os_system_is_low_severity(self, py_ast):
        """os.system with hardcoded string should be LOW severity."""
        code = '''
import os

def rebase():
    if os.system("git update-index --refresh") != 0:
        die("Files are modified")
'''
        matches = py_ast.analyze(code, "git-p4.py")
        cmd_matches = [m for m in matches if "os.system" in m.match_text]
        if cmd_matches:
            assert cmd_matches[0].rule.severity == "LOW"
            assert cmd_matches[0].rule.confidence == "LOW"

    def test_dynamic_os_system_is_high_severity(self, py_ast):
        """os.system with variable should be HIGH severity."""
        code = '''
import os

def run_cmd(user_cmd):
    os.system(user_cmd)
'''
        matches = py_ast.analyze(code, "app.py")
        cmd_matches = [m for m in matches if "os.system" in m.match_text]
        if cmd_matches:
            assert cmd_matches[0].rule.severity == "HIGH"
            assert cmd_matches[0].rule.confidence == "HIGH"


class TestDeduplication:
    """Test that overlapping regex and AST findings are deduplicated."""

    def test_same_location_same_category_deduped(self):
        """Two findings at same file:line:category should be merged."""
        from backend.scanner.finding_collector import FindingCollector
        from backend.models.finding import Finding, Severity, VulnCategory

        collector = FindingCollector()

        # Simulate regex finding
        f1 = Finding(
            scan_id="test",
            rule_id="PY-CMDI-002",
            category=VulnCategory.COMMAND_INJECTION,
            severity=Severity.HIGH,
            title="os.system() command execution",
            description="os.system() regex match",
            file_path="app.py",
            line_number=10,
            code_snippet="os.system(cmd)",
            match_text="os.system(",
            cwe_id="CWE-78",
            cvss_score=9.8,
            confidence="HIGH",
            false_positive_risk="LOW",
            language="python",
        )

        # Simulate AST finding at same location
        f2 = Finding(
            scan_id="test",
            rule_id="python-ast-command_injection-10",
            category=VulnCategory.COMMAND_INJECTION,
            severity=Severity.HIGH,
            title="AST: Dangerous call: os.system",
            description="AST-detected os.system with variable arg",
            file_path="app.py",
            line_number=10,
            code_snippet="os.system(cmd)",
            match_text="os.system(cmd)",
            cwe_id="CWE-78",
            cvss_score=6.0,
            confidence="HIGH",
            false_positive_risk="LOW",
            language="python",
        )

        collector.add(f1)
        collector.add(f2)

        findings = collector.get_findings()
        # Should be merged into 1, keeping the higher CVSS one
        assert len(findings) == 1
        assert findings[0].cvss_score == 9.8


class TestSafeCodeProducesNoFindings:
    """Known-safe code patterns that should not produce HIGH confidence findings."""

    def test_safe_python_orm_code(self, engine):
        """SQLAlchemy ORM code should not trigger SQL injection."""
        code = '''
from sqlalchemy import select
from sqlalchemy.orm import Session

def get_user(session: Session, user_id: int):
    stmt = select(User).where(User.id == user_id)
    return session.execute(stmt).scalar_one_or_none()
'''
        matches = engine.scan_file(code, "safe_orm.py", "python")
        high_conf = [m for m in matches if m.rule.confidence == "HIGH"]
        assert len(high_conf) == 0

    def test_safe_subprocess_list_args(self, engine):
        """subprocess.run with list args and shell=False should not trigger."""
        code = '''
import subprocess

def run_safe(filename):
    result = subprocess.run(["git", "log", "--oneline", filename], capture_output=True)
    return result.stdout
'''
        matches = engine.scan_file(code, "safe_subprocess.py", "python")
        cmd_matches = [
            m for m in matches
            if m.rule.category == "COMMAND_INJECTION" and m.rule.confidence == "HIGH"
        ]
        assert len(cmd_matches) == 0
