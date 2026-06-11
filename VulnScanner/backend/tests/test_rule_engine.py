"""Tests for the YAML rule engine."""

from pathlib import Path

import pytest

from backend.scanner.rule_engine import RuleEngine


@pytest.fixture
def rule_engine():
    """Create and load a rule engine instance."""
    engine = RuleEngine()
    engine.load_rules()
    return engine


class TestRuleEngineLoading:
    """Tests for rule loading."""

    def test_loads_rules(self, rule_engine):
        """Test that rules are loaded from YAML files."""
        assert rule_engine.rule_count > 0

    def test_loads_multiple_languages(self, rule_engine):
        """Test rules load for multiple languages."""
        assert len(rule_engine.languages) >= 5

    def test_python_rules_exist(self, rule_engine):
        """Test Python rules are loaded."""
        assert "python" in rule_engine.languages

    def test_javascript_rules_exist(self, rule_engine):
        """Test JavaScript rules are loaded."""
        assert "javascript" in rule_engine.languages


class TestRuleEngineScanning:
    """Tests for pattern matching."""

    def test_detects_python_sqli(self, rule_engine, python_vuln_code):
        """Test detection of SQL injection in Python."""
        # Need code with SQL injection
        sqli_code = '''
import sqlite3
conn = sqlite3.connect("db.sqlite")
cursor = conn.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
'''
        matches = rule_engine.scan_file(sqli_code, "app.py", "python")
        sqli_matches = [m for m in matches if "SQL" in m.rule.category.upper()]
        assert len(sqli_matches) >= 1

    def test_detects_command_injection(self, rule_engine):
        """Test detection of command injection."""
        code = '''
import os
import subprocess
os.system(f"rm -rf {user_input}")
subprocess.call(user_input, shell=True)
'''
        matches = rule_engine.scan_file(code, "app.py", "python")
        cmd_matches = [m for m in matches if "COMMAND" in m.rule.category.upper()]
        assert len(cmd_matches) >= 1

    def test_detects_hardcoded_secrets(self, rule_engine):
        """Test detection of hardcoded secrets."""
        code = '''
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
password = "super_secret_password_123"
'''
        matches = rule_engine.scan_file(code, "config.py", "python")
        secret_matches = [m for m in matches if "SECRET" in m.rule.category.upper()]
        assert len(secret_matches) >= 1

    def test_detects_javascript_xss(self, rule_engine, javascript_vuln_code):
        """Test detection of XSS in JavaScript."""
        matches = rule_engine.scan_file(javascript_vuln_code, "app.js", "javascript")
        xss_matches = [m for m in matches if "XSS" in m.rule.category.upper()]
        assert len(xss_matches) >= 1

    def test_no_matches_on_safe_code(self, rule_engine):
        """Test that safe code produces no/minimal matches."""
        safe_code = '''
from sqlalchemy import select
from sqlalchemy.orm import Session

def get_user(session: Session, user_id: int):
    stmt = select(User).where(User.id == user_id)
    return session.execute(stmt).scalar_one_or_none()
'''
        matches = rule_engine.scan_file(safe_code, "safe.py", "python")
        # Should produce few or no matches
        high_confidence = [m for m in matches if m.rule.confidence == "HIGH"]
        assert len(high_confidence) == 0

    def test_context_extraction(self, rule_engine):
        """Test that context lines are extracted correctly."""
        code = "line1\nline2\nline3\nos.system(cmd)\nline5\nline6\nline7"
        matches = rule_engine.scan_file(code, "test.py", "python")
        if matches:
            m = matches[0]
            assert len(m.context_before) <= 3
            assert len(m.context_after) <= 3

    def test_line_numbers_correct(self, rule_engine):
        """Test that line numbers are 1-indexed."""
        code = "\n\n\nos.system(user_input)\n"
        matches = rule_engine.scan_file(code, "test.py", "python")
        cmd_matches = [m for m in matches if "COMMAND" in m.rule.category.upper()]
        if cmd_matches:
            assert cmd_matches[0].line_number == 4

    def test_universal_rules_apply(self, rule_engine):
        """Test that universal rules match regardless of language."""
        code = 'AKIA1234567890ABCDEF = "secret"'
        py_matches = rule_engine.scan_file(code, "test.py", "python")
        js_matches = rule_engine.scan_file(code, "test.js", "javascript")
        # Universal rules should fire for both
        assert len(py_matches) >= 1 or len(js_matches) >= 1
