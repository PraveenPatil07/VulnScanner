"""Rule regression test suite.

Each test defines a code sample and the expected detection (or lack thereof).
This ensures rules don't regress when patterns are modified.
"""

import pytest
import sys
from pathlib import Path

# Ensure backend is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.scanner.rule_engine import RuleEngine
from backend.scanner.ast_analyzers.python_ast import PythonASTAnalyzer
from backend.scanner.ast_analyzers.js_ast import JSASTAnalyzer


@pytest.fixture(scope="module")
def engine():
    e = RuleEngine()
    e.load_rules()
    return e


@pytest.fixture(scope="module")
def py_ast():
    return PythonASTAnalyzer()


@pytest.fixture(scope="module")
def js_ast():
    return JSASTAnalyzer()


# ═══════════════════════════════════════════════════════════════════════
# TRUE POSITIVES — Should detect
# ═══════════════════════════════════════════════════════════════════════

class TestPythonDetections:
    """Python rules should detect these vulnerable patterns."""

    def test_sql_injection_fstring(self, engine):
        code = '''
import sqlite3
def get_user(username):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cursor
'''
        matches = engine.scan_file(code, "app.py", "python")
        assert any("SQLI" in m.rule.id or "SQL" in m.rule.category for m in matches)

    def test_command_injection_os_system(self, engine):
        code = '''
import os
def run_cmd(user_input):
    os.system(f"ping {user_input}")
'''
        matches = engine.scan_file(code, "cmd.py", "python")
        assert any("CMDI" in m.rule.id or "COMMAND" in m.rule.category for m in matches)

    def test_hardcoded_password(self, engine):
        code = '''
DB_PASSWORD = "super_secret_password_123"
API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
'''
        matches = engine.scan_file(code, "config.py", "python")
        assert any("SECRET" in m.rule.id or "SECRET" in m.rule.category for m in matches)

    def test_ssrf_requests(self, engine):
        code = '''
import requests
def fetch_url(url):
    return requests.get(url)
'''
        matches = engine.scan_file(code, "fetch.py", "python")
        assert any("SSRF" in m.rule.id for m in matches)

    def test_eval_ast_detection(self, py_ast):
        code = '''
def process(data):
    result = eval(data)
    return result
'''
        matches = py_ast.analyze(code, "eval_test.py")
        assert len(matches) > 0
        assert any("COMMAND_INJECTION" in m.rule.category for m in matches)

    def test_pickle_deserialization(self, py_ast):
        code = '''
import pickle
def load_data(raw):
    return pickle.loads(raw)
'''
        matches = py_ast.analyze(code, "deser.py")
        assert any("DESERIALIZATION" in m.rule.category for m in matches)


class TestJavaScriptDetections:
    """JavaScript rules should detect these vulnerable patterns."""

    def test_xss_innerhtml(self, engine):
        code = '''
function render(userInput) {
    document.getElementById("output").innerHTML = userInput;
}
'''
        matches = engine.scan_file(code, "app.js", "javascript")
        assert any("XSS" in m.rule.id or "XSS" in m.rule.category for m in matches)

    def test_sql_injection(self, engine):
        code = '''
const mysql = require("mysql");
function getUser(name) {
    connection.query(`SELECT * FROM users WHERE name = '${name}'`);
}
'''
        matches = engine.scan_file(code, "db.js", "javascript")
        assert any("SQLI" in m.rule.id or "SQL" in m.rule.category for m in matches)

    def test_prototype_pollution(self, engine):
        code = '''
function merge(target, source) {
    for (let key in source) {
        target[key] = source[key];
    }
}
'''
        matches = engine.scan_file(code, "merge.js", "javascript")
        # Regex rule should catch this pattern
        assert any("PROTO" in m.rule.id or "POLLUTION" in m.rule.category for m in matches)

    def test_taint_flow_sql(self, js_ast):
        code = '''
const express = require("express");
app.get("/users", (req, res) => {
    const name = req.query.name;
    db.query("SELECT * FROM users WHERE name = '" + name + "'");
});
'''
        matches = js_ast.analyze(code, "taint.js")
        assert any("SQL" in m.rule.id for m in matches)

    def test_taint_flow_command(self, js_ast):
        code = '''
app.post("/run", (req, res) => {
    const cmd = req.body.command;
    child_process.exec(cmd);
});
'''
        matches = js_ast.analyze(code, "cmd.js")
        assert any("CMDI" in m.rule.id for m in matches)


class TestTerraformDetections:
    """Terraform rules should detect misconfigurations."""

    def test_public_s3_bucket(self, engine):
        code = '''
resource "aws_s3_bucket" "public" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}
'''
        matches = engine.scan_file(code, "main.tf", "terraform")
        assert any("TF-MISCONF-002" in m.rule.id for m in matches)

    def test_open_security_group(self, engine):
        code = '''
resource "aws_security_group_rule" "allow_all" {
  type        = "ingress"
  from_port   = 0
  to_port     = 65535
  cidr_blocks = ["0.0.0.0/0"]
}
'''
        matches = engine.scan_file(code, "sg.tf", "terraform")
        assert any("TF-MISCONF-003" in m.rule.id for m in matches)

    def test_hardcoded_aws_key(self, engine):
        code = '''
provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE1234"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY12345"
}
'''
        matches = engine.scan_file(code, "provider.tf", "terraform")
        assert any("TF-MISCONF-006" in m.rule.id or "SECRET" in m.rule.category for m in matches)

    def test_wildcard_iam(self, engine):
        code = '''
resource "aws_iam_policy" "admin" {
  policy = jsonencode({
    Statement = [{
      "Action" : "*",
      "Effect" : "Allow",
      "Resource" : "*"
    }]
  })
}
'''
        matches = engine.scan_file(code, "iam.tf", "terraform")
        assert any("TF-MISCONF-008" in m.rule.id for m in matches)


class TestDockerfileDetections:
    """Dockerfile rules should detect misconfigurations."""

    def test_user_root(self, engine):
        code = '''FROM ubuntu:20.04
RUN apt-get update
USER root
CMD ["app"]
'''
        matches = engine.scan_file(code, "Dockerfile", "dockerfile")
        assert any("DOCKER-MISCONF-001" in m.rule.id for m in matches)

    def test_latest_tag(self, engine):
        code = '''FROM node:latest
COPY . /app
'''
        matches = engine.scan_file(code, "Dockerfile", "dockerfile")
        assert any("DOCKER-MISCONF-002" in m.rule.id for m in matches)

    def test_hardcoded_secret_env(self, engine):
        code = '''FROM python:3.11
ENV DATABASE_PASSWORD=mysecretpassword123
CMD ["python", "app.py"]
'''
        matches = engine.scan_file(code, "Dockerfile", "dockerfile")
        assert any("DOCKER-MISCONF-005" in m.rule.id for m in matches)


class TestUniversalDetections:
    """Universal rules should detect cross-language patterns."""

    def test_aws_access_key(self, engine):
        code = '''
const config = {
    awsKey: "AKIAZ5GMXU4CTORFQ7P2"
};
'''
        matches = engine.scan_file(code, "config.js", "javascript")
        assert any("UNI-SECRET-001" in m.rule.id for m in matches)

    def test_github_pat(self, engine):
        code = '''
TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
'''
        matches = engine.scan_file(code, "deploy.py", "python")
        assert any("UNI-SECRET-002" in m.rule.id for m in matches)


# ═══════════════════════════════════════════════════════════════════════
# FALSE POSITIVES — Should NOT detect
# ═══════════════════════════════════════════════════════════════════════

class TestFalsePositivesSuppressed:
    """These patterns should NOT trigger findings."""

    def test_no_verify_attribute(self, engine):
        """self.no_verify = False should NOT match TLS disabled rule."""
        code = '''
class GitConfig:
    def __init__(self):
        self.no_verify = False
'''
        matches = engine.scan_file(code, "config.py", "python")
        tls_matches = [m for m in matches if "UNI-MISCONF-005" in m.rule.id]
        assert len(tls_matches) == 0

    def test_comment_innerhtml(self, engine):
        """innerHTML in a comment should NOT trigger XSS rule."""
        code = '''
// Don't use innerHTML for user content
// element.innerHTML = sanitized;
function render(text) {
    element.textContent = text;
}
'''
        matches = engine.scan_file(code, "safe.js", "javascript")
        xss_matches = [m for m in matches if "XSS" in m.rule.id]
        assert len(xss_matches) == 0

    def test_credential_helper_code(self, engine):
        """Code that handles credentials (like git credential helpers) should not flag."""
        code = '''
void credential_fill(struct credential *cred) {
    char *password = getenv("GIT_PASSWORD");
    if (password) cred->password = xstrdup(password);
}
'''
        matches = engine.scan_file(code, "credential.c", "c")
        secret_matches = [m for m in matches if "SECRET" in m.rule.id]
        assert len(secret_matches) == 0

    def test_example_key_not_flagged(self, engine):
        """Known example/placeholder keys should not be flagged."""
        code = '''
# Example configuration
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
'''
        matches = engine.scan_file(code, "example.py", "python")
        aws_matches = [m for m in matches if "UNI-SECRET-001" in m.rule.id]
        assert len(aws_matches) == 0

    def test_debug_in_c_not_flagged(self, engine):
        """DEBUG macro in C should not trigger debug-mode rule."""
        code = '''
#ifdef DEBUG
    printf("Debug info: %d\\n", value);
#endif
'''
        matches = engine.scan_file(code, "main.c", "c")
        debug_matches = [m for m in matches if "UNI-MISCONF-003" in m.rule.id]
        assert len(debug_matches) == 0

    def test_git_diff_path_not_traversal(self, engine):
        """File paths with '..' as git range notation should not flag."""
        code = '''
diff --git a/t/t4013/diff.diff_--abbrev_initial..side b/t/t4013/diff.diff_--abbrev_initial..side
--- a/t/t4013/diff.diff_--abbrev_initial..side
'''
        matches = engine.scan_file(code, "test.patch", "yaml")
        traversal_matches = [m for m in matches if "TRAVERSAL" in m.rule.category]
        assert len(traversal_matches) == 0


class TestCommentStripping:
    """Verify comment-aware scanning works correctly."""

    def test_python_comment_stripped(self, engine):
        code = '''
# password = "hardcoded_secret_123"
real_password = get_from_vault()
'''
        matches = engine.scan_file(code, "safe.py", "python")
        secret_matches = [m for m in matches if "SECRET" in m.rule.category]
        assert len(secret_matches) == 0

    def test_js_block_comment_stripped(self, engine):
        code = '''
/*
 * Dangerous patterns (documentation only):
 * eval(user_input)
 * document.innerHTML = data
 */
function safe() {
    return sanitize(input);
}
'''
        matches = engine.scan_file(code, "safe.js", "javascript")
        # Should not match patterns inside block comments
        xss_matches = [m for m in matches if "XSS" in m.rule.id]
        assert len(xss_matches) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
