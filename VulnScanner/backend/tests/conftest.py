"""Pytest configuration and shared fixtures."""

import io
import os
import tempfile
import zipfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test extractions."""
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp)


@pytest.fixture
def sample_zip_bytes():
    """Create a simple ZIP file in memory with sample source code."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("app.py", '''
import os
import subprocess

def run_command(user_input):
    # Vulnerable: command injection
    os.system(f"echo {user_input}")
    subprocess.call(user_input, shell=True)

def get_file(filename):
    # Vulnerable: path traversal
    path = "/var/data/" + filename
    return open(path).read()

password = "hardcoded_secret_123"
''')
        zf.writestr("utils/db.py", '''
import sqlite3

def query_user(conn, username):
    # Vulnerable: SQL injection
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cursor.fetchall()
''')
        zf.writestr("config.js", '''
const API_KEY = "AKIA1234567890ABCDEF";
const password = "super_secret_password";

function getUser(id) {
    // Vulnerable: SQL injection
    const query = "SELECT * FROM users WHERE id = " + id;
    return db.query(query);
}
''')
    return buf.getvalue()


@pytest.fixture
def malicious_zip_bytes():
    """Create a ZIP with path traversal attempt."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../etc/passwd", "root:x:0:0:root:/root:/bin/bash")
    return buf.getvalue()


@pytest.fixture
def empty_zip_bytes():
    """Create an empty ZIP file."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        pass
    return buf.getvalue()


@pytest.fixture
def large_file_zip_bytes():
    """Create a ZIP with a file exceeding size limits."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Create a 6MB file (exceeds 5MB default)
        zf.writestr("large.py", "x = 1\n" * 1_000_000)
    return buf.getvalue()


@pytest.fixture
def python_vuln_code():
    """Sample vulnerable Python code."""
    return '''
import os
import pickle
import subprocess
import yaml

def dangerous_eval(user_input):
    result = eval(user_input)
    return result

def unsafe_pickle(data):
    obj = pickle.loads(data)
    return obj

def command_exec(cmd):
    subprocess.call(cmd, shell=True)
    os.system(cmd)

def unsafe_yaml(content):
    data = yaml.load(content)
    return data

SECRET_KEY = "my-super-secret-key-12345"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
'''


@pytest.fixture
def javascript_vuln_code():
    """Sample vulnerable JavaScript code."""
    return '''
const mysql = require('mysql');

function getUser(userId) {
    const query = "SELECT * FROM users WHERE id = '" + userId + "'";
    return db.query(query);
}

function renderPage(userInput) {
    document.innerHTML = userInput;
    document.write(userInput);
}

const API_SECRET = "ghp_1234567890abcdefABCDEF1234567890abcd";
const password = "admin123";
'''
