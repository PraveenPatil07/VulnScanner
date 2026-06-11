"""Tests for the API endpoints."""

import io
import zipfile

import pytest
from httpx import ASGITransport, AsyncClient

from backend.main import app


@pytest.fixture
def sample_upload_zip():
    """Create a ZIP for upload testing."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("vulnerable.py", '''
import os
password = "hardcoded123"
os.system(f"rm {user_input}")
''')
    return buf.getvalue()


@pytest.mark.asyncio
async def test_health_endpoint():
    """Test /health returns healthy status."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


@pytest.mark.asyncio
async def test_scan_upload(sample_upload_zip):
    """Test POST /api/scan accepts a ZIP file."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/scan",
            files={"file": ("test.zip", sample_upload_zip, "application/zip")},
        )
    assert response.status_code == 200
    data = response.json()
    assert "scan_id" in data
    assert data["status"] == "SCANNING"


@pytest.mark.asyncio
async def test_scan_rejects_non_zip():
    """Test POST /api/scan rejects non-ZIP files."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/scan",
            files={"file": ("test.txt", b"not a zip", "text/plain")},
        )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_scan_not_found():
    """Test GET /api/scan/{id}/result returns 404 for unknown scan."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/scan/nonexistent-id/result")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_sarif_not_found():
    """Test GET /api/scan/{id}/sarif returns 404 for unknown scan."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/scan/nonexistent-id/sarif")
    assert response.status_code == 404
