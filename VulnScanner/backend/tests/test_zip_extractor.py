"""Tests for the ZIP extractor security features."""

import io
import zipfile
from pathlib import Path

import pytest

from backend.scanner.zip_extractor import ExtractResult, ZipSecurityError, extract_zip


@pytest.mark.asyncio
async def test_extract_basic_zip(sample_zip_bytes, temp_dir):
    """Test basic ZIP extraction works."""
    result = await extract_zip(sample_zip_bytes, temp_dir)
    assert isinstance(result, ExtractResult)
    assert len(result.extracted_files) >= 3
    assert len(result.errors) == 0


@pytest.mark.asyncio
async def test_path_traversal_blocked(malicious_zip_bytes, temp_dir):
    """Test that path traversal attempts are blocked."""
    with pytest.raises(ZipSecurityError, match="[Pp]ath traversal"):
        await extract_zip(malicious_zip_bytes, temp_dir)


@pytest.mark.asyncio
async def test_empty_zip(empty_zip_bytes, temp_dir):
    """Test empty ZIP extraction."""
    result = await extract_zip(empty_zip_bytes, temp_dir)
    assert len(result.extracted_files) == 0
    assert len(result.errors) == 0


@pytest.mark.asyncio
async def test_file_size_limit(large_file_zip_bytes, temp_dir):
    """Test files exceeding size limit are skipped."""
    result = await extract_zip(large_file_zip_bytes, temp_dir)
    assert len(result.skipped_files) >= 1


@pytest.mark.asyncio
async def test_invalid_zip(temp_dir):
    """Test invalid ZIP data is handled gracefully."""
    result = await extract_zip(b"not a zip file", temp_dir)
    assert len(result.errors) >= 1


@pytest.mark.asyncio
async def test_zip_bomb_detection(temp_dir):
    """Test that zip bombs are detected."""
    # Create a ZIP with extreme compression ratio
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Highly compressible data
        zf.writestr("bomb.txt", "\x00" * (100 * 1024 * 1024))

    with pytest.raises(ZipSecurityError, match="(ratio|bomb|size)"):
        await extract_zip(buf.getvalue(), temp_dir)


@pytest.mark.asyncio
async def test_file_count_limit(temp_dir):
    """Test file count limits."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(100):
            zf.writestr(f"file_{i}.txt", f"content {i}")

    # Should succeed with default limit (10000)
    result = await extract_zip(buf.getvalue(), temp_dir)
    assert len(result.extracted_files) == 100

    # Should fail with low limit
    with pytest.raises(ZipSecurityError, match="exceeding limit"):
        await extract_zip(buf.getvalue(), temp_dir, max_files=50)


@pytest.mark.asyncio
async def test_dangerous_extensions_skipped(temp_dir):
    """Test that dangerous file extensions are skipped."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("safe.py", "print('hello')")
        zf.writestr("evil.exe", b"\x00" * 100)
        zf.writestr("malware.dll", b"\x00" * 100)

    result = await extract_zip(buf.getvalue(), temp_dir)
    assert len(result.extracted_files) == 1
    assert len(result.skipped_files) == 2
