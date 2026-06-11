"""High-Level Design document parser for image/PDF conversion."""

import base64
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

MAX_HLD_SIZE_MB = 20
MAX_HLD_SIZE = MAX_HLD_SIZE_MB * 1024 * 1024

SUPPORTED_IMAGE_TYPES: dict[str, str] = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".bmp": "image/bmp",
    ".svg": "image/svg+xml",
}

SUPPORTED_DOC_TYPES: dict[str, str] = {
    ".pdf": "application/pdf",
}


def parse_hld(file_path: Path) -> dict | None:
    """
    Parse an HLD (High-Level Design) document for inclusion in LLM context.

    Converts images and PDFs to base64 for multi-modal LLM consumption.
    Returns None if the file is unsupported or too large.

    Returns:
        dict with keys: type, media_type, data (base64), filename, size_bytes
    """
    ext = file_path.suffix.lower()

    if ext not in SUPPORTED_IMAGE_TYPES and ext not in SUPPORTED_DOC_TYPES:
        logger.debug("Unsupported HLD format: %s", ext)
        return None

    try:
        size = file_path.stat().st_size
    except OSError as e:
        logger.warning("Cannot read HLD file %s: %s", file_path, e)
        return None

    if size > MAX_HLD_SIZE:
        logger.warning(
            "HLD file %s too large (%d bytes, limit %d bytes)",
            file_path, size, MAX_HLD_SIZE,
        )
        return None

    if size == 0:
        return None

    try:
        raw_data = file_path.read_bytes()
    except (OSError, IOError) as e:
        logger.warning("Cannot read HLD file %s: %s", file_path, e)
        return None

    encoded = base64.b64encode(raw_data).decode("ascii")

    media_type = (
        SUPPORTED_IMAGE_TYPES.get(ext)
        or SUPPORTED_DOC_TYPES.get(ext)
    )

    doc_type = "image" if ext in SUPPORTED_IMAGE_TYPES else "document"

    return {
        "type": doc_type,
        "media_type": media_type,
        "data": encoded,
        "filename": file_path.name,
        "size_bytes": size,
    }
