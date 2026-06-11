"""Security-hardened ZIP extractor with path traversal prevention and bomb detection."""

import logging
import os
import unicodedata
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

DANGEROUS_EXTENSIONS = {".exe", ".dll", ".so", ".dylib", ".bin", ".elf"}
MAX_COMPRESSION_RATIO = 200


@dataclass
class ExtractResult:
    """Result of ZIP extraction operation."""
    extracted_files: list[Path] = field(default_factory=list)
    skipped_files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class ZipSecurityError(Exception):
    """Raised when a ZIP file contains security threats."""
    pass


async def extract_zip(
    zip_bytes: bytes,
    extract_to: Path,
    max_file_size_mb: int = 5,
    max_total_mb: int = 200,
    max_files: int = 10_000,
) -> ExtractResult:
    """
    Extract a ZIP file with comprehensive security controls.

    Security measures:
    - Path traversal prevention (Zip Slip)
    - File size limits (individual and total)
    - File count limits
    - Zip bomb detection (compression ratio check)
    - Symlink rejection
    - Dangerous extension blocking
    - Null byte injection prevention
    - Unicode normalization of filenames
    """
    import io

    result = ExtractResult()
    max_file_size = max_file_size_mb * 1024 * 1024
    max_total_size = max_total_mb * 1024 * 1024

    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile as e:
        result.errors.append(f"Invalid ZIP file: {e}")
        return result
    except RuntimeError as e:
        if "password" in str(e).lower() or "encrypted" in str(e).lower():
            result.errors.append("Password-protected ZIP files are not supported")
        else:
            result.errors.append(f"ZIP error: {e}")
        return result

    entries = zf.infolist()

    # File count check
    if len(entries) > max_files:
        raise ZipSecurityError(
            f"ZIP contains {len(entries)} entries, exceeding limit of {max_files}"
        )

    # Calculate total uncompressed size for bomb detection
    total_uncompressed = sum(e.file_size for e in entries)
    total_compressed = sum(e.compress_size for e in entries)

    if total_uncompressed > max_total_size:
        raise ZipSecurityError(
            f"Total uncompressed size ({total_uncompressed} bytes) exceeds "
            f"limit of {max_total_size} bytes"
        )

    # Global compression ratio check
    if total_compressed > 0 and total_uncompressed / total_compressed > MAX_COMPRESSION_RATIO:
        raise ZipSecurityError(
            f"ZIP compression ratio ({total_uncompressed / total_compressed:.0f}:1) "
            f"exceeds maximum allowed ratio of {MAX_COMPRESSION_RATIO}:1 (potential zip bomb)"
        )

    extract_to.mkdir(parents=True, exist_ok=True)
    extract_to_real = os.path.realpath(str(extract_to))

    for entry in entries:
        try:
            # Decode filename safely
            filename = entry.filename
            try:
                filename = filename.encode("cp437").decode("utf-8")
            except (UnicodeDecodeError, UnicodeEncodeError):
                pass

            # Strip null bytes
            filename = filename.replace("\x00", "")

            # Unicode normalization (NFC)
            filename = unicodedata.normalize("NFC", filename)

            # Skip directories
            if filename.endswith("/"):
                continue

            # Skip symlinks
            if entry.external_attr >> 28 == 0xA:
                result.skipped_files.append(f"{filename} (symlink)")
                continue

            # Check for path traversal (../ or ..\ as path component)
            parts = filename.replace("\\", "/").split("/")
            if any(part == ".." for part in parts) or filename.startswith("/") or filename.startswith("\\"):
                raise ZipSecurityError(
                    f"Path traversal detected in ZIP entry: {filename}"
                )

            # Check for Windows drive letters
            if len(filename) >= 2 and filename[1] == ":":
                raise ZipSecurityError(
                    f"Absolute path with drive letter in ZIP entry: {filename}"
                )

            # Resolve the target path and verify containment
            target_path = os.path.realpath(
                os.path.join(str(extract_to), filename)
            )
            if not target_path.startswith(extract_to_real):
                raise ZipSecurityError(
                    f"Path traversal detected: {filename} resolves outside extraction directory"
                )

            # Per-entry compression ratio check
            if entry.compress_size > 0:
                ratio = entry.file_size / entry.compress_size
                if ratio > MAX_COMPRESSION_RATIO:
                    raise ZipSecurityError(
                        f"Entry {filename} has compression ratio {ratio:.0f}:1 "
                        f"(potential zip bomb)"
                    )

            # File size check
            if entry.file_size > max_file_size:
                result.skipped_files.append(
                    f"{filename} (exceeds {max_file_size_mb}MB limit)"
                )
                continue

            # Dangerous extension check
            ext = os.path.splitext(filename)[1].lower()
            if ext in DANGEROUS_EXTENSIONS:
                result.skipped_files.append(f"{filename} (dangerous extension: {ext})")
                continue

            # Extract the file
            target = Path(target_path)
            target.parent.mkdir(parents=True, exist_ok=True)

            data = zf.read(entry.filename)

            # Verify actual size matches declared size (additional bomb check)
            if len(data) > max_file_size:
                result.skipped_files.append(
                    f"{filename} (actual size exceeds {max_file_size_mb}MB limit)"
                )
                continue

            target.write_bytes(data)
            result.extracted_files.append(target)

        except ZipSecurityError:
            raise
        except Exception as e:
            result.errors.append(f"Error extracting {entry.filename}: {e}")
            logger.warning("Error extracting %s: %s", entry.filename, e)

    zf.close()
    return result
