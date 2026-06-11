"""Recursive file tree walker with language detection and binary filtering."""

import logging
import os
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

EXTENSION_MAP: dict[str, str] = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".jsx": "javascript",
    ".java": "java",
    ".php": "php", ".php3": "php", ".php5": "php", ".phtml": "php",
    ".go": "go",
    ".rb": "ruby", ".rake": "ruby",
    ".cs": "csharp",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp",
    ".c": "c",
    ".h": "c", ".hpp": "cpp",
    ".rs": "rust",
    ".kt": "kotlin",
    ".swift": "swift",
    ".yaml": "yaml", ".yml": "yaml",
    ".json": "json",
    ".xml": "xml",
    ".properties": "properties",
    ".tf": "terraform",
    ".dockerfile": "dockerfile",
    ".env": "yaml",
}

SKIP_DIRS: set[str] = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "vendor", "dist", "build", "target", ".idea", ".vscode",
    ".tox", ".mypy_cache", ".pytest_cache", "site-packages",
}

BINARY_MIME_PREFIXES = (
    "image/", "audio/", "video/",
    "application/octet-stream", "application/zip",
    "application/x-executable", "application/x-mach-binary",
    "application/x-sharedlib",
)

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


@dataclass
class FileEntry:
    """Represents a file ready for scanning."""
    path: Path
    rel_path: str
    language: str
    content: str
    size_bytes: int
    line_count: int


def _detect_language(file_path: Path) -> str | None:
    """Detect programming language from file extension or name."""
    name = file_path.name.lower()

    # Special cases for files without standard extensions
    if name == "dockerfile" or name.startswith("dockerfile."):
        return "dockerfile"
    if name == "makefile" or name == "gnumakefile":
        return "yaml"
    if name == ".env" or name.endswith(".env"):
        return "yaml"

    ext = file_path.suffix.lower()
    return EXTENSION_MAP.get(ext)


def _is_binary_fallback(file_path: Path) -> bool:
    """
    Fallback binary detection when python-magic is unavailable.
    Reads first 8KB and checks for non-printable byte ratio.
    """
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(8192)
        if not chunk:
            return False
        # Count non-printable, non-whitespace bytes
        non_printable = sum(
            1 for byte in chunk
            if byte < 8 or (byte > 13 and byte < 32 and byte != 27)
        )
        ratio = non_printable / len(chunk)
        return ratio > 0.30
    except (OSError, IOError):
        return True


def _is_binary(file_path: Path) -> bool:
    """Check if file is binary using python-magic or fallback."""
    try:
        import magic
        mime = magic.from_file(str(file_path), mime=True)
        if mime and any(mime.startswith(prefix) for prefix in BINARY_MIME_PREFIXES):
            return True
        return False
    except (ImportError, OSError):
        return _is_binary_fallback(file_path)


def _read_file_content(file_path: Path) -> str | None:
    """Read file content with encoding normalization."""
    try:
        # Try UTF-8 first
        content = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            # Try UTF-8 with BOM
            content = file_path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            try:
                # Fallback to latin-1 (never fails)
                content = file_path.read_text(encoding="latin-1")
            except Exception:
                return None

    # Normalize line endings
    content = content.replace("\r\n", "\n").replace("\r", "\n")
    return content


def walk_files(root_dir: Path) -> list[FileEntry]:
    """
    Walk directory tree and return FileEntry objects for scannable files.

    Applies:
    - Directory skip list
    - Language detection
    - Binary file detection
    - File size limits
    - Encoding normalization
    """
    entries: list[FileEntry] = []
    root_dir = root_dir.resolve()

    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Remove skip directories from traversal (modifies in-place)
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS and not d.startswith(".")
        ]

        for filename in filenames:
            file_path = Path(dirpath) / filename

            # Size check
            try:
                size = file_path.stat().st_size
            except OSError:
                continue

            if size > MAX_FILE_SIZE or size == 0:
                continue

            # Language detection
            language = _detect_language(file_path)
            if language is None:
                continue

            # Binary check
            if _is_binary(file_path):
                continue

            # Read content
            content = _read_file_content(file_path)
            if content is None:
                continue

            # Compute relative path with forward slashes
            try:
                rel_path = str(file_path.relative_to(root_dir)).replace("\\", "/")
            except ValueError:
                rel_path = file_path.name

            entries.append(FileEntry(
                path=file_path,
                rel_path=rel_path,
                language=language,
                content=content,
                size_bytes=size,
                line_count=content.count("\n") + 1,
            ))

    return entries
