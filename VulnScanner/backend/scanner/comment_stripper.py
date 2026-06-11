"""Language-aware comment stripping to reduce false positives.

Strips comments from source code before regex scanning so that patterns
don't match inside comments. Preserves line numbers by replacing comment
content with spaces (keeping newlines intact).
"""

import re
from functools import lru_cache

# Language -> (single_line_comment_patterns, block_comment_start, block_comment_end)
COMMENT_SYNTAX: dict[str, dict] = {
    "python": {
        "line": [r"#"],
        "block": [('"""', '"""'), ("'''", "'''")],
    },
    "javascript": {
        "line": [r"//"],
        "block": [("/*", "*/")],
    },
    "typescript": {
        "line": [r"//"],
        "block": [("/*", "*/")],
    },
    "java": {
        "line": [r"//"],
        "block": [("/*", "*/")],
    },
    "csharp": {
        "line": [r"//"],
        "block": [("/*", "*/")],
    },
    "go": {
        "line": [r"//"],
        "block": [("/*", "*/")],
    },
    "rust": {
        "line": [r"//"],
        "block": [("/*", "*/")],
    },
    "c": {
        "line": [r"//"],
        "block": [("/*", "*/")],
    },
    "cpp": {
        "line": [r"//"],
        "block": [("/*", "*/")],
    },
    "php": {
        "line": [r"//", r"#"],
        "block": [("/*", "*/")],
    },
    "ruby": {
        "line": [r"#"],
        "block": [("=begin", "=end")],
    },
    "kotlin": {
        "line": [r"//"],
        "block": [("/*", "*/")],
    },
    "swift": {
        "line": [r"//"],
        "block": [("/*", "*/")],
    },
    "terraform": {
        "line": [r"#", r"//"],
        "block": [("/*", "*/")],
    },
    "yaml": {
        "line": [r"#"],
        "block": [],
    },
}


def _replace_with_spaces(text: str) -> str:
    """Replace text with spaces, preserving newlines for line-number stability."""
    return "".join("\n" if ch == "\n" else " " for ch in text)


def strip_comments(content: str, language: str) -> str:
    """
    Strip comments from source code while preserving line numbers.

    Comments are replaced with whitespace so that line offsets remain stable
    for reporting. This prevents regex rules from matching inside comments.

    Args:
        content: The raw source file content.
        language: The programming language identifier.

    Returns:
        Content with comments replaced by spaces (newlines preserved).
    """
    syntax = COMMENT_SYNTAX.get(language)
    if not syntax:
        return content

    # Use a state-machine approach for accurate parsing
    result = list(content)
    i = 0
    length = len(content)

    while i < length:
        # Check if we're inside a string literal (skip strings)
        if content[i] in ('"', "'"):
            quote_char = content[i]
            # Check for triple-quote (Python)
            if language == "python" and i + 2 < length and content[i:i+3] in ('"""', "'''"):
                triple = content[i:i+3]
                # Check if this is actually a block comment (not assigned)
                # For Python, triple-quoted strings on their own line = docstring/comment
                # We'll check if it's at the start of a statement
                line_start = content.rfind("\n", 0, i) + 1
                prefix = content[line_start:i].strip()
                if prefix == "" or prefix.endswith("="):
                    # Standalone triple-quote or assigned - skip as string
                    end_idx = content.find(triple, i + 3)
                    if end_idx == -1:
                        break
                    i = end_idx + 3
                    continue
                else:
                    i += 3
                    continue
            # Regular string - skip to end
            i += 1
            while i < length:
                if content[i] == "\\" and i + 1 < length:
                    i += 2  # Skip escaped char
                elif content[i] == quote_char:
                    i += 1
                    break
                elif content[i] == "\n":
                    # Unterminated string - stop
                    break
                else:
                    i += 1
            continue

        # Check for block comments
        matched_block = False
        for block_start, block_end in syntax.get("block", []):
            if content[i:i+len(block_start)] == block_start:
                # For Python triple quotes used as comments, handle specially
                end_idx = content.find(block_end, i + len(block_start))
                if end_idx == -1:
                    # Unterminated block comment - blank to end
                    for j in range(i, length):
                        if content[j] != "\n":
                            result[j] = " "
                    i = length
                else:
                    end_pos = end_idx + len(block_end)
                    for j in range(i, end_pos):
                        if content[j] != "\n":
                            result[j] = " "
                    i = end_pos
                matched_block = True
                break

        if matched_block:
            continue

        # Check for line comments
        matched_line = False
        for line_prefix in syntax.get("line", []):
            prefix_len = len(line_prefix)
            if content[i:i+prefix_len] == line_prefix:
                # Blank from here to end of line
                j = i
                while j < length and content[j] != "\n":
                    result[j] = " "
                    j += 1
                i = j
                matched_line = True
                break

        if matched_line:
            continue

        i += 1

    return "".join(result)


@lru_cache(maxsize=256)
def get_comment_line_set(content: str, language: str) -> frozenset[int]:
    """
    Return the set of 0-based line numbers that are comment-only lines.

    This is useful for quickly checking if a match is on a comment line
    without fully stripping the file.
    """
    stripped = strip_comments(content, language)
    original_lines = content.split("\n")
    stripped_lines = stripped.split("\n")

    comment_lines: set[int] = set()
    for idx, (orig, stripped_line) in enumerate(zip(original_lines, stripped_lines)):
        # If the original had non-whitespace but stripped is all whitespace -> comment line
        if orig.strip() and not stripped_line.strip():
            comment_lines.add(idx)

    return frozenset(comment_lines)
