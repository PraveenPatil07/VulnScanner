"""YAML rule engine: loads rules, matches patterns, extracts context."""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .comment_stripper import strip_comments

logger = logging.getLogger(__name__)

FLAG_MAP = {
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
    "IGNORECASE": re.IGNORECASE,
    "VERBOSE": re.VERBOSE,
}

RULES_DIR = Path(__file__).parent.parent / "rules"


@dataclass
class Rule:
    """Compiled rule with patterns ready for matching."""
    id: str
    name: str
    description: str
    severity: str
    cwe: str
    cvss_score: float
    cvss_vector: str
    mitre_attack: str
    nist_csf: list[str]
    confidence: str
    false_positive_risk: str
    remediation: str
    references: list[str]
    patterns: list[re.Pattern]
    false_positive_filters: list[re.Pattern]
    language: str
    category: str
    owasp_top10: str = ""
    skip_languages: list[str] = field(default_factory=list)


@dataclass
class RawMatch:
    """A raw pattern match from scanning."""
    rule: Rule
    file_path: str
    line_number: int
    line_content: str
    context_before: list[str]
    context_after: list[str]
    match_text: str
    column_start: int = 0
    column_end: int = 0


class RuleEngine:
    """Loads YAML rules and matches them against file content."""

    # Class-level rule cache shared across instances in the same process
    _cache: dict[str, tuple[dict[str, list], list]] | None = None
    _cache_mtime: float = 0.0

    def __init__(self, rules_dir: Path | None = None):
        self._rules_dir = rules_dir or RULES_DIR
        self._rules: dict[str, list[Rule]] = {}  # language -> rules
        self._universal_rules: list[Rule] = []
        self._loaded = False

    def load_rules(self) -> int:
        """Load all YAML rule files. Returns total rule count. Uses class-level cache."""
        # Check if rules dir mtime changed (hot-reload support)
        try:
            current_mtime = max(
                f.stat().st_mtime
                for f in self._rules_dir.rglob("*.yaml")
            ) if self._rules_dir.exists() else 0.0
        except (ValueError, OSError):
            current_mtime = 0.0

        if (
            RuleEngine._cache is not None
            and current_mtime <= RuleEngine._cache_mtime
            and self._rules_dir == RULES_DIR
        ):
            self._rules, self._universal_rules = RuleEngine._cache  # type: ignore
            self._loaded = True
            total = sum(len(r) for r in self._rules.values()) + len(self._universal_rules)
            logger.info("Loaded %d rules from cache", total)
            return total

        total = 0
        if not self._rules_dir.exists():
            logger.warning("Rules directory not found: %s", self._rules_dir)
            return 0

        for lang_dir in self._rules_dir.iterdir():
            if not lang_dir.is_dir():
                continue

            language = lang_dir.name

            for rule_file in lang_dir.glob("*.yaml"):
                try:
                    rules = self._load_rule_file(rule_file, language)
                    if language == "universal":
                        self._universal_rules.extend(rules)
                    else:
                        self._rules.setdefault(language, []).extend(rules)
                    total += len(rules)
                except Exception as e:
                    logger.error("Error loading %s: %s", rule_file, e)

        self._loaded = True
        # Store in class-level cache for reuse across instances
        if self._rules_dir == RULES_DIR:
            RuleEngine._cache = (self._rules, self._universal_rules)
            RuleEngine._cache_mtime = current_mtime
        logger.info("Loaded %d rules across %d languages", total, len(self._rules))
        return total

    def _load_rule_file(self, path: Path, language: str) -> list[Rule]:
        """Parse a single YAML rule file into Rule objects."""
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data or "rules" not in data:
            return []

        file_language = data.get("language", language)
        category = data.get("category", "")
        rules = []

        for rule_data in data["rules"]:
            try:
                rule = self._compile_rule(rule_data, file_language, category)
                if rule:
                    rules.append(rule)
            except Exception as e:
                logger.warning(
                    "Error compiling rule %s: %s",
                    rule_data.get("id", "unknown"), e,
                )

        return rules

    def _compile_rule(self, data: dict, language: str, category: str) -> Rule | None:
        """Compile a single rule dict into a Rule object with compiled patterns."""
        patterns = []
        for p in data.get("patterns", []):
            if p.get("type") != "regex":
                continue
            flags = 0
            for flag_name in p.get("flags", []):
                flags |= FLAG_MAP.get(flag_name, 0)
            try:
                compiled = re.compile(p["pattern"], flags)
                patterns.append(compiled)
            except re.error as e:
                logger.warning("Invalid regex in rule %s: %s", data.get("id"), e)
                continue

        if not patterns:
            return None

        # Compile false positive filters
        fp_filters = []
        for fp in data.get("false_positive_filters", []):
            try:
                fp_filters.append(re.compile(fp, re.MULTILINE))
            except re.error:
                pass

        return Rule(
            id=data["id"],
            name=data["name"],
            description=data["description"],
            severity=data["severity"],
            cwe=data.get("cwe", ""),
            cvss_score=float(data.get("cvss_score", 0)),
            cvss_vector=data.get("cvss_vector", ""),
            mitre_attack=data.get("mitre_attack", ""),
            nist_csf=data.get("nist_csf", []),
            confidence=data.get("confidence", "MEDIUM"),
            false_positive_risk=data.get("false_positive_risk", "MEDIUM"),
            remediation=data.get("remediation", ""),
            references=data.get("references", []),
            patterns=patterns,
            false_positive_filters=fp_filters,
            language=language,
            category=category,
            owasp_top10=data.get("owasp_top10", ""),
            skip_languages=data.get("skip_languages", []),
        )

    def scan_file(self, content: str, file_path: str, language: str) -> list[RawMatch]:
        """
        Scan file content against all applicable rules.

        Applies language-specific rules + universal rules.
        Strips comments before matching to reduce false positives.
        Filters out false positives.
        Extracts ±3 lines of context.
        """
        if not self._loaded:
            self.load_rules()

        matches = []
        lines = content.split("\n")

        # Strip comments for matching (preserves line numbers)
        stripped_content = strip_comments(content, language)

        # Get applicable rules
        applicable_rules = list(self._rules.get(language, []))
        # Kotlin shares JVM APIs with Java — also apply Java rules
        if language == "kotlin" and "java" in self._rules:
            applicable_rules.extend(self._rules["java"])
        # Universal rules: skip languages specified in skip_languages
        for rule in self._universal_rules:
            if language not in rule.skip_languages:
                applicable_rules.append(rule)

        for rule in applicable_rules:
            for pattern in rule.patterns:
                for match in pattern.finditer(stripped_content):
                    # Calculate line number
                    line_start = stripped_content[:match.start()].count("\n")
                    line_content = lines[line_start] if line_start < len(lines) else ""

                    # Check false positive filters against ORIGINAL content
                    if self._is_false_positive(rule, line_content, lines, line_start, file_path):
                        continue

                    # Extract context (±3 lines)
                    context_start = max(0, line_start - 3)
                    context_end = min(len(lines), line_start + 4)
                    context_before = lines[context_start:line_start]
                    context_after = lines[line_start + 1:context_end]

                    # Column position
                    line_offset = stripped_content[:match.start()].rfind("\n") + 1
                    col_start = match.start() - line_offset
                    col_end = col_start + len(match.group())

                    matches.append(RawMatch(
                        rule=rule,
                        file_path=file_path,
                        line_number=line_start + 1,  # 1-indexed
                        line_content=line_content,
                        context_before=context_before,
                        context_after=context_after,
                        match_text=match.group(),
                        column_start=col_start,
                        column_end=col_end,
                    ))

        return matches

    def _is_false_positive(
        self, rule: Rule, line: str, lines: list[str], line_idx: int, file_path: str = ""
    ) -> bool:
        """Check if a match is a false positive using rule filters + heuristics."""
        # Check context window for false positive patterns
        context_start = max(0, line_idx - 2)
        context_end = min(len(lines), line_idx + 3)
        context_block = "\n".join(lines[context_start:context_end])

        for fp_pattern in rule.false_positive_filters:
            if fp_pattern.search(line) or fp_pattern.search(context_block):
                return True
            # Also check against file path for path-based suppression
            if file_path and fp_pattern.search(file_path):
                return True

        # Heuristic: credential helper programs intentionally handle secrets
        if rule.category in ("HARDCODED_SECRETS",) and file_path:
            credential_indicators = (
                "credential", "keychain", "keyring", "vault",
                "secret-manager", "secrets-manager", "auth-helper",
            )
            file_path_lower = file_path.lower()
            if any(ind in file_path_lower for ind in credential_indicators):
                return True

        # Heuristic: SSTI - skip string.Template (not Jinja2)
        if rule.category == "SSTI" and file_path:
            # Check imports in the first 30 lines for string.Template
            head = "\n".join(lines[:min(30, len(lines))])
            if "from string import" in head and "Template" in head:
                return True
            if "string.Template" in head:
                return True
            # Class-internal Template (e.g., Module.InfoTemplate)
            if "InfoTemplate" in line or "class Template" in line:
                return True

        return False

    @property
    def rule_count(self) -> int:
        """Total loaded rules."""
        total = sum(len(rules) for rules in self._rules.values())
        return total + len(self._universal_rules)

    @property
    def languages(self) -> list[str]:
        """List of loaded languages."""
        return list(self._rules.keys())
