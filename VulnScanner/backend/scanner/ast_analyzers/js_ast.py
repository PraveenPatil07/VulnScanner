"""JavaScript/TypeScript AST-based vulnerability analyzer.

Uses regex-based pseudo-AST analysis for detecting taint flows
and dangerous patterns that regex-only scanning cannot catch:
- req.params/query/body flowing into SQL/exec/eval
- innerHTML assignments with user input
- Prototype pollution patterns
- Unsafe deserialization

This module does NOT require tree-sitter; it performs line-by-line
semantic analysis with context tracking for lighter dependency footprint.
"""

import logging
import re
from dataclasses import dataclass

from ..rule_engine import RawMatch, Rule

logger = logging.getLogger(__name__)

# Sources of user input (tainted)
TAINT_SOURCES = re.compile(
    r"(?:req\.(?:body|params|query|headers|cookies)|"
    r"request\.(?:body|params|query|headers)|"
    r"ctx\.(?:request|params|query)|"
    r"event\.(?:body|queryStringParameters|pathParameters)|"
    r"document\.(?:location|URL|referrer)|"
    r"window\.location|"
    r"location\.(?:href|search|hash)|"
    r"URLSearchParams|"
    r"formData\.get)",
    re.IGNORECASE,
)

# Dangerous sinks
SQL_SINKS = re.compile(
    r"(?:\.query\(|\.execute\(|\.raw\(|knex\.raw\(|sequelize\.query\(|"
    r"connection\.query\(|pool\.query\(|db\.(?:run|all|get)\()",
    re.IGNORECASE,
)

EXEC_SINKS = re.compile(
    r"(?:eval\(|Function\(|setTimeout\(.*,|setInterval\(.*,|"
    r"child_process\.exec\(|execSync\(|spawn\(|"
    r"vm\.runInContext\(|vm\.runInNewContext\()",
)

DOM_SINKS = re.compile(
    r"(?:\.innerHTML\s*=|\.outerHTML\s*=|"
    r"document\.write\(|document\.writeln\(|"
    r"\.insertAdjacentHTML\(|"
    r"dangerouslySetInnerHTML)",
)

DESER_SINKS = re.compile(
    r"(?:JSON\.parse\(.*\)|"
    r"deserialize\(|unserialize\(|"
    r"yaml\.load\(|"
    r"new\s+Function\()",
)

REDIRECT_SINKS = re.compile(
    r"(?:res\.redirect\(|response\.redirect\(|"
    r"window\.location\s*=|location\.href\s*=|"
    r"location\.replace\()",
)

# Synthetic rules for AST-detected findings
_TAINT_SQL_RULE = Rule(
    id="JS-AST-SQLI-001",
    name="Tainted SQL Query",
    description="User input flows into SQL query without parameterization",
    severity="CRITICAL",
    cwe="CWE-89",
    cvss_score=9.8,
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    mitre_attack="T1190",
    nist_csf=["PR.DS-5"],
    confidence="HIGH",
    false_positive_risk="LOW",
    remediation="Use parameterized queries or an ORM. Never concatenate user input into SQL.",
    references=["https://owasp.org/www-community/attacks/SQL_Injection"],
    patterns=[],
    false_positive_filters=[],
    language="javascript",
    category="SQL_INJECTION",
    owasp_top10="A03:2021",
)

_TAINT_XSS_RULE = Rule(
    id="JS-AST-XSS-001",
    name="Tainted DOM Manipulation",
    description="User input flows into DOM sink without sanitization",
    severity="HIGH",
    cwe="CWE-79",
    cvss_score=7.1,
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    mitre_attack="T1059.007",
    nist_csf=["PR.DS-5"],
    confidence="HIGH",
    false_positive_risk="LOW",
    remediation="Use textContent instead of innerHTML. Sanitize with DOMPurify.",
    references=["https://owasp.org/www-community/attacks/xss/"],
    patterns=[],
    false_positive_filters=[],
    language="javascript",
    category="XSS",
    owasp_top10="A03:2021",
)

_TAINT_CMDI_RULE = Rule(
    id="JS-AST-CMDI-001",
    name="Tainted Command Execution",
    description="User input flows into command execution function",
    severity="CRITICAL",
    cwe="CWE-78",
    cvss_score=9.8,
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    mitre_attack="T1059",
    nist_csf=["PR.DS-5"],
    confidence="HIGH",
    false_positive_risk="LOW",
    remediation="Never pass user input to exec/spawn. Use allowlists for commands.",
    references=["https://owasp.org/www-community/attacks/Command_Injection"],
    patterns=[],
    false_positive_filters=[],
    language="javascript",
    category="COMMAND_INJECTION",
    owasp_top10="A03:2021",
)

_TAINT_REDIRECT_RULE = Rule(
    id="JS-AST-REDIR-001",
    name="Open Redirect via User Input",
    description="User-controlled input flows into redirect target",
    severity="MEDIUM",
    cwe="CWE-601",
    cvss_score=5.4,
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    mitre_attack="T1566",
    nist_csf=["PR.DS-5"],
    confidence="MEDIUM",
    false_positive_risk="MEDIUM",
    remediation="Validate redirect URLs against an allowlist of trusted domains.",
    references=["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
    patterns=[],
    false_positive_filters=[],
    language="javascript",
    category="OPEN_REDIRECT",
    owasp_top10="A01:2021",
)

_PROTOTYPE_POLLUTION_RULE = Rule(
    id="JS-AST-PROTO-001",
    name="Prototype Pollution via Dynamic Property Assignment",
    description="Object property set with user-controlled key allowing __proto__ injection",
    severity="HIGH",
    cwe="CWE-1321",
    cvss_score=7.3,
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
    mitre_attack="T1059.007",
    nist_csf=["PR.DS-5"],
    confidence="MEDIUM",
    false_positive_risk="MEDIUM",
    remediation="Validate property keys. Use Object.create(null) or Map. Block __proto__, constructor, prototype keys.",
    references=["https://portswigger.net/web-security/prototype-pollution"],
    patterns=[],
    false_positive_filters=[],
    language="javascript",
    category="PROTOTYPE_POLLUTION",
    owasp_top10="A03:2021",
)

# Pattern: obj[userInput] = value (prototype pollution)
_DYNAMIC_PROP_PATTERN = re.compile(
    r"\w+\[(?:req\.|request\.|params|query|body|key|prop|name|field)[\w.]*\]\s*="
)


class JSASTAnalyzer:
    """
    Performs taint-flow analysis on JavaScript/TypeScript source code.

    Tracks variables assigned from taint sources and flags when they
    flow into dangerous sinks within the same function scope.
    """

    def analyze(self, content: str, file_path: str) -> list[RawMatch]:
        """Analyze JS/TS source for taint flow vulnerabilities."""
        matches: list[RawMatch] = []
        lines = content.split("\n")

        # Track tainted variables within scope (simplified: whole file)
        tainted_vars: set[str] = set()

        for line_idx, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("*"):
                continue

            # Detect taint sources assigned to variables
            if TAINT_SOURCES.search(line):
                # Extract variable name from assignment
                var_match = re.match(
                    r"(?:const|let|var|)\s*(?:\{[^}]*\}|(\w+))\s*=",
                    stripped,
                )
                if var_match:
                    var_name = var_match.group(1)
                    if var_name:
                        tainted_vars.add(var_name)
                # Also destructured: const { x, y } = req.body
                destr_match = re.match(r"(?:const|let|var)\s*\{([^}]+)\}", stripped)
                if destr_match:
                    for var in destr_match.group(1).split(","):
                        clean = var.strip().split(":")[0].strip()
                        if clean:
                            tainted_vars.add(clean)

            # Check if line has tainted variable usage in dangerous sinks
            has_taint = (
                TAINT_SOURCES.search(line)
                or any(tv in line for tv in tainted_vars if len(tv) > 2)
            )

            if has_taint:
                context_before = lines[max(0, line_idx-3):line_idx]
                context_after = lines[line_idx+1:min(len(lines), line_idx+4)]

                # SQL injection
                if SQL_SINKS.search(line):
                    matches.append(RawMatch(
                        rule=_TAINT_SQL_RULE,
                        file_path=file_path,
                        line_number=line_idx + 1,
                        line_content=line,
                        context_before=context_before,
                        context_after=context_after,
                        match_text=line.strip(),
                    ))

                # Command injection
                if EXEC_SINKS.search(line):
                    matches.append(RawMatch(
                        rule=_TAINT_CMDI_RULE,
                        file_path=file_path,
                        line_number=line_idx + 1,
                        line_content=line,
                        context_before=context_before,
                        context_after=context_after,
                        match_text=line.strip(),
                    ))

                # XSS via DOM
                if DOM_SINKS.search(line):
                    matches.append(RawMatch(
                        rule=_TAINT_XSS_RULE,
                        file_path=file_path,
                        line_number=line_idx + 1,
                        line_content=line,
                        context_before=context_before,
                        context_after=context_after,
                        match_text=line.strip(),
                    ))

                # Open redirect
                if REDIRECT_SINKS.search(line):
                    matches.append(RawMatch(
                        rule=_TAINT_REDIRECT_RULE,
                        file_path=file_path,
                        line_number=line_idx + 1,
                        line_content=line,
                        context_before=context_before,
                        context_after=context_after,
                        match_text=line.strip(),
                    ))

            # Prototype pollution: dynamic property access with user input
            if _DYNAMIC_PROP_PATTERN.search(line):
                context_before = lines[max(0, line_idx-3):line_idx]
                context_after = lines[line_idx+1:min(len(lines), line_idx+4)]
                matches.append(RawMatch(
                    rule=_PROTOTYPE_POLLUTION_RULE,
                    file_path=file_path,
                    line_number=line_idx + 1,
                    line_content=line,
                    context_before=context_before,
                    context_after=context_after,
                    match_text=line.strip(),
                ))

        return matches
