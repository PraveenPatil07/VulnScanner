"""Builds structured prompts for the LLM report generation phase."""

import json
from ..models.finding import Finding


SYSTEM_PROMPT = """You are a senior application security engineer writing a vulnerability assessment report.

Your task is to analyze the static analysis findings provided and generate a comprehensive security report.

Guidelines:
- Group findings by severity and category
- Provide actionable remediation guidance for each finding
- Highlight the most critical risks first
- Include CVSS scores and CWE references
- Suggest prioritization based on exploitability and impact
- Note any patterns that suggest systemic issues
- Be concise but thorough
- Use markdown formatting for readability

Output structure:
1. Executive Summary (2-3 sentences)
2. Critical Findings (if any)
3. High Severity Findings
4. Medium Severity Findings
5. Low/Info Findings (summarized)
6. Remediation Priorities
7. Systemic Recommendations"""

FINDING_TEMPLATE = """### {title}
- **Severity**: {severity} | **Confidence**: {confidence}
- **Category**: {category} | **CWE**: {cwe_id}
- **CVSS**: {cvss_score} ({cvss_vector})
- **File**: `{file_path}` (line {line_number})
- **Rule**: {rule_id}

**Code Context**:
```
{code_snippet}
```

**Description**: {description}
**Remediation**: {remediation}
"""


class PromptBuilder:
    """Builds prompts for the LLM report generation phase."""

    def __init__(self, max_tokens: int = 100_000):
        self._max_tokens = max_tokens
        self._chars_per_token = 4

    @property
    def system_prompt(self) -> str:
        """Get the system prompt for the LLM."""
        return SYSTEM_PROMPT

    def build_findings_prompt(
        self,
        findings: list[Finding],
        scan_stats: dict | None = None,
    ) -> str:
        """
        Build the user prompt containing findings for analysis.

        Formats findings into a structured prompt within token budget.
        """
        parts = []

        # Header with context
        parts.append("# Vulnerability Scan Findings\n")

        if scan_stats:
            parts.append(f"**Total Findings**: {scan_stats.get('total_findings', len(findings))}")
            parts.append(f"**Duplicates Removed**: {scan_stats.get('duplicates_removed', 0)}")
            if scan_stats.get("by_severity"):
                sev_str = ", ".join(
                    f"{k}: {v}" for k, v in scan_stats["by_severity"].items()
                )
                parts.append(f"**By Severity**: {sev_str}")
            if scan_stats.get("by_language"):
                lang_str = ", ".join(
                    f"{k}: {v}" for k, v in scan_stats["by_language"].items()
                )
                parts.append(f"**Languages Scanned**: {lang_str}")
            parts.append("")

        # Add each finding
        parts.append("## Detailed Findings\n")

        token_count = self._estimate_tokens("\n".join(parts))

        for i, finding in enumerate(findings, 1):
            finding_text = self._format_finding(finding, i)
            finding_tokens = self._estimate_tokens(finding_text)

            if token_count + finding_tokens > self._max_tokens:
                remaining = len(findings) - i + 1
                parts.append(
                    f"\n*({remaining} additional findings omitted due to token budget)*"
                )
                break

            parts.append(finding_text)
            token_count += finding_tokens

        parts.append("\n---\nPlease analyze these findings and generate a security report.")
        return "\n".join(parts)

    def build_hld_context(self, hld_data: dict) -> list[dict]:
        """Build content blocks for HLD image/document context."""
        if hld_data["type"] == "image":
            return [
                {
                    "type": "text",
                    "text": f"Architecture diagram ({hld_data['filename']}):"
                },
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": hld_data["media_type"],
                        "data": hld_data["data"],
                    },
                },
            ]
        else:
            return [
                {
                    "type": "text",
                    "text": f"[Document: {hld_data['filename']} ({hld_data['size_bytes']} bytes)]",
                },
            ]

    def _format_finding(self, finding: Finding, index: int) -> str:
        """Format a single finding for the prompt."""
        return FINDING_TEMPLATE.format(
            title=f"{index}. {finding.title}",
            severity=finding.severity.value,
            confidence=finding.confidence,
            category=finding.category.value,
            cwe_id=finding.cwe_id,
            cvss_score=finding.cvss_score,
            cvss_vector=finding.cvss_vector or "N/A",
            file_path=finding.file_path,
            line_number=finding.line_number,
            rule_id=finding.rule_id,
            code_snippet=finding.code_snippet or "N/A",
            description=finding.description,
            remediation=finding.remediation or "See CWE reference for remediation guidance.",
        )

    def _estimate_tokens(self, text: str) -> int:
        """Estimate token count from text length."""
        return max(1, len(text) // self._chars_per_token)
