"""Python AST-based vulnerability analyzer for deeper code analysis."""

import ast
import logging
from dataclasses import dataclass

from ..rule_engine import RawMatch, Rule

logger = logging.getLogger(__name__)

DANGEROUS_CALLS = {
    "eval": ("COMMAND_INJECTION", "CWE-95", "Dangerous use of eval()"),
    "exec": ("COMMAND_INJECTION", "CWE-95", "Dangerous use of exec()"),
    "compile": ("COMMAND_INJECTION", "CWE-95", "Dynamic code compilation"),
    "__import__": ("COMMAND_INJECTION", "CWE-502", "Dynamic import"),
}

DANGEROUS_MODULES = {
    "pickle": ("INSECURE_DESERIALIZATION", "CWE-502"),
    "shelve": ("INSECURE_DESERIALIZATION", "CWE-502"),
    "marshal": ("INSECURE_DESERIALIZATION", "CWE-502"),
    "yaml": ("INSECURE_DESERIALIZATION", "CWE-502"),
}

DANGEROUS_MODULE_CALLS = {
    ("subprocess", "call"): ("COMMAND_INJECTION", "CWE-78", "shell=True"),
    ("subprocess", "Popen"): ("COMMAND_INJECTION", "CWE-78", "shell=True"),
    ("subprocess", "run"): ("COMMAND_INJECTION", "CWE-78", "shell=True"),
    ("os", "system"): ("COMMAND_INJECTION", "CWE-78", "OS command execution"),
    ("os", "popen"): ("COMMAND_INJECTION", "CWE-78", "OS command execution"),
    ("pickle", "loads"): ("INSECURE_DESERIALIZATION", "CWE-502", "Untrusted deserialization"),
    ("pickle", "load"): ("INSECURE_DESERIALIZATION", "CWE-502", "Untrusted deserialization"),
    ("yaml", "load"): ("INSECURE_DESERIALIZATION", "CWE-502", "Unsafe YAML loading"),
}


@dataclass
class ASTFinding:
    """An AST-based vulnerability finding."""
    category: str
    cwe: str
    description: str
    line_number: int
    col_offset: int
    node_text: str
    confidence: str
    severity: str


class PythonASTAnalyzer:
    """Analyzes Python AST for vulnerability patterns."""

    def analyze(self, content: str, file_path: str) -> list[RawMatch]:
        """
        Parse Python source and identify vulnerabilities via AST inspection.

        Returns list of RawMatch for integration with the rule engine pipeline.
        """
        try:
            tree = ast.parse(content, filename=file_path)
        except SyntaxError:
            return []

        findings = []
        lines = content.split("\n")

        for node in ast.walk(tree):
            # Check dangerous built-in calls
            if isinstance(node, ast.Call):
                finding = self._check_call(node, lines)
                if finding:
                    findings.append(finding)

            # Check dangerous imports
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in DANGEROUS_MODULES:
                        cat, cwe = DANGEROUS_MODULES[alias.name]
                        findings.append(ASTFinding(
                            category=cat,
                            cwe=cwe,
                            description=f"Import of potentially dangerous module: {alias.name}",
                            line_number=node.lineno,
                            col_offset=node.col_offset,
                            node_text=f"import {alias.name}",
                            confidence="LOW",
                            severity="MEDIUM",
                        ))

        return self._convert_to_raw_matches(findings, content, file_path, lines)

    def _check_call(self, node: ast.Call, lines: list[str]) -> ASTFinding | None:
        """Check if a function call is dangerous, with taint-aware severity."""
        func_name = self._get_call_name(node)
        if not func_name:
            return None

        # Direct dangerous calls (eval, exec)
        if func_name in DANGEROUS_CALLS:
            cat, cwe, desc = DANGEROUS_CALLS[func_name]
            # Check if arguments come from variables (potential user input)
            if node.args and not isinstance(node.args[0], ast.Constant):
                return ASTFinding(
                    category=cat,
                    cwe=cwe,
                    description=desc,
                    line_number=node.lineno,
                    col_offset=node.col_offset,
                    node_text=ast.get_source_segment(
                        "\n".join(lines), node
                    ) or func_name,
                    confidence="HIGH",
                    severity="CRITICAL",
                )

        # Module-qualified dangerous calls
        parts = func_name.rsplit(".", 1)
        if len(parts) == 2:
            module, method = parts
            key = (module, method)
            if key in DANGEROUS_MODULE_CALLS:
                cat, cwe, condition = DANGEROUS_MODULE_CALLS[key]

                # For subprocess calls, check for shell=True
                if "shell" in condition:
                    has_shell_true = any(
                        isinstance(kw.value, ast.Constant)
                        and kw.value.value is True
                        and kw.arg == "shell"
                        for kw in node.keywords
                    )
                    if not has_shell_true:
                        return None

                # For yaml.load, check for safe Loader
                if func_name == "yaml.load":
                    has_safe_loader = any(
                        kw.arg == "Loader"
                        and isinstance(kw.value, ast.Attribute)
                        and "Safe" in getattr(kw.value, "attr", "")
                        for kw in node.keywords
                    )
                    if has_safe_loader:
                        return None

                # Taint-aware: determine if arguments are hardcoded or dynamic
                is_hardcoded = self._args_are_constant(node)
                if is_hardcoded:
                    severity = "LOW"
                    confidence = "LOW"
                    desc_suffix = " (hardcoded argument — low risk)"
                else:
                    severity = "HIGH"
                    confidence = "HIGH"
                    desc_suffix = ""

                return ASTFinding(
                    category=cat,
                    cwe=cwe,
                    description=f"Dangerous call: {func_name} ({condition}){desc_suffix}",
                    line_number=node.lineno,
                    col_offset=node.col_offset,
                    node_text=ast.get_source_segment(
                        "\n".join(lines), node
                    ) or func_name,
                    confidence=confidence,
                    severity=severity,
                )

        return None

    def _args_are_constant(self, node: ast.Call) -> bool:
        """Check if all arguments to a call are constants (not user-controlled)."""
        if not node.args:
            return False
        for arg in node.args:
            if isinstance(arg, ast.Constant):
                continue
            if isinstance(arg, ast.JoinedStr):
                # f-string: check if all values are constants
                if all(isinstance(v, (ast.Constant, ast.FormattedValue)) for v in arg.values):
                    if all(
                        isinstance(v, ast.Constant) or
                        (isinstance(v, ast.FormattedValue) and isinstance(v.value, ast.Constant))
                        for v in arg.values
                    ):
                        continue
                return False
            return False
        return True

    def _get_call_name(self, node: ast.Call) -> str | None:
        """Extract the fully-qualified name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
        return None

    def _convert_to_raw_matches(
        self,
        findings: list[ASTFinding],
        content: str,
        file_path: str,
        lines: list[str],
    ) -> list[RawMatch]:
        """Convert AST findings to RawMatch objects."""
        matches = []

        for f in findings:
            line_idx = f.line_number - 1
            line_content = lines[line_idx] if line_idx < len(lines) else ""

            context_start = max(0, line_idx - 3)
            context_end = min(len(lines), line_idx + 4)

            rule = Rule(
                id=f"python-ast-{f.category.lower()}-{f.line_number}",
                name=f"AST: {f.description}",
                description=f.description,
                severity=f.severity,
                cwe=f.cwe,
                cvss_score=7.5 if f.severity == "CRITICAL" else 6.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                mitre_attack="T1059",
                nist_csf=["DE.CM-4"],
                confidence=f.confidence,
                false_positive_risk="LOW",
                remediation=f"Avoid using {f.node_text} with untrusted input",
                references=[],
                patterns=[],
                false_positive_filters=[],
                language="python",
                category=f.category,
            )

            matches.append(RawMatch(
                rule=rule,
                file_path=file_path,
                line_number=f.line_number,
                line_content=line_content,
                context_before=lines[context_start:line_idx],
                context_after=lines[line_idx + 1:context_end],
                match_text=f.node_text,
                column_start=f.col_offset,
                column_end=f.col_offset + len(f.node_text),
            ))

        return matches
