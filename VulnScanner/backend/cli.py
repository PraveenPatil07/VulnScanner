"""CLI interface for the Code Vulnerability Scanner.

Usage:
    python -m backend.cli scan ./path/to/project --format json|sarif|markdown
    python -m backend.cli scan ./archive.zip --format json --output results.json
    python -m backend.cli scan ./src --threshold CRITICAL --exit-code

Supports CI/CD integration with quality gates.
"""

import argparse
import json
import os
import sys
import tempfile
import time
import zipfile
from pathlib import Path

# Ensure backend package is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.scanner.ast_analyzers.python_ast import PythonASTAnalyzer
from backend.scanner.ast_analyzers.js_ast import JSASTAnalyzer
from backend.scanner.file_walker import walk_files
from backend.scanner.finding_collector import FindingCollector
from backend.scanner.rule_engine import RuleEngine
from backend.scanner.skill_mapper import SkillMapper
from backend.models.sarif import generate_sarif


SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def scan_directory(target_path: Path) -> dict:
    """Scan a directory or ZIP file and return results dict."""
    start = time.perf_counter()

    # If it's a ZIP, extract to temp
    if target_path.suffix.lower() == ".zip":
        import asyncio
        from backend.scanner.zip_extractor import extract_zip

        tmp_dir = tempfile.mkdtemp()
        extract_path = Path(tmp_dir)
        with open(target_path, "rb") as f:
            zip_bytes = f.read()

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(extract_zip(zip_bytes, extract_path))
        finally:
            loop.close()

        scan_path = extract_path
    else:
        scan_path = target_path

    # Walk files
    file_entries = walk_files(scan_path)
    total_lines = sum(f.line_count for f in file_entries)

    # Load rules and scan
    engine = RuleEngine()
    engine.load_rules()
    mapper = SkillMapper()
    mapper.load_metadata()
    collector = FindingCollector()
    py_ast = PythonASTAnalyzer()
    js_ast = JSASTAnalyzer()

    for entry in file_entries:
        raw_matches = engine.scan_file(entry.content, entry.rel_path, entry.language)
        findings = mapper.map_matches(raw_matches, "cli-scan")
        collector.add_many(findings)

        if entry.language == "python":
            ast_matches = py_ast.analyze(entry.content, entry.rel_path)
            collector.add_many(mapper.map_matches(ast_matches, "cli-scan"))

        if entry.language in ("javascript", "typescript"):
            js_matches = js_ast.analyze(entry.content, entry.rel_path)
            collector.add_many(mapper.map_matches(js_matches, "cli-scan"))

    all_findings = collector.get_findings()
    stats = collector.get_stats()
    elapsed_ms = int((time.perf_counter() - start) * 1000)

    # Build result
    findings_by_severity = {}
    findings_by_category = {}
    findings_by_language = {}
    for f in all_findings:
        s = f.severity.value
        findings_by_severity[s] = findings_by_severity.get(s, 0) + 1
        c = f.category.value
        findings_by_category[c] = findings_by_category.get(c, 0) + 1
        lang = f.language
        findings_by_language[lang] = findings_by_language.get(lang, 0) + 1

    return {
        "scan_id": "cli-scan",
        "status": "COMPLETED",
        "total_files": len(file_entries),
        "files_scanned": len(file_entries),
        "lines_scanned": total_lines,
        "total_findings": len(all_findings),
        "findings_by_severity": findings_by_severity,
        "findings_by_category": findings_by_category,
        "findings_by_language": findings_by_language,
        "findings": [f.model_dump(mode="json") for f in all_findings],
        "scan_duration_ms": elapsed_ms,
    }


def format_markdown(result: dict) -> str:
    """Format results as markdown report."""
    lines = []
    lines.append("# Code Vulnerability Scanner Report\n")
    lines.append(f"**Files Scanned**: {result['files_scanned']}")
    lines.append(f"**Lines Scanned**: {result['lines_scanned']}")
    lines.append(f"**Total Findings**: {result['total_findings']}")
    lines.append(f"**Duration**: {result['scan_duration_ms']}ms\n")

    lines.append("## Severity Breakdown\n")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = result["findings_by_severity"].get(sev, 0)
        if count:
            lines.append(f"- **{sev}**: {count}")

    lines.append("\n## Findings\n")
    for f in result["findings"]:
        lines.append(f"### [{f['severity']}] {f['title']}")
        lines.append(f"- **File**: `{f['file_path']}:{f['line_number']}`")
        lines.append(f"- **CWE**: {f['cwe_id']} | **CVSS**: {f['cvss_score']}")
        lines.append(f"- **Rule**: {f['rule_id']}")
        lines.append(f"- **Description**: {f['description']}")
        if f.get("remediation"):
            lines.append(f"- **Remediation**: {f['remediation']}")
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        prog="cvs",
        description="Code Vulnerability Scanner - Static Analysis CLI",
    )
    subparsers = parser.add_subparsers(dest="command")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a directory or ZIP file")
    scan_parser.add_argument("target", type=str, help="Path to directory or ZIP file")
    scan_parser.add_argument(
        "--format", "-f",
        choices=["json", "sarif", "markdown"],
        default="json",
        help="Output format (default: json)",
    )
    scan_parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Output file path (default: stdout)",
    )
    scan_parser.add_argument(
        "--threshold",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=None,
        help="Fail (exit code 1) if findings at or above this severity exist",
    )
    scan_parser.add_argument(
        "--min-confidence",
        choices=["HIGH", "MEDIUM", "LOW"],
        default=None,
        help="Only report findings at or above this confidence level",
    )

    args = parser.parse_args()

    if args.command != "scan":
        parser.print_help()
        sys.exit(0)

    target = Path(args.target)
    if not target.exists():
        print(f"Error: {target} does not exist", file=sys.stderr)
        sys.exit(2)

    # Run scan
    print(f"Scanning {target}...", file=sys.stderr)
    result = scan_directory(target)
    print(
        f"Scan complete: {result['total_findings']} findings in "
        f"{result['files_scanned']} files ({result['scan_duration_ms']}ms)",
        file=sys.stderr,
    )

    # Filter by confidence if specified
    if args.min_confidence:
        conf_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        min_conf = conf_order.get(args.min_confidence, 0)
        result["findings"] = [
            f for f in result["findings"]
            if conf_order.get(f.get("confidence", "MEDIUM"), 0) >= min_conf
        ]
        result["total_findings"] = len(result["findings"])

    # Format output
    if args.format == "json":
        output = json.dumps(result, indent=2)
    elif args.format == "sarif":
        # Build minimal ScanResult for SARIF generation
        from backend.models.scan import ScanResult, ScanStatus
        from backend.models.finding import Finding

        findings = [Finding(**f) for f in result["findings"]]
        scan_result = ScanResult(
            scan_id=result["scan_id"],
            status=ScanStatus.COMPLETED,
            findings=findings,
            total_findings=len(findings),
            findings_by_severity=result["findings_by_severity"],
            findings_by_category=result["findings_by_category"],
            findings_by_language=result["findings_by_language"],
            scan_duration_ms=result["scan_duration_ms"],
            files_scanned=result["files_scanned"],
            lines_scanned=result["lines_scanned"],
        )
        sarif = generate_sarif(scan_result)
        output = json.dumps(sarif.model_dump(by_alias=True), indent=2)
    elif args.format == "markdown":
        output = format_markdown(result)
    else:
        output = json.dumps(result, indent=2)

    # Write output
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Results written to {args.output}", file=sys.stderr)
    else:
        print(output)

    # Quality gate
    if args.threshold:
        threshold_level = SEVERITY_ORDER.get(args.threshold, 0)
        has_violation = any(
            SEVERITY_ORDER.get(f.get("severity", "INFO"), 0) >= threshold_level
            for f in result["findings"]
        )
        if has_violation:
            count = sum(
                1 for f in result["findings"]
                if SEVERITY_ORDER.get(f.get("severity", "INFO"), 0) >= threshold_level
            )
            print(
                f"\nQuality gate FAILED: {count} findings at or above {args.threshold}",
                file=sys.stderr,
            )
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
