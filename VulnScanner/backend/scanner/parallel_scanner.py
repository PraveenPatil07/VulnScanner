"""Parallel scanning helper — used by ProcessPoolExecutor in the worker task.

Each function here runs in a separate process and must be importable at module level.
"""

from backend.scanner.rule_engine import RuleEngine, RawMatch
from backend.scanner.ast_analyzers.python_ast import PythonASTAnalyzer
from backend.scanner.ast_analyzers.js_ast import JSASTAnalyzer
from backend.scanner.file_walker import FileEntry

# Per-process singletons (initialized on first use in each worker process)
_rule_engine: RuleEngine | None = None
_py_ast: PythonASTAnalyzer | None = None
_js_ast: JSASTAnalyzer | None = None

# Pre-filter keywords: only run AST analysis if content contains these
_PYTHON_AST_TRIGGERS = frozenset({
    "eval", "exec", "compile", "__import__",
    "pickle", "shelve", "marshal", "yaml",
    "subprocess", "os.system", "os.popen",
    "import pickle", "import marshal", "import shelve",
    "from pickle", "from marshal", "from yaml",
})

_JS_AST_TRIGGERS = frozenset({
    "req.body", "req.params", "req.query", "req.headers",
    "request.body", "request.params", "request.query",
    ".query(", ".execute(", ".raw(",
    "eval(", "Function(", "child_process",
    "innerHTML", "outerHTML", "document.write",
    "__proto__", "prototype",
})


def _ensure_engine() -> RuleEngine:
    global _rule_engine
    if _rule_engine is None:
        _rule_engine = RuleEngine()
        _rule_engine.load_rules()
    return _rule_engine


def _ensure_py_ast() -> PythonASTAnalyzer:
    global _py_ast
    if _py_ast is None:
        _py_ast = PythonASTAnalyzer()
    return _py_ast


def _ensure_js_ast() -> JSASTAnalyzer:
    global _js_ast
    if _js_ast is None:
        _js_ast = JSASTAnalyzer()
    return _js_ast


def _should_run_python_ast(content: str) -> bool:
    """Quick check if content contains patterns worth AST-analyzing."""
    return any(trigger in content for trigger in _PYTHON_AST_TRIGGERS)


def _should_run_js_ast(content: str) -> bool:
    """Quick check if content contains patterns worth JS AST-analyzing."""
    return any(trigger in content for trigger in _JS_AST_TRIGGERS)


def scan_single_file(content: str, rel_path: str, language: str) -> list[dict]:
    """
    Scan a single file (regex + AST) and return serializable match dicts.

    This function runs in a worker process within ProcessPoolExecutor.
    Returns list of dicts representing RawMatch fields for later mapping.
    """
    engine = _ensure_engine()
    matches: list[RawMatch] = engine.scan_file(content, rel_path, language)

    # AST analysis with pre-filtering for performance
    if language == "python" and _should_run_python_ast(content):
        ast_analyzer = _ensure_py_ast()
        matches.extend(ast_analyzer.analyze(content, rel_path))

    if language in ("javascript", "typescript") and _should_run_js_ast(content):
        js_analyzer = _ensure_js_ast()
        matches.extend(js_analyzer.analyze(content, rel_path))

    # Serialize to dicts for cross-process transfer
    results = []
    for m in matches:
        results.append({
            "rule_id": m.rule.id,
            "rule_name": m.rule.name,
            "rule_description": m.rule.description,
            "rule_severity": m.rule.severity,
            "rule_cwe": m.rule.cwe,
            "rule_cvss_score": m.rule.cvss_score,
            "rule_cvss_vector": m.rule.cvss_vector,
            "rule_mitre_attack": m.rule.mitre_attack,
            "rule_nist_csf": m.rule.nist_csf,
            "rule_confidence": m.rule.confidence,
            "rule_false_positive_risk": m.rule.false_positive_risk,
            "rule_remediation": m.rule.remediation,
            "rule_references": m.rule.references,
            "rule_language": m.rule.language,
            "rule_category": m.rule.category,
            "rule_owasp_top10": m.rule.owasp_top10,
            "file_path": m.file_path,
            "line_number": m.line_number,
            "line_content": m.line_content,
            "context_before": m.context_before,
            "context_after": m.context_after,
            "match_text": m.match_text,
            "column_start": m.column_start,
            "column_end": m.column_end,
        })

    return results
