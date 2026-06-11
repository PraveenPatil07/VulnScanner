"""Celery tasks for vulnerability scanning and report generation."""

import asyncio
import logging
import os
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import redis

from ..celery_app import celery_app
from ..llm.anthropic_client import AnthropicStreamClient
from ..llm.prompt_builder import PromptBuilder
from ..llm.report_assembler import ReportAssembler
from ..models.database import save_scan_result
from ..scanner.ast_analyzers.python_ast import PythonASTAnalyzer
from ..scanner.ast_analyzers.js_ast import JSASTAnalyzer
from ..scanner.file_walker import walk_files
from ..scanner.finding_collector import FindingCollector
from ..scanner.hld_parser import parse_hld
from ..scanner.rule_engine import RuleEngine
from ..scanner.skill_mapper import SkillMapper
from ..scanner.zip_extractor import ZipSecurityError, extract_zip

logger = logging.getLogger(__name__)

# Redis client for publishing SSE progress to the API server
_redis_url = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
_redis = redis.Redis.from_url(_redis_url)

# Singleton scanner components (per-worker process)
_rule_engine: RuleEngine | None = None
_skill_mapper: SkillMapper | None = None


def _get_rule_engine() -> RuleEngine:
    global _rule_engine
    if _rule_engine is None:
        _rule_engine = RuleEngine()
        _rule_engine.load_rules()
    return _rule_engine


def _get_skill_mapper() -> SkillMapper:
    global _skill_mapper
    if _skill_mapper is None:
        _skill_mapper = SkillMapper()
        _skill_mapper.load_metadata()
    return _skill_mapper


def _publish_progress(scan_id: str, event: dict) -> None:
    """Publish progress event to Redis pub/sub for SSE streaming."""
    import json
    _redis.publish(f"scan:{scan_id}:progress", json.dumps(event))


def _run_async(coro):
    """Run an async function from synchronous Celery task context."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(bind=True, name="backend.worker.tasks.run_scan_task", max_retries=1)
def run_scan_task(self, scan_id: str, zip_source: str, filename: str | None = None) -> dict:
    """
    Main scan task: extract ZIP, run static analysis, then chain report generation.

    Args:
        scan_id: Unique scan identifier.
        zip_source: Either a Redis blob key (starts with "scan:") or hex-encoded bytes (legacy).
        filename: Original filename for display purposes.

    Returns:
        dict with scan results.
    """
    start_time = time.perf_counter()

    # Retrieve ZIP bytes from Redis blob store or hex string (backward compat)
    if zip_source.startswith("scan:"):
        zip_bytes = _redis.get(zip_source)
        if zip_bytes is None:
            assembler = ReportAssembler()
            return _fail_scan(scan_id, "ZIP blob expired or not found in Redis", start_time, assembler)
        _redis.delete(zip_source)  # Clean up after retrieval
    else:
        zip_bytes = bytes.fromhex(zip_source)

    assembler = ReportAssembler()

    try:
        # Phase 1: Extract ZIP
        _publish_progress(scan_id, {
            "type": "progress", "phase": "extracting",
            "message": "Extracting ZIP archive...",
        })

        with tempfile.TemporaryDirectory() as tmp_dir:
            extract_path = Path(tmp_dir)

            try:
                result = _run_async(extract_zip(zip_bytes, extract_path))
            except ZipSecurityError as e:
                return _fail_scan(scan_id, str(e), start_time, assembler)

            if result.errors and not result.extracted_files:
                return _fail_scan(
                    scan_id,
                    f"Extraction failed: {'; '.join(result.errors)}",
                    start_time, assembler,
                )

            _publish_progress(scan_id, {
                "type": "progress", "phase": "extracted",
                "message": f"Extracted {len(result.extracted_files)} files",
                "skipped": len(result.skipped_files),
            })

            # Phase 2: Walk files
            _publish_progress(scan_id, {
                "type": "progress", "phase": "scanning",
                "message": "Scanning files...",
            })
            file_entries = walk_files(extract_path)
            total_lines = sum(f.line_count for f in file_entries)

            _publish_progress(scan_id, {
                "type": "progress", "phase": "files_found",
                "message": f"Found {len(file_entries)} scannable files ({total_lines} lines)",
            })

            # Phase 3: Rule matching (parallel for large codebases)
            engine = _get_rule_engine()
            mapper = _get_skill_mapper()
            collector = FindingCollector()
            ast_analyzer = PythonASTAnalyzer()
            js_ast_analyzer = JSASTAnalyzer()

            # Use parallel scanning for large file sets (>100 files)
            PARALLEL_THRESHOLD = 100
            if len(file_entries) > PARALLEL_THRESHOLD:
                from ..scanner.parallel_scanner import scan_single_file
                max_workers = min(4, os.cpu_count() or 2)

                with ProcessPoolExecutor(max_workers=max_workers) as executor:
                    futures = {
                        executor.submit(
                            scan_single_file,
                            entry.content,
                            entry.rel_path,
                            entry.language,
                        ): entry
                        for entry in file_entries
                    }

                    completed = 0
                    for future in as_completed(futures):
                        completed += 1
                        try:
                            match_dicts = future.result()
                            for md in match_dicts:
                                # Reconstruct RawMatch from dict for mapping
                                from ..scanner.rule_engine import Rule, RawMatch as RM
                                rule = Rule(
                                    id=md["rule_id"],
                                    name=md["rule_name"],
                                    description=md["rule_description"],
                                    severity=md["rule_severity"],
                                    cwe=md["rule_cwe"],
                                    cvss_score=md["rule_cvss_score"],
                                    cvss_vector=md["rule_cvss_vector"],
                                    mitre_attack=md["rule_mitre_attack"],
                                    nist_csf=md["rule_nist_csf"],
                                    confidence=md["rule_confidence"],
                                    false_positive_risk=md["rule_false_positive_risk"],
                                    remediation=md["rule_remediation"],
                                    references=md["rule_references"],
                                    patterns=[],
                                    false_positive_filters=[],
                                    language=md["rule_language"],
                                    category=md["rule_category"],
                                    owasp_top10=md.get("rule_owasp_top10", ""),
                                )
                                raw_match = RM(
                                    rule=rule,
                                    file_path=md["file_path"],
                                    line_number=md["line_number"],
                                    line_content=md["line_content"],
                                    context_before=md["context_before"],
                                    context_after=md["context_after"],
                                    match_text=md["match_text"],
                                    column_start=md["column_start"],
                                    column_end=md["column_end"],
                                )
                                findings = mapper.map_matches([raw_match], scan_id)
                                collector.add_many(findings)
                        except Exception as e:
                            logger.warning("Parallel scan error: %s", e)

                        if completed % 100 == 0:
                            _publish_progress(scan_id, {
                                "type": "progress", "phase": "scanning",
                                "message": f"Scanned {completed}/{len(file_entries)} files",
                                "findings_so_far": len(collector.get_findings(sort=False)),
                            })
                        logger.info("[%s] Parallel scan progress: %d/%d files", scan_id[:8], completed, len(file_entries))
            else:
                # Sequential scan for smaller codebases
                for i, entry in enumerate(file_entries):
                    logger.info("[%s] Scanning file %d/%d: %s", scan_id[:8], i + 1, len(file_entries), entry.rel_path)
                    _publish_progress(scan_id, {
                        "type": "progress", "phase": "scanning",
                        "message": f"Scanning {entry.rel_path}",
                        "current_file": entry.rel_path,
                        "files_scanned": i + 1,
                        "total_files": len(file_entries),
                    })
                    raw_matches = engine.scan_file(entry.content, entry.rel_path, entry.language)
                    findings = mapper.map_matches(raw_matches, scan_id)
                    collector.add_many(findings)

                    if entry.language == "python":
                        ast_matches = ast_analyzer.analyze(entry.content, entry.rel_path)
                        ast_findings = mapper.map_matches(ast_matches, scan_id)
                        collector.add_many(ast_findings)

                    if entry.language in ("javascript", "typescript"):
                        js_matches = js_ast_analyzer.analyze(entry.content, entry.rel_path)
                        js_findings = mapper.map_matches(js_matches, scan_id)
                        collector.add_many(js_findings)

                    if (i + 1) % 50 == 0:
                        _publish_progress(scan_id, {
                            "type": "progress", "phase": "scanning",
                            "message": f"Scanned {i + 1}/{len(file_entries)} files",
                            "findings_so_far": len(collector.get_findings(sort=False)),
                        })

            all_findings = collector.get_findings()
            stats = collector.get_stats()

            _publish_progress(scan_id, {
                "type": "progress", "phase": "scan_complete",
                "message": f"Static scan complete: {len(all_findings)} findings",
                "stats": stats,
            })

            # Phase 4: LLM Report Generation
            api_key = os.environ.get("AZURE_FOUNDRY_API_KEY", "")
            llm_report = ""

            if api_key and all_findings:
                _publish_progress(scan_id, {
                    "type": "progress", "phase": "reporting",
                    "message": "Generating LLM report...",
                })

                prompt_builder = PromptBuilder()
                budget_findings = collector.get_findings_within_budget()
                user_prompt = prompt_builder.build_findings_prompt(budget_findings, stats)

                hld_content = None
                for entry in file_entries:
                    hld_data = parse_hld(entry.path)
                    if hld_data:
                        hld_content = prompt_builder.build_hld_context(hld_data)
                        break

                client = AnthropicStreamClient(api_key=api_key)

                async def _stream_report():
                    chunks = []
                    async for chunk in client.stream_report(
                        system_prompt=prompt_builder.system_prompt,
                        user_prompt=user_prompt,
                        hld_content=hld_content,
                    ):
                        chunks.append(chunk)
                        _publish_progress(scan_id, {
                            "type": "report_chunk",
                            "data": chunk,
                        })
                    return "".join(chunks)

                llm_report = _run_async(_stream_report())

            # Assemble final result
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            scan_result = assembler.assemble(
                scan_id=scan_id,
                findings=all_findings,
                llm_report=llm_report,
                scan_duration_ms=elapsed_ms,
                files_scanned=len(file_entries),
                lines_scanned=total_lines,
            )

            result_dict = scan_result.model_dump(mode="json")

            # Persist to database
            try:
                save_scan_result(scan_id, result_dict, filename=filename)
            except Exception as db_err:
                logger.warning("Failed to persist scan to DB: %s", db_err)

            _publish_progress(scan_id, {
                "type": "complete",
                "result": result_dict,
            })

            return result_dict

    except Exception as e:
        logger.exception("Scan task failed: %s", e)
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        error_result = _fail_scan(scan_id, str(e), start_time, assembler)
        return error_result


def _fail_scan(scan_id: str, error: str, start_time: float, assembler: ReportAssembler) -> dict:
    """Handle scan failure."""
    elapsed_ms = int((time.perf_counter() - start_time) * 1000)
    result = assembler.assemble_error(scan_id, error, elapsed_ms)
    result_dict = result.model_dump(mode="json")

    _publish_progress(scan_id, {
        "type": "error",
        "message": error,
        "result": result_dict,
    })

    return result_dict
