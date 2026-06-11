"""PDF report generation using HTML templates and WeasyPrint (or fallback to markdown-based)."""

import html
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#2563eb",
    "INFO": "#6b7280",
}


def generate_pdf_report(result: dict) -> bytes:
    """
    Generate a PDF report from scan results.

    Uses WeasyPrint if available, otherwise falls back to a simple text-based PDF.
    Returns raw PDF bytes.
    """
    html_content = _build_html_report(result)

    # Try WeasyPrint first, then xhtml2pdf, then fpdf2 fallback
    try:
        from weasyprint import HTML
        return HTML(string=html_content).write_pdf()
    except ImportError:
        pass

    try:
        import io
        import re
        from xhtml2pdf import pisa

        # xhtml2pdf doesn't support modern CSS; strip unsupported rules/properties
        clean_html = re.sub(r'@page\s*\{(?:[^{}]*|\{[^{}]*\})*\}', '', html_content)
        # Remove unsupported properties
        clean_html = re.sub(r'display:\s*flex;?', '', clean_html)
        clean_html = re.sub(r'gap:\s*[^;]+;?', '', clean_html)
        clean_html = re.sub(r'flex:\s*[^;]+;?', '', clean_html)
        clean_html = re.sub(r'page-break-inside:\s*[^;]+;?', '', clean_html)
        clean_html = re.sub(r'page-break-before:\s*[^;]+;?', '', clean_html)
        buffer = io.BytesIO()
        pisa_status = pisa.CreatePDF(clean_html, dest=buffer)
        if not pisa_status.err:
            return buffer.getvalue()
        logger.warning("xhtml2pdf rendering failed, using fpdf2 fallback")
    except (ImportError, Exception) as e:
        logger.warning("xhtml2pdf unavailable or failed: %s, using fpdf2 fallback", e)

    return _fallback_pdf(result)


def _build_html_report(result: dict) -> str:
    """Build an HTML report suitable for PDF conversion."""
    findings = result.get("findings", [])
    severity_counts = result.get("findings_by_severity", {})
    scan_duration = result.get("scan_duration_ms", 0) / 1000

    # Group findings by severity
    grouped = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
    for f in findings:
        sev = f.get("severity", "INFO")
        grouped.setdefault(sev, []).append(f)

    findings_html = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if not grouped.get(sev):
            continue
        color = SEVERITY_COLORS.get(sev, "#6b7280")
        findings_html += f'<h2 style="color: {color}; border-bottom: 2px solid {color}; padding-bottom: 4px;">{sev} Findings ({len(grouped[sev])})</h2>\n'
        for f in grouped[sev]:
            findings_html += _render_finding_html(f, color)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
    body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; color: #1e293b; line-height: 1.6; }}
    h1 {{ color: #1e40af; border-bottom: 3px solid #1e40af; padding-bottom: 8px; }}
    h2 {{ margin-top: 30px; }}
    .meta {{ color: #64748b; font-size: 0.9em; margin-bottom: 20px; }}
    .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
    .stat-box {{ background: #f1f5f9; border-radius: 8px; padding: 15px 20px; text-align: center; flex: 1; }}
    .stat-box .number {{ font-size: 2em; font-weight: bold; }}
    .stat-box .label {{ color: #64748b; font-size: 0.85em; text-transform: uppercase; }}
    .finding {{ border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin: 12px 0; page-break-inside: avoid; }}
    .finding-header {{ display: flex; justify-content: space-between; align-items: center; }}
    .finding-title {{ font-weight: 600; font-size: 1.05em; }}
    .finding-meta {{ color: #64748b; font-size: 0.85em; margin: 8px 0; }}
    .code {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 4px; padding: 8px 12px; font-family: monospace; font-size: 0.85em; white-space: pre-wrap; overflow-wrap: break-word; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75em; font-weight: 600; color: white; }}
    .remediation {{ background: #f0fdf4; border-left: 4px solid #16a34a; padding: 8px 12px; margin-top: 8px; font-size: 0.9em; }}
    @page {{ margin: 2cm; @bottom-center {{ content: "Page " counter(page) " of " counter(pages); font-size: 9pt; color: #94a3b8; }} }}
</style>
</head>
<body>
<h1>Code Vulnerability Scanner Report</h1>
<div class="meta">
    Generated: {now} | Scan ID: {html.escape(result.get('scan_id', 'N/A'))}
</div>

<div class="summary">
    <div class="stat-box">
        <div class="number">{result.get('total_findings', 0)}</div>
        <div class="label">Total Findings</div>
    </div>
    <div class="stat-box">
        <div class="number" style="color: {SEVERITY_COLORS['CRITICAL']}">{severity_counts.get('CRITICAL', 0)}</div>
        <div class="label">Critical</div>
    </div>
    <div class="stat-box">
        <div class="number" style="color: {SEVERITY_COLORS['HIGH']}">{severity_counts.get('HIGH', 0)}</div>
        <div class="label">High</div>
    </div>
    <div class="stat-box">
        <div class="number">{result.get('files_scanned', 0)}</div>
        <div class="label">Files Scanned</div>
    </div>
    <div class="stat-box">
        <div class="number">{scan_duration:.1f}s</div>
        <div class="label">Duration</div>
    </div>
</div>

{findings_html}

{_render_llm_report_section(result.get('llm_report', ''))}

<div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #e2e8f0; color: #94a3b8; font-size: 0.8em;">
    Generated by Code Vulnerability Scanner v2.0.0
</div>
</body>
</html>"""


def _render_finding_html(f: dict, color: str) -> str:
    """Render a single finding as HTML."""
    code = html.escape(f.get("code_snippet", "")[:500])
    return f"""
<div class="finding">
    <div class="finding-header">
        <span class="finding-title">{html.escape(f.get('title', ''))}</span>
        <span class="badge" style="background: {color}">{f.get('severity', '')}</span>
    </div>
    <div class="finding-meta">
        {html.escape(f.get('file_path', ''))}:{f.get('line_number', 0)} |
        CWE: {html.escape(f.get('cwe_id', ''))} |
        CVSS: {f.get('cvss_score', 0)} |
        Rule: {html.escape(f.get('rule_id', ''))}
    </div>
    <p>{html.escape(f.get('description', ''))}</p>
    {f'<div class="code">{code}</div>' if code else ''}
    {f'<div class="remediation"><strong>Remediation:</strong> {html.escape(f.get("remediation", ""))}</div>' if f.get("remediation") else ''}
</div>
"""


def _render_llm_report_section(report: str) -> str:
    """Render the LLM report section if available."""
    if not report:
        return ""
    # Simple markdown-to-html conversion for key elements
    escaped = html.escape(report)
    escaped = escaped.replace("\n## ", "\n<h2>").replace("\n### ", "\n<h3>")
    return f"""
<div style="page-break-before: always;"></div>
<h1 style="color: #7c3aed;">AI Security Analysis</h1>
<div style="white-space: pre-wrap; font-size: 0.9em;">
{escaped}
</div>
"""


def _fallback_pdf(result: dict) -> bytes:
    """
    Fallback PDF generation using fpdf2 if available, otherwise return empty.
    """
    try:
        from fpdf import FPDF

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, "Code Vulnerability Scanner Report", ln=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 8, f"Scan ID: {result.get('scan_id', 'N/A')}", ln=True)
        pdf.cell(0, 8, f"Total Findings: {result.get('total_findings', 0)}", ln=True)
        pdf.cell(0, 8, f"Files Scanned: {result.get('files_scanned', 0)}", ln=True)
        pdf.ln(10)

        for f in result.get("findings", [])[:100]:
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, f"[{f.get('severity', '')}] {f.get('title', '')}", ln=True)
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(0, 5, f"  {f.get('file_path', '')}:{f.get('line_number', 0)} | {f.get('cwe_id', '')}", ln=True)
            pdf.ln(3)

        return bytes(pdf.output())
    except ImportError:
        logger.error("Neither weasyprint nor fpdf2 is installed for PDF generation")
        return b""
