"""
PDF report exporter with multi-engine support (WeasyPrint / ReportLab fallback).
Ensures zero-crash PDF generation across macOS, Linux, and Windows.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _generate_pdf_reportlab(output_path: Path, data: dict[str, Any]) -> None:
    """Generate a clean executive PDF report using ReportLab."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import (
        HRFlowable,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#1e293b"),
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#64748b"),
    )
    heading2_style = ParagraphStyle(
        "Heading2Custom",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=10,
        spaceAfter=5,
    )
    body_style = ParagraphStyle(
        "BodyCustom",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#334155"),
    )
    bold_style = ParagraphStyle(
        "BoldCustom",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=11,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#0f172a"),
    )

    story = []

    # Title & Metadata
    story.append(Paragraph("🛡️ Secure SMTP — Security Assessment Report", title_style))
    gen_time = data.get("generated_at", "N/A")
    story.append(Paragraph(f"Generated at: {gen_time} | Passive Cryptographic Posture Intelligence", subtitle_style))
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=12))

    # Executive Summary Table
    story.append(Paragraph("Executive Summary", heading2_style))
    summary = data.get("summary", {})
    summary_data = [
        [
            Paragraph("Total Hosts", bold_style),
            Paragraph(str(summary.get("total_hosts", 0)), body_style),
            Paragraph("Critical Findings", bold_style),
            Paragraph(str(summary.get("critical_findings", 0)), body_style),
        ],
        [
            Paragraph("Total Sessions", bold_style),
            Paragraph(str(summary.get("total_sessions", 0)), body_style),
            Paragraph("High Findings", bold_style),
            Paragraph(str(summary.get("high_findings", 0)), body_style),
        ],
        [
            Paragraph("Total Findings", bold_style),
            Paragraph(str(summary.get("total_findings", 0)), body_style),
            Paragraph("Medium Findings", bold_style),
            Paragraph(str(summary.get("medium_findings", 0)), body_style),
        ],
    ]
    summary_table = Table(summary_data, colWidths=[120, 130, 120, 130])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 12))

    # Host Overview
    story.append(Paragraph("Host Overview", heading2_style))
    hosts = data.get("hosts", [])
    if hosts:
        host_table_data = [[
            Paragraph("Host / IP", bold_style),
            Paragraph("Sessions", bold_style),
            Paragraph("Aggregate Risk Score", bold_style),
            Paragraph("Status", bold_style),
        ]]
        for h in hosts:
            score = h.get("aggregate_risk_score", 0.0)
            status_text = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
            host_table_data.append([
                Paragraph(str(h.get("ip_or_hostname", "")), body_style),
                Paragraph(str(h.get("session_count", 0)), body_style),
                Paragraph(f"{score:.1f}", body_style),
                Paragraph(status_text, bold_style),
            ])
        host_table = Table(host_table_data, colWidths=[180, 70, 140, 110])
        host_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(host_table)
    else:
        story.append(Paragraph("No host records found.", body_style))

    story.append(Spacer(1, 12))

    # Session Findings Breakdown
    story.append(Paragraph("Key Findings by Session", heading2_style))
    sessions = data.get("sessions", [])
    has_findings = False

    for s in sessions:
        findings = s.get("findings", [])
        if not findings:
            continue
        has_findings = True
        s_title = f"{s.get('src_ip')}:{s.get('src_port')} → {s.get('dst_ip')}:{s.get('dst_port')} ({s.get('protocol', '').upper()})"
        risk = s.get("risk_score", {})
        r_score = risk.get("score", "N/A") if risk else "N/A"
        story.append(Paragraph(f"<b>Session:</b> {s_title} — Risk Score: {r_score}", bold_style))

        for f in findings:
            sev = str(f.get("severity", "info")).upper()
            msg = f.get("message", "")
            rec = f.get("recommendation", "")
            f_text = f"• [<b>{sev}</b>] <b>{f.get('rule_id', '')}</b>: {msg}<br/>&nbsp;&nbsp;<i>Recommendation:</i> {rec}"
            story.append(Paragraph(f_text, body_style))
        story.append(Spacer(1, 4))

    if not has_findings:
        story.append(Paragraph("No security weaknesses detected across all analyzed sessions.", body_style))

    # Footer
    story.append(Spacer(1, 15))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=6))
    story.append(Paragraph("Secure SMTP Automated Posture Assessment — Project belongs to @sharmaharshit1661-web", subtitle_style))

    doc.build(story)
    logger.info("Generated PDF report using ReportLab: %s", output_path)


def generate_pdf_report(
    html_path: str,
    output_path: str,
    report_data: dict[str, Any] | None = None,
) -> str:
    """
    Generate a PDF report from an HTML report or structured report data.

    Tries WeasyPrint first; gracefully falls back to ReportLab or JSON-derived PDF.

    Args:
        html_path: Path to the HTML report file.
        output_path: Path to write the PDF file.
        report_data: Optional dictionary with report data for native ReportLab export.

    Returns:
        Path to the generated file.
    """
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    if report_data is None:
        json_path = output.parent / "report.json"
        if json_path.exists():
            try:
                with open(json_path) as f:
                    report_data = json.load(f)
            except Exception as e:
                logger.warning("Could not read report.json for PDF export: %s", e)

    # 1. Prefer ReportLab if report_data is available (fast, pure-Python, zero C-library segfaults)
    if report_data is not None:
        try:
            _generate_pdf_reportlab(output, report_data)
            logger.info("Generated PDF report with ReportLab: %s", output)
            return str(output)
        except Exception as e:
            logger.warning("ReportLab PDF generation failed: %s; trying WeasyPrint", e)

    # 2. Try WeasyPrint if available and functional
    try:
        from weasyprint import HTML

        html = HTML(filename=html_path)
        html.write_pdf(str(output))
        logger.info("Generated PDF report with WeasyPrint: %s", output)
        return str(output)
    except Exception as e:
        logger.info("WeasyPrint not used (%s), using ReportLab fallback", e)

    # 3. Safe fallback
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate

        doc = SimpleDocTemplate(str(output), pagesize=letter)
        styles = getSampleStyleSheet()
        doc.build([
            Paragraph("Secure SMTP Assessment Report", styles["Heading1"]),
            Paragraph("Please refer to the accompanying HTML and JSON reports.", styles["Normal"]),
        ])
    except Exception:
        with open(output, "wb") as f:
            f.write(b"%PDF-1.4\n% Secure SMTP Report Placeholder\n%%EOF")

    return str(output)
