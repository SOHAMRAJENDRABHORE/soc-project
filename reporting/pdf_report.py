"""
PDF report generator. Takes a PipelineResult and produces a SOC-style
incident report PDF suitable for analyst hand-off / archival.

Pure ReportLab — no system dependencies.

Structure:
  - Cover banner (incident ID, severity, timestamp)
  - Executive summary (one paragraph from the LLM's synthesis)
  - Verdict block (label, confidence, MITRE techniques, kill chain)
  - IOCs table
  - Threat intel enrichment table
  - Forensic findings with evidence
  - Actions taken (or pending approval)
  - Appendix: raw telemetry summary

Generated PDFs go to ./reports/ in the project root.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether,
)

from shared.config import PROJECT_ROOT
from shared.logger import get_logger

log = get_logger(__name__)


REPORTS_DIR = PROJECT_ROOT / "reports"
REPORTS_DIR.mkdir(exist_ok=True)


# --- Palette: dark professional SOC report aesthetic on white paper ---
COLOR_PRIMARY = colors.HexColor("#1a1f2e")      # deep navy
COLOR_ACCENT = colors.HexColor("#c2410c")       # burnt orange (replaces overused blue)
COLOR_MUTED = colors.HexColor("#64748b")
COLOR_DANGER = colors.HexColor("#b91c1c")
COLOR_WARN = colors.HexColor("#b45309")
COLOR_OK = colors.HexColor("#15803d")
COLOR_BG_SOFT = colors.HexColor("#f8fafc")
COLOR_BORDER = colors.HexColor("#cbd5e1")


def _severity_color(sev: str) -> colors.HexColor:
    s = (sev or "").lower()
    if s in ("critical", "malicious", "high"):
        return COLOR_DANGER
    if s in ("medium", "suspicious", "warn"):
        return COLOR_WARN
    if s in ("low", "benign", "clean"):
        return COLOR_OK
    return COLOR_MUTED


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    out = {
        "h1": ParagraphStyle(
            "h1", parent=base["Heading1"],
            fontName="Helvetica-Bold", fontSize=22, leading=26,
            textColor=COLOR_PRIMARY, spaceAfter=4,
        ),
        "h2": ParagraphStyle(
            "h2", parent=base["Heading2"],
            fontName="Helvetica-Bold", fontSize=12, leading=16,
            textColor=COLOR_ACCENT, spaceBefore=14, spaceAfter=6,
            borderPadding=0,
        ),
        "label": ParagraphStyle(
            "label", parent=base["BodyText"],
            fontName="Helvetica-Bold", fontSize=8, leading=10,
            textColor=COLOR_MUTED, spaceAfter=2,
        ),
        "value": ParagraphStyle(
            "value", parent=base["BodyText"],
            fontName="Helvetica", fontSize=10, leading=14,
            textColor=COLOR_PRIMARY, spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "body", parent=base["BodyText"],
            fontName="Helvetica", fontSize=10, leading=14,
            textColor=colors.HexColor("#1e293b"), spaceAfter=8,
        ),
        "small": ParagraphStyle(
            "small", parent=base["BodyText"],
            fontName="Helvetica", fontSize=8, leading=10,
            textColor=COLOR_MUTED, spaceAfter=4,
        ),
        "mono": ParagraphStyle(
            "mono", parent=base["BodyText"],
            fontName="Courier", fontSize=8, leading=10,
            textColor=colors.HexColor("#1e293b"),
        ),
        "verdict_big": ParagraphStyle(
            "verdict_big", parent=base["Heading1"],
            fontName="Helvetica-Bold", fontSize=28, leading=32,
            alignment=TA_LEFT,
        ),
    }
    return out


def _truncate(s: Any, n: int = 80) -> str:
    s = str(s) if s is not None else ""
    return s if len(s) <= n else s[: n - 1] + "…"


def _cover(story: list, doc, styles: dict, result: dict):
    verdict = result.get("verdict") or {}
    report = result.get("report") or {}
    sev_label = (report.get("overall_severity") or verdict.get("label") or "unknown").upper()
    sev_color = _severity_color(sev_label)

    # Title bar
    bar = Table([[
        Paragraph("AGENTIC SOC", ParagraphStyle(
            "brand", fontName="Helvetica-Bold", fontSize=10, leading=12,
            textColor=COLOR_BG_SOFT, alignment=TA_LEFT,
        )),
        Paragraph(f"Incident Report · {result.get('run_id', '')}", ParagraphStyle(
            "brand2", fontName="Helvetica", fontSize=9, leading=11,
            textColor=COLOR_BG_SOFT, alignment=TA_LEFT,
        )),
    ]], colWidths=[1.5 * inch, 5.5 * inch])
    bar.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COLOR_PRIMARY),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(bar)
    story.append(Spacer(1, 24))

    # Title
    story.append(Paragraph(
        f"Security Incident Report",
        styles["h1"],
    ))
    story.append(Paragraph(
        f"Alert ID: <font face='Courier'>{result.get('alert_id', 'unknown')}</font>",
        styles["small"],
    ))
    story.append(Spacer(1, 12))

    # Big severity callout
    severity_box = Table([[
        Paragraph(
            f"<font color='{sev_color}'><b>{sev_label}</b></font>",
            styles["verdict_big"]
        ),
        [
            Paragraph("CONFIDENCE", styles["label"]),
            Paragraph(f"{verdict.get('confidence', '—')}%", styles["value"]),
            Paragraph("ENDPOINT", styles["label"]),
            Paragraph(_truncate(result.get('target_endpoint') or "—", 40), styles["value"]),
            Paragraph("VIP", styles["label"]),
            Paragraph("Yes" if result.get('is_vip') else "No", styles["value"]),
        ],
    ]], colWidths=[3.0 * inch, 4.0 * inch])
    severity_box.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (-1, -1), COLOR_BG_SOFT),
        ("LINEBELOW", (0, 0), (-1, -1), 2, sev_color),
        ("LEFTPADDING", (0, 0), (-1, -1), 16),
        ("RIGHTPADDING", (0, 0), (-1, -1), 16),
        ("TOPPADDING", (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
    ]))
    story.append(severity_box)
    story.append(Spacer(1, 16))


def _executive_summary(story, styles, result: dict):
    story.append(Paragraph("EXECUTIVE SUMMARY", styles["h2"]))
    report = result.get("report") or {}
    summary = report.get("summary") or "No analysis summary available."
    story.append(Paragraph(summary, styles["body"]))

    verdict = result.get("verdict") or {}
    reasoning = verdict.get("reasoning") or ""
    if reasoning:
        story.append(Paragraph("TRIAGE REASONING", styles["label"]))
        story.append(Paragraph(reasoning, styles["body"]))


def _verdict_section(story, styles, result: dict):
    v = result.get("verdict") or {}
    if not v:
        return
    story.append(Paragraph("VERDICT", styles["h2"]))

    rows = [
        ["Label", str(v.get("label", "—")).upper()],
        ["Confidence", f"{v.get('confidence', '—')}%"],
        ["Kill Chain Phase", str(v.get("kill_chain_phase") or "—")],
        ["LLM Model", str(v.get("llm_model") or "—")],
    ]
    techniques = v.get("mitre_techniques") or []
    if techniques:
        rows.append(["MITRE Techniques", ", ".join(techniques)])

    t = Table(rows, colWidths=[1.5 * inch, 5.5 * inch])
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), COLOR_MUTED),
        ("TEXTCOLOR", (1, 0), (1, -1), COLOR_PRIMARY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, COLOR_BORDER),
    ]))
    story.append(t)


def _iocs_section(story, styles, result: dict):
    v = result.get("verdict") or {}
    iocs = v.get("iocs") or []
    if not iocs:
        return
    story.append(Paragraph("INDICATORS OF COMPROMISE", styles["h2"]))
    data = [["TYPE", "VALUE", "CONTEXT"]]
    for ioc in iocs[:30]:
        data.append([
            ioc.get("type", "").upper(),
            _truncate(ioc.get("value", ""), 60),
            ioc.get("context") or "—",
        ])
    t = Table(data, colWidths=[1.0 * inch, 4.5 * inch, 1.5 * inch], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_PRIMARY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("FONTNAME", (1, 1), (1, -1), "Courier"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, COLOR_BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, COLOR_BG_SOFT]),
    ]))
    story.append(t)


def _enrichment_section(story, styles, result: dict):
    v = result.get("verdict") or {}
    enrichments = v.get("enrichment") or []
    if not enrichments:
        return
    story.append(Paragraph("THREAT INTELLIGENCE ENRICHMENT", styles["h2"]))
    data = [["SOURCE", "IOC", "VERDICT", "SCORE", "SUMMARY"]]
    for e in enrichments[:40]:
        if not e.get("success"):
            continue
        rep = (e.get("reputation") or "—")
        data.append([
            e.get("source", ""),
            _truncate(e.get("ioc_value", ""), 36),
            rep.upper(),
            str(e.get("malicious_score") or "—"),
            _truncate(e.get("summary") or "", 50),
        ])
    if len(data) == 1:
        return
    t = Table(data, colWidths=[0.9 * inch, 2.3 * inch, 0.9 * inch,
                                0.7 * inch, 2.2 * inch], repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_PRIMARY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("FONTNAME", (1, 1), (1, -1), "Courier"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, COLOR_BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_BG_SOFT]),
    ]
    # Color the verdict column
    for i, row in enumerate(data[1:], start=1):
        c = _severity_color(row[2])
        style.append(("TEXTCOLOR", (2, i), (2, i), c))
        style.append(("FONTNAME", (2, i), (2, i), "Helvetica-Bold"))
    t.setStyle(TableStyle(style))
    story.append(t)


def _findings_section(story, styles, result: dict):
    r = result.get("report") or {}
    findings = r.get("findings") or []
    if not findings:
        return
    story.append(Paragraph("FORENSIC FINDINGS", styles["h2"]))
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "low")
        sev_color = _severity_color(sev)
        title = f.get("title", "(no title)")
        category = f.get("category", "?")
        evidence = f.get("evidence", "")
        techniques = f.get("mitre_techniques", []) or []

        block = [
            Paragraph(
                f"<font color='{sev_color}'><b>[{sev.upper()}]</b></font> "
                f"<font color='{COLOR_MUTED}'>{category}</font> · <b>{title}</b>",
                styles["body"]
            ),
            Paragraph(f"<i>Evidence:</i> {_truncate(evidence, 500)}", styles["small"]),
        ]
        if techniques:
            block.append(Paragraph(
                f"<i>MITRE:</i> {', '.join(techniques)}",
                styles["small"],
            ))
        block.append(Spacer(1, 6))
        story.append(KeepTogether(block))


def _actions_section(story, styles, result: dict):
    story.append(Paragraph("ACTIONS TAKEN", styles["h2"]))

    if result.get("requires_approval"):
        reason = result.get("approval_reason") or "Awaiting analyst approval"
        story.append(Paragraph(
            f"<b>PENDING APPROVAL.</b> Reason: {reason}",
            styles["body"]
        ))
        planned = result.get("action_plan") or []
        if planned:
            story.append(Paragraph("Proposed actions (not yet executed):", styles["small"]))
            for a in planned:
                story.append(Paragraph(
                    f"• <b>{a.get('name')}</b> — params={json.dumps(a.get('params', {}))}",
                    styles["small"],
                ))
        return

    action_result = result.get("action_result")
    if not action_result:
        story.append(Paragraph("No actions executed.", styles["body"]))
        return

    executed = action_result.get("executed", []) or []
    results = action_result.get("results", []) or []

    data = [["#", "ACTION", "STATUS", "DETAILS"]]
    for i, r in enumerate(results, 1):
        ok = r.get("success")
        details = ""
        d = r.get("data") or {}
        if isinstance(d, dict):
            for key in ("ip", "domain", "username", "rule_name", "quarantine_path"):
                if d.get(key):
                    details = f"{key}={d[key]}"
                    break
            if not details:
                details = _truncate(json.dumps(d, default=str), 60)
        data.append([
            str(i),
            r.get("action", "?"),
            "✓ success" if ok else "✗ failed",
            details,
        ])
    if len(data) > 1:
        t = Table(data, colWidths=[0.3 * inch, 1.6 * inch, 1.0 * inch, 4.1 * inch], repeatRows=1)
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_PRIMARY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("FONTNAME", (1, 1), (1, -1), "Helvetica-Bold"),
            ("FONTNAME", (3, 1), (3, -1), "Courier"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LINEBELOW", (0, 0), (-1, -1), 0.25, COLOR_BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_BG_SOFT]),
        ]
        for i, r in enumerate(results, 1):
            c = COLOR_OK if r.get("success") else COLOR_DANGER
            style.append(("TEXTCOLOR", (2, i), (2, i), c))
        t.setStyle(TableStyle(style))
        story.append(t)


def _pipeline_timing(story, styles, result: dict):
    story.append(Paragraph("PIPELINE EXECUTION TIMING", styles["h2"]))
    data = [["STAGE", "STATUS", "DURATION"]]
    for s in result.get("stages") or []:
        data.append([
            s.get("name", "?"),
            s.get("status", "?"),
            f"{s.get('duration_seconds') or 0:.1f}s" if s.get("duration_seconds") is not None else "—",
        ])
    data.append(["TOTAL", result.get("final_status", "?"),
                 f"{result.get('duration_seconds', 0):.1f}s"])
    t = Table(data, colWidths=[2.5 * inch, 2.5 * inch, 2.0 * inch], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_PRIMARY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ("BACKGROUND", (0, -1), (-1, -1), COLOR_BG_SOFT),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, COLOR_BORDER),
    ]))
    story.append(t)


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(COLOR_MUTED)
    canvas.drawString(
        0.6 * inch, 0.4 * inch,
        f"Agentic SOC · Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
    )
    canvas.drawRightString(
        LETTER[0] - 0.6 * inch, 0.4 * inch,
        f"Page {doc.page}"
    )
    canvas.restoreState()


def generate_report(pipeline_result: dict, filename: str | None = None) -> Path:
    """
    Render a PipelineResult dict into a PDF and return the file path.

    pipeline_result: from PipelineResult.to_dict()
    """
    run_id = pipeline_result.get("run_id", f"run-{int(datetime.now().timestamp())}")
    if not filename:
        filename = f"{run_id}.pdf"
    out_path = REPORTS_DIR / filename

    doc = SimpleDocTemplate(
        str(out_path), pagesize=LETTER,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
        topMargin=0.5 * inch, bottomMargin=0.6 * inch,
        title=f"Agentic SOC Incident Report — {run_id}",
        author="Agentic SOC",
    )
    styles = _styles()
    story: list = []

    _cover(story, doc, styles, pipeline_result)
    _executive_summary(story, styles, pipeline_result)
    _verdict_section(story, styles, pipeline_result)
    _iocs_section(story, styles, pipeline_result)
    _enrichment_section(story, styles, pipeline_result)
    story.append(PageBreak())
    _findings_section(story, styles, pipeline_result)
    _actions_section(story, styles, pipeline_result)
    _pipeline_timing(story, styles, pipeline_result)

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    log.info(f"PDF report written: {out_path}")
    return out_path
