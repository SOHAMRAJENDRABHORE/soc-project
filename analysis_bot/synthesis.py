"""
Send Verdict + ActionResults to the LLM, get back a structured AnalysisReport.
"""
from __future__ import annotations

import json
from shared.llm_client import LLMClient
from shared.schemas import (
    Verdict, ActionResult, AnalysisReport, Finding,
)
from shared.logger import get_logger

log = get_logger(__name__)


SYSTEM_PROMPT = """\
You are a senior digital forensics analyst. You receive:
1. A triage Verdict produced by an earlier triage stage.
2. Raw forensic telemetry collected from the endpoint (process list,
   network connections, persistence mechanisms, memory analysis, binary RE).

Your job is to identify CONCRETE findings backed by the evidence and produce
an analysis report for the Action Bot, which will remediate the endpoint.

Rules:
- Each finding MUST cite specific evidence from the telemetry. No speculation.
- Map findings to MITRE ATT&CK techniques where applicable.
- `recommended_actions` are imperative instructions for the Action Bot
  (e.g., "isolate endpoint from network", "kill process pid=4892",
  "block outbound to 91.219.236.222", "quarantine C:\\Users\\Public\\READ_ME.txt").
- `overall_severity` reflects the worst finding. critical > high > medium > low.
- `summary` is a 3-5 sentence narrative for a human analyst.

Return ONLY valid JSON matching exactly:
{
  "findings": [
    {
      "category": "process|network|persistence|memory|binary|file",
      "severity": "low|medium|high|critical",
      "title": "<short>",
      "evidence": "<the specific telemetry that supports this>",
      "mitre_techniques": ["T1059.001", ...]
    }
  ],
  "overall_severity": "low|medium|high|critical",
  "summary": "<3-5 sentences>",
  "recommended_actions": ["<imperative action 1>", "<action 2>", ...]
}
"""


def _format_telemetry(results: list[ActionResult]) -> str:
    """Compact the raw telemetry so the prompt stays within reasonable size."""
    chunks = []
    for r in results:
        header = f"### Action: {r.action} (success={r.success}, took {r.duration_seconds}s)"
        if r.error:
            chunks.append(f"{header}\nERROR: {r.error}")
            continue
        # Truncate large blobs
        data_str = json.dumps(r.data, default=str, indent=2)
        if len(data_str) > 6000:
            data_str = data_str[:6000] + "\n...<truncated>..."
        chunks.append(f"{header}\n{data_str}")
    return "\n\n".join(chunks)


def synthesize(
    verdict: Verdict,
    telemetry: list[ActionResult],
    job_id: str,
    llm: LLMClient | None = None,
) -> AnalysisReport:
    llm = llm or LLMClient()

    user_prompt = f"""\
VERDICT (from triage stage)
---------------------------
Alert ID: {verdict.alert_id}
Label: {verdict.label.value}
Confidence: {verdict.confidence}
Reasoning: {verdict.reasoning}
MITRE (from triage): {verdict.mitre_techniques}
Recommended next step: {verdict.recommended_next_step}

IOCs
----
{json.dumps([i.model_dump() for i in verdict.iocs], indent=2)}

FORENSIC TELEMETRY
------------------
{_format_telemetry(telemetry)}

Produce your analysis JSON now.
"""

    parsed = llm.generate_json(SYSTEM_PROMPT, user_prompt)

    findings = []
    for f in parsed.get("findings", []):
        try:
            findings.append(Finding(
                category=f.get("category", "process"),
                severity=f.get("severity", "low"),
                title=f.get("title", ""),
                evidence=f.get("evidence", ""),
                mitre_techniques=f.get("mitre_techniques", []) or [],
            ))
        except Exception as e:
            log.warning(f"Skipping malformed finding: {e}")

    report = AnalysisReport(
        alert_id=verdict.alert_id,
        endpoint_id=None,   # filled in by caller
        job_id=job_id,
        verdict_label=verdict.label,
        findings=findings,
        overall_severity=parsed.get("overall_severity", "low"),
        summary=parsed.get("summary", "(no summary)"),
        recommended_actions=parsed.get("recommended_actions", []) or [],
        raw_telemetry=telemetry,
        llm_model=llm.model_name,
    )
    log.info(f"Synthesized report: {len(findings)} findings, "
             f"severity={report.overall_severity}")
    return report
