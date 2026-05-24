"""
Sends the alert + enrichment to the LLM, parses the verdict.

The prompt is the most important file in Decision Bot. If verdicts are wrong,
you tune this. Keep it precise and structured.
"""
from __future__ import annotations

import json
from shared.llm_client import LLMClient
from shared.schemas import (
    Alert, IOC, EnrichmentResult, Verdict, VerdictLabel,
)
from shared.logger import get_logger

log = get_logger(__name__)


SYSTEM_PROMPT = """\
You are a senior SOC analyst. You triage endpoint security alerts and produce
machine-readable verdicts. You think in terms of the MITRE ATT&CK framework
and the Lockheed Martin Cyber Kill Chain.

Rules:
- Base your verdict ONLY on the alert and enrichment data provided.
- If enrichment is missing or inconclusive, say so in `reasoning` and lower confidence.
- Never invent IOCs or evidence that wasn't given to you.
- Be concise. `reasoning` should be 2-4 sentences. No fluff.
- `recommended_next_step` is an instruction to the downstream Analysis Bot;
  be specific about which forensic data to collect (memory, processes, network,
  persistence, binary RE, etc.) and from which endpoint.

Return ONLY valid JSON matching exactly this schema:
{
  "label": "benign" | "suspicious" | "malicious" | "unknown",
  "confidence": <integer 0-100>,
  "reasoning": "<string>",
  "mitre_techniques": ["T1059.001", "T1486", ...],
  "kill_chain_phase": "reconnaissance" | "weaponization" | "delivery" | "exploitation" | "installation" | "command_and_control" | "actions_on_objectives" | null,
  "recommended_next_step": "<string>"
}
"""


def _format_enrichment(enrichment: list[EnrichmentResult]) -> str:
    if not enrichment:
        return "No enrichment data available."
    rows = []
    for e in enrichment:
        if e.success:
            rows.append(
                f"- [{e.source}] {e.ioc_type.value}={e.ioc_value} → "
                f"{e.reputation or '?'} (score={e.malicious_score}) "
                f"tags={e.tags} | {e.summary or ''}"
            )
        else:
            rows.append(f"- [{e.source}] {e.ioc_value} → FAILED: {e.error}")
    return "\n".join(rows)


def _format_iocs(iocs: list[IOC]) -> str:
    if not iocs:
        return "No IOCs extracted."
    return "\n".join(f"- {i.type.value}: {i.value}" for i in iocs)


def generate_verdict(
    alert: Alert,
    iocs: list[IOC],
    enrichment: list[EnrichmentResult],
    llm: LLMClient | None = None,
) -> Verdict:
    llm = llm or LLMClient()

    user_prompt = f"""\
ALERT
-----
ID: {alert.alert_id}
Source: {alert.source}
Severity: {alert.severity or 'unknown'}
Title: {alert.title or '(no title)'}
Description: {alert.description or '(no description)'}
Endpoint: {alert.endpoint_id or 'unknown'}

Raw payload:
{json.dumps(alert.raw, indent=2, default=str)[:2000]}

EXTRACTED IOCs
--------------
{_format_iocs(iocs)}

THREAT INTEL ENRICHMENT
-----------------------
{_format_enrichment(enrichment)}

Produce your verdict JSON now.
"""

    parsed = llm.generate_json(SYSTEM_PROMPT, user_prompt)

    # Defensive parsing — the LLM should follow the schema but be lenient
    try:
        label = VerdictLabel(parsed.get("label", "unknown").lower())
    except ValueError:
        label = VerdictLabel.UNKNOWN

    confidence = int(parsed.get("confidence", 0))
    confidence = max(0, min(100, confidence))

    verdict = Verdict(
        alert_id=alert.alert_id,
        label=label,
        confidence=confidence,
        reasoning=parsed.get("reasoning", "(no reasoning provided)"),
        mitre_techniques=parsed.get("mitre_techniques", []) or [],
        kill_chain_phase=parsed.get("kill_chain_phase"),
        recommended_next_step=parsed.get("recommended_next_step",
                                        "Collect baseline endpoint telemetry."),
        iocs=iocs,
        enrichment=enrichment,
        llm_model=llm.model_name,
    )
    log.info(f"Verdict for {alert.alert_id}: {label.value} ({confidence}%)")
    return verdict
