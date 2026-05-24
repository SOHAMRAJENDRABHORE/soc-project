"""
Decision Bot main entry point.

Call decide(alert) and you get a Verdict.
This is what Analysis Bot will call later via the central server.
"""
from __future__ import annotations

from typing import Callable
from shared.schemas import Alert, Verdict
from shared.logger import get_logger

from .ioc_extractor import extract_iocs
from .enrichment import enrich_all
from .verdict_engine import generate_verdict

log = get_logger(__name__)


def decide(
    alert: Alert,
    progress_cb: Callable[[str, dict], None] | None = None,
) -> Verdict:
    """
    Run the full Decision Bot pipeline on an alert.

    Args:
        alert: the alert to triage
        progress_cb: optional callback for UI progress. Called with
                    (stage_name, stage_data) at each step.

    Returns:
        Verdict with full reasoning, IOCs, and enrichment evidence.
    """
    def _emit(stage: str, data: dict):
        if progress_cb:
            progress_cb(stage, data)

    log.info(f"=== Decision Bot start: alert {alert.alert_id} ===")
    _emit("start", {"alert_id": alert.alert_id})

    # Stage 1: IOC extraction
    iocs = extract_iocs(alert)
    _emit("iocs_extracted", {"count": len(iocs), "iocs": [i.model_dump() for i in iocs]})

    # Stage 2: Enrichment (parallel)
    enrichment = enrich_all(iocs) if iocs else []
    _emit("enrichment_done", {
        "count": len(enrichment),
        "results": [e.model_dump() for e in enrichment],
    })

    # Stage 3: LLM verdict
    _emit("verdict_starting", {})
    verdict = generate_verdict(alert, iocs, enrichment)
    _emit("verdict_done", {"verdict": verdict.model_dump()})

    log.info(f"=== Decision Bot done: {verdict.label.value} ({verdict.confidence}%) ===")
    return verdict
