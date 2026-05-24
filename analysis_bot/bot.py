"""
Analysis Bot main entry point.

Usage:
    from analysis_bot.bot import analyze
    report = analyze(verdict, agent_id="agent-vm-abc123")
"""
from __future__ import annotations

from typing import Callable
from shared.schemas import Verdict, AnalysisReport
from shared.logger import get_logger

from .action_planner import plan_actions
from .dispatcher import CentralServerClient
from .synthesis import synthesize

log = get_logger(__name__)


def analyze(
    verdict: Verdict,
    agent_id: str,
    timeout_seconds: int = 600,
    progress_cb: Callable[[str, dict], None] | None = None,
) -> AnalysisReport:
    """
    Run the full Analysis Bot pipeline.

    Args:
        verdict: the Verdict produced by Decision Bot
        agent_id: which endpoint agent to dispatch the job to
        timeout_seconds: how long to wait for the agent's results
        progress_cb: optional UI progress callback (stage, data)

    Returns:
        AnalysisReport (consumed by Action Bot next)

    Raises:
        TimeoutError if the agent doesn't return in time
        RuntimeError if the job fails or expires
    """
    def _emit(stage: str, data: dict):
        if progress_cb:
            progress_cb(stage, data)

    log.info(f"=== Analysis Bot start: alert={verdict.alert_id} agent={agent_id} ===")
    _emit("start", {"alert_id": verdict.alert_id, "agent_id": agent_id})

    # 1. Plan
    actions = plan_actions(verdict)
    _emit("plan_ready", {"actions": [a.model_dump() for a in actions]})

    # 2. Dispatch
    client = CentralServerClient()
    job_id = client.dispatch(
        agent_id=agent_id,
        actions=actions,
        requested_by=f"analysis_bot:alert={verdict.alert_id}",
    )
    _emit("dispatched", {"job_id": job_id})

    # 3. Wait
    log.info(f"Waiting for job {job_id} (timeout={timeout_seconds}s)...")
    _emit("waiting", {"job_id": job_id, "timeout": timeout_seconds})
    results, status = client.wait_for_result(job_id, timeout=timeout_seconds)
    _emit("agent_done", {
        "status": status,
        "results_count": len(results),
        "results": [r.model_dump() for r in results],
    })

    if status != "done":
        raise RuntimeError(f"Job {job_id} did not complete: status={status}")

    # 4. Synthesize with LLM
    _emit("synthesizing", {})
    report = synthesize(verdict, results, job_id=job_id)
    report.endpoint_id = verdict.iocs and None  # placeholder; caller can override

    _emit("report_done", {"report": report.model_dump(mode="json")})
    log.info(f"=== Analysis Bot done: {len(report.findings)} findings, "
             f"severity={report.overall_severity} ===")
    return report
