"""Action Bot main entry point."""
from __future__ import annotations

from typing import Callable, Optional
from datetime import datetime, timezone
from shared.schemas import AnalysisReport
from shared.logger import get_logger
from .mapper import map_recommendations
from .executor import execute

log = get_logger(__name__)


def plan(report: AnalysisReport) -> list[dict]:
    """Return mapped actions WITHOUT executing them."""
    return map_recommendations(report)


def act(
    report: AnalysisReport,
    agent_id: str,
    mode: str = "manual",
    approved_actions: Optional[list[dict]] = None,
    timeout: int = 120,
    progress_cb: Optional[Callable[[str, dict], None]] = None,
) -> dict:
    def emit(stage, data):
        if progress_cb:
            try: progress_cb(stage, data)
            except: pass

    log.info(f"=== Action Bot: alert={report.alert_id} mode={mode} ===")
    emit("start", {"alert_id": report.alert_id, "mode": mode})

    planned = map_recommendations(report)
    emit("planned", {"actions": planned})

    if mode == "auto":
        to_run = planned
    elif mode == "manual":
        if approved_actions is None:
            raise ValueError("manual mode requires approved_actions")
        to_run = approved_actions
    else:
        raise ValueError(f"unknown mode: {mode}")

    emit("executing", {"actions": to_run})
    exec_result = execute(agent_id, to_run, alert_id=report.alert_id, timeout=timeout)
    emit("done", exec_result)
    return {
        "alert_id": report.alert_id, "mode": mode,
        "planned": planned, "executed": to_run,
        "executed_at": datetime.now(timezone.utc).isoformat(),
        **exec_result,
    }
