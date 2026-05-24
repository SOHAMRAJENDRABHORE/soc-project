"""Sends approved actions to endpoint via central server, waits for results."""
from __future__ import annotations

from shared.schemas import ForensicAction
from shared.logger import get_logger
from analysis_bot.dispatcher import CentralServerClient

log = get_logger(__name__)


def execute(agent_id: str, approved_actions: list[dict],
            alert_id: str, timeout: int = 120) -> dict:
    if not approved_actions:
        return {"job_id": None, "status": "skipped",
                "results": [], "note": "No actions approved"}

    forensic_actions = [
        ForensicAction(name=a["name"], params=a.get("params", {}))
        for a in approved_actions
    ]
    client = CentralServerClient()
    job_id = client.dispatch(
        agent_id=agent_id, actions=forensic_actions,
        requested_by=f"action_bot:alert={alert_id}",
    )
    log.info(f"Action Bot dispatched job {job_id} ({len(forensic_actions)} actions)")
    results, status = client.wait_for_result(job_id, timeout=timeout)
    return {
        "job_id": job_id, "status": status,
        "results": [r.model_dump() for r in results],
    }
