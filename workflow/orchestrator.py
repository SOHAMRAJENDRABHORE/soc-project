"""
Workflow orchestrator. Runs Decision → Analysis → Action as one pipeline.

VIP rule:
  If the target endpoint belongs to a VIP user (config.VIP_USERS), Action Bot
  requires explicit human approval even in auto-execute mode. This is enforced
  here by returning the planned actions instead of executing them, and setting
  `requires_approval=True` on the result.

Non-VIP endpoints in auto mode: actions run automatically.
Manual mode: always returns plan without executing.

The frontend can call this end-to-end and get back a PipelineResult that has
verdict + report + (executed actions OR pending approval).
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional, Any

from shared.schemas import Alert, Verdict, AnalysisReport
from shared.config import settings
from shared.logger import get_logger
from decision_bot.bot import decide
from analysis_bot.bot import analyze
from action_bot.bot import plan as action_plan, act as action_act

log = get_logger(__name__)


@dataclass
class PipelineStage:
    name: str
    status: str = "pending"             # pending | running | done | failed | skipped
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    output: Optional[dict[str, Any]] = None
    error: Optional[str] = None


@dataclass
class PipelineResult:
    run_id: str
    alert_id: str
    started_at: str
    finished_at: Optional[str]
    duration_seconds: float
    target_endpoint: Optional[str]
    is_vip: bool
    requires_approval: bool
    approval_reason: Optional[str]
    stages: list[PipelineStage]
    verdict: Optional[dict] = None
    report: Optional[dict] = None
    action_plan: list[dict] = field(default_factory=list)
    action_result: Optional[dict] = None
    final_status: str = "unknown"        # success | partial | failed | requires_approval

    def to_dict(self) -> dict:
        d = {
            "run_id": self.run_id,
            "alert_id": self.alert_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "target_endpoint": self.target_endpoint,
            "is_vip": self.is_vip,
            "requires_approval": self.requires_approval,
            "approval_reason": self.approval_reason,
            "stages": [s.__dict__ for s in self.stages],
            "verdict": self.verdict,
            "report": self.report,
            "action_plan": self.action_plan,
            "action_result": self.action_result,
            "final_status": self.final_status,
        }
        return d


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _endpoint_vip_check(alert: Alert, verdict: Verdict) -> tuple[bool, Optional[str]]:
    """
    Determine if the target endpoint belongs to a VIP user.

    We look at multiple signals:
      - alert.endpoint_id
      - alert.raw (often contains user/account fields)
      - any user-like IOCs in verdict
    """
    candidates: list[str] = []
    if alert.endpoint_id:
        candidates.append(alert.endpoint_id)
    raw = alert.raw or {}
    for key in ("user", "username", "userPrincipalName", "account", "owner"):
        v = raw.get(key)
        if isinstance(v, str):
            candidates.append(v)
        elif isinstance(v, dict):
            # Microsoft Graph sometimes has nested user objects
            for sub in v.values():
                if isinstance(sub, str):
                    candidates.append(sub)
    # Also check loggedOnUsers from Graph evidence shape
    for ev in raw.get("evidence", []) or []:
        if isinstance(ev, dict):
            for u in ev.get("loggedOnUsers", []) or []:
                if isinstance(u, dict) and u.get("accountName"):
                    candidates.append(u["accountName"])

    for c in candidates:
        if settings.is_vip(c):
            return True, c
    return False, None


def run_pipeline(
    alert: Alert,
    agent_id: str,
    mode: str = "auto",
    approved_actions: Optional[list[dict]] = None,
    progress_cb: Optional[Callable[[str, dict], None]] = None,
) -> PipelineResult:
    """
    End-to-end pipeline: Decision → Analysis → Action.

    Args:
      alert: the incoming alert
      agent_id: which endpoint agent to dispatch forensics & actions to
      mode: 'auto' = execute all planned actions, 'manual' = return plan only
      approved_actions: if continuing after approval, the actions analyst approved
      progress_cb: optional callback (stage_name, data) for live UI updates

    VIP override:
      If the endpoint maps to a VIP user, mode is forced to 'manual' regardless
      of caller, and the result will have requires_approval=True. Caller can
      re-invoke with approved_actions to actually execute.
    """
    def emit(stage: str, data: dict):
        if progress_cb:
            try:
                progress_cb(stage, data)
            except Exception:
                pass

    run_id = f"run-{uuid.uuid4().hex[:12]}"
    started_at = _now()
    t0 = time.time()

    stages = [
        PipelineStage(name="decision"),
        PipelineStage(name="analysis"),
        PipelineStage(name="action_planning"),
        PipelineStage(name="action_execution"),
    ]
    result = PipelineResult(
        run_id=run_id,
        alert_id=alert.alert_id,
        started_at=started_at,
        finished_at=None,
        duration_seconds=0.0,
        target_endpoint=alert.endpoint_id,
        is_vip=False,
        requires_approval=False,
        approval_reason=None,
        stages=stages,
    )

    emit("pipeline_start", {"run_id": run_id, "alert_id": alert.alert_id, "agent_id": agent_id})

    # ---------- Stage 1: Decision Bot ----------
    s = stages[0]
    s.status = "running"; s.started_at = _now()
    emit("decision_start", {})
    try:
        st1 = time.time()
        verdict = decide(alert)
        s.duration_seconds = round(time.time() - st1, 2)
        s.output = {"label": verdict.label.value, "confidence": verdict.confidence}
        s.status = "done"
        s.finished_at = _now()
        result.verdict = verdict.model_dump(mode="json")
        emit("decision_done", {"verdict": result.verdict})
    except Exception as e:
        s.status = "failed"; s.error = str(e); s.finished_at = _now()
        result.final_status = "failed"
        result.finished_at = _now()
        result.duration_seconds = round(time.time() - t0, 2)
        log.error(f"Decision Bot failed: {e}")
        return result

    # VIP check (uses verdict + alert)
    is_vip, vip_match = _endpoint_vip_check(alert, verdict)
    result.is_vip = is_vip
    if is_vip:
        result.approval_reason = f"VIP user detected: '{vip_match}'"
        log.warning(f"[{run_id}] {result.approval_reason}")

    # ---------- Stage 2: Analysis Bot ----------
    s = stages[1]
    s.status = "running"; s.started_at = _now()
    emit("analysis_start", {})
    try:
        st2 = time.time()
        report = analyze(verdict, agent_id=agent_id)
        s.duration_seconds = round(time.time() - st2, 2)
        s.output = {
            "findings": len(report.findings),
            "severity": report.overall_severity,
        }
        s.status = "done"
        s.finished_at = _now()
        result.report = report.model_dump(mode="json")
        emit("analysis_done", {"report": result.report})
    except Exception as e:
        s.status = "failed"; s.error = str(e); s.finished_at = _now()
        result.final_status = "partial"
        result.finished_at = _now()
        result.duration_seconds = round(time.time() - t0, 2)
        log.error(f"Analysis Bot failed: {e}")
        return result

    # ---------- Stage 3: Action planning ----------
    s = stages[2]
    s.status = "running"; s.started_at = _now()
    emit("action_planning_start", {})
    try:
        st3 = time.time()
        planned = action_plan(report)
        s.duration_seconds = round(time.time() - st3, 2)
        s.output = {"planned_count": len(planned)}
        s.status = "done"
        s.finished_at = _now()
        result.action_plan = planned
        emit("action_planning_done", {"planned": planned})
    except Exception as e:
        s.status = "failed"; s.error = str(e); s.finished_at = _now()
        result.final_status = "partial"
        result.finished_at = _now()
        result.duration_seconds = round(time.time() - t0, 2)
        log.error(f"Action planning failed: {e}")
        return result

    # ---------- VIP gate: pause if VIP and no approval yet ----------
    if is_vip and approved_actions is None:
        stages[3].status = "skipped"
        stages[3].error = "Awaiting human approval (VIP endpoint)"
        result.requires_approval = True
        result.final_status = "requires_approval"
        result.finished_at = _now()
        result.duration_seconds = round(time.time() - t0, 2)
        emit("requires_approval", {"reason": result.approval_reason,
                                   "planned": planned})
        log.info(f"[{run_id}] PAUSED for approval — VIP endpoint")
        return result

    # ---------- Manual mode: return plan without executing ----------
    if mode == "manual" and approved_actions is None:
        stages[3].status = "skipped"
        stages[3].error = "Manual mode — actions returned for review"
        result.final_status = "requires_approval"
        result.requires_approval = True
        result.approval_reason = result.approval_reason or "Manual mode selected"
        result.finished_at = _now()
        result.duration_seconds = round(time.time() - t0, 2)
        emit("manual_pause", {"planned": planned})
        return result

    # ---------- Stage 4: Action execution ----------
    s = stages[3]
    s.status = "running"; s.started_at = _now()
    emit("action_execution_start", {})

    # Decide which actions to actually run
    actions_to_execute = approved_actions if approved_actions is not None else planned

    try:
        st4 = time.time()
        # Use action_bot.act in manual mode with our list (we already approved them here)
        # action_bot.act expects mode='manual' + approved_actions for selective execution
        action_result = action_act(
            report=report,
            agent_id=agent_id,
            mode="manual",
            approved_actions=actions_to_execute,
        )
        s.duration_seconds = round(time.time() - st4, 2)
        s.output = {"status": action_result.get("status"),
                    "executed_count": len(action_result.get("executed", []))}
        s.status = "done" if action_result.get("status") == "done" else "partial"
        s.finished_at = _now()
        result.action_result = action_result
        result.final_status = "success" if action_result.get("status") == "done" else "partial"
        emit("action_execution_done", {"action_result": action_result})
    except Exception as e:
        s.status = "failed"; s.error = str(e); s.finished_at = _now()
        result.final_status = "partial"

    result.finished_at = _now()
    result.duration_seconds = round(time.time() - t0, 2)
    emit("pipeline_done", {"final_status": result.final_status})
    log.info(f"[{run_id}] Pipeline complete: {result.final_status} "
             f"in {result.duration_seconds}s")
    return result
