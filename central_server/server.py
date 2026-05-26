"""
Central Server (FastAPI).

Roles:
  - Agents register, heartbeat, poll for jobs, post results
  - Analysis Bot (or any client with auth) dispatches jobs, fetches results
  - SQLite persistence

Run:
  python -m central_server.server
or:
  uvicorn central_server.server:app --host 0.0.0.0 --port 8080
"""
from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Optional

from fastapi import FastAPI, Header, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from shared.config import settings
from shared.logger import get_logger
from shared.schemas import (
    AgentRegistration, Heartbeat, Job, JobResult, JobStatus, ForensicAction,
)

from . import db
from forensics.api import router as forensics_router

log = get_logger(__name__)


# ---------- App ----------

_DASHBOARD_DIR = Path(__file__).parent.parent / "frontend" / "dashboard"


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    db.init_pipeline_runs()
    log.info("Central server ready")
    if _DASHBOARD_DIR.exists():
        log.info(f"Dashboard available at http://localhost:{settings.CENTRAL_SERVER_PORT}/ui/index.html")
    yield


app = FastAPI(title="Agentic SOC Central Server", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve the static dashboard files under /ui
if _DASHBOARD_DIR.exists():
    app.mount("/ui", StaticFiles(directory=str(_DASHBOARD_DIR), html=True), name="dashboard-ui")


@app.get("/dashboard-ui", response_class=HTMLResponse, include_in_schema=False)
def dashboard_ui_redirect():
    """Convenience: open /dashboard-ui to reach the dashboard."""
    index = _DASHBOARD_DIR / "index.html"
    if not index.exists():
        raise HTTPException(404, "Dashboard not built")
    return HTMLResponse(content=index.read_text(encoding="utf-8"))


# ---------- Auth ----------

def require_auth(authorization: Annotated[Optional[str], Header()] = None):
    """Bearer token check. Used on every agent and job endpoint."""
    if not settings.AGENT_AUTH_TOKEN:
        log.error("AGENT_AUTH_TOKEN not configured")
        raise HTTPException(503, "Server not configured")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    if token != settings.AGENT_AUTH_TOKEN:
        raise HTTPException(403, "Invalid token")


# ---------- Health ----------

@app.get("/health")
def health():
    return {
        "status": "ok",
        "time": datetime.now(timezone.utc).isoformat(),
        "agents_registered": len(db.list_agents()),
    }


# ---------- Agent endpoints ----------

@app.post("/agents/register", dependencies=[Depends(require_auth)])
def register_agent(reg: AgentRegistration):
    db.upsert_agent(reg.model_dump(mode="json"))
    log.info(f"Agent registered: {reg.agent_id} ({reg.hostname}, {reg.os})")
    return {"ok": True, "agent_id": reg.agent_id}


@app.post("/agents/heartbeat", dependencies=[Depends(require_auth)])
def heartbeat(hb: Heartbeat):
    if not db.get_agent(hb.agent_id):
        raise HTTPException(404, "Unknown agent — register first")
    db.update_heartbeat(hb.agent_id)
    return {"ok": True}


@app.get("/agents", dependencies=[Depends(require_auth)])
def list_agents():
    """Used by the UI / Analysis Bot to see which endpoints are online."""
    db.expire_old_jobs()
    agents = db.list_agents()
    cutoff = datetime.now(timezone.utc).timestamp() - settings.AGENT_OFFLINE_AFTER_SECONDS
    for a in agents:
        last = datetime.fromisoformat(a["last_seen_at"]).timestamp()
        a["online"] = last >= cutoff
    return agents


# ---------- Job endpoints ----------

class JobCreateRequest(BaseModel):
    agent_id: str
    actions: list[ForensicAction]
    requested_by: Optional[str] = None


@app.post("/jobs", dependencies=[Depends(require_auth)])
def create_job(req: JobCreateRequest):
    if not db.get_agent(req.agent_id):
        raise HTTPException(404, f"Unknown agent: {req.agent_id}")
    job_id = f"job-{uuid.uuid4().hex[:12]}"
    db.create_job(
        job_id=job_id,
        agent_id=req.agent_id,
        actions=[a.model_dump() for a in req.actions],
        requested_by=req.requested_by,
    )
    log.info(f"Job {job_id} created for {req.agent_id} ({len(req.actions)} actions)")
    return {"job_id": job_id, "status": "queued"}


@app.get("/agents/{agent_id}/next-job", dependencies=[Depends(require_auth)])
def next_job(agent_id: str):
    """Agent polling endpoint. Returns next job or 204 No Content."""
    db.update_heartbeat(agent_id)
    db.expire_old_jobs()
    job = db.claim_next_job(agent_id)
    if not job:
        return {"job": None}
    return {"job": job}


@app.post("/jobs/{job_id}/result", dependencies=[Depends(require_auth)])
def post_result(job_id: str, result: JobResult):
    if not db.get_job(job_id):
        raise HTTPException(404, "Unknown job")
    db.save_result(job_id, result.agent_id,
                   [r.model_dump() for r in result.results])
    log.info(f"Job {job_id} completed ({len(result.results)} actions)")
    return {"ok": True}


@app.get("/jobs/{job_id}", dependencies=[Depends(require_auth)])
def get_job_status(job_id: str):
    """Used by Analysis Bot to poll for completion."""
    job = db.get_job(job_id)
    if not job:
        raise HTTPException(404, "Unknown job")
    result = db.get_result(job_id)
    return {"job": job, "result": result}


# ---------- Onboarding: tenants ----------

@app.get("/tenants", dependencies=[Depends(require_auth)])
def list_tenants_endpoint(enabled_only: bool = False):
    return db.list_tenants(enabled_only=enabled_only)


@app.get("/tenants/{tenant_id}", dependencies=[Depends(require_auth)])
def get_tenant_endpoint(tenant_id: str):
    t = db.get_tenant(tenant_id)
    if not t:
        raise HTTPException(404, "Tenant not found")
    # Never expose encrypted_credentials over the network
    t.pop("encrypted_credentials", None)
    return t


# ---------- Onboarding: pending alerts inbox ----------

@app.get("/alerts/pending", dependencies=[Depends(require_auth)])
def list_pending_alerts_endpoint(status: Optional[str] = None,
                                  tenant_id: Optional[str] = None,
                                  limit: int = 100):
    return db.list_pending_alerts(status=status, tenant_id=tenant_id, limit=limit)


@app.get("/alerts/pending/{pending_id}", dependencies=[Depends(require_auth)])
def get_pending_alert_endpoint(pending_id: str):
    p = db.get_pending_alert(pending_id)
    if not p:
        raise HTTPException(404, "Pending alert not found")
    return p


class StatusUpdateRequest(BaseModel):
    status: str
    verdict_alert_id: Optional[str] = None
    auto_result_summary: Optional[str] = None


@app.post("/alerts/pending/{pending_id}/status", dependencies=[Depends(require_auth)])
def update_pending_status_endpoint(pending_id: str, body: StatusUpdateRequest):
    if not db.get_pending_alert(pending_id):
        raise HTTPException(404, "Pending alert not found")
    db.update_pending_status(
        pending_id, status=body.status,
        verdict_alert_id=body.verdict_alert_id,
        auto_result_summary=body.auto_result_summary,
    )
    return {"ok": True}


# ---------- Onboarding: webhook receiver ----------

@app.post("/webhooks/{webhook_token}/ingest")
def webhook_ingest(webhook_token: str, payload: dict):
    """
    Public webhook endpoint. Auth via the per-tenant webhook_token in the
    URL path. Does NOT use the AGENT_AUTH_TOKEN because external systems
    won't know it.

    Body should be a Graph-shaped alert (or close to it).
    """
    # Find the tenant that owns this token
    tenants = db.list_tenants(enabled_only=True)
    target = None
    for t in tenants:
        if t["provider_type"] != "webhook":
            continue
        if t["provider_config"].get("webhook_token") == webhook_token:
            target = t
            break
    if not target:
        raise HTTPException(404, "Unknown webhook token")

    # Defer normalization + routing to onboarding_agent so this endpoint
    # stays small. Local import to avoid circular dependency at server start.
    from onboarding_agent.normalizer import normalize
    from onboarding_agent.ingestion_modes import route_alert

    try:
        alert = normalize(payload, "webhook", target["tenant_id"])
        pending_id = route_alert(alert, target, payload)
        return {"ok": True, "pending_id": pending_id}
    except Exception as e:
        log.error(f"Webhook ingest failed for tenant {target['tenant_id']}: {e}")
        raise HTTPException(400, f"Failed to ingest: {e}")


# ---------- Workflow orchestration ----------

class WorkflowRunRequest(BaseModel):
    alert: dict                          # serialized Alert
    agent_id: str
    mode: str = "auto"                   # auto | manual
    approved_actions: Optional[list[dict]] = None


@app.post("/workflow/run", dependencies=[Depends(require_auth)])
def workflow_run(req: WorkflowRunRequest):
    """
    Run the full Decision → Analysis → Action pipeline synchronously.

    Returns the complete PipelineResult including PDF path. The frontend
    polls /workflow/runs/{run_id} for incremental updates if needed, but
    this endpoint returns the full result on completion.

    VIP gating: if endpoint is VIP and no approved_actions supplied,
    returns with requires_approval=True instead of executing.
    """
    # Local imports to avoid circular references at startup
    from shared.schemas import Alert
    from workflow.orchestrator import run_pipeline
    from reporting.pdf_report import generate_report

    try:
        alert = Alert(**req.alert)
    except Exception as e:
        raise HTTPException(400, f"Invalid alert: {e}")

    try:
        result = run_pipeline(
            alert=alert,
            agent_id=req.agent_id,
            mode=req.mode,
            approved_actions=req.approved_actions,
        )
    except Exception as e:
        log.exception("Workflow run failed")
        raise HTTPException(500, f"Pipeline failed: {e}")

    result_dict = result.to_dict()

    # Store original alert + agent for the approval flow
    result_dict["original_alert"] = req.alert
    result_dict["original_agent_id"] = req.agent_id

    # Generate PDF (only if there's actual content to report)
    pdf_path = None
    try:
        if result_dict.get("verdict"):
            pdf_file = generate_report(result_dict)
            pdf_path = str(pdf_file)
            result_dict["pdf_path"] = pdf_path
    except Exception as e:
        log.error(f"PDF generation failed: {e}")
        result_dict["pdf_generation_error"] = str(e)

    # Persist
    try:
        db.save_pipeline_run(result_dict, req.agent_id, pdf_path)
    except Exception as e:
        log.error(f"Failed to persist pipeline run: {e}")

    return result_dict


@app.get("/workflow/runs", dependencies=[Depends(require_auth)])
def list_runs(limit: int = 50, status: Optional[str] = None):
    return db.list_pipeline_runs(limit=limit, status=status)


@app.get("/workflow/runs/{run_id}", dependencies=[Depends(require_auth)])
def get_run(run_id: str):
    r = db.get_pipeline_run(run_id)
    if not r:
        raise HTTPException(404, "Run not found")
    return r


class ApproveRequest(BaseModel):
    approved_actions: list[dict]


@app.post("/workflow/runs/{run_id}/approve", dependencies=[Depends(require_auth)])
def approve_run(run_id: str, body: ApproveRequest):
    """Execute analyst-approved actions for a run that requires_approval."""
    r = db.get_pipeline_run(run_id)
    if not r:
        raise HTTPException(404, "Run not found")
    if not r.get("requires_approval"):
        raise HTTPException(400, "Run does not require approval")

    from action_bot.executor import execute as execute_actions

    result_dict = r["result"]
    agent_id = result_dict.get("original_agent_id") or r.get("agent_id")
    alert_id = result_dict.get("alert_id", run_id)

    try:
        exec_result = execute_actions(
            agent_id=agent_id,
            approved_actions=body.approved_actions,
            alert_id=alert_id,
            timeout=120,
        )
    except Exception as e:
        log.exception("Approve execution failed")
        raise HTTPException(500, f"Execution failed: {e}")

    # Update stored run: mark approval done
    result_dict["requires_approval"] = False
    result_dict["action_result"] = exec_result
    exec_status = exec_result.get("status", "done")
    result_dict["final_status"] = "done" if exec_status in ("done", "skipped") else exec_status
    db.save_pipeline_run(result_dict, agent_id, r.get("pdf_path"))

    return {"ok": True, "exec_result": exec_result}


@app.get("/workflow/runs/{run_id}/report.pdf", dependencies=[Depends(require_auth)])
def download_run_pdf(run_id: str):
    """Stream the PDF report for a run."""
    from fastapi.responses import FileResponse
    r = db.get_pipeline_run(run_id)
    if not r:
        raise HTTPException(404, "Run not found")
    pdf = r.get("pdf_path")
    if not pdf:
        raise HTTPException(404, "No PDF available for this run")
    import os as _os
    if not _os.path.exists(pdf):
        raise HTTPException(410, "PDF file no longer exists on disk")
    return FileResponse(
        pdf, media_type="application/pdf",
        filename=f"{run_id}.pdf",
    )


# ---------- Dashboard ----------

@app.get("/dashboard/stats", dependencies=[Depends(require_auth)])
def dashboard_stats():
    """Aggregate stats for the dashboard."""
    agents = db.list_agents()
    cutoff = datetime.now(timezone.utc).timestamp() - settings.AGENT_OFFLINE_AFTER_SECONDS
    online = sum(1 for a in agents if datetime.fromisoformat(a["last_seen_at"]).timestamp() >= cutoff)
    return {
        "pipeline_runs": db.pipeline_runs_stats(),
        "agents": {
            "total": len(agents),
            "online": online,
            "offline": len(agents) - online,
        },
        "tenants": {
            "total": len(db.list_tenants()),
            "enabled": len(db.list_tenants(enabled_only=True)),
        },
        "pending_alerts": {
            "new": len(db.list_pending_alerts(status="new", limit=1000)),
        },
        "enrichers": settings.enricher_status(),
        "vip_list": list(settings.vip_list()),
    }


@app.get("/dashboard/chart-data", dependencies=[Depends(require_auth)])
def dashboard_chart_data():
    """Time-series and distribution data for dashboard charts."""
    return db.chart_data()


# ---------- Forensics Lab ----------

app.include_router(forensics_router, dependencies=[Depends(require_auth)])


# ---------- Real-time Forensics Findings ----------

class ForensicFindingRequest(BaseModel):
    source: str                          # "file_watcher" | "process_monitor"
    title: str
    description: str
    severity: str = "medium"
    timestamp: Optional[str] = None
    agent_id: Optional[str] = None
    file_path: Optional[str] = None
    sha256: Optional[str] = None
    yara_hits: Optional[int] = None
    yara_result: Optional[dict] = None
    ghidra_result: Optional[dict] = None
    process: Optional[dict] = None


@app.post("/forensics/finding", dependencies=[Depends(require_auth)])
def ingest_forensic_finding(req: ForensicFindingRequest):
    """
    Receives real-time findings from the endpoint file watcher / process monitor.
    Stores them as pending alerts so they appear in the dashboard Inbox.
    """
    import uuid as _uuid
    from shared.schemas import Alert

    pending_id = f"fw-{_uuid.uuid4().hex[:12]}"
    alert_id = f"rtf-{_uuid.uuid4().hex[:10]}"

    alert = Alert(
        alert_id=alert_id,
        source=req.source,
        severity=req.severity,
        title=req.title,
        description=req.description,
        endpoint_id=req.agent_id,
        raw={
            "file_path": req.file_path,
            "sha256": req.sha256,
            "yara_hits": req.yara_hits,
            "yara_result": req.yara_result,
            "ghidra_result": req.ghidra_result,
            "process": req.process,
            "agent_id": req.agent_id,
        },
    )

    db.create_pending_alert({
        "pending_id": pending_id,
        "tenant_id": req.agent_id or "endpoint",
        "tenant_name": f"Endpoint Agent ({req.agent_id or 'unknown'})",
        "alert": alert.model_dump(mode="json"),
        "status": "new",
        "ingested_at": req.timestamp or datetime.now(timezone.utc).isoformat(),
    })

    log.info(f"[ForensicFinding] {req.source}: {req.title} [{req.severity}] from {req.agent_id}")
    return {"ok": True, "pending_id": pending_id, "alert_id": alert_id}


# ---------- SOC AI Chatbot ----------

_SOC_SYSTEM_PROMPT = """You are SOC-AI, an expert security operations assistant embedded in an Agentic SOC platform.

You help analysts understand:
- Pipeline results (Decision Bot → Analysis Bot → Action Bot → Endpoint Agent)
- MITRE ATT&CK techniques, tactics, and kill chain phases
- Threat intelligence and IOC enrichment (VirusTotal, AbuseIPDB, OTX, Shodan)
- YARA rules and malware scanning
- Memory forensics with Volatility (Windows/Linux)
- Binary reverse engineering with Ghidra
- Azure OpenAI models used in the platform (gpt-4.1-mini deployment)
- Incident response workflows and remediation steps
- SOC dashboard features and how to use them

Be concise, accurate, and security-focused. When discussing specific threats use MITRE technique IDs where applicable.
Do not speculate about credentials, keys, or internal infrastructure. If asked about something outside security operations, redirect to your core purpose."""


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: list[ChatMessage]


@app.post("/chat", dependencies=[Depends(require_auth)])
async def chat_endpoint(req: ChatRequest):
    """SOC-AI chatbot — multi-turn conversation endpoint."""
    import asyncio
    from shared.llm_client import LLMClient

    if not req.messages:
        raise HTTPException(400, "No messages provided")

    try:
        llm = LLMClient()
        msgs = [{"role": m.role, "content": m.content} for m in req.messages]
        reply = await asyncio.to_thread(llm.chat, msgs, _SOC_SYSTEM_PROMPT)
        return {"reply": reply}
    except RuntimeError as e:
        raise HTTPException(503, str(e))
    except Exception as e:
        log.error(f"Chat endpoint error: {e}")
        raise HTTPException(500, "Chat failed")


class BatchRunRequest(BaseModel):
    pending_ids: list[str]
    agent_id: str
    mode: str = "auto"


@app.post("/workflow/run-inbox-batch", dependencies=[Depends(require_auth)])
def workflow_run_inbox_batch(req: BatchRunRequest):
    """
    Trigger the full pipeline for a batch of pending inbox alerts.
    Returns a list of {pending_id, run_id, status} for the caller to poll.
    Each alert is dispatched synchronously; for large batches the caller
    should expect a slow response and prefer background polling.
    """
    from shared.schemas import Alert
    from workflow.orchestrator import run_pipeline
    from reporting.pdf_report import generate_report

    results = []
    for pid in req.pending_ids:
        p = db.get_pending_alert(pid)
        if not p:
            results.append({"pending_id": pid, "error": "not found"})
            continue
        try:
            alert = Alert(**p["alert"])
        except Exception as e:
            results.append({"pending_id": pid, "error": f"invalid alert: {e}"})
            continue
        try:
            result = run_pipeline(alert=alert, agent_id=req.agent_id, mode=req.mode)
            result_dict = result.to_dict()
            pdf_path = None
            try:
                if result_dict.get("verdict"):
                    pdf_path = str(generate_report(result_dict))
                    result_dict["pdf_path"] = pdf_path
            except Exception:
                pass
            db.save_pipeline_run(result_dict, req.agent_id, pdf_path)
            db.update_pending_status(pid, status="auto_processed",
                                     verdict_alert_id=result_dict.get("alert_id"),
                                     auto_result_summary=result_dict.get("final_status"))
            results.append({"pending_id": pid, "run_id": result_dict["run_id"],
                            "status": result_dict.get("final_status", "done")})
        except Exception as e:
            log.exception(f"Batch pipeline failed for {pid}")
            results.append({"pending_id": pid, "error": str(e)})

    return {"results": results, "total": len(results),
            "succeeded": sum(1 for r in results if "run_id" in r)}


# ---------- Entry point ----------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=settings.CENTRAL_SERVER_HOST,
        port=settings.CENTRAL_SERVER_PORT,
        reload=False,
    )
