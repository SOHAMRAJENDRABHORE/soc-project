"""
SQLite storage for the central server. Just sqlite3 from stdlib — no ORM.

Tables:
  agents:   one row per registered endpoint
  jobs:     work units sent to agents
  results:  completed work
"""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

from shared.config import settings, PROJECT_ROOT
from shared.logger import get_logger

log = get_logger(__name__)

_db_path = PROJECT_ROOT / settings.CENTRAL_DB_PATH
_lock = threading.Lock()


SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
  agent_id        TEXT PRIMARY KEY,
  hostname        TEXT NOT NULL,
  os              TEXT NOT NULL,
  os_version      TEXT NOT NULL,
  agent_version   TEXT NOT NULL,
  capabilities    TEXT NOT NULL,           -- JSON list
  registered_at   TEXT NOT NULL,
  last_seen_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jobs (
  job_id          TEXT PRIMARY KEY,
  agent_id        TEXT NOT NULL,
  actions         TEXT NOT NULL,           -- JSON list
  status          TEXT NOT NULL,           -- queued|in_progress|done|failed|expired
  created_at      TEXT NOT NULL,
  picked_up_at    TEXT,
  completed_at    TEXT,
  requested_by    TEXT
);
CREATE INDEX IF NOT EXISTS idx_jobs_agent_status ON jobs(agent_id, status);

CREATE TABLE IF NOT EXISTS results (
  job_id          TEXT PRIMARY KEY,
  agent_id        TEXT NOT NULL,
  results         TEXT NOT NULL,           -- JSON list of ActionResult
  completed_at    TEXT NOT NULL
);

-- ---------- Onboarding Agent ----------

CREATE TABLE IF NOT EXISTS tenants (
  tenant_id              TEXT PRIMARY KEY,
  display_name           TEXT NOT NULL,
  provider_type          TEXT NOT NULL,    -- mock|graph|webhook
  ingestion_mode         TEXT NOT NULL,    -- inbox|auto
  enabled                INTEGER NOT NULL, -- 0|1
  provider_config        TEXT NOT NULL,    -- JSON
  encrypted_credentials  TEXT,             -- Fernet ciphertext, NULL if none
  last_polled_at         TEXT,
  cursor_state           TEXT,             -- provider-specific state (e.g. last seen alert ID)
  created_at             TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pending_alerts (
  pending_id             TEXT PRIMARY KEY,
  tenant_id              TEXT NOT NULL,
  tenant_name            TEXT NOT NULL,
  alert_json             TEXT NOT NULL,    -- the normalized Alert as JSON
  raw_payload            TEXT,             -- provider's original payload
  status                 TEXT NOT NULL,    -- new|triaged|auto_processed|dismissed
  ingested_at            TEXT NOT NULL,
  verdict_alert_id       TEXT,             -- set when triaged/auto-processed
  auto_result_summary    TEXT
);
CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_alerts(status, ingested_at);
CREATE INDEX IF NOT EXISTS idx_pending_tenant ON pending_alerts(tenant_id);
"""


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    with _lock:
        conn = sqlite3.connect(_db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()


def init_db():
    log.info(f"Initializing DB at {_db_path}")
    with get_conn() as c:
        c.executescript(SCHEMA)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------- Agents ----------

def upsert_agent(reg: dict[str, Any]):
    now = _now()
    with get_conn() as c:
        c.execute("""
            INSERT INTO agents (agent_id, hostname, os, os_version, agent_version,
                                capabilities, registered_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
              hostname=excluded.hostname,
              os=excluded.os,
              os_version=excluded.os_version,
              agent_version=excluded.agent_version,
              capabilities=excluded.capabilities,
              last_seen_at=excluded.last_seen_at
        """, (
            reg["agent_id"], reg["hostname"], reg["os"], reg["os_version"],
            reg["agent_version"], json.dumps(reg.get("capabilities", [])),
            now, now,
        ))


def update_heartbeat(agent_id: str):
    with get_conn() as c:
        c.execute("UPDATE agents SET last_seen_at = ? WHERE agent_id = ?",
                  (_now(), agent_id))


def list_agents() -> list[dict]:
    with get_conn() as c:
        rows = c.execute("SELECT * FROM agents ORDER BY last_seen_at DESC").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["capabilities"] = json.loads(d["capabilities"])
        out.append(d)
    return out


def get_agent(agent_id: str) -> Optional[dict]:
    with get_conn() as c:
        row = c.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["capabilities"] = json.loads(d["capabilities"])
    return d


# ---------- Jobs ----------

def create_job(job_id: str, agent_id: str, actions: list[dict],
               requested_by: str | None = None):
    with get_conn() as c:
        c.execute("""
            INSERT INTO jobs (job_id, agent_id, actions, status, created_at, requested_by)
            VALUES (?, ?, ?, 'queued', ?, ?)
        """, (job_id, agent_id, json.dumps(actions), _now(), requested_by))


def claim_next_job(agent_id: str) -> Optional[dict]:
    """Atomically: find next queued job for this agent and mark it in_progress."""
    with get_conn() as c:
        row = c.execute("""
            SELECT * FROM jobs
            WHERE agent_id = ? AND status = 'queued'
            ORDER BY created_at ASC
            LIMIT 1
        """, (agent_id,)).fetchone()
        if not row:
            return None
        c.execute("""
            UPDATE jobs SET status = 'in_progress', picked_up_at = ?
            WHERE job_id = ?
        """, (_now(), row["job_id"]))
    d = dict(row)
    d["actions"] = json.loads(d["actions"])
    d["status"] = "in_progress"
    return d


def get_job(job_id: str) -> Optional[dict]:
    with get_conn() as c:
        row = c.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["actions"] = json.loads(d["actions"])
    return d


def expire_old_jobs():
    """Mark queued/in_progress jobs older than JOB_EXPIRY_SECONDS as expired."""
    cutoff = datetime.now(timezone.utc).timestamp() - settings.JOB_EXPIRY_SECONDS
    with get_conn() as c:
        rows = c.execute("""
            SELECT job_id, created_at FROM jobs
            WHERE status IN ('queued', 'in_progress')
        """).fetchall()
        expired = []
        for r in rows:
            ts = datetime.fromisoformat(r["created_at"]).timestamp()
            if ts < cutoff:
                expired.append(r["job_id"])
        if expired:
            placeholders = ",".join("?" * len(expired))
            c.execute(f"UPDATE jobs SET status = 'expired' WHERE job_id IN ({placeholders})",
                      expired)
    if expired:
        log.warning(f"Expired {len(expired)} stale jobs")


# ---------- Results ----------

def save_result(job_id: str, agent_id: str, results: list[dict]):
    with get_conn() as c:
        c.execute("""
            INSERT OR REPLACE INTO results (job_id, agent_id, results, completed_at)
            VALUES (?, ?, ?, ?)
        """, (job_id, agent_id, json.dumps(results), _now()))
        c.execute("UPDATE jobs SET status = 'done', completed_at = ? WHERE job_id = ?",
                  (_now(), job_id))


def get_result(job_id: str) -> Optional[dict]:
    with get_conn() as c:
        row = c.execute("SELECT * FROM results WHERE job_id = ?", (job_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["results"] = json.loads(d["results"])
    return d


# ---------- Tenants ----------

def upsert_tenant(t: dict[str, Any]):
    with get_conn() as c:
        c.execute("""
            INSERT INTO tenants (tenant_id, display_name, provider_type, ingestion_mode,
                                  enabled, provider_config, encrypted_credentials,
                                  last_polled_at, cursor_state, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id) DO UPDATE SET
              display_name=excluded.display_name,
              provider_type=excluded.provider_type,
              ingestion_mode=excluded.ingestion_mode,
              enabled=excluded.enabled,
              provider_config=excluded.provider_config,
              encrypted_credentials=COALESCE(excluded.encrypted_credentials,
                                             tenants.encrypted_credentials)
        """, (
            t["tenant_id"], t["display_name"], t["provider_type"], t["ingestion_mode"],
            1 if t.get("enabled", True) else 0,
            json.dumps(t.get("provider_config", {})),
            t.get("encrypted_credentials"),
            t.get("last_polled_at"),
            t.get("cursor_state"),
            t.get("created_at") or _now(),
        ))


def list_tenants(enabled_only: bool = False) -> list[dict]:
    q = "SELECT * FROM tenants"
    if enabled_only:
        q += " WHERE enabled = 1"
    q += " ORDER BY created_at DESC"
    with get_conn() as c:
        rows = c.execute(q).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["provider_config"] = json.loads(d["provider_config"] or "{}")
        d["enabled"] = bool(d["enabled"])
        out.append(d)
    return out


def get_tenant(tenant_id: str) -> Optional[dict]:
    with get_conn() as c:
        row = c.execute("SELECT * FROM tenants WHERE tenant_id = ?", (tenant_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["provider_config"] = json.loads(d["provider_config"] or "{}")
    d["enabled"] = bool(d["enabled"])
    return d


def delete_tenant(tenant_id: str):
    with get_conn() as c:
        c.execute("DELETE FROM tenants WHERE tenant_id = ?", (tenant_id,))


def update_tenant_polling_state(tenant_id: str, cursor_state: str | None = None):
    """Called after a successful poll. Updates last_polled_at and optionally cursor."""
    with get_conn() as c:
        if cursor_state is not None:
            c.execute(
                "UPDATE tenants SET last_polled_at = ?, cursor_state = ? WHERE tenant_id = ?",
                (_now(), cursor_state, tenant_id),
            )
        else:
            c.execute(
                "UPDATE tenants SET last_polled_at = ? WHERE tenant_id = ?",
                (_now(), tenant_id),
            )


# ---------- Pending Alerts ----------

def create_pending_alert(p: dict[str, Any]):
    with get_conn() as c:
        c.execute("""
            INSERT INTO pending_alerts (pending_id, tenant_id, tenant_name, alert_json,
                                        raw_payload, status, ingested_at,
                                        verdict_alert_id, auto_result_summary)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            p["pending_id"], p["tenant_id"], p["tenant_name"],
            json.dumps(p["alert"], default=str),
            json.dumps(p.get("raw_provider_payload", {}), default=str),
            p.get("status", "new"),
            p.get("ingested_at") or _now(),
            p.get("verdict_alert_id"),
            p.get("auto_result_summary"),
        ))


def list_pending_alerts(
    status: Optional[str] = None,
    tenant_id: Optional[str] = None,
    limit: int = 100,
) -> list[dict]:
    q = "SELECT * FROM pending_alerts"
    where = []
    params: list[Any] = []
    if status:
        where.append("status = ?")
        params.append(status)
    if tenant_id:
        where.append("tenant_id = ?")
        params.append(tenant_id)
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY ingested_at DESC LIMIT ?"
    params.append(limit)
    with get_conn() as c:
        rows = c.execute(q, params).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["alert"] = json.loads(d.pop("alert_json"))
        d["raw_provider_payload"] = json.loads(d.pop("raw_payload") or "{}")
        out.append(d)
    return out


def get_pending_alert(pending_id: str) -> Optional[dict]:
    with get_conn() as c:
        row = c.execute(
            "SELECT * FROM pending_alerts WHERE pending_id = ?", (pending_id,)
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    d["alert"] = json.loads(d.pop("alert_json"))
    d["raw_provider_payload"] = json.loads(d.pop("raw_payload") or "{}")
    return d


def update_pending_status(pending_id: str, status: str,
                          verdict_alert_id: str | None = None,
                          auto_result_summary: str | None = None):
    with get_conn() as c:
        c.execute("""
            UPDATE pending_alerts
            SET status = ?,
                verdict_alert_id = COALESCE(?, verdict_alert_id),
                auto_result_summary = COALESCE(?, auto_result_summary)
            WHERE pending_id = ?
        """, (status, verdict_alert_id, auto_result_summary, pending_id))


def pending_alert_exists_by_source_id(tenant_id: str, source_alert_id: str) -> bool:
    """De-dup: did we already ingest this provider-side alert ID for this tenant?"""
    with get_conn() as c:
        row = c.execute("""
            SELECT pending_id FROM pending_alerts
            WHERE tenant_id = ?
              AND json_extract(alert_json, '$.alert_id') = ?
            LIMIT 1
        """, (tenant_id, source_alert_id)).fetchone()
    return row is not None


# ---------- Pipeline Runs (workflow orchestrator) ----------

PIPELINE_RUNS_SCHEMA = """
CREATE TABLE IF NOT EXISTS pipeline_runs (
  run_id         TEXT PRIMARY KEY,
  alert_id       TEXT NOT NULL,
  started_at     TEXT NOT NULL,
  finished_at    TEXT,
  duration_seconds REAL,
  final_status   TEXT NOT NULL,
  is_vip         INTEGER NOT NULL,
  requires_approval INTEGER NOT NULL,
  approval_reason TEXT,
  target_endpoint TEXT,
  agent_id       TEXT,
  result_json    TEXT NOT NULL,
  pdf_path       TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_started ON pipeline_runs(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_runs_status ON pipeline_runs(final_status);
"""


def init_pipeline_runs():
    with get_conn() as c:
        c.executescript(PIPELINE_RUNS_SCHEMA)


def save_pipeline_run(result: dict, agent_id: str | None, pdf_path: str | None):
    with get_conn() as c:
        c.execute("""
            INSERT OR REPLACE INTO pipeline_runs (
                run_id, alert_id, started_at, finished_at, duration_seconds,
                final_status, is_vip, requires_approval, approval_reason,
                target_endpoint, agent_id, result_json, pdf_path
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result["run_id"], result["alert_id"],
            result["started_at"], result.get("finished_at"),
            result.get("duration_seconds") or 0.0,
            result.get("final_status", "unknown"),
            1 if result.get("is_vip") else 0,
            1 if result.get("requires_approval") else 0,
            result.get("approval_reason"),
            result.get("target_endpoint"),
            agent_id,
            json.dumps(result, default=str),
            pdf_path,
        ))


def list_pipeline_runs(limit: int = 50, status: str | None = None) -> list[dict]:
    q = ("SELECT run_id, alert_id, started_at, finished_at, duration_seconds, "
         "final_status, is_vip, requires_approval, approval_reason, "
         "target_endpoint, agent_id, pdf_path, "
         "json_extract(result_json, '$.report.overall_severity') AS sev "
         "FROM pipeline_runs")
    params: list = []
    if status:
        q += " WHERE final_status = ?"
        params.append(status)
    q += " ORDER BY started_at DESC LIMIT ?"
    params.append(limit)
    with get_conn() as c:
        rows = c.execute(q, params).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["is_vip"] = bool(d["is_vip"])
        d["requires_approval"] = bool(d["requires_approval"])
        out.append(d)
    return out


def get_pipeline_run(run_id: str) -> Optional[dict]:
    with get_conn() as c:
        row = c.execute(
            "SELECT * FROM pipeline_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    d["is_vip"] = bool(d["is_vip"])
    d["requires_approval"] = bool(d["requires_approval"])
    d["result"] = json.loads(d.pop("result_json"))
    return d


def chart_data() -> dict:
    """Return time-series and distribution data for dashboard charts."""
    from datetime import timedelta

    now = datetime.now(timezone.utc)

    # Volume per day for last 7 days, broken down by severity
    volume_7d = []
    with get_conn() as c:
        for offset in range(6, -1, -1):
            day_start = (now - timedelta(days=offset)).replace(hour=0, minute=0, second=0, microsecond=0)
            day_end   = day_start + timedelta(days=1)
            row = {"date": f"{day_start.strftime('%b')} {day_start.day}"}
            for sev in ("critical", "high", "medium", "low"):
                count = c.execute("""
                    SELECT COUNT(*) FROM pipeline_runs
                    WHERE started_at >= ? AND started_at < ?
                      AND json_extract(result_json, '$.report.overall_severity') = ?
                """, (day_start.isoformat(), day_end.isoformat(), sev)).fetchone()[0]
                row[sev] = count
            volume_7d.append(row)

    with get_conn() as c:
        # Severity distribution (pending alerts)
        sev_rows = c.execute("""
            SELECT json_extract(alert_json,'$.severity') AS sev, COUNT(*)
            FROM pending_alerts GROUP BY sev
        """).fetchall()
        severity_dist = {r[0]: r[1] for r in sev_rows if r[0]}

        # IOC type distribution from result_json (best-effort)
        ioc_rows = c.execute("""
            SELECT json_extract(result_json,'$.verdict.iocs') FROM pipeline_runs
            WHERE json_extract(result_json,'$.verdict.iocs') IS NOT NULL LIMIT 200
        """).fetchall()

    return {
        "volume_7d": volume_7d,
        "severity_dist": severity_dist,
    }


def pipeline_runs_stats() -> dict:
    """Aggregate stats for dashboard."""
    with get_conn() as c:
        total = c.execute("SELECT COUNT(*) FROM pipeline_runs").fetchone()[0]
        by_status = {}
        for r in c.execute(
            "SELECT final_status, COUNT(*) FROM pipeline_runs GROUP BY final_status"
        ):
            by_status[r[0]] = r[1]
        by_severity = {}
        for r in c.execute(
            "SELECT json_extract(result_json, '$.report.overall_severity') AS sev, COUNT(*) "
            "FROM pipeline_runs WHERE sev IS NOT NULL GROUP BY sev"
        ):
            by_severity[r["sev"]] = r[1]
        vip_count = c.execute(
            "SELECT COUNT(*) FROM pipeline_runs WHERE is_vip = 1"
        ).fetchone()[0]
        avg_duration_row = c.execute(
            "SELECT AVG(duration_seconds) FROM pipeline_runs"
        ).fetchone()
        avg_duration = (avg_duration_row[0] or 0) if avg_duration_row else 0
        # Last 24h count
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        last_24h = c.execute(
            "SELECT COUNT(*) FROM pipeline_runs WHERE started_at >= ?", (cutoff,)
        ).fetchone()[0]
    return {
        "total_runs": total,
        "by_status": by_status,
        "by_severity": by_severity,
        "vip_count": vip_count,
        "avg_duration_seconds": round(avg_duration, 1),
        "last_24h": last_24h,
    }
