"""
Endpoint Agent. Runs on every endpoint (laptop, server, VM).

Lifecycle:
  1. Register with central server (POST /agents/register)
  2. Loop forever:
     a. Heartbeat (POST /agents/heartbeat)
     b. Poll for next job (GET /agents/{id}/next-job)
     c. If job exists: run actions locally, POST result
     d. Sleep AGENT_POLL_INTERVAL seconds

Run from project root:
  python -m endpoint_agent.agent

Stops on Ctrl+C.
"""
from __future__ import annotations

import os
import platform
import socket
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx

from shared.config import settings, PROJECT_ROOT
from shared.logger import get_logger
from shared.schemas import (
    AgentRegistration, Heartbeat, JobResult, ActionResult,
)

from .modules import REGISTRY, available_actions

log = get_logger(__name__)

AGENT_VERSION = "0.1.0"
AGENT_ID_FILE = PROJECT_ROOT / ".agent_id"


def _get_or_create_agent_id() -> str:
    """Persist agent_id locally so restarts don't re-register as a new agent."""
    if settings.AGENT_ID:
        return settings.AGENT_ID
    if AGENT_ID_FILE.exists():
        return AGENT_ID_FILE.read_text().strip()
    new_id = f"agent-{socket.gethostname()}-{uuid.uuid4().hex[:8]}"
    AGENT_ID_FILE.write_text(new_id)
    return new_id


def _registration() -> AgentRegistration:
    return AgentRegistration(
        agent_id=_get_or_create_agent_id(),
        hostname=socket.gethostname(),
        os=platform.system(),
        os_version=platform.version(),
        agent_version=AGENT_VERSION,
        capabilities=available_actions(),
    )


def _auth_headers() -> dict:
    if not settings.AGENT_AUTH_TOKEN:
        log.error("AGENT_AUTH_TOKEN not configured in .env on the agent side")
        sys.exit(2)
    return {"Authorization": f"Bearer {settings.AGENT_AUTH_TOKEN}"}


def register(client: httpx.Client, reg: AgentRegistration) -> bool:
    try:
        r = client.post(
            f"{settings.CENTRAL_SERVER_URL}/agents/register",
            json=reg.model_dump(mode="json"),
            headers=_auth_headers(),
            timeout=10,
        )
        if r.status_code == 200:
            log.info(f"Registered with central server as {reg.agent_id}")
            return True
        log.error(f"Registration failed: HTTP {r.status_code}: {r.text[:200]}")
        return False
    except httpx.HTTPError as e:
        log.error(f"Registration failed (network): {e}")
        return False


def heartbeat(client: httpx.Client, agent_id: str):
    try:
        client.post(
            f"{settings.CENTRAL_SERVER_URL}/agents/heartbeat",
            json=Heartbeat(agent_id=agent_id).model_dump(mode="json"),
            headers=_auth_headers(),
            timeout=10,
        )
    except httpx.HTTPError as e:
        log.warning(f"Heartbeat failed: {e}")


def fetch_job(client: httpx.Client, agent_id: str) -> dict | None:
    try:
        r = client.get(
            f"{settings.CENTRAL_SERVER_URL}/agents/{agent_id}/next-job",
            headers=_auth_headers(),
            timeout=10,
        )
        if r.status_code != 200:
            log.warning(f"Job fetch HTTP {r.status_code}: {r.text[:200]}")
            return None
        return r.json().get("job")
    except httpx.HTTPError as e:
        log.warning(f"Job fetch failed: {e}")
        return None


def execute_job(job: dict) -> JobResult:
    job_id = job["job_id"]
    agent_id = job["agent_id"]
    log.info(f"Executing job {job_id} ({len(job['actions'])} actions)")

    results: list[ActionResult] = []
    for action in job["actions"]:
        name = action["name"]
        params = action.get("params", {}) or {}
        handler = REGISTRY.get(name)
        if not handler:
            results.append(ActionResult(
                action=name, success=False, duration_seconds=0.0,
                error=f"No handler for action '{name}'",
            ))
            continue
        start = time.time()
        try:
            log.info(f"  → action: {name}")
            data = handler(params)
            dur = time.time() - start
            results.append(ActionResult(
                action=name, success=True, duration_seconds=round(dur, 2), data=data,
            ))
            log.info(f"  ✓ {name} done in {dur:.1f}s")
        except Exception as e:
            dur = time.time() - start
            log.error(f"  ✗ {name} failed: {e}")
            results.append(ActionResult(
                action=name, success=False, duration_seconds=round(dur, 2),
                error=str(e),
            ))

    return JobResult(job_id=job_id, agent_id=agent_id, results=results)


def submit_result(client: httpx.Client, result: JobResult) -> bool:
    try:
        r = client.post(
            f"{settings.CENTRAL_SERVER_URL}/jobs/{result.job_id}/result",
            json=result.model_dump(mode="json"),
            headers=_auth_headers(),
            timeout=30,
        )
        if r.status_code == 200:
            log.info(f"Result submitted for {result.job_id}")
            return True
        log.error(f"Result submission HTTP {r.status_code}: {r.text[:200]}")
        return False
    except httpx.HTTPError as e:
        log.error(f"Result submission failed: {e}")
        return False


def main():
    reg = _registration()
    log.info("=" * 60)
    log.info(f"Endpoint Agent {AGENT_VERSION} starting")
    log.info(f"  agent_id   = {reg.agent_id}")
    log.info(f"  hostname   = {reg.hostname}")
    log.info(f"  os         = {reg.os}")
    log.info(f"  server     = {settings.CENTRAL_SERVER_URL}")
    log.info(f"  capabilities = {reg.capabilities}")
    log.info("=" * 60)

    backoff = 2
    with httpx.Client() as client:
        # Register with backoff retry — server might not be up yet
        while not register(client, reg):
            log.info(f"Retrying registration in {backoff}s...")
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
        backoff = 2

        # Main loop
        try:
            while True:
                heartbeat(client, reg.agent_id)
                job = fetch_job(client, reg.agent_id)
                if job:
                    result = execute_job(job)
                    submit_result(client, result)
                else:
                    time.sleep(settings.AGENT_POLL_INTERVAL)
        except KeyboardInterrupt:
            log.info("Agent stopped (Ctrl+C)")


if __name__ == "__main__":
    main()
