"""
Talks to the central server on behalf of Analysis Bot.

Dispatches jobs, polls for results, returns ActionResults.
"""
from __future__ import annotations

import time
import httpx
from shared.config import settings
from shared.logger import get_logger
from shared.schemas import ForensicAction, ActionResult, JobStatus

log = get_logger(__name__)


class CentralServerClient:
    def __init__(self, base_url: str | None = None, token: str | None = None):
        self.base_url = (base_url or settings.CENTRAL_SERVER_URL).rstrip("/")
        self.token = token or settings.AGENT_AUTH_TOKEN
        if not self.token:
            raise RuntimeError("AGENT_AUTH_TOKEN not set in .env")

    @property
    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"}

    def list_agents(self) -> list[dict]:
        r = httpx.get(f"{self.base_url}/agents", headers=self._headers, timeout=10)
        r.raise_for_status()
        return r.json()

    def list_online_agents(self) -> list[dict]:
        return [a for a in self.list_agents() if a.get("online")]

    def dispatch(self, agent_id: str, actions: list[ForensicAction],
                 requested_by: str = "analysis_bot") -> str:
        r = httpx.post(
            f"{self.base_url}/jobs",
            json={
                "agent_id": agent_id,
                "actions": [a.model_dump() for a in actions],
                "requested_by": requested_by,
            },
            headers=self._headers,
            timeout=15,
        )
        r.raise_for_status()
        job_id = r.json()["job_id"]
        log.info(f"Dispatched job {job_id} to agent {agent_id}")
        return job_id

    def wait_for_result(self, job_id: str, timeout: int = 600, poll: float = 2.0
                        ) -> tuple[list[ActionResult], str]:
        """
        Poll until the job completes, fails, or expires.

        Returns: (results, final_status)
        """
        start = time.time()
        while time.time() - start < timeout:
            r = httpx.get(f"{self.base_url}/jobs/{job_id}",
                          headers=self._headers, timeout=10)
            r.raise_for_status()
            data = r.json()
            status = data["job"]["status"]
            if status == JobStatus.DONE.value:
                raw = data["result"]["results"]
                return [ActionResult(**x) for x in raw], status
            if status in (JobStatus.FAILED.value, JobStatus.EXPIRED.value):
                return [], status
            time.sleep(poll)
        return [], "timeout"
