"""
Real-time monitoring coordinator.

Starts the file watcher and process monitor as background threads.
Reports findings to the central server as forensic alerts that appear
in the dashboard's Alert Inbox.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import httpx

from shared.logger import get_logger
from .modules.file_watcher import FileWatcher
from .modules.process_monitor import ProcessMonitor

log = get_logger(__name__)


class RealTimeWatcher:
    """
    Manages file + process monitoring for one agent.
    Call start() once; findings are automatically sent to the server.
    """

    def __init__(
        self,
        server_url: str,
        auth_token: str,
        agent_id: str,
        watch_dirs: list[str] | None = None,
        enable_file_watcher: bool = True,
        enable_process_monitor: bool = True,
        process_score_threshold: int = 40,
    ):
        self._server_url = server_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {auth_token}",
                         "Content-Type": "application/json"}
        self._agent_id = agent_id
        self._file_watcher: FileWatcher | None = None
        self._process_monitor: ProcessMonitor | None = None

        if enable_file_watcher:
            self._file_watcher = FileWatcher(
                watch_dirs=watch_dirs,
                on_finding=self._on_finding,
            )

        if enable_process_monitor:
            self._process_monitor = ProcessMonitor(
                on_finding=self._on_finding,
                score_threshold=process_score_threshold,
            )

    def start(self):
        if self._file_watcher:
            self._file_watcher.start()
        if self._process_monitor:
            self._process_monitor.start()
        log.info("[RealTimeWatcher] All monitors started")

    def stop(self):
        if self._file_watcher:
            self._file_watcher.stop()
        if self._process_monitor:
            self._process_monitor.stop()
        log.info("[RealTimeWatcher] All monitors stopped")

    def update_watch_dirs(self, dirs: list[str]):
        """Hot-update watched directories without restarting."""
        if self._file_watcher:
            self._file_watcher._dirs = dirs
            log.info(f"[RealTimeWatcher] Watch dirs updated: {dirs}")

    def _on_finding(self, finding: dict[str, Any]):
        """Callback — called from watcher threads. Posts finding to server."""
        log.info(f"[RealTimeWatcher] Finding: {finding.get('title')} [{finding.get('severity')}]")
        try:
            with httpx.Client(timeout=10, verify=False) as client:
                r = client.post(
                    f"{self._server_url}/forensics/finding",
                    json={**finding, "agent_id": self._agent_id},
                    headers=self._headers,
                )
                if r.status_code not in (200, 201):
                    log.warning(f"[RealTimeWatcher] Server rejected finding: HTTP {r.status_code}")
        except Exception as e:
            log.warning(f"[RealTimeWatcher] Could not report finding: {e}")
