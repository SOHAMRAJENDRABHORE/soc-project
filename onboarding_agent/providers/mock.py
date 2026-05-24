"""
Mock provider.

Reads alerts from a JSON file matching the Microsoft Graph Security alerts_v2
schema. Returns 1-2 new alerts per poll, then quietly stops (or wraps around
based on the 'loop' config). Lets you demo a steady drip of alerts.

Provider config:
  {
    "alert_file": "acme_corp.json",    # filename inside ONBOARDING_SAMPLE_DIR
    "alerts_per_poll": 1,              # how many to release each poll cycle
    "loop": false                      # if true, restart from index 0 when done
  }
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from shared.config import settings, PROJECT_ROOT
from shared.logger import get_logger
from .base import AlertProvider

log = get_logger(__name__)


class MockProvider(AlertProvider):
    provider_type = "mock"

    def _resolve_file(self) -> Path:
        cfg = self.tenant["provider_config"]
        filename = cfg.get("alert_file", "")
        if not filename:
            return Path()  # invalid, validate() will catch
        sample_dir = PROJECT_ROOT / settings.ONBOARDING_SAMPLE_DIR
        return sample_dir / filename

    def _load_all(self) -> list[dict]:
        path = self._resolve_file()
        if not path.exists():
            log.warning(f"[mock:{self.tenant_id}] file not found: {path}")
            return []
        try:
            data = json.loads(path.read_text())
        except Exception as e:
            log.error(f"[mock:{self.tenant_id}] failed to parse {path}: {e}")
            return []
        # Accept either { "value": [...] } (Graph response shape) or a bare list
        if isinstance(data, dict) and "value" in data:
            return data["value"]
        if isinstance(data, list):
            return data
        log.error(f"[mock:{self.tenant_id}] unexpected JSON shape in {path}")
        return []

    def validate(self) -> tuple[bool, str]:
        path = self._resolve_file()
        if not path.exists():
            return False, f"Alert file not found: {path}"
        alerts = self._load_all()
        if not alerts:
            return False, f"File parsed but contains no alerts: {path.name}"
        return True, f"OK — {len(alerts)} alerts available in {path.name}"

    def fetch_new_alerts(self) -> list[dict[str, Any]]:
        all_alerts = self._load_all()
        if not all_alerts:
            return []

        cfg = self.tenant["provider_config"]
        per_poll = int(cfg.get("alerts_per_poll", 1))
        loop = bool(cfg.get("loop", False))

        # cursor_state stores the index of the next alert to return
        try:
            cursor = int(self.cursor_state) if self.cursor_state else 0
        except ValueError:
            cursor = 0

        if cursor >= len(all_alerts):
            if loop:
                cursor = 0
            else:
                return []  # exhausted

        end = min(cursor + per_poll, len(all_alerts))
        batch = all_alerts[cursor:end]
        new_cursor = end
        if loop and new_cursor >= len(all_alerts):
            new_cursor = 0

        self.cursor_state = str(new_cursor)
        log.info(
            f"[mock:{self.tenant_id}] returning {len(batch)} alerts "
            f"(cursor {cursor} → {new_cursor} of {len(all_alerts)})"
        )
        return batch
