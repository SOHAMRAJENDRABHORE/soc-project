"""
Webhook provider.

This is different from the others: it's PUSH not PULL. External systems
POST alerts to:

  POST /webhooks/{webhook_token}/ingest
  Header: Authorization: Bearer <webhook_token>  (also accepted in path)
  Body: a Graph-shaped alert JSON

The central server's webhook endpoint handles receipt; this provider is
only used during onboarding to validate the token config and during status
checks. fetch_new_alerts() always returns [] — alerts arrive via the
webhook endpoint, not via polling.

Provider config:
  {
    "webhook_token": "<random secret>"   # generated at onboarding time
  }
"""
from __future__ import annotations

import secrets
from typing import Any
from shared.logger import get_logger
from .base import AlertProvider

log = get_logger(__name__)


class WebhookProvider(AlertProvider):
    provider_type = "webhook"

    @staticmethod
    def generate_token() -> str:
        """Used by the onboarding UI to mint a new webhook token."""
        return secrets.token_urlsafe(24)

    def validate(self) -> tuple[bool, str]:
        token = self.tenant["provider_config"].get("webhook_token")
        if not token:
            return False, "No webhook_token in provider_config"
        return True, "OK — webhook ready to receive at /webhooks/<token>/ingest"

    def fetch_new_alerts(self) -> list[dict[str, Any]]:
        # Webhook alerts arrive via the central server endpoint, not polling.
        return []
