"""
Base class for alert providers.

To add a new alert source (Sentinel, CrowdStrike, custom SIEM), subclass
AlertProvider and implement fetch_new_alerts(). The Onboarding Agent picks
it up by its provider_type identifier.

Providers emit alerts in the **Microsoft Graph Security alerts_v2 schema**
where reasonable, because that's the most established alert schema and lets
us swap in a real Graph provider later without changing the normalizer.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any
from shared.logger import get_logger

log = get_logger(__name__)


class AlertProvider(ABC):
    """One provider instance per tenant. Stateful — owns the cursor."""

    #: identifier matching ProviderType enum value
    provider_type: str = "base"

    def __init__(self, tenant: dict, credentials: dict | None = None):
        """
        tenant: the tenant DB row (already decrypted by tenant_manager)
        credentials: decrypted credentials dict, or None if provider doesn't need any
        """
        self.tenant = tenant
        self.tenant_id = tenant["tenant_id"]
        self.tenant_name = tenant["display_name"]
        self.credentials = credentials or {}
        self.cursor_state = tenant.get("cursor_state")  # provider can read/update

    @abstractmethod
    def fetch_new_alerts(self) -> list[dict[str, Any]]:
        """
        Pull alerts newer than self.cursor_state.

        Returns: list of raw provider-shaped alerts (Graph schema preferred).
                 Must NOT raise — return [] on errors instead, log internally.

        Side effect: should update self.cursor_state to reflect what's been
                     consumed so the next poll resumes correctly.
        """
        ...

    def validate(self) -> tuple[bool, str]:
        """
        Optional: check that the provider is configured correctly.
        Used by the Tenant Onboarding UI's 'Test Connection' button.

        Returns: (ok, message)
        """
        return True, "No validation implemented for this provider."
