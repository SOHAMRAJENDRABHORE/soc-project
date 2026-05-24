"""
Tenant lifecycle management. Wraps the DB layer with credential encryption.

Public API:
  - create_tenant(...)        — onboards a new org
  - list_tenants(...)
  - get_tenant(tenant_id)     — returns DB row + DECRYPTED credentials
  - enable_tenant(tenant_id)
  - disable_tenant(tenant_id)
  - delete_tenant(tenant_id)
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from shared.crypto import get_crypto
from shared.logger import get_logger
from shared.schemas import ProviderType, IngestionMode
from central_server import db
from .providers import get_provider_class

log = get_logger(__name__)


def create_tenant(
    display_name: str,
    provider_type: str,
    provider_config: dict[str, Any],
    credentials: Optional[dict[str, Any]] = None,
    ingestion_mode: str = "inbox",
    enabled: bool = True,
) -> dict:
    """
    Onboard a new tenant. Returns the stored tenant dict (no plaintext creds).
    """
    if provider_type not in {p.value for p in ProviderType}:
        raise ValueError(f"Unknown provider_type: {provider_type}")
    if ingestion_mode not in {m.value for m in IngestionMode}:
        raise ValueError(f"Unknown ingestion_mode: {ingestion_mode}")

    tenant_id = f"tenant-{uuid.uuid4().hex[:12]}"
    encrypted = None
    if credentials:
        encrypted = get_crypto().encrypt(credentials)

    row = {
        "tenant_id": tenant_id,
        "display_name": display_name,
        "provider_type": provider_type,
        "ingestion_mode": ingestion_mode,
        "enabled": enabled,
        "provider_config": provider_config,
        "encrypted_credentials": encrypted,
        "last_polled_at": None,
        "cursor_state": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    db.upsert_tenant(row)
    log.info(f"Tenant created: {tenant_id} ({display_name}, provider={provider_type})")
    return _redact(row)


def update_tenant(tenant_id: str, **changes: Any) -> dict:
    """Partial update. Credentials, if provided, are re-encrypted."""
    existing = db.get_tenant(tenant_id)
    if not existing:
        raise ValueError(f"Unknown tenant_id: {tenant_id}")

    if "credentials" in changes:
        creds = changes.pop("credentials")
        existing["encrypted_credentials"] = get_crypto().encrypt(creds) if creds else None

    for k, v in changes.items():
        if k in existing:
            existing[k] = v

    db.upsert_tenant(existing)
    return _redact(existing)


def list_tenants(enabled_only: bool = False) -> list[dict]:
    return [_redact(t) for t in db.list_tenants(enabled_only=enabled_only)]


def get_tenant_with_credentials(tenant_id: str) -> Optional[dict]:
    """
    For internal use by the polling bot. Returns the tenant with decrypted
    credentials added as 'credentials' field. DO NOT return this from any
    HTTP endpoint.
    """
    t = db.get_tenant(tenant_id)
    if not t:
        return None
    if t.get("encrypted_credentials"):
        try:
            t["credentials"] = get_crypto().decrypt(t["encrypted_credentials"])
        except Exception as e:
            log.error(f"Failed to decrypt credentials for {tenant_id}: {e}")
            t["credentials"] = None
    else:
        t["credentials"] = None
    return t


def enable_tenant(tenant_id: str):
    return update_tenant(tenant_id, enabled=True)


def disable_tenant(tenant_id: str):
    return update_tenant(tenant_id, enabled=False)


def delete_tenant(tenant_id: str):
    db.delete_tenant(tenant_id)
    log.info(f"Tenant deleted: {tenant_id}")


def test_connection(tenant_id: str) -> tuple[bool, str]:
    """Used by the UI's 'Test Connection' button on the onboarding form."""
    t = get_tenant_with_credentials(tenant_id)
    if not t:
        return False, "Tenant not found"
    cls = get_provider_class(t["provider_type"])
    if not cls:
        return False, f"Provider not implemented: {t['provider_type']}"
    try:
        provider = cls(t, credentials=t.get("credentials"))
        return provider.validate()
    except Exception as e:
        return False, f"Provider init failed: {e}"


def _redact(row: dict) -> dict:
    """Strip encrypted_credentials before returning to callers/UI."""
    safe = {k: v for k, v in row.items() if k != "encrypted_credentials"}
    safe["has_credentials"] = bool(row.get("encrypted_credentials"))
    return safe
