"""
Onboarding Agent main loop.

Runs as a separate process:
  python -m onboarding_agent.bot

Lifecycle:
  - On startup: init DB, log configured tenants
  - Every ONBOARDING_POLL_INTERVAL seconds:
      for each enabled tenant:
        - Instantiate provider with tenant config + credentials
        - Call provider.fetch_new_alerts()
        - For each alert: normalize → route (inbox or auto)
        - Update tenant.cursor_state
  - On SIGINT: clean exit
"""
from __future__ import annotations

import signal
import sys
import time
from typing import Any

from shared.config import settings
from shared.logger import get_logger
from central_server import db
from .providers import get_provider_class
from .tenant_manager import get_tenant_with_credentials
from .normalizer import normalize
from .ingestion_modes import route_alert

log = get_logger(__name__)

_stop = False


def _signal_handler(signum, frame):
    global _stop
    log.info("Shutdown signal received")
    _stop = True


def _poll_one_tenant(tenant: dict[str, Any]) -> int:
    """Run one poll cycle for one tenant. Returns count of new alerts ingested."""
    tenant_id = tenant["tenant_id"]
    provider_type = tenant["provider_type"]

    cls = get_provider_class(provider_type)
    if not cls:
        log.warning(f"[{tenant_id}] No provider implementation for '{provider_type}' — skipping")
        return 0

    try:
        provider = cls(tenant, credentials=tenant.get("credentials"))
    except Exception as e:
        log.error(f"[{tenant_id}] Provider init failed: {e}")
        return 0

    try:
        raw_alerts = provider.fetch_new_alerts()
    except Exception as e:
        log.error(f"[{tenant_id}] fetch_new_alerts crashed: {e}")
        return 0

    ingested = 0
    for raw in raw_alerts:
        try:
            source_alert_id = raw.get("id") or raw.get("alert_id")
            if source_alert_id and db.pending_alert_exists_by_source_id(tenant_id, source_alert_id):
                log.debug(f"[{tenant_id}] dedup: alert {source_alert_id} already ingested")
                continue
            alert = normalize(raw, provider_type, tenant_id)
            route_alert(alert, tenant, raw)
            ingested += 1
        except Exception as e:
            log.error(f"[{tenant_id}] Failed to process one alert: {e}")
            continue

    # Persist cursor state if the provider updated it
    db.update_tenant_polling_state(tenant_id, cursor_state=provider.cursor_state)
    return ingested


def _poll_cycle() -> int:
    """One sweep across all enabled tenants. Returns total alerts ingested."""
    total = 0
    tenants = db.list_tenants(enabled_only=True)
    if not tenants:
        log.debug("No enabled tenants. Add one via the Tenant Onboarding UI.")
        return 0

    for t in tenants:
        # Need decrypted credentials for the actual provider call
        t_full = get_tenant_with_credentials(t["tenant_id"])
        if not t_full:
            continue
        n = _poll_one_tenant(t_full)
        if n > 0:
            log.info(f"[{t_full['tenant_id']}] +{n} new alerts ingested")
        total += n
    return total


def main():
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    log.info("=" * 60)
    log.info("Onboarding Agent starting")
    log.info(f"  poll_interval = {settings.ONBOARDING_POLL_INTERVAL}s")
    log.info(f"  encryption    = {'configured' if settings.ONBOARDING_ENCRYPTION_KEY else 'MISSING'}")
    log.info("=" * 60)

    if not settings.ONBOARDING_ENCRYPTION_KEY:
        log.error("ONBOARDING_ENCRYPTION_KEY not set in .env — aborting.")
        log.error("Generate one with:")
        log.error('  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"')
        sys.exit(2)

    # Make sure DB schema is up to date (idempotent)
    db.init_db()

    tenants = db.list_tenants()
    if not tenants:
        log.info("No tenants configured yet. Will keep polling — add tenants via the UI.")
    else:
        log.info(f"Configured tenants: {[(t['tenant_id'], t['display_name'], t['provider_type']) for t in tenants]}")

    while not _stop:
        try:
            n = _poll_cycle()
            log.debug(f"Cycle complete. {n} alerts ingested.")
        except Exception as e:
            log.exception(f"Cycle crashed: {e}")
        # Sleep in 1-second chunks so SIGINT is responsive
        for _ in range(settings.ONBOARDING_POLL_INTERVAL):
            if _stop:
                break
            time.sleep(1)

    log.info("Onboarding Agent stopped.")


if __name__ == "__main__":
    main()
