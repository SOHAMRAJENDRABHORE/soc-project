"""
After the Onboarding Agent normalizes an alert, this module decides what
happens to it next based on the tenant's ingestion mode.

- INBOX mode:  insert into pending_alerts with status='new'.
               UI shows it; analyst clicks to send through Decision Bot.

- AUTO mode:   immediately run Decision → Analysis → (Action Bot in manual
               approval mode is the safer default). Result summary stored
               in the pending_alerts row.

Auto mode dispatches synchronously per alert to keep it simple. In production
you'd queue it.
"""
from __future__ import annotations

import uuid
from typing import Any
from shared.schemas import Alert, IngestionMode
from shared.logger import get_logger
from central_server import db

log = get_logger(__name__)


def _make_pending_id() -> str:
    return f"pend-{uuid.uuid4().hex[:12]}"


def ingest_to_inbox(
    alert: Alert,
    tenant_id: str,
    tenant_name: str,
    raw_payload: dict[str, Any],
) -> str:
    """Queue alert for analyst review. Returns the pending_id."""
    pending_id = _make_pending_id()
    db.create_pending_alert({
        "pending_id": pending_id,
        "tenant_id": tenant_id,
        "tenant_name": tenant_name,
        "alert": alert.model_dump(mode="json"),
        "raw_provider_payload": raw_payload,
        "status": "new",
    })
    log.info(
        f"Ingested to INBOX: {pending_id} (tenant={tenant_name}, alert={alert.alert_id})"
    )
    return pending_id


def ingest_to_auto(
    alert: Alert,
    tenant_id: str,
    tenant_name: str,
    raw_payload: dict[str, Any],
) -> str:
    """
    Run alert through Decision Bot synchronously.
    Stores result in pending_alerts with status='auto_processed'.

    Note: we do NOT auto-run Analysis or Action Bot here. Two reasons:
      1. Analysis Bot needs an agent_id, which the alert may not specify.
      2. Action Bot taking destructive actions without human review on
         freshly-ingested alerts is poor practice. Auto mode = auto-triage
         (verdict only). Analysis & action stay analyst-driven.
    """
    from decision_bot.bot import decide  # local import to avoid Streamlit-side overhead

    pending_id = _make_pending_id()
    # Create the pending row first so it appears even if Decision Bot fails
    db.create_pending_alert({
        "pending_id": pending_id,
        "tenant_id": tenant_id,
        "tenant_name": tenant_name,
        "alert": alert.model_dump(mode="json"),
        "raw_provider_payload": raw_payload,
        "status": "new",
    })

    try:
        verdict = decide(alert)
        summary = (
            f"{verdict.label.value} ({verdict.confidence}%): "
            f"{verdict.reasoning[:200]}"
        )
        db.update_pending_status(
            pending_id, status="auto_processed",
            verdict_alert_id=verdict.alert_id,
            auto_result_summary=summary,
        )
        log.info(f"AUTO-processed {pending_id}: {verdict.label.value}")
    except Exception as e:
        log.error(f"AUTO processing failed for {pending_id}: {e}")
        db.update_pending_status(
            pending_id, status="new",
            auto_result_summary=f"Auto-triage failed: {e}",
        )
    return pending_id


def route_alert(
    alert: Alert,
    tenant: dict,
    raw_payload: dict[str, Any],
) -> str:
    """Single entry point used by the polling bot. Picks inbox or auto based on tenant."""
    mode = tenant.get("ingestion_mode", "inbox")
    if mode == IngestionMode.AUTO.value:
        return ingest_to_auto(
            alert, tenant["tenant_id"], tenant["display_name"], raw_payload
        )
    return ingest_to_inbox(
        alert, tenant["tenant_id"], tenant["display_name"], raw_payload
    )
