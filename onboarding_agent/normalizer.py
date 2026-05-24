"""
Normalize provider-specific alert formats into the standard shared.schemas.Alert.

We support the Microsoft Graph Security alerts_v2 schema as the primary
shape. Other providers can either emit Graph-shaped JSON or have their own
branch added here.

Graph alerts_v2 sample shape (simplified):
  {
    "id": "abc123",
    "displayName": "Suspicious PowerShell execution",
    "description": "...",
    "severity": "high",
    "createdDateTime": "2025-...Z",
    "evidence": [
       {"@odata.type": "#microsoft.graph.security.processEvidence", ...},
       {"@odata.type": "#microsoft.graph.security.ipEvidence", "ipAddress": "..."},
       ...
    ],
    "alertWebUrl": "...",
    ...
  }

We map this into our Alert schema, preserving the original payload in `raw`
so downstream code can still introspect Graph-specific fields if needed.
"""
from __future__ import annotations

import uuid
from typing import Any
from datetime import datetime, timezone
from shared.schemas import Alert
from shared.logger import get_logger

log = get_logger(__name__)


_GRAPH_SEVERITY_MAP = {
    "informational": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
    "unknownfuturevalue": "medium",
}


def _normalize_severity(s: Any) -> str:
    if not s:
        return "medium"
    return _GRAPH_SEVERITY_MAP.get(str(s).lower(), "medium")


def _extract_endpoint(graph_alert: dict) -> str | None:
    """Pull out an endpoint identifier from Graph evidence."""
    for ev in graph_alert.get("evidence", []) or []:
        odata = (ev.get("@odata.type") or "").lower()
        if "deviceevidence" in odata:
            return ev.get("deviceDnsName") or ev.get("mdeDeviceId") or ev.get("deviceId")
        if "userevidence" in odata and ev.get("userAccount"):
            # Falls back to userPrincipalName if no device
            return ev["userAccount"].get("userPrincipalName")
    # Also check older Graph shapes
    if graph_alert.get("hostStates"):
        hs = graph_alert["hostStates"][0]
        return hs.get("fqdn") or hs.get("netBiosName")
    return None


def _parse_timestamp(ts: Any) -> datetime:
    if not ts:
        return datetime.now(timezone.utc)
    if isinstance(ts, datetime):
        return ts
    try:
        # Graph returns ISO 8601 with Z
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc)


def normalize_graph_alert(graph_alert: dict, tenant_id: str) -> Alert:
    """Microsoft Graph Security alerts_v2 → Alert."""
    alert_id = graph_alert.get("id") or f"unknown-{uuid.uuid4().hex[:8]}"
    return Alert(
        alert_id=alert_id,
        source=f"graph_security:{tenant_id}",
        timestamp=_parse_timestamp(
            graph_alert.get("createdDateTime") or graph_alert.get("lastUpdatedDateTime")
        ),
        severity=_normalize_severity(graph_alert.get("severity")),
        title=graph_alert.get("displayName") or graph_alert.get("title"),
        description=graph_alert.get("description"),
        endpoint_id=_extract_endpoint(graph_alert),
        raw=graph_alert,
    )


def normalize(provider_alert: dict, provider_type: str, tenant_id: str) -> Alert:
    """
    Main entry point. Dispatches by provider_type.
    Mock and Graph both emit Graph-shaped JSON; webhook payloads may too.
    """
    # All current providers emit Graph-shaped alerts. If a provider needs
    # its own normalizer, add a branch here.
    if provider_type in ("mock", "graph", "webhook"):
        return normalize_graph_alert(provider_alert, tenant_id)
    log.warning(f"Unknown provider_type '{provider_type}'; using Graph normalizer")
    return normalize_graph_alert(provider_alert, tenant_id)
