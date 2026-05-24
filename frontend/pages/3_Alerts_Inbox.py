"""
Alerts Inbox — pending alerts from all tenants, ready for analyst triage.

Pick one → click "Triage" → it routes into Decision Bot (with the alert
already loaded into session for the Decision Bot page).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st
import httpx

from shared.config import settings
from central_server import db as central_db

from _components.styling import inject as inject_css
from _components import widgets as W


st.set_page_config(page_title="Alerts Inbox · SOC", page_icon="◓", layout="wide")
inject_css()

W.banner(
    "◓ ALERTS INBOX",
    "Triage Queue · Pending alerts from all onboarded tenants",
    variant="decision",
)


# ============================================================
# Sidebar — server status + filters
# ============================================================
with st.sidebar:
    W.section_header("Central Server")
    try:
        r = httpx.get(f"{settings.CENTRAL_SERVER_URL}/health", timeout=3)
        if r.status_code == 200:
            st.success("Connected")
        else:
            st.error(f"HTTP {r.status_code}")
    except Exception as e:
        st.error(f"unreachable: {type(e).__name__}")

    W.section_header("Filters")
    status_filter = st.selectbox(
        "Status",
        ["all", "new", "triaged", "auto_processed", "dismissed"],
        index=1,   # default to 'new'
    )

    tenants = central_db.list_tenants()
    tenant_options = {"All tenants": None}
    for t in tenants:
        tenant_options[f"{t['display_name']} ({t['provider_type']})"] = t["tenant_id"]
    tenant_choice = st.selectbox("Tenant", list(tenant_options.keys()))
    tenant_filter = tenant_options[tenant_choice]

    if st.button("↻ Refresh", use_container_width=True):
        st.rerun()


# ============================================================
# Main — pending alerts list
# ============================================================
W.section_header("Pending Alerts")

if not tenants:
    st.warning("No tenants configured. Go to **Tenant Onboarding** page first.")
    st.stop()

alerts = central_db.list_pending_alerts(
    status=None if status_filter == "all" else status_filter,
    tenant_id=tenant_filter,
    limit=200,
)

if not alerts:
    st.caption("No alerts matching filters. If the Onboarding Agent is running, "
               "new alerts will arrive on the next poll cycle.")
    st.stop()


SEV_TO_BADGE = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}


for p in alerts:
    a = p["alert"]
    sev = a.get("severity", "medium")
    badge = SEV_TO_BADGE.get(sev, "medium")
    status = p["status"]
    title = a.get("title") or "(untitled)"
    desc = (a.get("description") or "")[:280]
    endpoint = a.get("endpoint_id") or "—"

    with st.container():
        st.markdown(f"""
        <div class="finding-card {badge}">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <div class="finding-title">{title}</div>
            <div>
              <span class="badge {badge}">{sev}</span>
              <span class="badge unknown" style="margin-left:6px;">{status}</span>
            </div>
          </div>
          <div style="color:#94a3b8; font-size:0.8rem; margin-top:6px;">
            <span style="color:#60a5fa;">{p['tenant_name']}</span>
            &nbsp;·&nbsp; endpoint: <span class="mono">{endpoint}</span>
            &nbsp;·&nbsp; ingested: <span class="mono">{p['ingested_at']}</span>
          </div>
          <div style="color:#cbd5e1; font-size:0.85rem; margin-top:6px;">{desc}</div>
        </div>
        """, unsafe_allow_html=True)

        col1, col2, col3 = st.columns([1, 1, 2])
        with col1:
            if status == "new":
                if st.button("→ Triage", key=f"triage_{p['pending_id']}",
                             use_container_width=True):
                    # Stash the alert into session so the Decision Bot page picks it up
                    st.session_state["loaded_alert"] = a
                    # Mark as triaged
                    central_db.update_pending_status(
                        p["pending_id"], status="triaged",
                        verdict_alert_id=a["alert_id"],
                    )
                    st.success(
                        f"Loaded into Decision Bot. Open the **Decision Bot** "
                        f"page in the sidebar to run the pipeline."
                    )
                    st.rerun()
            else:
                # Already triaged or auto-processed — show summary
                summary = p.get("auto_result_summary") or "Already triaged"
                st.caption(f"✓ {summary[:120]}")

        with col2:
            if status == "new":
                if st.button("Dismiss", key=f"dismiss_{p['pending_id']}",
                             use_container_width=True):
                    central_db.update_pending_status(p["pending_id"], status="dismissed")
                    st.rerun()

        with col3:
            with st.expander("Show raw provider payload"):
                st.code(json.dumps(p["raw_provider_payload"], indent=2, default=str)[:5000],
                        language="json")
