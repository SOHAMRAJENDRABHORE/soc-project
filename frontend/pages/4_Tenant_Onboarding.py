"""
Tenant Onboarding — add a new organization to be monitored.

Three provider types in the dropdown:
  - Mock — point at a JSON file under onboarding_agent/sample_alerts/
  - Webhook — auto-generate a token; external systems POST alerts to a URL
  - Microsoft Graph — disabled (requires M365 tenant credentials, not yet built)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st

from shared.config import settings
from onboarding_agent.tenant_manager import (
    create_tenant, list_tenants, delete_tenant,
    enable_tenant, disable_tenant, test_connection,
)
from onboarding_agent.providers.webhook import WebhookProvider

from _components.styling import inject as inject_css
from _components import widgets as W


st.set_page_config(page_title="Tenant Onboarding · SOC", page_icon="◔", layout="wide")
inject_css()

W.banner(
    "◔ TENANT ONBOARDING",
    "Multi-tenant SOC · Connect a new organization",
    variant="analysis",
)


# Encryption-key warning
if not settings.ONBOARDING_ENCRYPTION_KEY:
    st.error(
        "**ONBOARDING_ENCRYPTION_KEY not set in .env.** "
        "Tenant credentials can't be encrypted. Generate one and add to .env:"
    )
    st.code(
        'python -c "from cryptography.fernet import Fernet; '
        'print(Fernet.generate_key().decode())"',
        language="bash",
    )
    st.stop()


# ============================================================
# Onboard a new tenant
# ============================================================
W.section_header("Onboard a New Organization")

col_form_l, col_form_r = st.columns([1, 1])

with col_form_l:
    display_name = st.text_input("Organization Display Name", placeholder="Acme Corp")
    provider_choice = st.selectbox(
        "Alert Source Provider",
        [
            "Mock (sample JSON file)",
            "Webhook (external systems POST alerts)",
            "Microsoft Graph (requires credentials — coming soon)",
        ],
    )
    ingestion_mode = st.radio(
        "Ingestion Mode",
        ["inbox", "auto"],
        format_func=lambda x: {
            "inbox": "Inbox — analyst triages each alert",
            "auto": "Auto — Decision Bot runs immediately",
        }[x],
    )

with col_form_r:
    # Provider-specific config block
    provider_type = None
    provider_config = {}
    credentials = None

    if provider_choice.startswith("Mock"):
        provider_type = "mock"
        # List available sample files
        sample_dir = PROJECT_ROOT / settings.ONBOARDING_SAMPLE_DIR
        available = sorted([f.name for f in sample_dir.glob("*.json")])
        if not available:
            st.warning(f"No JSON files in {sample_dir}. Add some samples first.")
            alert_file = ""
        else:
            alert_file = st.selectbox("Sample alert file", available)
        alerts_per_poll = st.number_input("Alerts per poll cycle", 1, 10, 1)
        loop = st.checkbox("Loop (replay alerts when exhausted)", value=False)
        provider_config = {
            "alert_file": alert_file,
            "alerts_per_poll": int(alerts_per_poll),
            "loop": loop,
        }

    elif provider_choice.startswith("Webhook"):
        provider_type = "webhook"
        token = WebhookProvider.generate_token()
        st.caption("A unique webhook token will be generated on creation.")
        st.code(f"Token preview: {token[:8]}...{token[-4:]}", language="text")
        provider_config = {"webhook_token": token}
        st.info(
            "After creating, external systems POST alerts to:\n\n"
            f"`{settings.CENTRAL_SERVER_URL}/webhooks/<webhook_token>/ingest`"
        )

    elif provider_choice.startswith("Microsoft Graph"):
        provider_type = "graph"
        st.warning(
            "**Microsoft Graph integration requires M365 tenant credentials.** "
            "Sign up for a Microsoft 365 Developer Program tenant at "
            "https://developer.microsoft.com/en-us/microsoft-365/dev-program, "
            "create an App Registration with `SecurityAlert.Read.All` permission, "
            "then return here to fill in:"
        )
        st.text_input("Azure Tenant ID", disabled=True, placeholder="(disabled)")
        st.text_input("Client ID", disabled=True, placeholder="(disabled)")
        st.text_input("Client Secret", disabled=True, type="password", placeholder="(disabled)")
        st.caption(
            "This provider is not yet implemented — the form is shown to "
            "demonstrate the multi-provider architecture."
        )


create_disabled = (
    not display_name
    or provider_type == "graph"
    or (provider_type == "mock" and not provider_config.get("alert_file"))
)

if st.button("◉ Onboard Tenant", type="primary", use_container_width=True,
             disabled=create_disabled):
    try:
        created = create_tenant(
            display_name=display_name,
            provider_type=provider_type,
            provider_config=provider_config,
            credentials=credentials,
            ingestion_mode=ingestion_mode,
            enabled=True,
        )
        st.success(f"Tenant created: {created['tenant_id']}")
        # Optionally test the connection right away
        ok, msg = test_connection(created["tenant_id"])
        if ok:
            st.info(f"✓ Connection test: {msg}")
        else:
            st.warning(f"⚠ Connection test: {msg}")
        st.rerun()
    except Exception as e:
        st.error(f"Failed to create tenant: {e}")


# ============================================================
# Existing tenants
# ============================================================
W.section_header("Configured Tenants")
existing = list_tenants()

if not existing:
    st.caption("No tenants configured yet. Use the form above to onboard one.")
else:
    for t in existing:
        col1, col2, col3, col4 = st.columns([3, 1, 1, 1])
        enabled_dot = "●" if t["enabled"] else "○"
        dot_color = "#10b981" if t["enabled"] else "#64748b"
        with col1:
            st.markdown(f"""
            <div class="finding-card low">
              <div class="finding-title">
                <span style="color:{dot_color}; margin-right:6px;">{enabled_dot}</span>
                {t['display_name']}
                <span class="badge unknown" style="margin-left:8px;">{t['provider_type']}</span>
                <span class="badge unknown" style="margin-left:4px;">{t['ingestion_mode']}</span>
              </div>
              <div style="color:#94a3b8; font-size:0.75rem; margin-top:4px;">
                <span class="mono">{t['tenant_id']}</span>
                &nbsp;·&nbsp; created: {t['created_at']}
                &nbsp;·&nbsp; last polled: {t.get('last_polled_at') or 'never'}
              </div>
              <div style="color:#64748b; font-size:0.75rem; margin-top:6px;">
                config: <span class="mono">{json.dumps(t['provider_config'])[:150]}</span>
              </div>
            </div>
            """, unsafe_allow_html=True)

        with col2:
            if t["enabled"]:
                if st.button("Disable", key=f"dis_{t['tenant_id']}", use_container_width=True):
                    disable_tenant(t["tenant_id"])
                    st.rerun()
            else:
                if st.button("Enable", key=f"en_{t['tenant_id']}", use_container_width=True):
                    enable_tenant(t["tenant_id"])
                    st.rerun()

        with col3:
            if st.button("Test", key=f"test_{t['tenant_id']}", use_container_width=True):
                ok, msg = test_connection(t["tenant_id"])
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)

        with col4:
            if st.button("Delete", key=f"del_{t['tenant_id']}", use_container_width=True):
                delete_tenant(t["tenant_id"])
                st.rerun()
