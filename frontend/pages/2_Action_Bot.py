"""
Action Bot UI

Executes remediation actions recommended by Analysis Bot.
Lets you review, approve, modify, and execute forensic actions on endpoints.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st
import httpx

from shared.schemas import AnalysisReport
from shared.config import settings
from action_bot.bot import plan, act
from analysis_bot.dispatcher import CentralServerClient

from _components.styling import inject as inject_css
from _components import widgets as W


st.set_page_config(
    page_title="Action Bot · Remediation Console",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded",
)
inject_css()

W.banner(
    "⚡ ACTION BOT",
    "Remediation Console · Agentic AI for Endpoint Security",
    variant="decision",
)


# ============================================================
# Sidebar: help + config status
# ============================================================
with st.sidebar:
    st.markdown("**Action Bot** executes remediation actions on endpoints.")
    st.markdown("""
    1. Run **Decision Bot** → **Analysis Bot** first
    2. Review recommended actions here
    3. Select which actions to execute
    4. Pick target endpoint
    5. Execute & monitor
    """)
    st.divider()
    
    if not settings.AZURE_OPENAI_KEY:
        st.error("❌ LLM not configured")
    else:
        st.success("✅ LLM configured")
        st.caption(f"Model: `{settings.AZURE_OPENAI_MODEL}`")


# ============================================================
# Load analysis report from session
# ============================================================
def get_analysis_report() -> dict | None:
    """Retrieve the latest analysis report from session state."""
    return st.session_state.get("latest_report")


report_dict = get_analysis_report()

if not report_dict:
    st.warning("⚠️ No analysis report in session yet.")
    st.info("👉 Run **Decision Bot** → **Analysis Bot** first to generate a report.")
    st.stop()

W.section_header("Analysis Report")
st.markdown(f"""
| Field | Value |
|-------|-------|
| **Alert ID** | `{report_dict["alert_id"]}` |
| **Endpoint** | `{report_dict["endpoint_id"]}` |
| **Severity** | {report_dict["overall_severity"]} |
| **Summary** | {report_dict.get("summary", "—")} |
""")


# ============================================================
# Recommended Actions → Structured Actions
# ============================================================
W.section_header("Recommended Actions")

try:
    report_obj = AnalysisReport(**report_dict)
    planned_actions = plan(report_obj)
except Exception as e:
    st.error(f"Failed to parse report: {e}")
    st.stop()

if not planned_actions:
    st.warning("No structured actions mapped from recommendations.")
    st.info(
        "The Analysis Bot's recommended text didn't match any action patterns. "
        "You can add custom rules to the mapper in `action_bot/mapper.py`."
    )
    st.stop()

# Display planned actions in an interactive table
st.subheader(f"Mapped Actions ({len(planned_actions)})")

# Create checkboxes for action approval
approved_actions = []
for i, action in enumerate(planned_actions):
    col1, col2, col3 = st.columns([0.5, 1, 3])
    
    with col1:
        checked = st.checkbox(
            "Approve",
            value=True,
            key=f"action_approve_{i}",
        )
    
    with col2:
        st.markdown(f"""
        <div style="background:#0f1623; padding:8px 12px; border-left:2px solid #06b6d4;
                    font-family: JetBrains Mono, monospace; font-size:0.80rem;
                    color:#06b6d4; border-radius:4px;">
          {action["name"]}
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        if action["params"]:
            params_str = " · ".join(f"{k}={v}" for k, v in action["params"].items())
            st.markdown(f"<small style='color:#94a3b8;'>{params_str}</small>", unsafe_allow_html=True)
        if action.get("reason"):
            st.markdown(f"<small style='color:#64748b;'>Reason: {action['reason'][:80]}</small>", unsafe_allow_html=True)
        
        badge_color = "#ef4444" if action.get("destructive") else "#10b981"
        badge_text = "🚨 Destructive" if action.get("destructive") else "✓ Safe"
        st.markdown(
            f"<small style='color:{badge_color};'>{badge_text}</small>",
            unsafe_allow_html=True
        )
    
    if checked:
        approved_actions.append(action)

st.divider()


# ============================================================
# Central server connectivity check
# ============================================================
def server_health() -> tuple[bool, str]:
    """Check if central server is healthy."""
    try:
        client = CentralServerClient()
        response = httpx.get(
            f"{client.base_url}/health",
            headers=client._headers,
            timeout=5
        )
        return response.status_code == 200, "✅ Connected"
    except Exception as e:
        return False, f"❌ {str(e)[:50]}"


healthy, status = server_health()
if not healthy:
    st.error(f"Central server offline: {status}")
    st.info("Make sure the central server is running: `python -m central_server.server`")
    st.stop()


# ============================================================
# Agent selection
# ============================================================
W.section_header("Target Endpoint")

try:
    client = CentralServerClient()
    agents = client.list_agents()
except Exception as e:
    st.error(f"Failed to fetch agents: {e}")
    st.stop()

online_agents = [a for a in agents if a.get("online")]
if not online_agents:
    st.warning("No online agents available. Start an agent on your VM first.")
    st.info("On your endpoint VM, run: `python -m endpoint_agent.agent`")
    st.stop()

agent_options = {
    f"{a['hostname']} · {a['os']} · {a['agent_id']}": a["agent_id"]
    for a in online_agents
}
selected_label = st.selectbox("Pick target endpoint", list(agent_options.keys()))
selected_agent_id = agent_options[selected_label]


# ============================================================
# Execution mode & approval
# ============================================================
W.section_header("Execution")

if not approved_actions:
    st.warning("No actions approved. Select at least one action above.")
    st.stop()

col1, col2 = st.columns(2)
with col1:
    mode = st.radio(
        "Execution mode",
        ["manual (review each action)", "auto (execute all)"],
        index=0,
    )
    mode = mode.split()[0].lower()

with col2:
    timeout_seconds = st.slider(
        "Timeout (seconds)",
        min_value=30,
        max_value=600,
        value=120,
        step=30,
    )

st.markdown(
    f"""
    <div style="background:#1f2937; padding:12px; border-left:3px solid #f59e0b; border-radius:4px; margin-bottom:16px;">
      <strong>⚠️ Warning</strong><br>
      {len(approved_actions)} action(s) will be executed on <code>{selected_label}</code>.
      This may have significant impact on the endpoint.
    </div>
    """,
    unsafe_allow_html=True,
)

execute_button = st.button(
    f"🚀 Execute {len(approved_actions)} Action(s)",
    type="primary",
    use_container_width=True,
)


# ============================================================
# Execute & monitor
# ============================================================
if execute_button:
    try:
        with st.spinner("Executing actions..."):
            result = act(
                report=report_obj,
                agent_id=selected_agent_id,
                mode=mode,
                approved_actions=approved_actions,
                timeout=timeout_seconds,
            )
        
        # Store result in session
        st.session_state["latest_action_result"] = result
        
        st.success("✅ Action execution completed!")
        st.divider()
        
        # Display results
        W.section_header("Execution Results")
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Job ID", result.get("job_id", "—")[:16])
        with col2:
            st.metric("Status", result.get("status", "unknown").upper())
        with col3:
            st.metric("Executed Actions", len(result.get("executed", [])))
        with col4:
            st.metric("Mode", result.get("mode", "—").upper())
        
        st.divider()
        
        # Execution details
        if result.get("results"):
            st.subheader("Action Results")
            for i, res in enumerate(result["results"], 1):
                status_icon = "✅" if res.get("success") else "❌"
                with st.expander(f"{status_icon} Action {i}: {res.get('name', 'unknown')}"):
                    st.json(res)
        
        # Full result JSON
        with st.expander("📋 Full Result JSON"):
            st.code(json.dumps(result, indent=2, default=str), language="json")
        
        # Save for audit
        st.info("✅ Result saved to session. Refresh page to clear.")
        
    except Exception as e:
        st.error(f"Execution failed: {e}")
        st.exception(e)
