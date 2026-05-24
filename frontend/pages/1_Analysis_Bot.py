"""
Analysis Bot UI

Run after Decision Bot has produced a Verdict (the page picks it up from session).
Pick an online agent, run the forensic job, see the report.
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

from shared.schemas import Verdict
from shared.config import settings
from analysis_bot.bot import analyze
from analysis_bot.action_planner import plan_actions
from analysis_bot.dispatcher import CentralServerClient

from _components.styling import inject as inject_css
from _components import widgets as W


st.set_page_config(
    page_title="Analysis Bot · Forensics Console",
    page_icon="◑",
    layout="wide",
    initial_sidebar_state="expanded",
)
inject_css()

W.banner(
    "◑ ANALYSIS BOT",
    "Forensics Console · Agentic AI for Endpoint Security",
    variant="analysis",
)


# ============================================================
# Central server connectivity check (sidebar)
# ============================================================
def server_health() -> tuple[bool, str]:
    try:
        r = httpx.get(f"{settings.CENTRAL_SERVER_URL}/health", timeout=3)
        if r.status_code == 200:
            return True, r.json().get("status", "ok")
        return False, f"HTTP {r.status_code}"
    except Exception as e:
        return False, f"unreachable: {type(e).__name__}"


with st.sidebar:
    W.section_header("Central Server")
    ok, msg = server_health()
    if ok:
        st.success(f"Connected · {settings.CENTRAL_SERVER_URL}")
    else:
        st.error(f"Not reachable: {msg}")
        st.caption(f"Expected at {settings.CENTRAL_SERVER_URL}")
        st.caption("Start it with: `python -m central_server.server`")

    W.section_header("Endpoint Agents")
    agents: list[dict] = []
    if ok and settings.AGENT_AUTH_TOKEN:
        try:
            client = CentralServerClient()
            agents = client.list_agents()
        except Exception as e:
            st.caption(f"Error listing agents: {e}")

    if not agents:
        st.caption("No agents registered yet.")
        st.caption("Start an agent on a VM with: `python -m endpoint_agent.agent`")
    else:
        for a in agents:
            online = a.get("online")
            dot_cls = "" if online else "offline"
            label = f"{a['hostname']} ({a['os']})"
            st.markdown(f"""
            <div class="agent-row">
              <div><span class="status-dot {dot_cls}"></span>{label}</div>
              <span style="color:#64748b; font-size:0.7rem;">{a['agent_id'][-8:]}</span>
            </div>
            """, unsafe_allow_html=True)


# ============================================================
# Verdict input — auto-load from Decision page, or paste JSON
# ============================================================
W.section_header("Input Verdict")

verdict_source = st.radio(
    "Source",
    ["From Decision Bot (session)", "Paste JSON manually"],
    horizontal=True,
)

verdict_dict = None
if verdict_source == "From Decision Bot (session)":
    cached = st.session_state.get("latest_verdict")
    if not cached:
        st.warning("No verdict in session yet. Run Decision Bot first, or paste JSON.")
    else:
        st.success(f"Loaded verdict for alert `{cached['alert_id']}` "
                   f"({cached['label']}, {cached['confidence']}%)")
        with st.expander("Show verdict JSON"):
            st.code(json.dumps(cached, indent=2, default=str), language="json")
        verdict_dict = cached
else:
    pasted = st.text_area(
        "Paste a Verdict JSON",
        height=250,
        placeholder='{"alert_id": "...", "label": "malicious", ...}',
    )
    if pasted.strip():
        try:
            verdict_dict = json.loads(pasted)
        except json.JSONDecodeError as e:
            st.error(f"Invalid JSON: {e}")


# ============================================================
# Agent selection
# ============================================================
W.section_header("Target Endpoint")

online_agents = [a for a in agents if a.get("online")]
if not online_agents:
    st.warning("No online agents available. Start an agent on your VM first.")
    selected_agent_id = None
else:
    agent_options = {f"{a['hostname']} · {a['os']} · {a['agent_id']}": a["agent_id"]
                     for a in online_agents}
    label = st.selectbox("Pick an online agent", list(agent_options.keys()))
    selected_agent_id = agent_options[label]


# ============================================================
# Action preview
# ============================================================
if verdict_dict and selected_agent_id:
    try:
        verdict_obj = Verdict(**verdict_dict)
    except Exception as e:
        st.error(f"Verdict JSON doesn't match the schema: {e}")
        verdict_obj = None
else:
    verdict_obj = None

if verdict_obj:
    W.section_header("Planned Forensic Actions")
    planned = plan_actions(verdict_obj)
    cols = st.columns(min(4, len(planned)))
    for i, a in enumerate(planned):
        with cols[i % len(cols)]:
            st.markdown(f"""
            <div class="stage-card">
              <div class="stage-label">{a.name}</div>
              <div class="stage-title" style="font-size:0.85rem;">
                {', '.join(f'{k}={v}' for k,v in a.params.items()) or 'default params'}
              </div>
            </div>
            """, unsafe_allow_html=True)


# ============================================================
# Run
# ============================================================
run_clicked = st.button(
    "▶ RUN ANALYSIS PIPELINE",
    use_container_width=True,
    type="secondary",
    disabled=not (verdict_obj and selected_agent_id),
)

if run_clicked and verdict_obj and selected_agent_id:
    W.section_header("Pipeline")

    stage_state = {}
    stages = st.container()
    s1 = stages.empty(); s2 = stages.empty(); s3 = stages.empty(); s4 = stages.empty()

    def on_progress(stage: str, data: dict):
        stage_state[stage] = data

    s1.markdown(
        '<div class="stage-card analysis active"><div class="stage-label">Stage 1</div>'
        '<div class="stage-title">▸ Planning forensic actions...</div></div>',
        unsafe_allow_html=True)

    timeout = st.session_state.get("analysis_timeout", 600)
    with st.spinner("Dispatching job to endpoint agent and waiting for results..."):
        start = time.time()
        try:
            report = analyze(
                verdict_obj,
                agent_id=selected_agent_id,
                timeout_seconds=timeout,
                progress_cb=on_progress,
            )
        except Exception as e:
            st.error(f"Pipeline failed: {e}")
            st.exception(e)
            st.stop()
        duration = time.time() - start

    actions_count = len(stage_state.get("plan_ready", {}).get("actions", []))
    job_id = stage_state.get("dispatched", {}).get("job_id", "?")
    results_count = stage_state.get("agent_done", {}).get("results_count", 0)

    s1.markdown(
        f'<div class="stage-card done"><div class="stage-label">Stage 1 · Action Planning</div>'
        f'<div class="stage-title">✓ Planned {actions_count} forensic actions</div></div>',
        unsafe_allow_html=True)
    s2.markdown(
        f'<div class="stage-card done"><div class="stage-label">Stage 2 · Dispatch</div>'
        f'<div class="stage-title">✓ Job <span class="mono">{job_id}</span> sent to agent</div></div>',
        unsafe_allow_html=True)
    s3.markdown(
        f'<div class="stage-card done"><div class="stage-label">Stage 3 · Agent Execution</div>'
        f'<div class="stage-title">✓ {results_count} action results received from endpoint</div></div>',
        unsafe_allow_html=True)
    s4.markdown(
        f'<div class="stage-card done"><div class="stage-label">Stage 4 · LLM Synthesis</div>'
        f'<div class="stage-title">✓ Analysis report generated · {duration:.1f}s total</div></div>',
        unsafe_allow_html=True)

    report_dict = report.model_dump(mode="json")
    st.session_state["latest_report"] = report_dict

    # Severity card
    sev = report_dict["overall_severity"]
    st.markdown(f"""
    <div class="verdict-card {sev}">
      <div class="stage-label">OVERALL SEVERITY</div>
      <p class="verdict-label {sev}">{sev}</p>
      <div style="display:flex; justify-content:space-between; margin-top:12px;">
        <span class="mono" style="color:#94a3b8; font-size:0.85rem;">FINDINGS</span>
        <span class="mono" style="color:#e2e8f0; font-weight:600;">{len(report_dict['findings'])}</span>
      </div>
    </div>
    """, unsafe_allow_html=True)

    W.section_header("Summary")
    st.markdown(
        f'<div style="background:#0f1623; padding:14px 18px; border-left:2px solid #8b5cf6; '
        f'font-size:0.95rem; line-height:1.6; color:#cbd5e1;">{report_dict["summary"]}</div>',
        unsafe_allow_html=True)

    W.section_header("Findings")
    if not report_dict["findings"]:
        st.caption("No specific findings — telemetry looked clean.")
    else:
        for f in report_dict["findings"]:
            W.render_finding(f)

    W.section_header("Recommended Actions → Action Bot")
    for i, a in enumerate(report_dict["recommended_actions"], 1):
        st.markdown(f"""
        <div style="background:#0f1623; padding:10px 14px; border-left:2px solid #f59e0b;
                    font-family: JetBrains Mono, monospace; font-size:0.85rem;
                    margin-bottom:6px; color:#fcd34d;">
          {i:02d}. {a}
        </div>
        """, unsafe_allow_html=True)

    # Tabs for the raw telemetry / full report
    tab1, tab2, tab3 = st.tabs(["⌬ Raw Telemetry", "⌬ Full Report JSON", "→ Action Bot Input"])
    with tab1:
        st.caption("What the agent actually collected from the endpoint")
        for r in report_dict["raw_telemetry"]:
            with st.expander(f"{r['action']} · success={r['success']} · {r['duration_seconds']}s"):
                if r.get("error"):
                    st.error(r["error"])
                else:
                    st.code(json.dumps(r.get("data", {}), indent=2, default=str)[:20000],
                            language="json")
    with tab2:
        st.code(json.dumps(report_dict, indent=2, default=str), language="json")
    with tab3:
        st.caption("Next steps: execute remediation actions")
        handoff = {
            "alert_id": report_dict["alert_id"],
            "endpoint_id": report_dict["endpoint_id"],
            "overall_severity": report_dict["overall_severity"],
            "recommended_actions": report_dict["recommended_actions"],
            "findings": report_dict["findings"],
        }
        col1, col2 = st.columns([2, 1])
        with col1:
            st.code(json.dumps(handoff, indent=2, default=str), language="json")
        with col2:
            st.markdown(
                """
                <div style="background:#065f46; padding:16px; border-radius:6px; text-align:center;">
                  <div style="font-size:1.2em; font-weight:bold; margin-bottom:8px;">✅ Analysis Done</div>
                  <p style="font-size:0.85em; color:#d1fae5; margin-bottom:12px;">
                    Report ready for remediation
                  </p>
                </div>
                """,
                unsafe_allow_html=True
            )
            if st.button("→ Go to Action Bot", use_container_width=True):
                st.switch_page("pages/2_Action_Bot.py")
