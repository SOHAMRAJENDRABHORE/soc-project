"""
Decision Bot — SOC Console UI (entry / home page)

Run with:
    streamlit run frontend/streamlit_app.py

Streamlit will auto-discover pages in frontend/pages/.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st
from shared.schemas import Alert
from shared.config import settings
from decision_bot.bot import decide

from _components.styling import inject as inject_css
from _components import widgets as W


st.set_page_config(
    page_title="Decision Bot · SOC Console",
    page_icon="◐",
    layout="wide",
    initial_sidebar_state="expanded",
)
inject_css()


W.banner(
    "◐ DECISION BOT",
    "SOC Triage Console · Agentic AI for Endpoint Security",
    variant="decision",
)


# ============================================================
# Sidebar
# ============================================================
with st.sidebar:
    W.section_header("System Status")

    missing = settings.missing_required_keys()
    if missing:
        st.error(f"Missing required: {', '.join(missing)}")
        st.caption("Add to .env then restart")
    else:
        st.success("LLM configured")
        st.caption(f"Model: `{settings.AZURE_OPENAI_MODEL}`")

    W.section_header("Enrichers")
    for name, ok in settings.enricher_status().items():
        icon = "●" if ok else "○"
        color = "#10b981" if ok else "#64748b"
        st.markdown(
            f'<div class="mono" style="color:{color}; font-size:0.85rem;">{icon} {name}</div>',
            unsafe_allow_html=True,
        )

    W.section_header("Load Sample Alert")
    sample_path = PROJECT_ROOT / "decision_bot" / "tests" / "sample_alerts.json"
    if sample_path.exists():
        samples_data = json.loads(sample_path.read_text())["samples"]
        sample_labels = [
            s.get("_comment", "Untitled")[:80] if s.get("_comment") else s.get("value", [{}])[0].get("displayName", "Untitled")
            for s in samples_data
        ]
        chosen = st.selectbox("Pick a scenario", ["(none)"] + sample_labels)
        if chosen != "(none)":
            chosen_sample = next((s for s in samples_data if (s.get("_comment", "")[:80] if s.get("_comment") else s.get("value", [{}])[0].get("displayName", ""))[:80] == chosen), None)
            if chosen_sample and st.button("◉ Load into form", use_container_width=True):
                # Load the first alert from the value array
                alert_value = chosen_sample.get("value", [])
                if alert_value:
                    st.session_state["loaded_alert"] = alert_value[0]
                    st.rerun()

    W.section_header("Navigate")
    st.markdown(
        '<div class="mono" style="color:#94a3b8; font-size:0.85rem;">'
        '→ Use the page selector above for Analysis Bot</div>',
        unsafe_allow_html=True,
    )


# ============================================================
# Main — alert input
# ============================================================
W.section_header("Alert Input")
loaded = st.session_state.get("loaded_alert", {})

col1, col2 = st.columns([1, 1])
with col1:
    alert_id = st.text_input("Alert ID", value=loaded.get("alert_id", "ALERT-001"))
    severity = st.selectbox(
        "Severity",
        ["low", "medium", "high", "critical"],
        index=["low", "medium", "high", "critical"].index(loaded.get("severity", "medium")),
    )
    endpoint_id = st.text_input("Endpoint ID", value=loaded.get("endpoint_id", ""))

with col2:
    title = st.text_input("Title", value=loaded.get("title", ""))
    source = st.text_input("Source", value=loaded.get("source", "manual"))

description = st.text_area("Description", value=loaded.get("description", ""), height=80)
raw_text = st.text_area(
    "Raw payload (JSON)",
    value=json.dumps(loaded.get("raw", {}), indent=2) if loaded.get("raw") else "{}",
    height=200,
    help="Free-form JSON. IOCs are auto-extracted from anywhere in this blob plus title and description.",
)

run_clicked = st.button("▶ RUN DECISION PIPELINE", use_container_width=True, type="primary")


# ============================================================
# Pipeline
# ============================================================
if run_clicked:
    if missing:
        st.error(f"Cannot run: missing keys {missing}. Add them to .env and restart.")
        st.stop()

    try:
        raw_dict = json.loads(raw_text) if raw_text.strip() else {}
    except json.JSONDecodeError as e:
        st.error(f"Raw payload is not valid JSON: {e}")
        st.stop()

    alert = Alert(
        alert_id=alert_id, source=source, severity=severity,
        title=title or None, description=description or None,
        endpoint_id=endpoint_id or None, raw=raw_dict,
    )

    W.section_header("Pipeline")
    stages_container = st.container()
    stage_state = {}

    def on_progress(stage: str, data: dict):
        stage_state[stage] = data

    with st.spinner("Running decision pipeline..."):
        s1 = stages_container.empty(); s2 = stages_container.empty(); s3 = stages_container.empty()
        s1.markdown(
            '<div class="stage-card active"><div class="stage-label">Stage 1</div>'
            '<div class="stage-title">▸ Extracting IOCs from alert...</div></div>',
            unsafe_allow_html=True)

        start = time.time()
        try:
            verdict = decide(alert, progress_cb=on_progress)
        except Exception as e:
            st.error(f"Pipeline failed: {e}")
            st.exception(e)
            st.stop()
        duration = time.time() - start

        ioc_count = len(stage_state.get("iocs_extracted", {}).get("iocs", []))
        enr_count = len(stage_state.get("enrichment_done", {}).get("results", []))

        s1.markdown(
            f'<div class="stage-card done"><div class="stage-label">Stage 1 · IOC Extraction</div>'
            f'<div class="stage-title">✓ Extracted {ioc_count} indicators</div></div>',
            unsafe_allow_html=True)
        s2.markdown(
            f'<div class="stage-card done"><div class="stage-label">Stage 2 · Parallel Enrichment</div>'
            f'<div class="stage-title">✓ {enr_count} enrichment results from threat intel sources</div></div>',
            unsafe_allow_html=True)
        s3.markdown(
            f'<div class="stage-card done"><div class="stage-label">Stage 3 · LLM Verdict</div>'
            f'<div class="stage-title">✓ Verdict generated · {duration:.1f}s total</div></div>',
            unsafe_allow_html=True)

    verdict_dict = verdict.model_dump(mode="json")

    # Save verdict to session so the Analysis page can pick it up
    st.session_state["latest_verdict"] = verdict_dict
    st.session_state["latest_alert"] = alert.model_dump(mode="json")

    W.render_verdict(verdict_dict)

    W.section_header("Reasoning")
    st.markdown(
        f'<div style="background:#0f1623; padding:14px 18px; border-left:2px solid #f59e0b; '
        f'font-size:0.95rem; line-height:1.6; color:#cbd5e1;">{verdict_dict["reasoning"]}</div>',
        unsafe_allow_html=True)

    if verdict_dict.get("mitre_techniques"):
        W.section_header("MITRE ATT&CK")
        W.render_mitre(verdict_dict["mitre_techniques"])

    if verdict_dict.get("kill_chain_phase"):
        W.section_header("Kill Chain Phase")
        st.markdown(
            f'<div class="mono" style="color:#fbbf24;">{verdict_dict["kill_chain_phase"]}</div>',
            unsafe_allow_html=True)

    W.section_header("Handoff to Analysis Bot")
    st.markdown(
        f'<div style="background:#0f1623; padding:14px 18px; border-left:2px solid #8b5cf6; '
        f'font-size:0.9rem; color:#cbd5e1; font-family: JetBrains Mono, monospace;">'
        f'{verdict_dict["recommended_next_step"]}</div>',
        unsafe_allow_html=True)

    st.info("→ Open the **Analysis Bot** page in the sidebar to run forensics on this verdict.")

    tab1, tab2, tab3, tab4 = st.tabs(["⛬ IOCs", "⌖ Enrichment", "⌬ Full JSON", "→ Next Bot Input"])
    with tab1:
        st.caption(f"{len(verdict_dict['iocs'])} indicators extracted via regex")
        W.render_iocs(verdict_dict["iocs"])
    with tab2:
        st.caption(f"{len(verdict_dict['enrichment'])} enrichment results")
        W.render_enrichment(verdict_dict["enrichment"])
    with tab3:
        st.code(json.dumps(verdict_dict, indent=2, default=str), language="json")
    with tab4:
        st.caption("Analysis Bot consumes this Verdict object directly.")
        st.code(json.dumps(verdict_dict, indent=2, default=str), language="json")
