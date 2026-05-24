"""
Reusable rendering helpers. Both pages call into here.
"""
from __future__ import annotations

import streamlit as st


def banner(title: str, subtitle: str, variant: str = "decision"):
    """Header banner with status dot."""
    cls = "console-banner" + (" analysis" if variant == "analysis" else "")
    st.markdown(f"""
    <div class="{cls}">
      <div>
        <h1>{title}</h1>
        <div class="subtitle">{subtitle}</div>
      </div>
      <div class="subtitle">
        <span class="status-dot"></span>SYSTEM ONLINE
      </div>
    </div>
    """, unsafe_allow_html=True)


def section_header(text: str):
    st.markdown(f'<div class="section-header">{text}</div>', unsafe_allow_html=True)


def render_verdict(verdict_dict: dict):
    label = verdict_dict["label"]
    confidence = verdict_dict["confidence"]
    st.markdown(f"""
    <div class="verdict-card {label}">
      <div class="stage-label">FINAL VERDICT</div>
      <p class="verdict-label {label}">{label}</p>
      <div style="display: flex; justify-content: space-between; margin-top: 12px;">
        <span class="mono" style="color: #94a3b8; font-size: 0.85rem;">CONFIDENCE</span>
        <span class="mono" style="color: #e2e8f0; font-weight: 600;">{confidence}%</span>
      </div>
      <div class="confidence-bar">
        <div class="confidence-fill" style="width: {confidence}%;"></div>
      </div>
    </div>
    """, unsafe_allow_html=True)


def render_iocs(iocs: list[dict]):
    if not iocs:
        st.caption("No IOCs.")
        return
    chips = "".join(
        f'<span class="ioc-chip"><span class="type">{i["type"]}</span>{i["value"]}</span>'
        for i in iocs
    )
    st.markdown(chips, unsafe_allow_html=True)


def render_mitre(techniques: list[str]):
    if not techniques:
        return
    chips = "".join(
        f'<span class="mitre-chip"><a href="https://attack.mitre.org/techniques/'
        f'{t.replace(".", "/")}/" target="_blank">{t}</a></span>'
        for t in techniques
    )
    st.markdown(chips, unsafe_allow_html=True)


def render_enrichment(results: list[dict]):
    if not results:
        st.caption("No enrichment results.")
        return
    for r in results:
        if r["success"]:
            rep = r.get("reputation") or "unknown"
            score = r.get("malicious_score")
            tags = " · ".join((r.get("tags") or [])[:5])
            st.markdown(f"""
            <div class="enrich-row {rep}">
              <div>
                <span style="color:#60a5fa;">[{r['source']}]</span>
                <span style="color:#94a3b8;">{r['ioc_type']}</span>
                <span style="color:#e2e8f0;">{r['ioc_value']}</span>
                <span style="color:#64748b; font-size:0.75rem; margin-left:8px;">{tags}</span>
              </div>
              <div>
                <span class="badge {rep}">{rep}</span>
                <span class="mono" style="color:#cbd5e1; margin-left:8px;">
                  {score if score is not None else '—'}
                </span>
              </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="enrich-row failed">
              <div>
                <span style="color:#60a5fa;">[{r['source']}]</span>
                <span style="color:#94a3b8;">{r['ioc_value']}</span>
                <span style="color:#94a3b8; margin-left:8px;">{(r.get('error') or '')[:80]}</span>
              </div>
              <span class="badge unknown">failed</span>
            </div>
            """, unsafe_allow_html=True)


def render_finding(f: dict):
    sev = f.get("severity", "low")
    techniques = f.get("mitre_techniques", []) or []
    chips = "".join(
        f'<span class="mitre-chip">{t}</span>' for t in techniques
    )
    st.markdown(f"""
    <div class="finding-card {sev}">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <div class="finding-title">{f.get('title', '(no title)')}</div>
        <span class="badge {sev}">{sev}</span>
      </div>
      <div style="color:#64748b; font-size:0.75rem; text-transform:uppercase; letter-spacing:0.08em; margin-top:2px;">
        {f.get('category', '?')}
      </div>
      <div class="finding-evidence">{f.get('evidence', '')}</div>
      <div style="margin-top:6px;">{chips}</div>
    </div>
    """, unsafe_allow_html=True)
