"""
Shared CSS injected on every page. SOC-console aesthetic.
Importing this module and calling `inject()` is all a page needs.
"""
import streamlit as st


CSS = """
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Space+Grotesk:wght@400;500;700&display=swap');

  html, body, [class*="css"]  { font-family: 'Space Grotesk', sans-serif; }
  code, pre, .mono { font-family: 'JetBrains Mono', monospace !important; }

  .stApp {
    background:
      radial-gradient(circle at 0% 0%, #14253a 0%, transparent 40%),
      radial-gradient(circle at 100% 100%, #1a1a2e 0%, transparent 40%),
      #0a0e1a;
    color: #e6e8ec;
  }

  .console-banner {
    background: linear-gradient(135deg, #1a1f2e 0%, #0f1420 100%);
    border: 1px solid #2a3245;
    border-left: 3px solid #f59e0b;
    padding: 18px 24px;
    margin-bottom: 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .console-banner.analysis { border-left-color: #8b5cf6; }
  .console-banner h1 {
    font-size: 1.4rem; margin: 0;
    color: #f8fafc; letter-spacing: -0.02em; font-weight: 700;
  }
  .console-banner .subtitle {
    color: #94a3b8;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }
  .status-dot {
    display: inline-block; width: 8px; height: 8px; border-radius: 50%;
    background: #10b981; box-shadow: 0 0 8px #10b981;
    margin-right: 8px; animation: pulse 2s infinite;
  }
  .status-dot.offline { background: #64748b; box-shadow: none; animation: none; }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }

  .stage-card {
    background: rgba(20, 28, 45, 0.6);
    border: 1px solid #1f2937;
    border-radius: 4px;
    padding: 14px 18px;
    margin-bottom: 12px;
  }
  .stage-card.active { border-color: #f59e0b; box-shadow: 0 0 0 1px #f59e0b33; }
  .stage-card.done { border-left: 3px solid #10b981; }
  .stage-card.analysis.active { border-color: #8b5cf6; box-shadow: 0 0 0 1px #8b5cf633; }
  .stage-label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem; text-transform: uppercase;
    letter-spacing: 0.1em; color: #64748b; margin-bottom: 4px;
  }
  .stage-title { font-size: 1rem; font-weight: 500; color: #e2e8f0; }

  .verdict-card {
    padding: 24px; border-radius: 4px; margin: 16px 0;
    border: 1px solid; position: relative; overflow: hidden;
  }
  .verdict-card.malicious { background: linear-gradient(135deg, #2d0a0a 0%, #1a0808 100%); border-color: #ef4444; }
  .verdict-card.suspicious { background: linear-gradient(135deg, #2d1f0a 0%, #1a1308 100%); border-color: #f59e0b; }
  .verdict-card.benign { background: linear-gradient(135deg, #0a2d1a 0%, #081a10 100%); border-color: #10b981; }
  .verdict-card.unknown { background: linear-gradient(135deg, #1a1a2d 0%, #08081a 100%); border-color: #64748b; }
  .verdict-card.critical { background: linear-gradient(135deg, #2d0a0a 0%, #1a0808 100%); border-color: #ef4444; }
  .verdict-card.high { background: linear-gradient(135deg, #2d1f0a 0%, #1a1308 100%); border-color: #f59e0b; }
  .verdict-card.medium { background: linear-gradient(135deg, #1f1f2d 0%, #18181a 100%); border-color: #fbbf24; }
  .verdict-card.low { background: linear-gradient(135deg, #0a2d1a 0%, #081a10 100%); border-color: #10b981; }

  .verdict-label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 2rem; font-weight: 700;
    letter-spacing: 0.08em; text-transform: uppercase; margin: 0;
  }
  .verdict-label.malicious, .verdict-label.critical { color: #fca5a5; }
  .verdict-label.suspicious, .verdict-label.high { color: #fcd34d; }
  .verdict-label.benign, .verdict-label.low { color: #6ee7b7; }
  .verdict-label.unknown { color: #cbd5e1; }
  .verdict-label.medium { color: #fbbf24; }

  .confidence-bar {
    height: 6px; background: #1f2937;
    border-radius: 3px; overflow: hidden; margin-top: 8px;
  }
  .confidence-fill {
    height: 100%;
    background: linear-gradient(90deg, #f59e0b, #fbbf24);
    transition: width 0.6s ease;
  }

  .ioc-chip {
    display: inline-block;
    background: #1e293b;
    border: 1px solid #334155;
    border-left: 2px solid #60a5fa;
    padding: 4px 10px; margin: 3px;
    border-radius: 3px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem; color: #cbd5e1;
  }
  .ioc-chip .type {
    color: #60a5fa; text-transform: uppercase;
    font-size: 0.65rem; letter-spacing: 0.08em; margin-right: 8px;
  }

  .enrich-row {
    background: #0f1623;
    border: 1px solid #1e293b;
    padding: 10px 14px; margin-bottom: 6px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.82rem;
    display: flex; justify-content: space-between; align-items: center;
  }
  .enrich-row.clean { border-left: 2px solid #10b981; }
  .enrich-row.suspicious { border-left: 2px solid #f59e0b; }
  .enrich-row.malicious { border-left: 2px solid #ef4444; }
  .enrich-row.failed { border-left: 2px solid #64748b; opacity: 0.6; }

  .badge {
    display: inline-block; padding: 2px 8px;
    border-radius: 2px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem; text-transform: uppercase;
    letter-spacing: 0.06em; font-weight: 600;
  }
  .badge.malicious, .badge.critical { background: #ef444422; color: #fca5a5; }
  .badge.suspicious, .badge.high { background: #f59e0b22; color: #fcd34d; }
  .badge.clean, .badge.low { background: #10b98122; color: #6ee7b7; }
  .badge.unknown { background: #64748b22; color: #cbd5e1; }
  .badge.medium { background: #fbbf2422; color: #fde68a; }

  .mitre-chip {
    display: inline-block;
    background: #422006;
    border: 1px solid #92400e;
    color: #fbbf24;
    padding: 3px 10px; margin: 3px;
    border-radius: 2px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem; font-weight: 600;
  }
  .mitre-chip a { color: #fbbf24; text-decoration: none; }

  h2, h3 {
    font-family: 'Space Grotesk', sans-serif !important;
    letter-spacing: -0.01em; color: #f1f5f9;
  }
  .section-header {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem; text-transform: uppercase;
    letter-spacing: 0.12em; color: #94a3b8;
    margin: 24px 0 8px 0; padding-bottom: 6px;
    border-bottom: 1px solid #1e293b;
  }

  section[data-testid="stSidebar"] {
    background: #0a0e1a;
    border-right: 1px solid #1e293b;
  }

  .stButton > button {
    background: #f59e0b; color: #0a0e1a; border: none;
    font-weight: 600; letter-spacing: 0.04em;
    font-family: 'JetBrains Mono', monospace;
    text-transform: uppercase; font-size: 0.85rem;
  }
  .stButton > button:hover { background: #fbbf24; color: #0a0e1a; }
  .stButton > button[kind="secondary"] { background: #8b5cf6; color: #0a0e1a; }
  .stButton > button[kind="secondary"]:hover { background: #a78bfa; }

  .stTextArea textarea, .stTextInput input {
    background: #0f1623 !important;
    color: #e2e8f0 !important;
    border: 1px solid #1e293b !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.85rem !important;
  }

  /* ---- Analysis specific ---- */
  .finding-card {
    background: #0f1623;
    border: 1px solid #1e293b;
    padding: 12px 16px;
    margin-bottom: 10px;
    border-radius: 4px;
  }
  .finding-card.critical { border-left: 3px solid #ef4444; }
  .finding-card.high { border-left: 3px solid #f59e0b; }
  .finding-card.medium { border-left: 3px solid #fbbf24; }
  .finding-card.low { border-left: 3px solid #10b981; }
  .finding-title { color: #f1f5f9; font-weight: 600; font-size: 0.95rem; margin-bottom: 4px; }
  .finding-evidence {
    color: #94a3b8;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    background: #050810;
    padding: 8px 10px;
    margin-top: 6px;
    border-radius: 2px;
  }
  .agent-row {
    background: #0f1623;
    border: 1px solid #1e293b;
    padding: 8px 14px;
    margin-bottom: 4px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    display: flex; justify-content: space-between;
  }
</style>
"""


def inject():
    st.markdown(CSS, unsafe_allow_html=True)
