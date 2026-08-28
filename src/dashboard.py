#!/usr/bin/env python3
"""
Streamlit triage dashboard for the Cowrie honeypot detection pipeline.

Run:
  pip install streamlit
  streamlit run src/dashboard.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))

from models import Disposition, Session
from parsers import load_sessions
from scoring import score_sessions, bucket_sessions

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG = ROOT / "samples" / "cowrie.json"

# ---------------------------------------------------------------------------
# Page config + custom CSS
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Honeypot Detection · Triage",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    /* Tighten top padding */
    .block-container { padding-top: 1.4rem; padding-bottom: 2rem; }

    /* Metric cards */
    [data-testid="stMetric"] {
        background: #0f172a;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 12px 16px;
    }
    [data-testid="stMetricLabel"] { color: #94a3b8 !important; font-size: 0.78rem !important; }
    [data-testid="stMetricValue"] { color: #f1f5f9 !important; font-size: 1.6rem !important; }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background: #0b1220;
        border-right: 1px solid #1e293b;
    }

    /* Expander headers */
    .streamlit-expanderHeader {
        font-size: 0.92rem !important;
        font-weight: 500 !important;
    }

    /* Score bar */
    .score-bar-bg {
        background: #1e293b;
        border-radius: 4px;
        height: 6px;
        width: 100%;
        margin: 4px 0 10px 0;
    }
    .score-bar-fill {
        height: 6px;
        border-radius: 4px;
    }

    /* Disposition badges */
    .badge {
        display: inline-block;
        padding: 2px 9px;
        border-radius: 4px;
        font-size: 0.72rem;
        font-weight: 600;
        letter-spacing: 0.04em;
        text-transform: uppercase;
    }
    .badge-alert  { background: #450a0a; color: #fca5a5; border: 1px solid #7f1d1d; }
    .badge-review { background: #431407; color: #fdba74; border: 1px solid #9a3412; }
    .badge-dismiss{ background: #1e293b; color: #94a3b8; border: 1px solid #334155; }

    /* Finding chips */
    .finding-chip {
        display: inline-block;
        background: #1e293b;
        border: 1px solid #334155;
        color: #cbd5e1;
        border-radius: 4px;
        padding: 2px 8px;
        font-size: 0.75rem;
        margin: 2px 4px 2px 0;
        font-family: ui-monospace, monospace;
    }

    /* Reason list */
    .reason-item {
        padding: 6px 0;
        border-bottom: 1px solid #1e293b;
        font-size: 0.9rem;
        color: #1e293b;
        line-height: 1.45;
    }
    .reason-item:last-child { border-bottom: none; }

    /* Section labels */
    .section-label {
        font-size: 0.72rem;
        font-weight: 600;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: #64748b;
        margin-bottom: 6px;
    }

    /* Hide Streamlit branding */
    #MainMenu { visibility: hidden; }
    footer { visibility: hidden; }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def score_color(score: float) -> str:
    if score >= 0.90:
        return "#ef4444"
    if score >= 0.30:
        return "#f97316"
    return "#64748b"


def badge_html(disposition: Disposition) -> str:
    cls = {
        Disposition.ALERT: "badge-alert",
        Disposition.REVIEW: "badge-review",
        Disposition.DISMISS: "badge-dismiss",
    }[disposition]
    return f'<span class="badge {cls}">{disposition.value}</span>'


def score_bar(score: float) -> str:
    color = score_color(score)
    pct = int(score * 100)
    return (
        f'<div class="score-bar-bg">'
        f'<div class="score-bar-fill" style="width:{pct}%;background:{color};"></div>'
        f'</div>'
    )


def render_session(session: Session, key_prefix: str) -> None:
    # Expander labels are plain text only (Streamlit escapes HTML)
    header = (
        f"{session.disposition.value.upper()}  ·  {session.score:.2f}  ·  "
        f"{session.session_id}  ·  {session.src_ip}  ·  "
        f"{len(session.events)} events  ·  {session.duration_seconds:.0f}s"
    )

    with st.expander(header, expanded=(session.disposition == Disposition.ALERT)):
        # Badge + score bar inside the body (HTML is allowed here)
        st.markdown(
            f"{badge_html(session.disposition)}&nbsp;&nbsp;"
            f"<span style='color:#f1f5f9;font-weight:600;font-size:1.05rem'>{session.score:.2f}</span>",
            unsafe_allow_html=True,
        )
        st.markdown(score_bar(session.score), unsafe_allow_html=True)

        left, right = st.columns([5, 3], gap="large")

        with left:
            st.markdown('<div class="section-label">Why this score</div>', unsafe_allow_html=True)
            if session.reasons:
                for r in session.reasons:
                    st.markdown(f'<div class="reason-item">{r}</div>', unsafe_allow_html=True)
            else:
                st.caption("No detector findings.")

            if session.commands:
                st.markdown('<br><div class="section-label">Commands</div>', unsafe_allow_html=True)
                # Show as a compact code block
                shown = session.commands[:10]
                block = "\n".join(shown)
                st.code(block, language="bash")
                if len(session.commands) > 10:
                    st.caption(f"+{len(session.commands) - 10} more commands")

        with right:
            st.markdown('<div class="section-label">Session</div>', unsafe_allow_html=True)
            facts = [
                ("Source IP", session.src_ip),
                ("Login", "success" if session.successful_login else "failed only"),
                ("Failed attempts", str(session.failed_login_count)),
                ("Usernames", ", ".join(session.usernames) or "—"),
                ("Downloads", ", ".join(session.download_urls) or "—"),
                ("Duration", f"{session.duration_seconds:.0f}s"),
            ]
            for label, val in facts:
                st.markdown(
                    f"<span style='color:#64748b;font-size:0.78rem'>{label}</span><br>"
                    f"<span style='color:#e2e8f0;font-size:0.9rem'>{val}</span>",
                    unsafe_allow_html=True,
                )
                st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)

            if session.findings:
                st.markdown('<div class="section-label" style="margin-top:8px">Detectors</div>', unsafe_allow_html=True)
                chips = " ".join(
                    f'<span class="finding-chip">{f.detector} · {f.severity:.2f}</span>'
                    for f in sorted(session.findings, key=lambda x: x.severity, reverse=True)
                )
                st.markdown(chips, unsafe_allow_html=True)

        # Human-in-the-loop controls
        if session.disposition == Disposition.REVIEW:
            st.markdown("---")
            st.caption("Human review required — mid-confidence session")
            b1, b2, _ = st.columns([1, 1, 3])
            with b1:
                if st.button("Promote to alert", key=f"{key_prefix}-a-{session.session_id}", use_container_width=True):
                    st.toast(f"{session.session_id} → alert", icon="⚠")
            with b2:
                if st.button("Dismiss", key=f"{key_prefix}-d-{session.session_id}", use_container_width=True):
                    st.toast(f"{session.session_id} dismissed", icon="✓")


def apply_filters(sessions: list[Session], min_score: float, show_dismissed: bool) -> list[Session]:
    out = [s for s in sessions if s.score >= min_score]
    if not show_dismissed:
        out = [s for s in out if s.disposition != Disposition.DISMISS]
    return out


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### Detection pipeline")
    st.caption("Cowrie sensor → session scoring → triage")
    st.markdown("---")

    uploaded = st.file_uploader("Cowrie JSON log", type=["json", "log", "txt"])
    use_sample = st.checkbox("Built-in sample", value=(uploaded is None))

    st.markdown("---")
    min_score = st.slider("Minimum score", 0.0, 1.0, 0.0, 0.05)
    show_dismissed = st.checkbox("Show dismissed", value=False)

    st.markdown("---")
    st.markdown(
        "<span style='color:#64748b;font-size:0.78rem'>"
        "Explainable noisy-OR scoring<br>"
        "Human-in-the-loop review queue<br>"
        "Pure Python · no external ML"
        "</span>",
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------------
@st.cache_data(show_spinner=False)
def load_and_score(source: str) -> list:
    return score_sessions(load_sessions(source))


if uploaded is not None:
    tmp = Path("/tmp/uploaded_cowrie.json")
    tmp.write_bytes(uploaded.getvalue())
    scored = load_and_score(str(tmp))
elif use_sample and DEFAULT_LOG.exists():
    scored = load_and_score(str(DEFAULT_LOG))
else:
    st.info("Upload a Cowrie JSON log or enable the built-in sample.")
    st.stop()

buckets = bucket_sessions(scored)

# ---------------------------------------------------------------------------
# Header + metrics
# ---------------------------------------------------------------------------
st.markdown("## Session triage")
st.caption("Scored attacker sessions from the honeypot · dismiss / review / alert")

m1, m2, m3, m4 = st.columns(4)
m1.metric("Sessions", len(scored))
m2.metric("Alert", len(buckets["alert"]))
m3.metric("Review", len(buckets["review"]))
m4.metric("Dismissed", len(buckets["dismiss"]))

st.markdown("")

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------
tab_alert, tab_review, tab_all = st.tabs(["Alert", "Review queue", "All sessions"])

with tab_alert:
    items = apply_filters(buckets["alert"], min_score, show_dismissed)
    if not items:
        st.caption("No alert-level sessions.")
    for s in items:
        render_session(s, "alert")

with tab_review:
    items = apply_filters(buckets["review"], min_score, show_dismissed)
    if not items:
        st.caption("Review queue is empty.")
    else:
        st.caption("Mid-confidence sessions held for human decision.")
    for s in items:
        render_session(s, "review")

with tab_all:
    items = apply_filters(scored, min_score, show_dismissed)
    for s in items:
        render_session(s, "all")
