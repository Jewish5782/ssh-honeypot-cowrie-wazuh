"""
Explainable scoring for honeypot sessions.

Uses the same noisy-OR combination as the log-anomaly pipeline so that:
- multiple weak signals can raise confidence
- scores stay in [0, 1] and saturate naturally
- every final disposition is transparent

Buckets:
  < 0.30  → dismiss
  0.30–0.89 → review   (human-in-the-loop)
  ≥ 0.90  → alert
"""

from __future__ import annotations

from models import Disposition, Finding, Session
from detectors import run_all


# Thresholds (easy to tune)
# Raised ALERT_AT so that pure recon / pure brute-force land in REVIEW
# while full attack chains (staging + reverse shell) stay ALERT.
DISMISS_BELOW = 0.30
ALERT_AT     = 0.90


def noisy_or(severities: list[float]) -> float:
    """
    Noisy-OR: 1 - Π(1 - s_i)
    Independent evidence combines without double-counting extremes.
    """
    if not severities:
        return 0.0
    product = 1.0
    for s in severities:
        s = max(0.0, min(1.0, s))
        product *= (1.0 - s)
    return 1.0 - product


def score_session(session: Session) -> Session:
    """
    Run detectors, combine with noisy-OR, set disposition and reasons.
    Mutates and returns the same Session object for convenience.
    """
    findings = run_all(session)
    session.findings = findings

    severities = [f.severity for f in findings]
    session.score = noisy_or(severities)

    # Collect unique plain-English reasons (highest severity first)
    ordered = sorted(findings, key=lambda f: f.severity, reverse=True)
    session.reasons = [f.reason for f in ordered]

    if session.score >= ALERT_AT:
        session.disposition = Disposition.ALERT
    elif session.score >= DISMISS_BELOW:
        session.disposition = Disposition.REVIEW
    else:
        session.disposition = Disposition.DISMISS

    return session


def score_sessions(sessions: list[Session]) -> list[Session]:
    """Score a list of sessions and return them sorted by score (desc)."""
    scored = [score_session(s) for s in sessions]
    scored.sort(key=lambda s: s.score, reverse=True)
    return scored


def bucket_sessions(sessions: list[Session]) -> dict[str, list[Session]]:
    """Partition already-scored sessions into the three triage buckets."""
    buckets = {
        Disposition.ALERT.value: [],
        Disposition.REVIEW.value: [],
        Disposition.DISMISS.value: [],
    }
    for s in sessions:
        buckets[s.disposition.value].append(s)
    return buckets
