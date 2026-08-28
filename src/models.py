"""
Core data model for the Cowrie honeypot detection pipeline.

Design principles (mirrors the log-anomaly pipeline):
- Plain dataclasses, no external dependencies
- Every Finding carries a human-readable reason
- Sessions are the primary unit of analysis (not isolated events)
- Scores are explainable and combinable via noisy-OR
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class Disposition(str, Enum):
    """Final triage bucket for a scored session / finding."""
    DISMISS = "dismiss"   # low confidence / noise
    REVIEW  = "review"    # mid-confidence → human-in-the-loop
    ALERT   = "alert"     # high confidence → surface immediately


@dataclass(frozen=True)
class Event:
    """A single Cowrie JSON event, normalized."""
    eventid: str
    timestamp: datetime
    session_id: str
    src_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    input: Optional[str] = None          # command input
    url: Optional[str] = None            # file download URL
    message: Optional[str] = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        d.pop("raw", None)
        return d


@dataclass
class Session:
    """
    All events belonging to one Cowrie session_id, ordered by time.
    This is the primary unit we score and triage.
    """
    session_id: str
    src_ip: str
    events: list[Event] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    # Populated by detectors / scoring
    findings: list["Finding"] = field(default_factory=list)
    score: float = 0.0
    disposition: Disposition = Disposition.DISMISS
    reasons: list[str] = field(default_factory=list)

    def add_event(self, event: Event) -> None:
        self.events.append(event)
        if self.start_time is None or event.timestamp < self.start_time:
            self.start_time = event.timestamp
        if self.end_time is None or event.timestamp > self.end_time:
            self.end_time = event.timestamp

    @property
    def duration_seconds(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    @property
    def usernames(self) -> list[str]:
        return list({e.username for e in self.events if e.username})

    @property
    def passwords(self) -> list[str]:
        return list({e.password for e in self.events if e.password})

    @property
    def commands(self) -> list[str]:
        return [e.input for e in self.events if e.input]

    @property
    def successful_login(self) -> bool:
        return any(e.eventid == "cowrie.login.success" for e in self.events)

    @property
    def failed_login_count(self) -> int:
        return sum(1 for e in self.events if e.eventid == "cowrie.login.failed")

    @property
    def download_urls(self) -> list[str]:
        return [e.url for e in self.events if e.url]

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "src_ip": self.src_ip,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds,
            "event_count": len(self.events),
            "successful_login": self.successful_login,
            "failed_login_count": self.failed_login_count,
            "usernames": self.usernames,
            "commands": self.commands,
            "download_urls": self.download_urls,
            "score": round(self.score, 4),
            "disposition": self.disposition.value,
            "reasons": self.reasons,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass(frozen=True)
class Finding:
    """
    One detector's contribution to a session's risk.
    Always carries a plain-English reason — explainability is non-negotiable.
    """
    detector: str
    severity: float          # 0.0 – 1.0
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "severity": round(self.severity, 4),
            "reason": self.reason,
            "evidence": self.evidence,
        }
