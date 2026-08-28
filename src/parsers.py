"""
Parse Cowrie JSON logs into Event and Session objects.

Supports:
- Offline sample files (samples/cowrie.json)
- Live Cowrie output (one JSON object per line)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, TextIO, Union

from models import Event, Session


def _parse_timestamp(value: str | float | int | None) -> datetime:
    """Best-effort timestamp parser for Cowrie's various formats."""
    if value is None:
        return datetime.now(timezone.utc)

    if isinstance(value, (int, float)):
        # epoch seconds (Cowrie can emit this when epoch_timestamp = true)
        return datetime.fromtimestamp(value, tz=timezone.utc)

    text = str(value).strip()
    # Common ISO formats Cowrie emits
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(text.replace("+00:00", "Z"), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue

    # Last resort
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc)


def parse_event(raw: dict) -> Event:
    """Turn one Cowrie JSON object into a normalized Event."""
    return Event(
        eventid=raw.get("eventid") or raw.get("event_id") or "unknown",
        timestamp=_parse_timestamp(raw.get("timestamp") or raw.get("time")),
        session_id=str(raw.get("session") or raw.get("session_id") or "unknown"),
        src_ip=str(raw.get("src_ip") or raw.get("srcIP") or "0.0.0.0"),
        src_port=_as_int(raw.get("src_port") or raw.get("srcPort")),
        dst_port=_as_int(raw.get("dst_port") or raw.get("dstPort")),
        username=raw.get("username"),
        password=raw.get("password"),
        input=raw.get("input") or raw.get("command"),
        url=raw.get("url"),
        message=raw.get("message"),
        raw=raw,
    )


def _as_int(value) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def iter_events(source: Union[str, Path, TextIO, Iterable[str]]) -> Iterator[Event]:
    """
    Yield Events from:
    - a file path
    - an open file-like object
    - an iterable of JSON lines
    """
    if isinstance(source, (str, Path)):
        path = Path(source)
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            yield from _iter_lines(fh)
    elif hasattr(source, "read"):
        yield from _iter_lines(source)  # type: ignore[arg-type]
    else:
        yield from _iter_lines(source)  # type: ignore[arg-type]


def _iter_lines(lines: Iterable[str]) -> Iterator[Event]:
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(raw, dict):
            continue
        yield parse_event(raw)


def build_sessions(events: Iterable[Event]) -> list[Session]:
    """
    Group events by session_id and return ordered Session objects.
    Sessions are sorted by start_time.
    """
    sessions: dict[str, Session] = {}

    for event in events:
        sid = event.session_id
        if sid not in sessions:
            sessions[sid] = Session(session_id=sid, src_ip=event.src_ip)
        sessions[sid].add_event(event)

    # Ensure events inside each session are time-ordered
    for sess in sessions.values():
        sess.events.sort(key=lambda e: e.timestamp)

    result = list(sessions.values())
    result.sort(key=lambda s: s.start_time or datetime.min.replace(tzinfo=timezone.utc))
    return result


def load_sessions(path: Union[str, Path]) -> list[Session]:
    """Convenience: load a Cowrie JSON log file and return Sessions."""
    return build_sessions(iter_events(path))
