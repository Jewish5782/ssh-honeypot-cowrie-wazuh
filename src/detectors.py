"""
Independent detectors that each produce zero or more Findings for a Session.

Every detector returns Findings with:
- a severity in [0.0, 1.0]
- a clear, plain-English reason
- optional structured evidence

The scorer later combines them with noisy-OR.
"""

from __future__ import annotations

import re
from typing import Callable

from models import Finding, Session


# ---------------------------------------------------------------------------
# Individual detectors
# ---------------------------------------------------------------------------

def detect_brute_force(session: Session) -> list[Finding]:
    """Many failed logins in a short window → credential attack."""
    fails = [e for e in session.events if e.eventid == "cowrie.login.failed"]
    if len(fails) < 5:
        return []

    # Simple density check: if ≥5 fails and session is short, raise severity
    duration = max(session.duration_seconds, 1.0)
    rate = len(fails) / duration  # fails per second

    if len(fails) >= 8 and duration <= 60:
        severity = 0.85
        reason = (
            f"Brute-force pattern: {len(fails)} failed logins from {session.src_ip} "
            f"in {duration:.0f}s"
        )
    elif len(fails) >= 5:
        severity = 0.55
        reason = (
            f"Multiple failed logins ({len(fails)}) from {session.src_ip} "
            f"— possible password spraying or brute-force"
        )
    else:
        return []

    return [Finding(
        detector="brute_force",
        severity=severity,
        reason=reason,
        evidence={
            "failed_count": len(fails),
            "duration_seconds": round(duration, 1),
            "usernames_tried": session.usernames,
        },
    )]


def detect_successful_login(session: Session) -> list[Finding]:
    """Any successful login into a honeypot is inherently interesting."""
    if not session.successful_login:
        return []

    successes = [e for e in session.events if e.eventid == "cowrie.login.success"]
    users = [e.username for e in successes if e.username]

    return [Finding(
        detector="successful_login",
        severity=0.50,
        reason=(
            f"Successful login into honeypot from {session.src_ip} "
            f"as {', '.join(users) or 'unknown'} — attacker is inside the decoy"
        ),
        evidence={"usernames": users},
    )]


def detect_recon_commands(session: Session) -> list[Finding]:
    """Classic post-exploitation / recon commands after login."""
    if not session.successful_login:
        return []

    RECON_PATTERNS = [
        (r"\buname\b", "uname"),
        (r"\bid\b", "id"),
        (r"\bwhoami\b", "whoami"),
        (r"\bcat\s+/etc/passwd\b", "cat /etc/passwd"),
        (r"\bcat\s+/etc/shadow\b", "cat /etc/shadow"),
        (r"\bps\s+aux\b", "ps aux"),
        (r"\bnetstat\b", "netstat"),
        (r"\bip\s+a\b", "ip a"),
        (r"\bifconfig\b", "ifconfig"),
        (r"\bhistory\b", "history"),
        (r"\bls\s+-la\s+/home\b", "ls -la /home"),
    ]

    matched = []
    for cmd in session.commands:
        for pat, label in RECON_PATTERNS:
            if re.search(pat, cmd, re.IGNORECASE):
                matched.append(label)

    if not matched:
        return []

    unique = sorted(set(matched))
    severity = min(0.35 + 0.07 * len(unique), 0.70)

    return [Finding(
        detector="recon_commands",
        severity=severity,
        reason=(
            f"Post-login reconnaissance from {session.src_ip}: "
            f"{', '.join(unique)}"
        ),
        evidence={"commands": unique},
    )]


def detect_download_and_stage(session: Session) -> list[Finding]:
    """
    File download (wget/curl) especially when followed by chmod / execution.
    Classic malware staging pattern.
    """
    downloads = session.download_urls
    commands = " ".join(session.commands).lower()

    has_download_cmd = any(
        re.search(r"\b(wget|curl|fetch|tftp)\b", cmd, re.I)
        for cmd in session.commands
    )
    has_chmod = bool(re.search(r"\bchmod\s+[+0-7]*x", commands))
    has_exec = bool(re.search(r"(/tmp/|\./|bash\s+|sh\s+)", commands))

    if not (downloads or has_download_cmd):
        return []

    severity = 0.60
    parts = []

    if downloads:
        parts.append(f"downloaded {len(downloads)} file(s)")
        severity += 0.15
    if has_download_cmd:
        parts.append("used wget/curl")
    if has_chmod:
        parts.append("made file executable (chmod)")
        severity += 0.15
    if has_exec and (downloads or has_download_cmd):
        parts.append("attempted execution")
        severity += 0.10

    severity = min(severity, 0.95)

    return [Finding(
        detector="download_stage",
        severity=severity,
        reason=(
            f"Malware staging indicators from {session.src_ip}: "
            + "; ".join(parts)
        ),
        evidence={
            "urls": downloads,
            "has_chmod": has_chmod,
            "has_execution_hint": has_exec,
        },
    )]


def detect_suspicious_commands(session: Session) -> list[Finding]:
    """High-signal destructive or reverse-shell style commands."""
    SUSPICIOUS = [
        (r"\bncmap\b|\bnmap\b", "port scanning tools"),
        (r"\bnc\s+-[lep]|ncat\s+|netcat\b", "netcat / reverse shell tools"),
        (r"\bpython\s+-c\s+.*socket|/dev/tcp/", "reverse shell via python or /dev/tcp"),
        (r"\bbase64\s+-d\b|\bxxd\b", "encoded payload decoding"),
        (r"\bcrontab\b|\becho\s+.*\s+>>\s+/etc/", "persistence attempt"),
        (r"\brm\s+-rf\s+/", "destructive rm -rf"),
        (r"\bminer|xmrig|cryptonight\b", "cryptominer indicators"),
        (r"\bcurl\s+.*\|\s*sh\b|\bwget\s+.*\|\s*bash\b", "pipe-to-shell download"),
    ]

    matched = []
    for cmd in session.commands:
        for pat, label in SUSPICIOUS:
            if re.search(pat, cmd, re.IGNORECASE):
                matched.append(label)

    if not matched:
        return []

    unique = sorted(set(matched))
    severity = min(0.65 + 0.1 * len(unique), 0.95)

    return [Finding(
        detector="suspicious_commands",
        severity=severity,
        reason=(
            f"High-risk commands observed from {session.src_ip}: "
            f"{', '.join(unique)}"
        ),
        evidence={"indicators": unique},
    )]


def detect_long_interactive_session(session: Session) -> list[Finding]:
    """
    Attackers who stay and explore are more interesting than hit-and-run scanners.
    """
    if not session.successful_login:
        return []

    cmd_count = len(session.commands)
    duration = session.duration_seconds

    if cmd_count >= 8 or duration >= 180:
        severity = 0.40
        reason = (
            f"Interactive session from {session.src_ip}: "
            f"{cmd_count} commands over {duration:.0f}s — operator appears engaged"
        )
        return [Finding(
            detector="interactive_session",
            severity=severity,
            reason=reason,
            evidence={"command_count": cmd_count, "duration_seconds": round(duration, 1)},
        )]
    return []


# ---------------------------------------------------------------------------
# Registry – easy to extend
# ---------------------------------------------------------------------------

DETECTORS: list[Callable[[Session], list[Finding]]] = [
    detect_brute_force,
    detect_successful_login,
    detect_recon_commands,
    detect_download_and_stage,
    detect_suspicious_commands,
    detect_long_interactive_session,
]


def run_all(session: Session) -> list[Finding]:
    """Run every detector and return the combined list of Findings."""
    findings: list[Finding] = []
    for det in DETECTORS:
        findings.extend(det(session))
    return findings
