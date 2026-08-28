#!/usr/bin/env python3
"""
CLI for the Cowrie honeypot detection pipeline.

Examples:
  python src/pipeline.py --logfile samples/cowrie.json
  python src/pipeline.py --logfile samples/cowrie.json --review
  python src/pipeline.py --logfile samples/cowrie.json --json findings.json
  python src/pipeline.py --logfile /path/to/cowrie.json --min-score 0.3
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running as `python src/pipeline.py` without installing a package
sys.path.insert(0, str(Path(__file__).resolve().parent))

from models import Disposition, Session
from parsers import load_sessions
from scoring import score_sessions, bucket_sessions


def print_session_summary(session: Session, verbose: bool = False) -> None:
    flag = {
        Disposition.ALERT:  "ALERT ",
        Disposition.REVIEW: "REVIEW",
        Disposition.DISMISS: "dismiss",
    }[session.disposition]

    print(f"[{flag}] score={session.score:.2f}  session={session.session_id}  src={session.src_ip}")
    print(f"         events={len(session.events)}  duration={session.duration_seconds:.0f}s  "
          f"login_ok={session.successful_login}  fails={session.failed_login_count}")

    if session.reasons:
        print(f"         reason: {session.reasons[0]}")
        if verbose:
            for r in session.reasons[1:]:
                print(f"                 {r}")

    if verbose and session.commands:
        print(f"         commands: {session.commands[:6]}")
        if len(session.commands) > 6:
            print(f"                   ... +{len(session.commands)-6} more")
    print()


def interactive_review(review_sessions: list[Session]) -> None:
    """Simple terminal human-in-the-loop review for the mid-confidence bucket."""
    if not review_sessions:
        print("No sessions in the review bucket.")
        return

    print(f"\n=== Human Review Queue ({len(review_sessions)} session(s)) ===\n")

    for i, session in enumerate(review_sessions, 1):
        print(f"--- Item {i}/{len(review_sessions)} ---")
        print_session_summary(session, verbose=True)

        while True:
            choice = input("Action? [a]lert  [d]ismiss  [s]kip  [q]uit > ").strip().lower()
            if choice in ("a", "alert"):
                session.disposition = Disposition.ALERT
                print("  → promoted to ALERT\n")
                break
            if choice in ("d", "dismiss"):
                session.disposition = Disposition.DISMISS
                print("  → dismissed\n")
                break
            if choice in ("s", "skip", ""):
                print("  → left in review\n")
                break
            if choice in ("q", "quit"):
                print("Exiting review.")
                return
            print("  Please enter a, d, s, or q.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Cowrie honeypot session analysis — explainable scoring + human triage"
    )
    parser.add_argument(
        "--logfile", "-l",
        required=True,
        help="Path to Cowrie JSON log (one event per line)",
    )
    parser.add_argument(
        "--json", "-j",
        metavar="FILE",
        help="Write machine-readable findings to FILE",
    )
    parser.add_argument(
        "--review", "-r",
        action="store_true",
        help="Interactive human review of the mid-confidence bucket",
    )
    parser.add_argument(
        "--min-score",
        type=float,
        default=0.0,
        help="Only show sessions with score >= this value (default: 0)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show full reasons and command previews",
    )
    args = parser.parse_args()

    path = Path(args.logfile)
    if not path.exists():
        print(f"Error: log file not found: {path}", file=sys.stderr)
        return 1

    print(f"Loading sessions from {path} ...")
    sessions = load_sessions(path)
    print(f"  {len(sessions)} session(s) loaded\n")

    scored = score_sessions(sessions)
    buckets = bucket_sessions(scored)

    # Summary counts
    print("=== Summary ===")
    print(f"  ALERT : {len(buckets['alert'])}")
    print(f"  REVIEW: {len(buckets['review'])}")
    print(f"  dismiss: {len(buckets['dismiss'])}")
    print()

    # Show alert + review (and anything above min-score)
    to_show = [
        s for s in scored
        if s.score >= args.min_score and s.disposition != Disposition.DISMISS
    ]
    if not to_show and args.min_score > 0:
        to_show = [s for s in scored if s.score >= args.min_score]

    for session in to_show:
        print_session_summary(session, verbose=args.verbose)

    if args.review:
        interactive_review(buckets["review"])

    if args.json:
        out = {
            "summary": {
                "total_sessions": len(scored),
                "alert": len(buckets["alert"]),
                "review": len(buckets["review"]),
                "dismiss": len(buckets["dismiss"]),
            },
            "sessions": [s.to_dict() for s in scored if s.score >= args.min_score],
        }
        Path(args.json).write_text(json.dumps(out, indent=2))
        print(f"Wrote findings to {args.json}")

    # Non-zero exit if unresolved alerts remain (useful for CI / cron)
    unresolved_alerts = [
        s for s in scored
        if s.disposition == Disposition.ALERT
    ]
    return 1 if unresolved_alerts else 0


if __name__ == "__main__":
    sys.exit(main())
