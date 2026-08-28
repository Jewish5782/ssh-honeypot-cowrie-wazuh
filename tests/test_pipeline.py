#!/usr/bin/env python3
"""Unit tests for the Cowrie honeypot detection pipeline."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from models import Disposition
from parsers import load_sessions, parse_event, build_sessions
from detectors import run_all
from scoring import score_session, score_sessions, noisy_or


SAMPLE = ROOT / "samples" / "cowrie.json"


class TestParsers(unittest.TestCase):
    def test_load_sessions(self):
        sessions = load_sessions(SAMPLE)
        self.assertGreaterEqual(len(sessions), 4)
        ids = {s.session_id for s in sessions}
        self.assertIn("a1", ids)
        self.assertIn("b2", ids)

    def test_session_a1_has_success_and_download(self):
        sessions = {s.session_id: s for s in load_sessions(SAMPLE)}
        a1 = sessions["a1"]
        self.assertTrue(a1.successful_login)
        self.assertGreater(a1.failed_login_count, 0)
        self.assertTrue(a1.download_urls)


class TestScoring(unittest.TestCase):
    def test_noisy_or_empty(self):
        self.assertEqual(noisy_or([]), 0.0)

    def test_noisy_or_single(self):
        self.assertAlmostEqual(noisy_or([0.7]), 0.7)

    def test_noisy_or_combines(self):
        # two independent 0.5 signals → 0.75
        self.assertAlmostEqual(noisy_or([0.5, 0.5]), 0.75)

    def test_full_attack_is_alert(self):
        sessions = {s.session_id: s for s in score_sessions(load_sessions(SAMPLE))}
        self.assertEqual(sessions["a1"].disposition, Disposition.ALERT)
        self.assertGreaterEqual(sessions["a1"].score, 0.90)

    def test_brute_force_high(self):
        sessions = {s.session_id: s for s in score_sessions(load_sessions(SAMPLE))}
        self.assertGreaterEqual(sessions["b2"].score, 0.7)

    def test_noisy_scanner_dismissed(self):
        sessions = {s.session_id: s for s in score_sessions(load_sessions(SAMPLE))}
        if "d4" in sessions:
            self.assertEqual(sessions["d4"].disposition, Disposition.DISMISS)


class TestDetectors(unittest.TestCase):
    def test_every_finding_has_reason(self):
        for session in load_sessions(SAMPLE):
            for f in run_all(session):
                self.assertTrue(f.reason, msg=f"Finding from {f.detector} has empty reason")
                self.assertGreaterEqual(f.severity, 0.0)
                self.assertLessEqual(f.severity, 1.0)


if __name__ == "__main__":
    unittest.main()
