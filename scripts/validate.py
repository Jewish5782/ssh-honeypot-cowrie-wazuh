#!/usr/bin/env python3
"""Offline validator for the Cowrie/Wazuh lab.

Docker isn't always available (and the Wazuh indexer is heavy), so this script
checks the parts that can be verified without booting the stack:

  1. docker-compose.yml is valid YAML with the expected services
  2. the decoder and rule XML files are well-formed
  3. every sample Cowrie event matches at least one custom rule

Run:  python3 scripts/validate.py
"""
from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FAIL = []


def ok(msg):
    print(f"  [OK]   {msg}")


def bad(msg):
    print(f"  [FAIL] {msg}")
    FAIL.append(msg)


def check_compose():
    print("Checking docker-compose.yml...")
    path = ROOT / "docker-compose.yml"
    try:
        import yaml  # optional
        data = yaml.safe_load(path.read_text())
        services = set(data.get("services", {}))
    except ImportError:
        # fall back to a light structural check
        text = path.read_text()
        services = set(re.findall(r"^  ([a-z][\w.]*):$", text, re.M))
        print("  (PyYAML not installed — using structural check)")
    expected = {"cowrie", "wazuh.manager", "wazuh.indexer", "wazuh.dashboard"}
    missing = expected - services
    if missing:
        bad(f"compose missing services: {sorted(missing)}")
    else:
        ok(f"all 4 services present: {sorted(expected)}")


def check_xml():
    print("Checking Wazuh decoder/rule XML...")
    for rel in ("wazuh/decoders/cowrie_decoders.xml", "wazuh/rules/cowrie_rules.xml"):
        p = ROOT / rel
        try:
            # Wazuh XML files have multiple roots by design; wrap them.
            ET.fromstring(f"<root>{p.read_text()}</root>")
            ok(f"{rel} is well-formed")
        except ET.ParseError as exc:
            bad(f"{rel} parse error: {exc}")


def load_rules():
    """Extract (id, level, eventid-regex) from the custom ruleset."""
    p = ROOT / "wazuh/rules/cowrie_rules.xml"
    tree = ET.fromstring(f"<root>{p.read_text()}</root>")
    rules = []
    for rule in tree.iter("rule"):
        ev = None
        for f in rule.findall("field"):
            if f.get("name") == "eventid":
                ev = f.text
        rules.append((rule.get("id"), int(rule.get("level", 0)), ev))
    return rules


def check_sample_coverage():
    print("Checking sample events match custom rules...")
    rules = load_rules()
    sample = ROOT / "samples/cowrie.json"
    events = [json.loads(l) for l in sample.read_text().splitlines() if l.strip()]
    for ev in events:
        eid = ev["eventid"]
        hits = [
            (rid, lvl) for rid, lvl, pat in rules
            if pat and pat not in (r"\.+",) and re.match(pat, eid)
        ]
        if hits:
            rid, lvl = hits[0]
            ok(f"{eid:34s} -> rule {rid} (level {lvl})")
        else:
            bad(f"{eid} matched no custom rule")


def main():
    check_compose()
    check_xml()
    check_sample_coverage()
    print()
    if FAIL:
        print(f"FAILED: {len(FAIL)} problem(s)")
        return 1
    print("All offline checks passed. Boot the stack with: docker compose up -d")
    return 0


if __name__ == "__main__":
    sys.exit(main())
