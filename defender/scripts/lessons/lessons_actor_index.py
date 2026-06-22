#!/usr/bin/env python3
"""List actor lessons by relevance_criteria.

Cheap discovery primitive for the actor stage: prints one
`<path>\\t<relevance_criteria>` line per lesson that passes the filters,
so the actor scans descriptions before deciding which files to Read.

v2 (schema-v2): one flat corpus at ``defender/lessons-actor/*.md``.
No channel split. Filters compose AND across keys, OR within a key.

Usage:
    lessons_actor_index.py                                # whole corpus (live only)
    lessons_actor_index.py --techniques T1078.004,T1550.001
    lessons_actor_index.py --alert-rule-ids 5712,5710
    lessons_actor_index.py --defender-lead-tags wazuh.auth-events-by-srcip
    lessons_actor_index.py --subject wazuh-rule-5712-threshold
    lessons_actor_index.py --include-stale                # author-only

Lessons missing a filtered field are skipped silently. Lessons with
``status: stale`` (only meaningful when ``mutable: true``) are hidden
by default; ``--include-stale`` surfaces them. The runtime actor must
never see stale claims.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Re-exec into defender/.venv so PyYAML resolves regardless of which
# python the caller invoked us with (the actor's Bash tool uses the
# system ``python3`` on PATH; the defender's venv carries pyyaml).
_VENV_PY = Path(__file__).resolve().parents[3] / "defender" / ".venv" / "bin" / "python3"
# Gated on __main__ so importing this module as a library never os.execv's away.
if __name__ == "__main__" and _VENV_PY.is_file() and Path(sys.executable) != _VENV_PY:
    os.execv(str(_VENV_PY), [str(_VENV_PY), __file__, *sys.argv[1:]])

# Put the workspace root on sys.path so the `defender.*` namespace import below
# resolves whether this file is imported or run directly (after the venv re-exec
# above, sys.path[0] is this script's dir, not the workspace root).
if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

import argparse

from defender._frontmatter import parse_frontmatter_or_none


REPO_ROOT = Path(__file__).resolve().parents[3]
LESSONS_ROOT = REPO_ROOT / "defender" / "lessons-actor"


def _as_list(v) -> list:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def _as_str_set(v) -> set[str]:
    return {str(x) for x in _as_list(v)}


def iter_lessons():
    if not LESSONS_ROOT.is_dir():
        return
    for path in sorted(LESSONS_ROOT.glob("*.md")):
        if path.name.startswith("_"):
            continue
        fm = parse_frontmatter_or_none(path.read_text())
        if fm is None:
            print(f"warn: skipping {path.relative_to(REPO_ROOT)} (malformed frontmatter)", file=sys.stderr)
            continue
        yield path, fm


def _csv_set(value: str | None) -> set[str]:
    if not value:
        return set()
    return {t.strip() for t in value.split(",") if t.strip()}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--techniques", help="Comma-separated MITRE T-IDs; OR within the list")
    ap.add_argument("--alert-rule-ids", help="Comma-separated SIEM rule IDs; OR within the list")
    ap.add_argument("--defender-lead-tags", help="Comma-separated lead-template tags ({system}.{kebab-name}); OR within the list")
    ap.add_argument("--subject", help="Exact subject match (single value — subject is the equivalence key)")
    ap.add_argument("--include-stale", action="store_true", help="Include lessons with status: stale (author-only)")
    ns = ap.parse_args(argv[1:])

    want_techniques = _csv_set(ns.techniques)
    want_rule_ids = _csv_set(ns.alert_rule_ids)
    want_lead_tags = _csv_set(ns.defender_lead_tags)
    want_subject = ns.subject.strip() if ns.subject else None

    for path, fm in iter_lessons():
        # Stale filter (default hide; mutable=false lessons never have
        # status=stale, so they pass through unconditionally).
        if not ns.include_stale and str(fm.get("status") or "live").strip() == "stale":
            continue

        # Subject is the equivalence key — exact match only when filter set.
        if want_subject is not None and str(fm.get("subject") or "").strip() != want_subject:
            continue

        # Multi-key filters: AND across, OR within.
        if want_techniques and _as_str_set(fm.get("techniques")).isdisjoint(want_techniques):
            continue
        if want_rule_ids and _as_str_set(fm.get("alert_rule_ids")).isdisjoint(want_rule_ids):
            continue
        if want_lead_tags and _as_str_set(fm.get("defender_lead_tags")).isdisjoint(want_lead_tags):
            continue

        criteria = fm.get("relevance_criteria") or ""
        criteria = str(criteria).strip().replace("\t", " ").replace("\n", " ")
        rel = path.relative_to(REPO_ROOT)
        print(f"{rel}\t{criteria}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
