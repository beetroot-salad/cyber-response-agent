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
    lessons_actor_index.py --defender-lead-tags {system}.auth-events-by-srcip
    lessons_actor_index.py --subject <subject-slug>
    lessons_actor_index.py --applies-to <env-fact-subject,...>
    lessons_actor_index.py --include-stale                # author-only

Lessons missing a filtered field are skipped silently. Lessons with
``status: stale`` (only meaningful when ``mutable: true``) are hidden
by default; ``--include-stale`` surfaces them. The runtime actor must
never see stale claims.
"""
from __future__ import annotations

import sys
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender._tsv import flatten_cell
from defender.scripts.lessons._lessons_common import (
    as_str_set,
    csv_set,
    iter_lessons,
    reexec_into_venv,
    rel_to_repo,
    use_utf8_stdio,
)

if __name__ == "__main__":
    reexec_into_venv(__file__)

import argparse


REPO_ROOT = Path(__file__).resolve().parents[3]
LESSONS_ROOT = REPO_ROOT / "defender" / "lessons-actor"


def main(argv: list[str]) -> int:
    use_utf8_stdio()
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--techniques", help="Comma-separated MITRE T-IDs; OR within the list")
    ap.add_argument("--alert-rule-ids", help="Comma-separated SIEM rule IDs; OR within the list")
    ap.add_argument("--defender-lead-tags", help="Comma-separated lead-template tags ({system}.{kebab-name}); OR within the list")
    ap.add_argument("--subject", help="Exact subject match (single value — subject is the equivalence key)")
    ap.add_argument("--applies-to", help="Comma-separated env-fact subjects; match pattern lessons whose applies_to lists any of them (OR within the list)")
    ap.add_argument("--include-stale", action="store_true", help="Include lessons with status: stale (author-only)")
    ns = ap.parse_args(argv[1:])

    want_techniques = csv_set(ns.techniques)
    want_rule_ids = csv_set(ns.alert_rule_ids)
    want_lead_tags = csv_set(ns.defender_lead_tags)
    want_applies_to = csv_set(ns.applies_to)
    want_subject = ns.subject.strip() if ns.subject else None

    for lesson in iter_lessons(LESSONS_ROOT, warn_label=lambda p: rel_to_repo(p, REPO_ROOT)):
        path, fm = lesson.path, lesson.fm
        if not ns.include_stale and str(fm.get("status") or "live").strip() == "stale":
            continue

        if want_subject is not None and str(fm.get("subject") or "").strip() != want_subject:
            continue

        if want_techniques and as_str_set(fm.get("techniques")).isdisjoint(want_techniques):
            continue
        if want_rule_ids and as_str_set(fm.get("alert_rule_ids")).isdisjoint(want_rule_ids):
            continue
        if want_lead_tags and as_str_set(fm.get("defender_lead_tags")).isdisjoint(want_lead_tags):
            continue
        if want_applies_to and as_str_set(fm.get("applies_to")).isdisjoint(want_applies_to):
            continue

        criteria = fm.get("relevance_criteria") or ""
        criteria = flatten_cell(str(criteria)).strip()
        rel = rel_to_repo(path, REPO_ROOT)
        print(f"{rel}\t{criteria}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
