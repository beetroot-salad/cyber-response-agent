#!/usr/bin/env python3
"""Grep defender lesson FRONTMATTER (only) + enumerate viable tags.

Plan-time discovery primitive for the defender orchestrator (SKILL §Lessons)
and the lessons author. It does two things, both scoped to frontmatter so the
freeform body can never false-match a tag query:

  1. Pattern mode — match one or more regexes (grep syntax) against each
     lesson's YAML frontmatter block, ANDing the patterns, and print one
     ``<path>\\t<description>`` line per match. That line is the cheap scan
     surface: read the descriptions, then Read the bodies of the ones that fit.
  2. ``--tags`` — enumerate the distinct values already in use per retrieval
     dimension (the *viable tags*), so a caller greps only tokens that exist
     and the author reuses a spelling instead of coining a near-synonym.

There is deliberately NO index — a per-call directory scan, fine at this
scale (mirrors ``lessons_env_retrieve.py``); revisit if it ever hurts.

Retrieval dimensions (frontmatter list fields):
  source_signature   alert rule.id(s) the lesson came from / bites
  telemetry_source   sensor(s) the check keys on (incl. the absent one it names)
  attack_phase       MITRE ATT&CK tactic(s) where the pitfall bites

Usage:
    defender-lessons                                   # whole corpus: <path>\\t<description>
    defender-lessons 'telemetry_source:.*\\bsshd\\b'     # one frontmatter regex
    defender-lessons 'source_signature:.*v2-cross-tier-ssh-pivot' 'attack_phase:.*persistence'
                                                       # AND across patterns (= piped greps)
    defender-lessons --tags                            # viable values for every dimension
    defender-lessons --tags telemetry_source           # viable values for one dimension
    defender-lessons --show defender/lessons/foo.md    # print just a lesson's frontmatter

PATTERNs are Python regexes matched case-insensitively against the frontmatter
text. Exit 0 always (no match = no output); a bad regex exits 2.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Put the workspace root on sys.path so the `defender.*` namespace import below
# resolves whether this file is imported or run directly (sys.path[0] is this
# script's dir, not the workspace root). Must precede the shared import.
if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender.scripts.lessons._lessons_common import as_list, reexec_into_venv, rel_to_repo

# Re-exec into defender/.venv so PyYAML resolves regardless of which python the
# caller used (the bin/ shim already points here; this covers a direct
# ``python3 defender/scripts/lessons/lessons_fm.py`` run). Gated on __main__ so
# importing this module as a library never execs the importing process away.
if __name__ == "__main__":
    reexec_into_venv(__file__)

import argparse
import re

import yaml


REPO_ROOT = Path(__file__).resolve().parents[3]
LESSONS_DIR = REPO_ROOT / "defender" / "lessons"

# The list-valued retrieval dimensions, in display order.
DIMENSIONS = ("source_signature", "telemetry_source", "attack_phase")


def _split_frontmatter(text: str) -> tuple[str, dict] | None:
    """Return (raw_frontmatter_text, parsed_dict) or None if malformed."""
    if not text.startswith("---\n"):
        return None
    end = text.find("\n---", 4)
    if end == -1:
        return None
    raw = text[4:end]
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError:
        return None
    return (raw, data) if isinstance(data, dict) else None


def iter_lessons():
    """Yield (path, raw_frontmatter, frontmatter_dict) per well-formed lesson."""
    if not LESSONS_DIR.is_dir():
        return
    for path in sorted(LESSONS_DIR.glob("*.md")):
        if path.name.startswith("_"):
            continue
        parsed = _split_frontmatter(path.read_text())
        if parsed is None:
            print(f"warn: skipping {path.name} (malformed frontmatter)", file=sys.stderr)
            continue
        raw, fm = parsed
        yield path, raw, fm


def _emit_match(path: Path, fm: dict) -> None:
    desc = str(fm.get("description") or "").strip().replace("\t", " ").replace("\n", " ")
    print(f"{rel_to_repo(path, REPO_ROOT)}\t{desc}")


def cmd_grep(patterns: list[str]) -> int:
    try:
        regexes = [re.compile(p, re.IGNORECASE) for p in patterns]
    except re.error as e:
        print(f"error: bad regex: {e}", file=sys.stderr)
        return 2
    for path, raw, fm in iter_lessons():
        if all(rx.search(raw) for rx in regexes):
            _emit_match(path, fm)
    return 0


def cmd_tags(field: str | None) -> int:
    fields = [field] if field else list(DIMENSIONS)
    if field and field not in DIMENSIONS:
        print(f"error: unknown dimension {field!r}; choose from {', '.join(DIMENSIONS)}", file=sys.stderr)
        return 2
    for f in fields:
        counts: dict[str, int] = {}
        for _path, _raw, fm in iter_lessons():
            for val in as_list(fm.get(f)):
                counts[str(val)] = counts.get(str(val), 0) + 1
        print(f"{f}:")
        for val in sorted(counts):
            print(f"  {val:<32} {counts[val]}")
    return 0


def cmd_show(paths: list[str]) -> int:
    rc = 0
    for raw_path in paths:
        p = Path(raw_path)
        if not p.is_absolute():
            p = REPO_ROOT / raw_path
        if not p.is_file():
            print(f"error: no such lesson: {raw_path}", file=sys.stderr)
            rc = 2
            continue
        parsed = _split_frontmatter(p.read_text())
        if parsed is None:
            print(f"error: {raw_path}: malformed frontmatter", file=sys.stderr)
            rc = 2
            continue
        print(f"--- {rel_to_repo(p, REPO_ROOT)}")
        print(parsed[0])
    return rc


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="defender-lessons",
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="frontmatter-only: the body is never matched or printed.",
    )
    ap.add_argument("patterns", nargs="*", help="regex(es) matched against frontmatter; ANDed")
    ap.add_argument("--tags", nargs="?", const="", metavar="DIMENSION",
                    help="enumerate viable tag values (all dimensions, or one named)")
    ap.add_argument("--show", nargs="+", metavar="PATH",
                    help="print only the frontmatter block of the given lesson(s)")
    ns = ap.parse_args(argv[1:])

    if ns.tags is not None:
        return cmd_tags(ns.tags or None)
    if ns.show:
        return cmd_show(ns.show)
    return cmd_grep(ns.patterns)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
