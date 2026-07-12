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

from defender.scripts.lessons._lessons_common import (
    as_list,
    iter_lessons,
    reexec_into_venv,
    rel_to_repo,
    use_utf8_stdio,
)

# Re-exec into defender/.venv so PyYAML resolves regardless of which python the
# caller used (the bin/ shim already points here; this covers a direct
# ``python3 defender/scripts/lessons/lessons_fm.py`` run). Gated on __main__ so
# importing this module as a library never execs the importing process away.
if __name__ == "__main__":
    reexec_into_venv(__file__)

import argparse
import re

# Below the re-exec gate (like the yaml import it replaces): `defender._frontmatter` is
# yaml-backed, and this script is launched by the actor under the SYSTEM interpreter, which
# has no PyYAML. Anything yaml-backed must be imported only after `reexec_into_venv`.
from defender._frontmatter import FrontmatterError, split_frontmatter

REPO_ROOT = Path(__file__).resolve().parents[3]
LESSONS_DIR = REPO_ROOT / "defender" / "lessons"

# The list-valued retrieval dimensions, in display order.
DIMENSIONS = ("source_signature", "telemetry_source", "attack_phase")


def _emit_match(path: Path, fm: dict) -> None:
    desc = str(fm.get("description") or "").strip().replace("\t", " ").replace("\n", " ")
    print(f"{rel_to_repo(path, REPO_ROOT)}\t{desc}")


def cmd_grep(patterns: list[str]) -> int:
    try:
        regexes = [re.compile(p, re.IGNORECASE) for p in patterns]
    except re.error as e:
        print(f"error: bad regex: {e}", file=sys.stderr)
        return 2
    for lesson in iter_lessons(LESSONS_DIR):
        if all(rx.search(lesson.raw) for rx in regexes):
            _emit_match(lesson.path, lesson.fm)
    return 0


def cmd_tags(field: str | None) -> int:
    fields = [field] if field else list(DIMENSIONS)
    if field and field not in DIMENSIONS:
        print(f"error: unknown dimension {field!r}; choose from {', '.join(DIMENSIONS)}", file=sys.stderr)
        return 2
    lessons = list(iter_lessons(LESSONS_DIR))  # one walk, not one per dimension
    for f in fields:
        counts: dict[str, int] = {}
        for lesson in lessons:
            for val in as_list(lesson.fm.get(f)):
                counts[str(val)] = counts.get(str(val), 0) + 1
        print(f"{f}:")
        for val in sorted(counts):
            print(f"  {val:<32} {counts[val]}")
    return 0


def cmd_show(paths: list[str]) -> int:
    rc = 0
    corpus = LESSONS_DIR.resolve()
    for raw_path in paths:
        p = Path(raw_path)
        if not p.is_absolute():
            p = REPO_ROOT / raw_path
        # --show is the one lesson read that takes a MODEL-SUPPLIED path, and nothing upstream
        # confines it: `defender-lessons` is an allowed main-loop shim (hooks/_cmd_segments.py)
        # and the bash allowlist pins the PROGRAM token, not its operands — the reader lane
        # compiles shims as `defender-lessons(?: .*)?`, so every argument passes. This read
        # therefore never reaches `decide_read`'s {run_dir, defender_dir} allowlist. Unconfined it
        # is a frontmatter-DISCLOSURE primitive for any fenced file the process can read
        # (`--show /tmp/anything.md` prints its YAML verbatim) plus a file-EXISTENCE oracle over
        # the whole filesystem. Confine it to the corpus this CLI is about — membership in the
        # walk is the confinement — and fail the off-corpus, absent and not-a-file cases with an
        # IDENTICAL message, so nothing can be probed through the difference between them.
        # `resolve()` first, so a symlink out of the corpus cannot smuggle a target back in.
        lesson = p.resolve()
        try:
            lesson.relative_to(corpus)
            inside = True
        except ValueError:
            inside = False
        if not inside or not lesson.is_file():
            print(f"error: no such lesson: {raw_path}", file=sys.stderr)
            rc = 2
            continue
        # Read exactly as the shared corpus walk does. The encoding is PINNED for the same reason
        # iter_lessons pins it: a bare read_text() decodes under the ambient locale, so where the
        # walk warn-skips an accented lesson this raised an ascii UnicodeDecodeError straight out
        # of main() — a traceback, on a shim the agent runs at PLAN. The fence split delegates to
        # the canonical parser so --show cannot disagree with --tags/the grep about where a
        # lesson's frontmatter ends.
        try:
            fm_raw = split_frontmatter(lesson.read_text(encoding="utf-8"))[1]
        except (FrontmatterError, OSError, UnicodeDecodeError) as e:
            print(f"error: {raw_path}: malformed lesson: {e}", file=sys.stderr)
            rc = 2
            continue
        print(f"--- {rel_to_repo(lesson, REPO_ROOT)}")
        print(fm_raw)
    return rc


def main(argv: list[str]) -> int:
    use_utf8_stdio()  # lessons carry non-ASCII; stdout must not decode under the ambient locale
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
