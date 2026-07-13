#!/usr/bin/env python3
"""Lesson → in-context-outcome traceability (platform-design §4.4 control loop).

For a merged lesson, surface which subsequent cases had it **in context** (the
``record_lesson_load`` hook captured the Read at PLAN) and what disposition each
reached — the post-merge visibility half of "no pre-merge sign-off, but a human
control loop after". This is **in context**, not demonstrably *influenced* — see
``defender/hooks/record_lesson_load.py``'s caveat; the green bar + one-click revert
are the load-bearing safety controls, this is best-effort visibility.

Usage:
  trace_lesson.py --all                 # <name>\\t<description>\\t<in_context_cases>
  trace_lesson.py <lesson_name>         # per-case: case_id  disposition  loaded_at

Runs scanned: the durable learning runs dir (``DEFAULT_PATHS.runs_dir`` —
``$DEFENDER_LEARNING_STATE_DIR/runs`` or in-repo ``defender/learning/runs/``),
where the learn worker persists each case's ``report.md`` + ``lessons_loaded.jsonl``.
Override with ``--runs-dir`` (e.g. the ephemeral ``$DEFENDER_RUNS_BASE`` for
``--no-learn`` dev runs that are never persisted). Lessons: ``defender/lessons/``, overridable with
``--lessons-dir``; ``--all`` walks it through the shared ``iter_lessons``, so it inherits the
corpus discovery rules (underscore-skip, warn on a malformed or unreadable lesson). A lesson the
walk skips still gets a marker row — the audit index must not silently lose a lesson that has
in-context cases (#590), so ``--all`` diffs the walk against ``iter_lesson_paths`` (the shared
discovery rule) and prints the skipped ones with an unwindowed count.
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from datetime import date, datetime, UTC
from pathlib import Path

# Put the workspace root on sys.path so `defender.*` namespace imports
# resolve whether this file is imported or run directly (see tests/conftest.py).
if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender._corpus import iter_lesson_paths, iter_lessons
from defender._io import TEXT_READ_ERRORS, read_jsonl_rows, read_text_utf8, use_utf8_stdio
from defender._frontmatter import parse_frontmatter_or_none
from defender._run_paths import RunPaths
from defender.learning.core.config import DEFAULT_PATHS

REPO_ROOT = Path(__file__).resolve().parents[3]
LESSONS_DIR = REPO_ROOT / "defender" / "lessons"


def _default_runs_dir() -> Path:
    """The durable learning runs dir, NOT the ephemeral ``$DEFENDER_RUNS_BASE``
    (/tmp) the live runtime writes to — that is swept on reboot, silently emptying
    the trace. ``--no-learn`` runs (dev-only, never persisted) are out of scope by
    default; pass ``--runs-dir`` to scan the ephemeral base directly."""
    return DEFAULT_PATHS.runs_dir


def _parse_dt(raw) -> datetime | None:
    """Parse a frontmatter/hook timestamp to a timezone-aware UTC datetime.

    ``created_at`` is LLM-authored, so accept the shapes PyYAML yields: a tz-aware
    or naive ``datetime`` (naive assumed UTC — the hook stamps ``datetime.now(UTC)``),
    a bare ``date`` (``created_at: 2026-06-04`` → UTC midnight), or an ISO-8601
    string. Always returns an *aware* datetime so comparisons against the aware hook
    timestamps never raise ``TypeError: can't compare offset-naive and offset-aware``.
    Check ``datetime`` before ``date`` — ``datetime`` is a ``date`` subclass."""
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=UTC)
    if isinstance(raw, date):
        return datetime(raw.year, raw.month, raw.day, tzinfo=UTC)
    if not isinstance(raw, str):
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


@dataclass
class CaseHit:
    case_id: str
    disposition: str
    loaded_at: str


def _report_disposition(run_dir: Path) -> str:
    """The run's recorded disposition, or ``"?"`` when it cannot be known.

    ``report.md`` is model-authored, and this runs once per hit inside the whole-runs-dir
    walk — one undecodable historical report must cost that one row's disposition, not the
    audit (#595, the #588/#589 ``UnicodeDecodeError ⊄ OSError`` class again)."""
    report = RunPaths(run_dir).report
    if not report.is_file():
        return "?"
    try:
        text = read_text_utf8(report)
    except TEXT_READ_ERRORS as e:
        print(f"warn: cannot read {report.parent.name}/report.md ({e}) — disposition unknown",
              file=sys.stderr)
        return "?"
    fm = parse_frontmatter_or_none(text) or {}
    return str(fm.get("disposition") or "?")


def _earliest_load(
    loaded: Path, lesson_name: str, created_at: datetime | None
) -> str | None:
    """Earliest ``ts`` in one run's ``lessons_loaded.jsonl`` that cites
    ``lesson_name`` at/after ``created_at`` (the lesson's current incarnation),
    or None if it was never qualifyingly loaded."""
    earliest: str | None = None
    for row in read_jsonl_rows(loaded):
        if row.get("lesson_name") != lesson_name:
            continue
        ts = _parse_dt(row.get("ts"))
        if created_at is not None and (ts is None or ts < created_at):
            continue  # loaded before this lesson's current incarnation
        if earliest is None or str(row.get("ts")) < earliest:
            earliest = str(row.get("ts"))
    return earliest


def in_context_cases(
    lesson_name: str, created_at: datetime | None, runs_dir: Path
) -> list[CaseHit]:
    """Cases whose lessons_loaded.jsonl cites ``lesson_name`` at/after ``created_at``
    (the lesson's current incarnation), with the case's recorded disposition. One hit
    per case (earliest qualifying load)."""
    hits: list[CaseHit] = []
    if not runs_dir.is_dir():
        return hits
    for run_dir in sorted(p for p in runs_dir.iterdir() if p.is_dir()):
        loaded = run_dir / "lessons_loaded.jsonl"
        if not loaded.is_file():
            continue
        earliest = _earliest_load(loaded, lesson_name, created_at)
        if earliest is not None:
            hits.append(CaseHit(run_dir.name, _report_disposition(run_dir), earliest))
    return hits


def _print_index(lessons_dir: Path, runs_dir: Path) -> None:
    """The ``--all`` audit table: one TSV row per DISCOVERED lesson, well-formed or not.

    Lesson identity is the **file stem** — that is what ``record_lesson_load`` writes into
    ``lessons_loaded.jsonl`` and what ``trace_lesson <name>`` / ``revert_lesson <name>`` take.
    A ``Lesson`` carries no ``.name``, and joining on the frontmatter ``name`` (which nothing
    forces to equal the stem) would silently miss every recorded load and report zero cases."""
    lessons = list(iter_lessons(lessons_dir))
    for lesson in lessons:
        name = lesson.path.stem
        created_at = _parse_dt(lesson.fm.get("created_at"))
        n = len(in_context_cases(name, created_at, runs_dir))
        print(f"{name}\t{str(lesson.fm.get('description') or '')}\t{n}")
    # A lesson iter_lessons warn-skipped (malformed/unreadable — e.g. a curator edit broke
    # its YAML) must still get an audit row: dropping it here loses exactly the lesson a
    # human is most likely investigating, while the named path still traces it (#590).
    # With no parseable created_at the count cannot be windowed to the current incarnation,
    # so the marker says so instead of printing a normal-looking row.
    yielded = {lesson.path for lesson in lessons}
    for path in iter_lesson_paths(lessons_dir):
        if path in yielded:
            continue
        n = len(in_context_cases(path.stem, None, runs_dir))
        print(f"{path.stem}\t(malformed frontmatter — unwindowed count)\t{n}")


def main(argv: list[str]) -> int:
    # Both output paths print non-ASCII: lesson descriptions under --all, and the em-dash in this
    # file's own trace header — so an ambient-locale stdout breaks the named path unconditionally.
    use_utf8_stdio()
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("lesson_name", nargs="?", help="lesson slug to trace")
    p.add_argument("--all", action="store_true",
                   help="list every lesson with its in-context case count (cheap scan)")
    p.add_argument("--runs-dir", type=Path, default=None)
    p.add_argument("--lessons-dir", type=Path, default=LESSONS_DIR,
                   help="Corpus directory (default: defender/lessons)")
    ns = p.parse_args(argv)
    runs_dir = ns.runs_dir or _default_runs_dir()
    lessons_dir = ns.lessons_dir

    if not lessons_dir.is_dir():
        print(f"no lessons dir: {lessons_dir}", file=sys.stderr)
        return 1

    if ns.all:
        _print_index(lessons_dir, runs_dir)
        return 0

    if not ns.lesson_name:
        print("give a <lesson_name> or --all", file=sys.stderr)
        return 1
    path = lessons_dir / f"{ns.lesson_name}.md"
    if not path.is_file():
        print(f"no such lesson: {path}", file=sys.stderr)
        return 1
    # ``iter_lessons`` is a directory walk and cannot serve a single named lesson without turning
    # an O(1) read into a whole-corpus parse, so this path keeps its own read. The posture is
    # tri-state: an UNREADABLE named lesson is an ERROR (printing "0 case(s)" for a file that was
    # never read is worse than failing); a readable lesson with MALFORMED/missing frontmatter
    # still traces, but warns that the trace is unwindowed (no created_at to window on); ``--all``
    # warn-skips the walk and prints a marker row instead.
    try:
        text = read_text_utf8(path)
    except TEXT_READ_ERRORS as e:
        print(f"error: cannot read {path.name}: {e}", file=sys.stderr)
        return 1
    parsed = parse_frontmatter_or_none(text)
    if parsed is None:
        print(f"warn: {path.name}: malformed or missing frontmatter — trace is unwindowed",
              file=sys.stderr)
    fm = parsed or {}
    created_at = _parse_dt(fm.get("created_at"))
    hits = in_context_cases(path.stem, created_at, runs_dir)
    print(f"# {path.stem} — {len(hits)} case(s) in context since {created_at}")
    for h in hits:
        print(f"{h.case_id}\t{h.disposition}\t{h.loaded_at}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
