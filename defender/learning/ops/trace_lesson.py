#!/usr/bin/env python3
"""Lesson → in-context-outcome traceability (platform-design §4.4 control loop).

For a merged lesson, surface which subsequent cases had it **in context** and what
disposition each reached — post-merge visibility for a human control loop. This is **in
context**, not demonstrably *influenced* (see ``defender/hooks/record_lesson_load.py``); the
green bar and one-click revert are the safety controls, this is best-effort visibility.

Two kinds of row reach ``lessons_loaded.jsonl``, each naming its ``kind`` and ``role``. A READ
records a lesson the model chose to open. A PUSH records a lesson whose ``description`` and
dimensions the runtime showed MAIN (on a frontier-moving write, or the compaction fold) —
weaker evidence than a read. The PLAN-time signature block pushes the same way but records
nothing, so a lesson with ``frontier_nodes``/``frontier_edges`` selectors has more ways to earn
a row; compare counts between lessons with that in mind.

The ``evidence`` column names the strongest class behind a case's "in context": ``read`` (a
MAIN read) > ``push`` (to MAIN) > ``indirect`` (another role only) > ``unknown`` (older rows
that do not say). ``loaded_at`` is the earliest row of that class. Both come from
``hooks.record_lesson_load.exposures``, the same reader the judge uses. Rows outside the
lesson's ``created_at`` window do not count. The value is emitted from that closed vocabulary,
never the row's bytes, so a forged ``kind`` cannot forge a column.

Usage:
  trace_lesson.py --all                 # <name>\\t<description>\\t<in_context_cases>\\t<main_read_cases>
  trace_lesson.py <lesson_name>         # per-case: case_id  disposition  loaded_at  evidence

Runs scanned: the durable learning runs dir (``DEFAULT_PATHS.runs_dir`` —
``$DEFENDER_LEARNING_STATE_DIR/runs`` or in-repo ``defender/learning/runs/``),
where the learn worker persists each case's ``report.md`` + ``lessons_loaded.jsonl``.
Override with ``--runs-dir`` (e.g. the ephemeral ``$DEFENDER_RUNS_BASE`` for
``--no-learn`` dev runs that are never persisted). Lessons: ``defender/lessons/``,
overridable with ``--lessons-dir``; ``--all`` walks it through the shared ``iter_lessons``
and so inherits the corpus discovery rules (underscore-skip, warn on a malformed lesson).
A lesson the walk skips still gets a marker row with an unwindowed count — the audit index
must not silently lose a lesson that has in-context cases.
"""
from __future__ import annotations

import argparse
import functools
import sys
from defender._model import model
from datetime import date, datetime, UTC
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender._clock import parse_iso_utc
from defender._corpus import iter_lessons
from defender.hooks.record_lesson_load import EVIDENCE_READ, exposures
from defender._io import read_jsonl_rows, read_text_soft, use_utf8_stdio
from defender._frontmatter import parse_frontmatter_or_none
from defender._report import UNKNOWN_DISPOSITION, read_report
from defender._tsv import flatten_cell as _flatten
from defender._run_paths import RunPaths
from defender.learning.core.config import DEFAULT_PATHS

REPO_ROOT = Path(__file__).resolve().parents[3]
LESSONS_DIR = REPO_ROOT / "defender" / "lessons"


def _echo_value(raw: object) -> str:
    flat = _flatten(str(raw))
    if len(flat) > 80:
        flat = flat[:80] + "…"
    return f'"{flat}"'


def _unwindowed_reason(raw: object) -> str:
    if raw is None:
        return "no created_at"
    return f"created_at {_echo_value(raw)} is unparseable"


def _default_runs_dir() -> Path:
    return DEFAULT_PATHS.runs_dir


def _parse_dt(raw) -> datetime | None:
    """`parse_iso_utc`, plus YAML frontmatter's already-parsed date and datetime values."""
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=UTC)
    if isinstance(raw, date):
        return datetime(raw.year, raw.month, raw.day, tzinfo=UTC)
    return parse_iso_utc(raw)


@model
class CaseHit:
    case_id: str
    disposition: str
    loaded_at: str
    evidence: str


@functools.cache
def _report_disposition(run_dir: Path) -> str:
    """This case's disposition for the trace table, or the unknown placeholder.

    Degrades rather than raises, so one bad report costs only its row. Warns when a present
    report has no readable headline; a report never written (an in-progress run) is silent.
    """
    report = RunPaths(run_dir).report
    if not report.is_file():
        return UNKNOWN_DISPOSITION
    read = read_report(report)
    if read.reason is not None:
        # Flattened: the reason can quote model-authored bytes, which could forge rows.
        print(f"warn: {_flatten(run_dir.name)}/{_flatten(read.reason)} — disposition unknown",
              file=sys.stderr)
    return read.disposition_or_unknown


def in_context_cases(
    lesson_name: str, created_at: datetime | None, runs_dir: Path
) -> list[CaseHit]:
    hits: list[CaseHit] = []
    if not runs_dir.is_dir():
        return hits
    for run_dir in sorted(p for p in runs_dir.iterdir() if p.is_dir()):
        loaded = RunPaths(run_dir).lessons_loaded
        if not loaded.is_file():
            continue
        # Filter to this lesson first: `--all` calls this once per lesson per run.
        mine = (r for r in read_jsonl_rows(loaded) if r.get("lesson_name") == lesson_name)
        for exposure in exposures(mine, since=created_at).lessons:
            hits.append(CaseHit(run_dir.name, _report_disposition(run_dir),
                                str(exposure.evidence_at), exposure.evidence))
    return hits


def _main_read_count(hits: list[CaseHit]) -> int:
    return sum(1 for h in hits if h.evidence == EVIDENCE_READ)


def _print_index(lessons_dir: Path, runs_dir: Path) -> None:
    skipped: list[Path] = []
    for lesson in iter_lessons(lessons_dir, on_skip=skipped.append):
        name = lesson.path.stem
        raw_created = lesson.fm.get("created_at")
        created_at = _parse_dt(raw_created)
        cases = in_context_cases(name, created_at, runs_dir)
        desc = _flatten(str(lesson.fm.get("description") or "")).strip()
        if created_at is None:
            desc = f"{desc} ({_unwindowed_reason(raw_created)} — unwindowed count)"
        print(f"{_flatten(name)}\t{desc}\t{len(cases)}\t{_main_read_count(cases)}")
    for path in skipped:
        cases = in_context_cases(path.stem, None, runs_dir)
        print(f"{_flatten(path.stem)}\t(malformed lesson — unwindowed count)\t{len(cases)}"
              f"\t{_main_read_count(cases)}")


def main(argv: list[str]) -> int:
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

    if ns.all and ns.lesson_name:
        print("give a <lesson_name> or --all, not both", file=sys.stderr)
        return 1

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
    text, reason = read_text_soft(path)
    if text is None:
        print(f"error: cannot read {path.name}: {reason}", file=sys.stderr)
        return 1
    parsed = parse_frontmatter_or_none(text)
    fm = parsed or {}
    raw_created = fm.get("created_at")
    created_at = _parse_dt(raw_created)
    if parsed is None:
        print(f"warn: {path.name}: malformed or missing frontmatter — trace is unwindowed",
              file=sys.stderr)
    elif created_at is None:
        print(f"warn: {path.name}: {_unwindowed_reason(raw_created)} — trace is unwindowed",
              file=sys.stderr)
    hits = in_context_cases(path.stem, created_at, runs_dir)
    since = str(created_at) if created_at is not None else f"? ({_unwindowed_reason(raw_created)})"
    print(f"# {_flatten(path.stem)} — {len(hits)} case(s) in context since {since}")
    for h in hits:
        # Every cell flattened, closed-vocabulary ones included — one rule for the row.
        print(f"{_flatten(h.case_id)}\t{_flatten(h.disposition)}\t{_flatten(h.loaded_at)}"
              f"\t{_flatten(h.evidence)}")
    return 0


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main(sys.argv[1:]))
