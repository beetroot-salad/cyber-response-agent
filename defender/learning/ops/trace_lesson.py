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
in-context cases (#590), so ``--all`` collects the skipped paths through ``iter_lessons``'
``on_skip`` seam (the same single walk — no second glob to race) and prints them with an
unwindowed count.
"""
from __future__ import annotations

import argparse
import functools
import sys
from dataclasses import dataclass
from datetime import date, datetime, UTC
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender._corpus import iter_lessons
from defender._io import read_jsonl_rows, read_text_soft, use_utf8_stdio
from defender._frontmatter import parse_frontmatter_or_none
from defender._tsv import flatten_cell as _flatten
from defender._run_paths import RunPaths
from defender.learning.core.config import DEFAULT_PATHS

REPO_ROOT = Path(__file__).resolve().parents[3]
LESSONS_DIR = REPO_ROOT / "defender" / "lessons"

_DT_MAX = datetime.max.replace(tzinfo=UTC)


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


@functools.cache
def _report_disposition(run_dir: Path) -> str:
    report = RunPaths(run_dir).report
    if not report.is_file():
        return "?"
    text, reason = read_text_soft(report)
    if text is None:
        print(f"warn: cannot read {report.parent.name}/report.md ({reason}) — disposition unknown",
              file=sys.stderr)
        return "?"
    fm = parse_frontmatter_or_none(text) or {}
    return str(fm.get("disposition") or "?")


def _earliest_load(
    loaded: Path, lesson_name: str, created_at: datetime | None
) -> str | None:
    qualifying: list[tuple[datetime | None, str]] = []
    for row in read_jsonl_rows(loaded):
        if row.get("lesson_name") != lesson_name:
            continue
        ts = _parse_dt(row.get("ts"))
        if created_at is not None and (ts is None or ts < created_at):
            continue
        qualifying.append((ts, str(row.get("ts"))))
    if not qualifying:
        return None
    return min(
        qualifying,
        key=lambda q: (q[0] is None, q[0] if q[0] is not None else _DT_MAX, q[1]),
    )[1]


def in_context_cases(
    lesson_name: str, created_at: datetime | None, runs_dir: Path
) -> list[CaseHit]:
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
    skipped: list[Path] = []
    for lesson in iter_lessons(lessons_dir, on_skip=skipped.append):
        name = lesson.path.stem
        raw_created = lesson.fm.get("created_at")
        created_at = _parse_dt(raw_created)
        n = len(in_context_cases(name, created_at, runs_dir))
        desc = _flatten(str(lesson.fm.get("description") or "")).strip()
        if created_at is None:
            desc = f"{desc} ({_unwindowed_reason(raw_created)} — unwindowed count)"
        print(f"{_flatten(name)}\t{desc}\t{n}")
    for path in skipped:
        n = len(in_context_cases(path.stem, None, runs_dir))
        print(f"{_flatten(path.stem)}\t(malformed lesson — unwindowed count)\t{n}")


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
        print(f"{_flatten(h.case_id)}\t{_flatten(h.disposition)}\t{_flatten(h.loaded_at)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
