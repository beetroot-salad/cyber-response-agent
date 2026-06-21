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
``--no-learn`` dev runs that are never persisted). Lessons: defender/lessons/.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path

# Put the workspace root on sys.path so `defender.*` namespace imports
# resolve whether this file is imported or run directly (see tests/conftest.py).
if (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)

from defender._frontmatter import parse_frontmatter_or_none
from defender.learning._loop_config import DEFAULT_PATHS

REPO_ROOT = Path(__file__).resolve().parents[2]
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
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    if isinstance(raw, date):
        return datetime(raw.year, raw.month, raw.day, tzinfo=timezone.utc)
    if not isinstance(raw, str):
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@dataclass
class LessonMeta:
    name: str
    description: str
    created_at: datetime | None


def lesson_meta(path: Path) -> LessonMeta:
    """Lesson identity is the **file stem** — that is what ``record_lesson_load``
    writes into ``lessons_loaded.jsonl`` and what ``trace_lesson <name>`` /
    ``revert_lesson <name>`` take. Matching on the frontmatter ``name`` (which
    nothing forces to equal the stem) would silently miss every recorded load."""
    fm = parse_frontmatter_or_none(path.read_text()) or {}
    return LessonMeta(
        name=path.stem,
        description=str(fm.get("description") or ""),
        created_at=_parse_dt(fm.get("created_at")),
    )


@dataclass
class CaseHit:
    case_id: str
    disposition: str
    loaded_at: str


def _report_disposition(run_dir: Path) -> str:
    fm = parse_frontmatter_or_none((run_dir / "report.md").read_text()) or {} if (run_dir / "report.md").is_file() else {}
    return str(fm.get("disposition") or "?")


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
        earliest: str | None = None
        for line in loaded.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("lesson_name") != lesson_name:
                continue
            ts = _parse_dt(row.get("ts"))
            if created_at is not None and (ts is None or ts < created_at):
                continue  # loaded before this lesson's current incarnation
            if earliest is None or str(row.get("ts")) < earliest:
                earliest = str(row.get("ts"))
        if earliest is not None:
            hits.append(CaseHit(run_dir.name, _report_disposition(run_dir), earliest))
    return hits


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("lesson_name", nargs="?", help="lesson slug to trace")
    p.add_argument("--all", action="store_true",
                   help="list every lesson with its in-context case count (cheap scan)")
    p.add_argument("--runs-dir", type=Path, default=None)
    ns = p.parse_args(argv)
    runs_dir = ns.runs_dir or _default_runs_dir()

    if not LESSONS_DIR.is_dir():
        print(f"no lessons dir: {LESSONS_DIR}", file=sys.stderr)
        return 1

    if ns.all:
        for path in sorted(LESSONS_DIR.glob("*.md")):
            m = lesson_meta(path)
            n = len(in_context_cases(m.name, m.created_at, runs_dir))
            print(f"{m.name}\t{m.description}\t{n}")
        return 0

    if not ns.lesson_name:
        print("give a <lesson_name> or --all", file=sys.stderr)
        return 1
    path = LESSONS_DIR / f"{ns.lesson_name}.md"
    if not path.is_file():
        print(f"no such lesson: {path}", file=sys.stderr)
        return 1
    m = lesson_meta(path)
    hits = in_context_cases(m.name, m.created_at, runs_dir)
    print(f"# {m.name} — {len(hits)} case(s) in context since {m.created_at}")
    for h in hits:
        print(f"{h.case_id}\t{h.disposition}\t{h.loaded_at}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
