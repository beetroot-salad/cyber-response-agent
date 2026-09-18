#!/usr/bin/env python3
"""Lesson → in-context-outcome traceability (platform-design §4.4 control loop).

For a merged lesson, surface which subsequent cases had it **in context** and what
disposition each reached — the post-merge visibility half of "no pre-merge sign-off, but a
human control loop after". This is **in context**, not demonstrably *influenced* — see
``defender/hooks/record_lesson_load.py``'s caveat; the green bar + one-click revert
are the load-bearing safety controls, this is best-effort visibility.

TWO KINDS OF ROW reach ``lessons_loaded.jsonl`` (#919), and since #936 each row says which
(``kind``) and for which agent (``role``). A READ (``runtime/tools._gated_read``) records a
lesson the model chose to open. A PUSH (``runtime/lessons_push``: the write return that moved
the investigation's frontier, and the compaction fold's frontier row) records each lesson
whose ``description`` and dimensions the runtime put in front of MAIN — the model saw enough
to act on and was told not to open the file to decide relevance, so the row is honest, but it
is weaker evidence than a Read. Neither covers ``runtime/orient.py``'s PLAN-time signature
block, which pushes the same way and records nothing. So a lesson carrying ``frontier_nodes``
/ ``frontier_edges`` selectors has more ways to earn a row than one that does not; read a
difference in counts between two lessons with that in mind.

The ``evidence`` column names the strongest class behind a case's "in context", from the
CLOSED vocabulary ``read`` (a MAIN read) > ``push`` > ``indirect`` (a read by another role
only — a GATHER agent or a curator) > ``unknown`` (rows from before #936, which cannot say —
an honest downgrade of history rather than an assumed read). Only qualifying rows count: a
row outside the lesson's ``created_at`` window lifts nothing. The value is EMITTED from that
vocabulary, never from the row's bytes: ``lessons_loaded.jsonl`` is a #1047 forgery
universal, and a ``kind`` carrying a tab must not forge a column.

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
from dataclasses import dataclass
from datetime import date, datetime, UTC
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender._clock import parse_iso_utc
from defender._corpus import iter_lessons
from defender.hooks.record_lesson_load import LOAD_KIND_PUSH, LOAD_KIND_READ
from defender.runtime.agent_role import AgentRole
from defender._io import read_jsonl_rows, read_text_soft, use_utf8_stdio
from defender._frontmatter import parse_frontmatter_or_none
from defender._report import UNKNOWN_DISPOSITION, read_report
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
    """`parse_iso_utc` plus the two already-typed shapes only this caller meets — a lesson's
    frontmatter is YAML, so a bare date or datetime arrives parsed rather than as a string."""
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=UTC)
    if isinstance(raw, date):
        return datetime(raw.year, raw.month, raw.day, tzinfo=UTC)
    return parse_iso_utc(raw)


#: The `evidence` vocabulary, strongest first. `read` and `push` are the writer's own `kind`
#: values; `indirect` and `unknown` are this reader's classifications of a row.
EVIDENCE_READ = "read"
EVIDENCE_PUSH = "push"
EVIDENCE_INDIRECT = "indirect"
EVIDENCE_UNKNOWN = "unknown"
_EVIDENCE_RANK = {EVIDENCE_READ: 3, EVIDENCE_PUSH: 2, EVIDENCE_INDIRECT: 1, EVIDENCE_UNKNOWN: 0}
_ROLES = frozenset(r.value for r in AgentRole)


def _row_evidence(row: dict) -> str:
    """One row's class, from the closed vocabulary and nothing else. A `kind` or `role`
    outside the writer's spelling — legacy rows, or bytes a forger put there — is `unknown`,
    never echoed, never guessed: `role` is matched against the `AgentRole` values, so a read
    under a role that is not one of them says "cannot say" rather than "another agent"."""
    kind, role = row.get("kind"), row.get("role")
    if kind == LOAD_KIND_PUSH:
        return EVIDENCE_PUSH
    # `isinstance` BEFORE the membership test: a forged `role` that is a list is unhashable,
    # and `in` on a set would raise here and cost the whole walk, not just this row.
    if kind == LOAD_KIND_READ and isinstance(role, str) and role in _ROLES:
        return EVIDENCE_READ if role == AgentRole.MAIN.value else EVIDENCE_INDIRECT
    return EVIDENCE_UNKNOWN


@dataclass
class CaseHit:
    case_id: str
    disposition: str
    loaded_at: str
    evidence: str


@functools.cache
def _report_disposition(run_dir: Path) -> str:
    """This case's disposition for the trace table, or the unknown placeholder.

    Degrades rather than raises: one unreadable historical report must cost its own row, not
    the whole walk. It warns for ANY unreadable headline, since a present-but-malformed report
    is where a silent `?` reads as "this case never resolved". A report that was never written
    stays silent — an ordinary in-progress run, not a defect.
    """
    report = RunPaths(run_dir).report
    if not report.is_file():
        return UNKNOWN_DISPOSITION
    read = read_report(report)
    if read.reason is not None:
        # Flattened like every other value this module prints: the reason quotes
        # model-authored bytes back (a YAML fence error carries the offending frontmatter line
        # verbatim), which unflattened could forge rows on this line-oriented stream.
        print(f"warn: {_flatten(run_dir.name)}/{_flatten(read.reason)} — disposition unknown",
              file=sys.stderr)
    return read.disposition_or_unknown


def _earliest_load(
    loaded: Path, lesson_name: str, created_at: datetime | None
) -> tuple[str, str] | None:
    """`(loaded_at, evidence)` over the QUALIFYING rows — the earliest timestamp, and the
    strongest evidence class any of them carries — or `None` when no row qualifies."""
    qualifying: list[tuple[datetime | None, str]] = []
    evidence = EVIDENCE_UNKNOWN
    for row in read_jsonl_rows(loaded):
        if row.get("lesson_name") != lesson_name:
            continue
        ts = _parse_dt(row.get("ts"))
        if created_at is not None and (ts is None or ts < created_at):
            continue
        qualifying.append((ts, str(row.get("ts"))))
        evidence = max(evidence, _row_evidence(row), key=_EVIDENCE_RANK.__getitem__)
    if not qualifying:
        return None
    earliest = min(
        qualifying,
        key=lambda q: (q[0] is None, q[0] if q[0] is not None else _DT_MAX, q[1]),
    )[1]
    return earliest, evidence


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
        found = _earliest_load(loaded, lesson_name, created_at)
        if found is not None:
            earliest, evidence = found
            hits.append(CaseHit(run_dir.name, _report_disposition(run_dir), earliest, evidence))
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
        # `evidence` goes through the same flatten as every other cell even though it is
        # emitted from a closed vocabulary — one rule for the row, not one per column.
        print(f"{_flatten(h.case_id)}\t{_flatten(h.disposition)}\t{_flatten(h.loaded_at)}"
              f"\t{_flatten(h.evidence)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
