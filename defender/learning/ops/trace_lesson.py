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
  trace_lesson.py --tenant T --all             # <name>\\t<description>\\t<in_context_cases>\\t<main_read_cases>
  trace_lesson.py --tenant T <lesson_name>     # per-case: case_id  disposition  loaded_at  evidence

Runs scanned: the natural runs of the tenant ``--tenant`` names (required, no default; #1105
J8), listed and opened through its run repository — every case's ``report.md`` +
``lessons_loaded.jsonl``. The listing rule applies (rev 4.1 H4): an entry in the runs folder
that is not a run (a stray file, an off-rule name) fails the trace loudly, naming it, rather
than being skipped. Lessons: ``defender/lessons/``,
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
from collections.abc import Iterable
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
from defender._knowledge import CHECKOUT_KNOWLEDGE
from defender._text import one_line
from defender.run_repository import Run

REPO_ROOT = Path(__file__).resolve().parents[3]
LESSONS_DIR = CHECKOUT_KNOWLEDGE.lessons_dir


def _echo_value(raw: object) -> str:
    flat = one_line(str(raw))
    if len(flat) > 80:
        flat = flat[:80] + "…"
    return f'"{flat}"'


def _unwindowed_reason(raw: object) -> str:
    if raw is None:
        return "no created_at"
    return f"created_at {_echo_value(raw)} is unparseable"


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
def _report_disposition(report: Path) -> str:
    """This case's disposition for the trace table (from its report, the opened run's
    `documents.report` record), or the unknown placeholder.

    Degrades rather than raises, so one bad report costs only its row. Warns when a present
    report has no readable headline; a report never written (an in-progress run) is silent.
    """
    if not report.is_file():
        return UNKNOWN_DISPOSITION
    read = read_report(report)
    if read.reason is not None:
        # Flattened: the reason can quote model-authored bytes, which could forge rows.
        print(f"warn: {one_line(report.parent.name)}/{one_line(read.reason)} — disposition "
              "unknown", file=sys.stderr)
    return read.disposition_or_unknown


def tenant_runs(raw_tenant: str) -> list[Run]:
    """Every natural run of the tenant `raw_tenant` names (accepted under the configured data
    root), in id order: `runs.list()` — whose listing rule refuses an entry that is not a run
    (`RunRefused`, naming it) — then `runs.open` for each. An absent runs folder holds none.
    `TenantRefused` when the tenant cannot be accepted."""
    from defender import _tenant
    from defender._paths import process_defender_dir

    tenant = _tenant.accept_tenant(
        _tenant.resolve_data_root(), _tenant.requested_tenant_id(raw_tenant),
        defender_dir=process_defender_dir())
    runs = tenant.runs_repository()
    return [runs.open(run_id) for run_id in runs.list()]


def in_context_cases(
    lesson_name: str, created_at: datetime | None, runs: Iterable[Run]
) -> list[CaseHit]:
    """The cases among `runs` (opened runs, `tenant_runs`) that had `lesson_name` in context
    since `created_at`, each with its disposition."""
    return [hit for run in runs for hit in _run_hits(lesson_name, created_at, run)]


def _run_hits(lesson_name: str, created_at: datetime | None, run: Run) -> list[CaseHit]:
    """One run's exposures to `lesson_name` since `created_at`, read through the run's own
    records (`lessons_loaded`, then `report` for the disposition)."""
    loaded = Path(run.observability.lessons_loaded.path)
    if not loaded.is_file():
        return []
    # Filter to this lesson first: `--all` calls this once per lesson per run.
    mine = (r for r in read_jsonl_rows(loaded) if r.get("lesson_name") == lesson_name)
    hits: list[CaseHit] = []
    disposition = None
    for exposure in exposures(mine, since=created_at).lessons:
        if disposition is None:
            disposition = _report_disposition(Path(run.documents.report.path))
        hits.append(CaseHit(str(run.run_id), disposition, str(exposure.evidence_at),
                            exposure.evidence))
    return hits


def _main_read_count(hits: list[CaseHit]) -> int:
    return sum(1 for h in hits if h.evidence == EVIDENCE_READ)


def _print_index(lessons_dir: Path, runs: list[Run]) -> None:
    skipped: list[Path] = []
    for lesson in iter_lessons(lessons_dir, on_skip=skipped.append):
        name = lesson.path.stem
        raw_created = lesson.fm.get("created_at")  # lint-lesson-text: ok — parsed as a date; a bad value prints through one_line
        created_at = _parse_dt(raw_created)
        cases = in_context_cases(name, created_at, runs)
        desc = lesson.line("description")
        if created_at is None:
            desc = f"{desc} ({_unwindowed_reason(raw_created)} — unwindowed count)"
        print(f"{one_line(name)}\t{desc}\t{len(cases)}\t{_main_read_count(cases)}")
    for path in skipped:
        cases = in_context_cases(path.stem, None, runs)
        print(f"{one_line(path.stem)}\t(malformed lesson — unwindowed count)\t{len(cases)}"
              f"\t{_main_read_count(cases)}")


def _scanned_runs(raw_tenant: str) -> list[Run] | None:
    """`tenant_runs`, or `None` with the refusal on stderr (one line, naming a stray entry
    or the refused tenant)."""
    from defender import _tenant
    from defender.run_repository import RunRefused

    try:
        return tenant_runs(raw_tenant)
    except (_tenant.TenantRefused, RunRefused) as refused:
        print(f"error: the runs of tenant {one_line(raw_tenant)} cannot be scanned: "
              f"{one_line(str(refused))}", file=sys.stderr)
        return None


def main(argv: list[str]) -> int:
    use_utf8_stdio()
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--tenant", required=True,
                   help="the tenant whose runs are scanned; required, with no default")
    p.add_argument("lesson_name", nargs="?", help="lesson slug to trace")
    p.add_argument("--all", action="store_true",
                   help="list every lesson with its in-context case count (cheap scan)")
    p.add_argument("--lessons-dir", type=Path, default=LESSONS_DIR,
                   help="Corpus directory (default: defender/lessons)")
    ns = p.parse_args(argv)
    lessons_dir = ns.lessons_dir

    if ns.all and ns.lesson_name:
        print("give a <lesson_name> or --all, not both", file=sys.stderr)
        return 1

    if not lessons_dir.is_dir():
        print(f"no lessons dir: {lessons_dir}", file=sys.stderr)
        return 1

    runs = _scanned_runs(ns.tenant)
    if runs is None:
        return 1

    if ns.all:
        _print_index(lessons_dir, runs)
        return 0

    if not ns.lesson_name:
        print("give a <lesson_name> or --all", file=sys.stderr)
        return 1
    return _trace_one(lessons_dir, ns.lesson_name, runs)


def _trace_one(lessons_dir: Path, lesson_name: str, runs: list[Run]) -> int:
    """`<lesson_name>`'s per-case table over `runs`."""
    path = lessons_dir / f"{lesson_name}.md"
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
    hits = in_context_cases(path.stem, created_at, runs)
    since = str(created_at) if created_at is not None else f"? ({_unwindowed_reason(raw_created)})"
    print(f"# {one_line(path.stem)} — {len(hits)} case(s) in context since {since}")
    for h in hits:
        # Every cell one line (the lesson loader's rule), closed-vocabulary ones included.
        print(f"{one_line(h.case_id)}\t{one_line(h.disposition)}\t{one_line(h.loaded_at)}"
              f"\t{one_line(h.evidence)}")
    return 0


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main(sys.argv[1:]))
