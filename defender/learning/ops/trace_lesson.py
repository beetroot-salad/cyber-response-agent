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

# Put the workspace root on sys.path so `defender.*` namespace imports
# resolve whether this file is imported or run directly (see tests/conftest.py).
if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender._corpus import iter_lessons
from defender._io import read_jsonl_rows, read_text_soft, use_utf8_stdio
from defender._frontmatter import parse_frontmatter_or_none
from defender._run_paths import RunPaths
from defender.learning.core.config import DEFAULT_PATHS

REPO_ROOT = Path(__file__).resolve().parents[3]
LESSONS_DIR = REPO_ROOT / "defender" / "lessons"

# Sorts an unparseable-ts load row after every parseable one (see _earliest_load).
_DT_MAX = datetime.max.replace(tzinfo=UTC)

# Every char ``str.splitlines`` treats as a line boundary, plus tab. The known consumer
# idiom parses this TSV via splitlines() + '#'-prefix drop, so ANY of these in an
# LLM/hook-authored value forges a row or a column — the \t/\n-only flatten is not
# enough for a value that must stay inside one cell (#596).
_BREAKERS = dict.fromkeys(map(ord, "\t\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"), " ")


def _flatten(value: str) -> str:
    """One cell, one line: every line/column breaker becomes a single space."""
    return value.translate(_BREAKERS)


def _echo_value(raw: object) -> str:
    """Quoted, flattened, clamped rendering of an untrusted value for one-line output.

    The quoting makes empty/whitespace-only breakage visible; the clamp (first 80
    flattened chars + ``…``) keeps a garbage payload from bloating the row."""
    flat = _flatten(str(raw))
    if len(flat) > 80:
        flat = flat[:80] + "…"
    return f'"{flat}"'


def _unwindowed_reason(raw: object) -> str:
    """Why a valid lesson can't be windowed: never stamped vs stamped garbage —
    different curator fixes, so the marker distinguishes them (#596)."""
    if raw is None:  # absent key and explicit ``created_at: null`` both read as never stamped
        return "no created_at"
    return f"created_at {_echo_value(raw)} is unparseable"


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


@functools.cache
def _report_disposition(run_dir: Path) -> str:
    """The run's recorded disposition, or ``"?"`` when it cannot be known.

    ``report.md`` is model-authored, and this runs once per hit inside the whole-runs-dir
    walk — one unreadable historical report must cost that one row's disposition, not the
    audit (#595, the #588/#589 ``UnicodeDecodeError ⊄ OSError`` class again; the guard is
    ``read_text_soft``, the shared skip-one-bad-file read). Cached per run dir: under
    ``--all`` the same report is hit once per lesson that cites the run, and each miss
    would re-read, re-parse, and re-warn.

    Third reader of report.md frontmatter, by design, not by drift: the LEARN gate is
    fail-loud (``core/validate.normalize_disposition`` raises ``RunUnprocessable``) and the
    renderer degrades to a body-only dict (``scripts/visualize`` ``parse_report``). All
    three share the #591 grammar (``_frontmatter``) and the pinned-read primitives — only
    the *posture* differs, and each posture is that consumer's contract."""
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
    """Earliest ``ts`` in one run's ``lessons_loaded.jsonl`` that cites
    ``lesson_name`` at/after ``created_at`` (the lesson's current incarnation),
    or None if it was never qualifyingly loaded.

    Earliest is CHRONOLOGICAL (the parsed ts), not lexicographic — a string min is
    only correct while every writer emits one canonical offset+precision, and the
    windowing five lines up already parses. A row whose ts doesn't parse (reachable
    only when ``created_at`` is None — the window guard drops it otherwise) sorts
    after every parseable row, lexicographic among its own kind; the raw string is
    the tiebreak so equal instants in different spellings stay deterministic."""
    qualifying: list[tuple[datetime | None, str]] = []
    for row in read_jsonl_rows(loaded):
        if row.get("lesson_name") != lesson_name:
            continue
        ts = _parse_dt(row.get("ts"))
        if created_at is not None and (ts is None or ts < created_at):
            continue  # loaded before this lesson's current incarnation
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
    skipped: list[Path] = []
    for lesson in iter_lessons(lessons_dir, on_skip=skipped.append):
        name = lesson.path.stem
        raw_created = lesson.fm.get("created_at")
        created_at = _parse_dt(raw_created)
        n = len(in_context_cases(name, created_at, runs_dir))
        # The description is LLM-authored and this is a TSV row — flatten the two chars that
        # would forge a column or a row (same idiom as lessons_fm._emit_match).
        desc = str(lesson.fm.get("description") or "").strip().replace("\t", " ").replace("\n", " ")
        # A VALID lesson with nothing to window on must say so on its own row — the count
        # is the unwindowed count, and a normal-looking row would pass it off as windowed
        # (#596; a stderr-only warn is exactly what #590 rejected). Not "malformed": the
        # lesson parses fine, only its created_at needs the curator's attention.
        if created_at is None:
            desc = f"{desc} ({_unwindowed_reason(raw_created)} — unwindowed count)"
        print(f"{name}\t{desc}\t{n}")
    # A lesson iter_lessons warn-skipped (malformed/unreadable — e.g. a curator edit broke
    # its YAML) must still get an audit row: dropping it here loses exactly the lesson a
    # human is most likely investigating, while the named path still traces it (#590).
    # ``on_skip`` reports from the walk itself, so the marker set is exactly the skipped
    # set — no second glob to race. With no parseable created_at the count cannot be
    # windowed to the current incarnation, so the marker says so instead of printing a
    # normal-looking row.
    for path in skipped:
        n = len(in_context_cases(path.stem, None, runs_dir))
        # "malformed lesson" is the walk's own vocabulary for all three skip causes (parse,
        # read, decode) — its stderr warn right above carries the specific reason.
        print(f"{path.stem}\t(malformed lesson — unwindowed count)\t{n}")


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

    # The two forms answer different questions; silently preferring one would hand the
    # operator the wrong report under a stray extra argument.
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
    # ``iter_lessons`` is a directory walk and cannot serve a single named lesson without turning
    # an O(1) read into a whole-corpus parse, so this path keeps its own read (``read_text_soft``,
    # the shared skip-one-bad-file guard). The posture is tri-state: an UNREADABLE named lesson is
    # an ERROR (printing "0 case(s)" for a file that was never read is worse than failing); a
    # readable lesson with nothing to window on — malformed/missing frontmatter, or a
    # missing/unparseable ``created_at`` — still traces, but warns that the trace is unwindowed;
    # ``--all`` warn-skips the walk and prints a marker row instead.
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
        # Valid frontmatter whose LLM-authored created_at is absent or unparseable is just as
        # unwindowed — "since None" must never print silently, and the echoed value tells the
        # curator what to fix without opening the file (#596's named-path half).
        print(f"warn: {path.name}: {_unwindowed_reason(raw_created)} — trace is unwindowed",
              file=sys.stderr)
    hits = in_context_cases(path.stem, created_at, runs_dir)
    # The header must stay honest too: never the Python ``None`` sentinel — an unwindowed
    # trace says so and names the reason (#596).
    since = str(created_at) if created_at is not None else f"? ({_unwindowed_reason(raw_created)})"
    print(f"# {path.stem} — {len(hits)} case(s) in context since {since}")
    for h in hits:
        # disposition is model-authored (report.md) and loaded_at hook-written — the same
        # value-in-TSV class as created_at, so they get the same flatten (#596).
        print(f"{h.case_id}\t{_flatten(h.disposition)}\t{_flatten(h.loaded_at)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
