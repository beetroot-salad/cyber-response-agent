"""Tests for defender/learning/trace_lesson.py — in-context-outcome traceability."""
from __future__ import annotations

import importlib.util
import json
import sys
from datetime import date, datetime, UTC
from pathlib import Path

TL_PATH = Path(__file__).resolve().parents[1] / "learning" / "trace_lesson.py"


def _load():
    spec = importlib.util.spec_from_file_location("trace_lesson", TL_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # Register before exec so the @dataclass decorators can resolve cls.__module__
    # (dataclasses reads sys.modules[cls.__module__] under `from __future__ annotations`).
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _mk_run(runs: Path, name: str, *, disposition: str, loads: list[dict]):
    rd = runs / name
    rd.mkdir(parents=True)
    (rd / "report.md").write_text(f"---\ndisposition: {disposition}\n---\nbody\n")
    (rd / "lessons_loaded.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in loads)
    )
    return rd


def test_in_context_cases_windows_on_created_at(tmp_path):
    tl = _load()
    runs = tmp_path / "runs"
    runs.mkdir()
    created = datetime(2026, 6, 4, tzinfo=UTC)
    _mk_run(runs, "caseA", disposition="benign",
            loads=[{"lesson_name": "L", "ts": "2026-06-05T00:00:00+00:00"}])  # after → counted
    _mk_run(runs, "caseB", disposition="malicious",
            loads=[{"lesson_name": "L", "ts": "2026-06-01T00:00:00+00:00"}])  # before → excluded
    _mk_run(runs, "caseC", disposition="benign",
            loads=[{"lesson_name": "OTHER", "ts": "2026-06-06T00:00:00+00:00"}])  # other lesson
    hits = tl.in_context_cases("L", created, runs)
    assert [(h.case_id, h.disposition) for h in hits] == [("caseA", "benign")]


def test_in_context_cases_dedups_per_case_keeps_earliest(tmp_path):
    tl = _load()
    runs = tmp_path / "runs"
    runs.mkdir()
    _mk_run(runs, "caseA", disposition="benign", loads=[
        {"lesson_name": "L", "ts": "2026-06-05T01:00:00+00:00"},
        {"lesson_name": "L", "ts": "2026-06-05T00:00:00+00:00"},
    ])
    hits = tl.in_context_cases("L", None, runs)
    assert len(hits) == 1
    assert hits[0].loaded_at == "2026-06-05T00:00:00+00:00"


def test_in_context_cases_missing_runs_dir_is_empty(tmp_path):
    tl = _load()
    assert tl.in_context_cases("L", None, tmp_path / "nope") == []


def _mk_lesson(lessons: Path, stem: str, *, body_frontmatter: str) -> Path:
    lessons.mkdir(exist_ok=True)
    p = lessons / f"{stem}.md"
    p.write_text(f"---\n{body_frontmatter}\n---\nbody\n")
    return p


def test_parse_dt_normalizes_to_aware():
    tl = _load()
    naive = tl._parse_dt("2026-06-04T00:00:00")        # ISO string, no offset
    assert naive is not None
    assert naive.tzinfo is not None
    assert tl._parse_dt(date(2026, 6, 4)) == datetime(2026, 6, 4, tzinfo=UTC)
    assert tl._parse_dt("2026-06-04T00:00:00Z").tzinfo is not None
    # naive datetime (PyYAML for a tz-less timestamp) → aware UTC
    assert tl._parse_dt(datetime(2026, 6, 4)).tzinfo is not None
    assert tl._parse_dt(123) is None                   # unsupported type


def test_naive_created_at_does_not_crash_trace(tmp_path):
    """A tz-less created_at (LLM-authored, no offset → PyYAML naive datetime) must not
    raise TypeError against the always-aware hook timestamps."""
    tl = _load()
    lesson = _mk_lesson(
        tmp_path / "lessons", "L",
        body_frontmatter="name: L\ndescription: d\ncreated_at: 2026-06-04T00:00:00",
    )
    runs = tmp_path / "runs"
    runs.mkdir()
    _mk_run(runs, "caseA", disposition="benign",
            loads=[{"lesson_name": "L", "ts": "2026-06-05T00:00:00+00:00"}])
    m = tl.lesson_meta(lesson)
    assert m.created_at is not None
    assert m.created_at.tzinfo is not None
    hits = tl.in_context_cases(m.name, m.created_at, runs)  # must not raise
    assert [(h.case_id, h.disposition) for h in hits] == [("caseA", "benign")]


def test_bare_date_created_at_windows_correctly(tmp_path):
    """`created_at: 2026-06-04` (PyYAML → date) is promoted to UTC midnight, not
    silently dropped — loads before it stay excluded."""
    tl = _load()
    lesson = _mk_lesson(
        tmp_path / "lessons", "L",
        body_frontmatter="name: L\ndescription: d\ncreated_at: 2026-06-04",
    )
    runs = tmp_path / "runs"
    runs.mkdir()
    _mk_run(runs, "before", disposition="benign",
            loads=[{"lesson_name": "L", "ts": "2026-06-01T00:00:00+00:00"}])  # excluded
    _mk_run(runs, "after", disposition="benign",
            loads=[{"lesson_name": "L", "ts": "2026-06-05T00:00:00+00:00"}])  # counted
    m = tl.lesson_meta(lesson)
    hits = tl.in_context_cases(m.name, m.created_at, runs)
    assert [h.case_id for h in hits] == ["after"]


def test_lesson_identity_is_stem_not_frontmatter_name(tmp_path):
    """The hook records the file stem; matching must key on the stem even when the
    frontmatter name differs, else every recorded load is silently missed."""
    tl = _load()
    lesson = _mk_lesson(
        tmp_path / "lessons", "foo-bar",
        body_frontmatter="name: foo_bar\ndescription: d",  # frontmatter name != stem
    )
    runs = tmp_path / "runs"
    runs.mkdir()
    _mk_run(runs, "caseA", disposition="malicious",
            loads=[{"lesson_name": "foo-bar", "ts": "2026-06-05T00:00:00+00:00"}])
    m = tl.lesson_meta(lesson)
    assert m.name == "foo-bar"  # stem, not the frontmatter "foo_bar"
    hits = tl.in_context_cases(m.name, m.created_at, runs)
    assert [h.case_id for h in hits] == ["caseA"]
