"""Tests for defender/learning/trace_lesson.py — in-context-outcome traceability."""
from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timezone
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
    created = datetime(2026, 6, 4, tzinfo=timezone.utc)
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
