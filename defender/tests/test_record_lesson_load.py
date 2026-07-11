"""Tests for defender/hooks/record_lesson_load.py.

PostToolUse-on-Read hook: appends a {lesson_name, ts} row to
{DEFENDER_RUN_DIR}/lessons_loaded.jsonl for each Read of a lesson .md under one of the
three corpora (defender/{lessons,lessons-actor,lessons-environment}/ — widened by #559
F3 from lessons/ only); always exits 0.
"""
from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path

HOOK_PATH = Path(__file__).resolve().parents[1] / "hooks" / "record_lesson_load.py"


def _load():
    spec = importlib.util.spec_from_file_location("record_lesson_load", HOOK_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _read_event(file_path: str) -> dict:
    return {"tool_name": "Read", "tool_input": {"file_path": file_path}}


def _run(mod, payload: dict) -> int:
    return mod.main(stdin=io.StringIO(json.dumps(payload)))


def test_records_runtime_lesson_read(monkeypatch, tmp_path):
    mod = _load()
    monkeypatch.setenv("DEFENDER_RUN_DIR", str(tmp_path))
    assert _run(mod, _read_event("/repo/defender/lessons/foo.md")) == 0
    rows = [
        json.loads(line)
        for line in (tmp_path / "lessons_loaded.jsonl").read_text().splitlines()
    ]
    assert rows[0]["lesson_name"] == "foo"
    assert "ts" in rows[0]


def test_records_all_three_lesson_corpora(monkeypatch, tmp_path):
    """#559 F3 widened the matcher from lessons/ only to all three lesson corpora: a Read of a
    findings, actor, OR env lesson is recorded (the curators' lesson_read reuses this matcher;
    the runtime read_file does too — the accepted cross-role blast radius)."""
    mod = _load()
    monkeypatch.setenv("DEFENDER_RUN_DIR", str(tmp_path))
    for fp in ("/repo/defender/lessons/a.md",
               "/repo/defender/lessons-actor/x.md",
               "/repo/defender/lessons-environment/y.md"):
        assert _run(mod, _read_event(fp)) == 0
    loaded = {
        json.loads(line)["lesson_name"]
        for line in (tmp_path / "lessons_loaded.jsonl").read_text().splitlines()
    }
    assert loaded == {"a", "x", "y"}


def test_ignores_template_schema(monkeypatch, tmp_path):
    """``_TEMPLATE.md`` is the corpus SCHEMA (the shape a curator reads before authoring), not a
    lesson — recording it would put a `_TEMPLATE` slug in the trace that no corpus can resolve."""
    mod = _load()
    monkeypatch.setenv("DEFENDER_RUN_DIR", str(tmp_path))
    for corpus in ("lessons", "lessons-actor", "lessons-environment"):
        assert mod.lesson_name(f"/repo/defender/{corpus}/_TEMPLATE.md") is None
        assert _run(mod, _read_event(f"/repo/defender/{corpus}/_TEMPLATE.md")) == 0
    assert not (tmp_path / "lessons_loaded.jsonl").exists()


def test_runtime_corpora_narrows_to_the_defender_lessons(monkeypatch, tmp_path):
    """The in-process runtime readers pass ``RUNTIME_LESSON_CORPORA``, keeping the AUTHOR corpora
    out of their case trace — the actor reads lessons-actor/ tradecraft via read_file every run and
    its run_dir IS the durable bundle trace_lesson scans. Only the curators' ``lesson_read`` opts
    into the full ``LESSON_CORPORA``."""
    mod = _load()
    runtime = mod.RUNTIME_LESSON_CORPORA
    assert mod.lesson_name("/repo/defender/lessons/a.md", runtime) == "a"
    assert mod.lesson_name("/repo/defender/lessons-actor/x.md", runtime) is None
    assert mod.lesson_name("/repo/defender/lessons-environment/y.md", runtime) is None


def test_ignores_nested_and_non_md(monkeypatch, tmp_path):
    mod = _load()
    monkeypatch.setenv("DEFENDER_RUN_DIR", str(tmp_path))
    _run(mod, _read_event("/repo/defender/lessons/sub/z.md"))   # nested, parent != lessons
    _run(mod, _read_event("/repo/defender/lessons/readme.txt"))  # non-md
    assert not (tmp_path / "lessons_loaded.jsonl").exists()


def test_ignores_non_read_tool(monkeypatch, tmp_path):
    mod = _load()
    monkeypatch.setenv("DEFENDER_RUN_DIR", str(tmp_path))
    rc = mod.main(stdin=io.StringIO(json.dumps(
        {"tool_name": "Bash", "tool_input": {"command": "cat defender/lessons/foo.md"}}
    )))
    assert rc == 0
    assert not (tmp_path / "lessons_loaded.jsonl").exists()


def test_noop_without_run_dir(monkeypatch):
    mod = _load()
    monkeypatch.delenv("DEFENDER_RUN_DIR", raising=False)
    assert _run(mod, _read_event("/repo/defender/lessons/foo.md")) == 0


def test_non_dict_payload_exits_zero(monkeypatch, tmp_path):
    """A JSON array/string on stdin must not raise AttributeError — exit 0 (best-effort)."""
    mod = _load()
    monkeypatch.setenv("DEFENDER_RUN_DIR", str(tmp_path))
    assert mod.main(stdin=io.StringIO("[]")) == 0
    assert mod.main(stdin=io.StringIO('"x"')) == 0
    assert not (tmp_path / "lessons_loaded.jsonl").exists()


def test_append_oserror_exits_zero(monkeypatch, tmp_path):
    """An OSError on the append (here: target path is a directory) must degrade to
    exit 0, not surface a traceback into the run."""
    mod = _load()
    monkeypatch.setenv("DEFENDER_RUN_DIR", str(tmp_path))
    (tmp_path / "lessons_loaded.jsonl").mkdir()  # open('a') → IsADirectoryError
    assert _run(mod, _read_event("/repo/defender/lessons/foo.md")) == 0
