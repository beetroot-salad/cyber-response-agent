"""Tests for defender/hooks/record_lesson_load.py.

PostToolUse-on-Read hook: appends a {lesson_name, ts} row to
{DEFENDER_RUN_DIR}/lessons_loaded.jsonl for each Read of a defender/lessons/*.md
file. Scoped to the runtime corpus only; always exits 0.
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


def test_ignores_author_corpora(monkeypatch, tmp_path):
    """lessons-actor/ and lessons-environment/ are author corpora the runtime never
    loads — a Read of them must not be recorded."""
    mod = _load()
    monkeypatch.setenv("DEFENDER_RUN_DIR", str(tmp_path))
    for fp in ("/repo/defender/lessons-actor/x.md",
               "/repo/defender/lessons-environment/y.md"):
        _run(mod, _read_event(fp))
    assert not (tmp_path / "lessons_loaded.jsonl").exists()


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
