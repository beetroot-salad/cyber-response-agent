"""Pins for the story renderer (#711 M9).

`story.md` is deliberately an oracle INPUT, so the hidden/visible split cannot
protect it — the seed negative control's story announced that it WAS a negative
control and that a faithful oracle "must therefore return `0` for every lead".
A renderer whose only input is the runner's record structurally cannot do that,
and these tests pin both halves: that it renders what happened, and that it
refuses to emit evaluation vocabulary even if a scenario's command text carries
some.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

GOLDEN_DIR = Path(__file__).resolve().parent
REPO_ROOT = GOLDEN_DIR.parents[2]
RUNS_DIR = REPO_ROOT / "playground-v2" / "attacks" / "runs"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


STORY = _load("oracle_golden_story", GOLDEN_DIR / "story_from_run.py")

META = {
    "run_id": "r-1", "scenario_id": "s", "description": "A scenario description.",
    "resolved": {"source_user": "dev.dana", "target_host": "canary-1"},
    "started_at": "2026-07-25T07:45:32+00:00",
    "finished_at": "2026-07-25T07:48:40+00:00",
    "aborted": False,
    "steps": [{"step_index": 0, "iteration": 0, "source_host": "office-ws-1",
               "source_user": "dev.dana", "cmd": "ssh root@canary-1 true",
               "rc": 0, "stdout_tail": "Permission denied", "stderr_tail": "",
               "started_at": "2026-07-25T07:45:32+00:00",
               "ended_at": "2026-07-25T07:45:52+00:00"}],
}

RUN_RECORDS = sorted(RUNS_DIR.glob("*/meta.json")) if RUNS_DIR.is_dir() else []


def test_the_story_states_the_identity_hosts_and_commands():
    story = STORY.render_story(META)
    for fragment in ("dev.dana", "office-ws-1", "canary-1",
                     "ssh root@canary-1 true", "Permission denied",
                     "2026-07-25T07:45:32+00:00"):
        assert fragment in story, fragment


def test_the_rendered_story_carries_no_evaluation_vocabulary():
    assert STORY.leaks(STORY.render_story(META)) == []


def test_an_aborted_run_says_so():
    story = STORY.render_story({**META, "aborted": True})
    assert "aborted" in story.lower()


def test_a_leaking_command_is_refused_rather_than_written(tmp_path):
    """If a scenario's own text ever carried the scoring vocabulary, the renderer
    must fail loudly. A leaked answer inside an oracle input invalidates every
    projection the case will record, and is invisible afterwards because the story
    is SUPPOSED to be visible."""
    meta = json.loads(json.dumps(META))
    meta["steps"][0]["cmd"] = "echo 'the expected result is +event'"
    meta_path = tmp_path / "meta.json"
    meta_path.write_text(json.dumps(meta), encoding="utf-8")
    out = tmp_path / "story.md"
    assert STORY.main([str(meta_path), str(out)]) == 1
    assert not out.exists()


def test_there_are_run_records_to_check():
    """Every sweep below would pass vacuously against an empty runs/ tree."""
    assert RUN_RECORDS


@pytest.mark.parametrize("meta_path", RUN_RECORDS, ids=lambda p: p.parent.name)
def test_every_checked_in_run_record_renders_cleanly(meta_path):
    """The four committed runner records are the renderer's real corpus."""
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    story = STORY.render_story(meta)
    assert STORY.leaks(story) == []
    assert (meta.get("resolved") or {}).get("target_host", "") in story
    assert len(story.splitlines()) > 5
