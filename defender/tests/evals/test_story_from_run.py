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

GOLDEN_DIR = Path(__file__).resolve().parents[2] / "evals" / "oracle_golden"
REPO_ROOT = GOLDEN_DIR.parents[2]
# `playground-v2/attacks/runs/` is `*`-ignored, so the runner records this suite
# sweeps existed only on the machine that produced them — the sweep collected
# nothing anywhere else and its guard failed. The corpus is checked in here
# instead; the live tree is still swept when a machine has one, so a run whose
# shape the renderer cannot handle is caught before it is snapshotted.
FIXTURE_RUNS_DIR = Path(__file__).resolve().parent / "_run_records"
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


def _run_records() -> list[Path]:
    """The checked-in corpus, plus any live run the local tree has that it lacks."""
    records = sorted(FIXTURE_RUNS_DIR.glob("*/meta.json"))
    seen = {p.parent.name for p in records}
    if RUNS_DIR.is_dir():
        records += [p for p in sorted(RUNS_DIR.glob("*/meta.json"))
                    if p.parent.name not in seen]
    return records


RUN_RECORDS = _run_records()


def test_the_story_states_the_identity_hosts_and_commands():
    story = STORY.render_story(META)
    for fragment in ("dev.dana", "office-ws-1", "canary-1",
                     "ssh root@canary-1 true", "Permission denied",
                     "2026-07-25T07:45:32+00:00"):
        assert fragment in story, fragment


def test_the_rendered_story_carries_no_evaluation_vocabulary():
    assert STORY.eval_tells_in(STORY.render_story(META)) == []


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
    """Every sweep below would pass vacuously against an empty corpus."""
    assert sorted(FIXTURE_RUNS_DIR.glob("*/meta.json"))


@pytest.mark.parametrize("meta_path", RUN_RECORDS, ids=lambda p: p.parent.name)
def test_every_checked_in_run_record_renders_cleanly(meta_path):
    """The checked-in runner records are the renderer's real corpus."""
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    story = STORY.render_story(meta)
    assert STORY.eval_tells_in(story) == []
    assert (meta.get("resolved") or {}).get("target_host", "") in story
    assert len(story.splitlines()) > 5


def test_the_catalog_description_is_not_rendered():
    """A retargeted run's catalog description names the scenario's DEFAULT target,
    so rendering it puts two different targets in one oracle input. `--target db-1`
    on ssh-brute-force-canary produced a story whose header said db-1 and whose
    description said "hammers canary-1's SSH". Any projection over that measures
    the contradiction, not the oracle — two #711 pilot cases were retired for it."""
    meta = {**META, "description": "hammers canary-1's SSH from a workstation",
            "resolved": {"source_user": "sre.alice", "target_host": "db-1"},
            "steps": [{**META["steps"][0], "cmd": "ssh root@db-1 true"}]}
    story = STORY.render_story(meta)
    assert "canary-1" not in story, "the scenario's DEFAULT target leaked into the story"
    assert "db-1" in story


@pytest.mark.parametrize("meta_path", RUN_RECORDS, ids=lambda p: p.parent.name)
def test_no_checked_in_record_renders_a_second_target(meta_path):
    """Whatever else a story says, the only host it may name as the target is the
    one the runner resolved."""
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    target = (meta.get("resolved") or {}).get("target_host")
    if not target:
        pytest.skip("record carries no resolved target")
    story = STORY.render_story(meta)
    others = {s.get("source_host") for s in meta.get("steps") or []} - {None}
    hosts = {"canary-1", "db-1", "web-1", "web-2", "jump-box-1",
             "dev-ws-1", "office-ws-1", "office-ws-2"}
    named = {h for h in hosts if h in story}
    assert named <= ({target} | others), (
        f"story names hosts beyond the resolved target and its sources: "
        f"{sorted(named - ({target} | others))}")
