"""A run records the commit it was made against (#976).

Against real throwaway repos rather than a faked git runner — git is local and deterministic,
so the facade is exercised for real (the #389 / #460 philosophy, as `test_git.py` states it).

The property under test is not "a field exists". It is that the record cannot quietly say
something FALSE: an unknown never reads as clean, a capped path sample never hides the true
count, and a run whose tree could not be interrogated at all still runs.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender import _git, _provenance  # type: ignore[import-not-found]
from defender._provenance import RunProvenance  # type: ignore[import-not-found]
from defender._run_paths import RunPaths  # type: ignore[import-not-found]


def _repo(tmp_path: Path, name: str = "repo") -> Path:
    repo = tmp_path / name
    repo.mkdir()
    _git.git(["init", "-q", "-b", "main"], cwd=repo)
    _git.git(["config", "user.email", "t@t"], cwd=repo)
    _git.git(["config", "user.name", "t"], cwd=repo)
    (repo / "seed.md").write_text("seed\n")
    _git.git(["add", "-A"], cwd=repo)
    _git.git(["commit", "-q", "-m", "seed"], cwd=repo)
    return repo


def test_clean_tree_records_the_head_sha_and_no_dirt(tmp_path):
    repo = _repo(tmp_path)
    prov = _provenance.capture_tree(repo)
    assert prov.commit == _git.git_head_sha(repo)
    assert prov.dirty is False
    assert prov.dirty_paths == ()
    assert prov.dirty_path_count == 0
    assert prov.unavailable is None


def test_uncommitted_edit_is_recorded_as_dirty_with_the_path(tmp_path):
    repo = _repo(tmp_path)
    (repo / "seed.md").write_text("edited\n")
    prov = _provenance.capture_tree(repo)
    assert prov.dirty is True
    assert "seed.md" in prov.dirty_paths
    assert prov.dirty_path_count == 1


def test_untracked_file_counts_as_dirty(tmp_path):
    """`--untracked-files=all`: a file nobody added is still a file the sha does not name, so
    a stamp that called this tree clean would be describing bytes that did not run."""
    repo = _repo(tmp_path)
    (repo / "stray.md").write_text("stray\n")
    prov = _provenance.capture_tree(repo)
    assert prov.dirty is True
    assert "stray.md" in prov.dirty_paths


def test_the_path_sample_is_capped_but_the_count_is_not(tmp_path):
    """The cap costs DETAIL and must never cost the FACT — a reader can still tell a small
    edit from a huge one, which is exactly what a silent truncation would hide."""
    repo = _repo(tmp_path)
    total = _provenance.DIRTY_PATH_SAMPLE + 7
    for i in range(total):
        (repo / f"stray-{i:03d}.md").write_text("x\n")
    prov = _provenance.capture_tree(repo)
    assert len(prov.dirty_paths) == _provenance.DIRTY_PATH_SAMPLE
    assert prov.dirty_path_count == total


def test_a_tree_git_cannot_answer_for_records_unknown_not_clean(tmp_path):
    """THE ONE ERROR THIS RECORD MUST NOT MAKE. A directory that is not a repository has no
    sha, and `dirty` stays `None` — collapsing it to `False` would file an unknown as a clean
    bill of health, which every downstream consumer reads as "the sha names the bytes"."""
    plain = tmp_path / "not-a-repo"
    plain.mkdir()
    prov = _provenance.capture_tree(plain)
    assert prov.commit is None
    assert prov.dirty is None
    assert prov.dirty is not False
    assert prov.unavailable is not None


def test_an_unborn_head_is_reported_with_its_reason(tmp_path):
    """A freshly-`init`ed tree has no HEAD to name. It is a different operator problem from
    "git is not installed", so the reason is kept rather than flattened to a bare `None`."""
    repo = tmp_path / "fresh"
    repo.mkdir()
    _git.git(["init", "-q", "-b", "main"], cwd=repo)
    prov = _provenance.capture_tree(repo)
    assert prov.commit is None
    assert prov.dirty is None
    assert prov.unavailable


def test_capture_never_raises_when_git_is_not_on_path(tmp_path, monkeypatch):
    """A run that cannot be stamped still has to run: this is a record, not a gate.

    Driven by emptying PATH rather than by patching the facade, so the exception is the REAL
    one this arm exists for: with no `git` to resolve, `subprocess` raises before git can
    report anything, so it is not a `GitError` and would otherwise escape as an unhandled
    OSError out of run-dir creation — the one shape a `GitError`-only handler misses."""
    repo = _repo(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    prov = _provenance.capture_tree(repo)
    assert prov.commit is None
    assert prov.dirty is None
    assert "unavailable" in prov.unavailable


def test_status_failing_after_a_good_sha_keeps_the_sha_and_unknowns_the_dirt(tmp_path):
    """The sha is worth keeping on its own; what is unknown is whether it describes the bytes
    that ran, and `dirty=None` is exactly that statement rather than a discarded record.

    A corrupted index is a REAL split between the two calls rather than an authored one:
    `rev-parse HEAD` reads refs and still answers, while `status` must read the index and
    cannot. Nothing else in this module can produce that asymmetry honestly."""
    repo = _repo(tmp_path)
    head = _git.git_head_sha(repo)
    (repo / ".git" / "index").write_bytes(b"\x00 not an index \xff" * 8)
    prov = _provenance.capture_tree(repo)
    assert prov.commit == head, "a readable HEAD was discarded because the index was not"
    assert prov.dirty is None
    assert prov.unavailable


def test_round_trips_through_disk(tmp_path):
    prov = RunProvenance(
        commit="a" * 40, dirty=True, dirty_paths=("x.md",), dirty_path_count=1
    )
    path = tmp_path / "provenance.json"
    _provenance.write(path, prov)
    assert _provenance.read(path) == prov


def test_a_missing_or_junk_stamp_reads_as_no_stamp(tmp_path):
    """This file sits in the box's rw bind, so a reader must treat whatever is there as
    arbitrary and answer "no usable record" rather than raise out of an archive walk."""
    assert _provenance.read(tmp_path / "absent.json") is None
    junk = tmp_path / "junk.json"
    junk.write_text("not json{")
    assert _provenance.read(junk) is None
    listy = tmp_path / "listy.json"
    listy.write_text(json.dumps(["not", "a", "record"]))
    assert _provenance.read(listy) is None
    wrong_type = tmp_path / "wrong.json"
    wrong_type.write_text(json.dumps({"commit": 17, "dirty": False}))
    assert _provenance.read(wrong_type) is None


def test_a_bool_is_not_accepted_as_the_path_count(tmp_path):
    """`isinstance(True, int)` is True in Python, so a `dirty_path_count` of `true` would
    otherwise be read back as the number 1 — a count nobody wrote."""
    path = tmp_path / "p.json"
    path.write_text(json.dumps({"commit": "a" * 40, "dirty": True, "dirty_path_count": True}))
    rec = _provenance.read(path)
    assert rec is not None
    assert rec.dirty_path_count == 0


def test_materialize_run_dir_stamps_every_run(tmp_path, monkeypatch):
    """Stamped at the ONE place a run bundle is created, so no caller can forget — the branch
    launcher materialises its siblings through this same call, which is what makes a family's
    worlds comparable on their code rather than merely assumed to be."""
    from defender import run_common

    runs = tmp_path / "runs"
    runs.mkdir()
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(runs))
    alert = tmp_path / "alert.json"
    alert.write_text(json.dumps({"id": "a1"}))

    run_dir = run_common.materialize_run_dir(alert, "20260101T000000Z-a1")
    stamp = RunPaths(run_dir).provenance
    assert stamp.is_file()
    rec = _provenance.read(stamp)
    assert rec is not None
    # The suite runs inside this repo, so the capture is a real one: a sha, or an explicit
    # reason there is none. What it must never be is silence.
    assert rec.commit is not None or rec.unavailable is not None


def test_the_stamp_is_not_named_in_the_model_facing_map(tmp_path):
    """The map IS the model's directory view. The run's record of its own build is
    infrastructure the operator reads, not a surface the investigator should reason about."""
    from defender.scripts import workspace_map

    assert "provenance.json" in workspace_map._UNLISTED
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    _provenance.write(RunPaths(run_dir).provenance, RunProvenance(commit="a" * 40, dirty=False))
    assert "provenance.json" not in workspace_map.workspace_map(run_dir)


@pytest.mark.parametrize("dirty", [True, False, None])
def test_the_three_valued_dirt_survives_the_round_trip(tmp_path, dirty):
    """`None` must come back as `None`. A JSON round trip that folded it to `false` would
    reintroduce the exact lie the three-valued field exists to prevent."""
    path = tmp_path / "p.json"
    _provenance.write(path, RunProvenance(commit="a" * 40, dirty=dirty))
    assert _provenance.read(path).dirty is dirty
