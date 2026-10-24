"""A run records the commit it was made against, against real throwaway repos; the record never says something false."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.support.shared._fixture_uuid import fixture_uuid

import json
import os
from dataclasses import fields
from pathlib import Path

import pytest

from defender import _git
from defender.records import _provenance  # type: ignore[import-not-found]
from defender.records._provenance import RunProvenance  # type: ignore[import-not-found]
from defender.run_repository import PROVENANCE, RunPaths  # type: ignore[import-not-found]
from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant  # type: ignore[import-not-found]
from defender.tests.support.shared.contracts._repo import seed_repo  # type: ignore[import-not-found]

TENANT_ID = fixture_uuid("tenant:t976")


def _set_up_tenant(tmp_path, monkeypatch):
    """A fresh, accepted tenant under its own data root — every run names its tenant, and there"""
    data_root = tmp_path / "data"
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(data_root))
    return set_up_tenant(data_root, TENANT_ID)


#: The seeded file's path, spelled once: every dirt arm below edits, removes or renames it, and
#: it has to sit under `CODE_SCOPE` for the scoped bit to see it at all.
SEED = f"{_provenance.CODE_SCOPE}/seed.md"


def _repo(tmp_path: Path) -> Path:
    """A throwaway repo with one commit, through `_repo.seed_repo` rather than a fifteenth
    hand-rolled `git init` — that module exists because the same five lines had drifted across
    fourteen sites under five different placeholder identities."""
    repo = tmp_path / "repo"
    (repo / _provenance.CODE_SCOPE).mkdir(parents=True)
    (repo / SEED).write_text("seed\n", encoding="utf-8")
    return seed_repo(repo)


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
    (repo / SEED).write_text("edited\n")
    prov = _provenance.capture_tree(repo)
    assert prov.dirty is True
    assert SEED in prov.dirty_paths
    assert prov.dirty_path_count == 1


def test_untracked_file_counts_as_dirty(tmp_path):
    """`--untracked-files=all`: a file nobody added is still a file the sha does not name, so
    a stamp that called this tree clean would be describing bytes that did not run."""
    repo = _repo(tmp_path)
    (repo / _provenance.CODE_SCOPE / "stray.md").write_text("stray\n")
    prov = _provenance.capture_tree(repo)
    assert prov.dirty is True
    assert f"{_provenance.CODE_SCOPE}/stray.md" in prov.dirty_paths


def test_the_path_sample_is_capped_but_the_count_is_not(tmp_path):
    """The cap costs DETAIL and must never cost the FACT — a reader can still tell a small
    edit from a huge one, which is exactly what a silent truncation would hide."""
    repo = _repo(tmp_path)
    total = _provenance.DIRTY_PATH_SAMPLE + 7
    for i in range(total):
        (repo / _provenance.CODE_SCOPE / f"stray-{i:03d}.md").write_text("x\n")
    prov = _provenance.capture_tree(repo)
    assert len(prov.dirty_paths) == _provenance.DIRTY_PATH_SAMPLE
    assert prov.dirty_path_count == total


def test_a_tree_git_cannot_answer_for_records_unknown_not_clean(tmp_path):
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
    """A run that cannot be stamped still has to run: this is a record, not a gate."""
    repo = _repo(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    prov = _provenance.capture_tree(repo)
    assert prov.commit is None
    assert prov.dirty is None
    assert prov.unavailable is not None
    assert "unavailable" in prov.unavailable


def test_status_failing_after_a_good_sha_keeps_the_sha_and_unknowns_the_dirt(tmp_path):
    """The sha is worth keeping on its own; what is unknown is whether it describes the bytes"""
    repo = _repo(tmp_path)
    head = _git.git_head_sha(repo)
    (repo / ".git" / "index").write_bytes(b"\x00 not an index \xff" * 8)
    prov = _provenance.capture_tree(repo)
    assert prov.commit == head, "a readable HEAD was discarded because the index was not"
    assert prov.dirty is None
    assert prov.unavailable


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


def test_materialize_run_dir_stamps_every_run(tmp_path, monkeypatch):
    from defender import run_common

    tenant = _set_up_tenant(tmp_path, monkeypatch)
    alert = tmp_path / "alert.json"
    alert.write_text(json.dumps({"id": "a1"}))

    run_dir = run_common.materialize_run(alert, tenant=tenant).run_dir
    stamp = RunPaths(run_dir).provenance
    assert stamp.is_file()
    rec = _provenance.read(stamp)
    assert rec is not None
    # The suite runs inside this repo, so the capture is a real one: a sha, or an explicit
    # reason there is none. What it must never be is silence.
    assert rec.commit is not None or rec.unavailable is not None



@pytest.mark.parametrize("dirty", [True, False, None])
def test_the_three_valued_dirt_survives_the_round_trip(tmp_path, dirty):
    """`None` must come back as `None`. A JSON round trip that folded it to `false` would
    reintroduce the exact lie the three-valued field exists to prevent."""
    path = tmp_path / "p.json"
    _provenance.write(path, RunProvenance(commit="a" * 40, dirty=dirty))
    rec = _provenance.read(path)
    assert rec is not None, "the round trip lost the record entirely"
    assert rec.dirty is dirty


def test_a_git_that_cannot_be_EXECUTED_is_recorded_rather_than_raised(tmp_path, monkeypatch):
    """The failure an absent-binary arm does NOT cover."""
    repo = _repo(tmp_path)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    broken = fake_bin / "git"
    broken.write_text("this is not a program\n", encoding="utf-8")
    broken.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))

    prov = _provenance.capture_tree(repo)
    assert prov.commit is None
    assert prov.dirty is None
    assert prov.unavailable


def test_a_stamp_that_is_a_planted_link_reads_as_no_stamp(tmp_path):
    real = tmp_path / "elsewhere.json"
    _provenance.write(real, RunProvenance(commit="b" * 40, dirty=False))
    planted = tmp_path / PROVENANCE
    planted.symlink_to(real)
    assert _provenance.read(planted) is None


def test_a_deeply_nested_payload_reads_as_no_stamp(tmp_path):
    path = tmp_path / PROVENANCE
    path.write_text("[" * 200_000 + "]" * 200_000, encoding="utf-8")
    assert _provenance.read(path) is None


@pytest.mark.parametrize(
    "doc",
    [
        {},
        {"commit": None, "dirty": None},
        {"commit": None, "dirty": False},
        {"commit": None, "dirty": True},
        {"commit": "", "dirty": False},
        {"commit": "", "dirty": None},
    ],
)
def test_a_record_capture_cannot_produce_is_not_a_record(tmp_path, doc):
    """Type-checking each field alone is not enough."""
    path = tmp_path / PROVENANCE
    path.write_text(json.dumps(doc), encoding="utf-8")
    assert _provenance.read(path) is None


def test_every_field_reaches_the_wire_and_comes_back(tmp_path):
    """`as_json` spells the wire shape out, which makes it a SECOND census of the class's"""
    declared = {f.name for f in fields(RunProvenance)}
    on_disk = json.loads(RunProvenance(commit="a" * 40, dirty=False).as_json())
    assert set(on_disk) == declared, (
        f"the wire shape and the record's fields disagree: {declared ^ set(on_disk)}"
    )
    # #1204: the tenant knowledge revision rides in the same record, so the rich record carries
    # one — imported HERE, not at module top, so a tree without it fails this arm alone.
    from defender.records._provenance import KnowledgeRevision  # type: ignore[attr-defined]

    rich = RunProvenance(
        commit="a" * 40, dirty=True, dirty_paths=("x.md", "y.md"), dirty_path_count=2,
        unavailable=None, knowledge=KnowledgeRevision.at("c" * 40),
    )
    path = tmp_path / PROVENANCE
    _provenance.write(path, rich)
    assert _provenance.read(path) == rich
    assert json.loads(path.read_text(encoding="utf-8"))["knowledge"] == {"commit": "c" * 40}


def test_a_rename_counts_both_paths_the_sha_fails_to_name(tmp_path):
    """The count must not UNDER-report, which is the direction that would be a lie."""
    repo = _repo(tmp_path)
    (repo / _provenance.CODE_SCOPE / "moved.md").write_text("moved\n", encoding="utf-8")
    _git.git(["add", "-A"], cwd=repo)
    _git.git(["commit", "-qm", "add"], cwd=repo)
    scope = _provenance.CODE_SCOPE
    _git.git(["mv", f"{scope}/moved.md", f"{scope}/elsewhere.md"], cwd=repo)

    prov = _provenance.capture_tree(repo)
    assert prov.dirty is True
    assert set(prov.dirty_paths) == {
        f"{scope}/moved.md", f"{scope}/elsewhere.md",
    }, prov.dirty_paths
    assert prov.dirty_path_count == 2, "a rename hid the path the sha no longer names"


def test_one_dirty_path_earning_two_status_records_is_counted_once(tmp_path):
    """`git status -z` emits one record per (path, reason) and a single path can earn two: `git rm --cached foo` leaves `D foo` AND `??"""
    repo = _repo(tmp_path)
    _git.git(["rm", "--cached", "-q", SEED], cwd=repo)

    prov = _provenance.capture_tree(repo)
    assert prov.dirty is True
    assert prov.dirty_paths == (SEED,), prov.dirty_paths
    assert prov.dirty_path_count == 1, "one dirty path was counted once per status record"


# The scoped dirt, the build stamp, the non-fatal write, the shared family
# capture, the archive copy, and the read gate (#976 follow-ups).


def test_dirt_is_scoped_to_the_code_the_box_mounts(tmp_path):
    """A scratch file outside the mounted package must not mark the run dirty."""
    repo = _repo(tmp_path)
    (repo / "docs").mkdir()
    (repo / "docs" / "note.md").write_text("scratch\n")
    (repo / "experiments").mkdir()
    (repo / "experiments" / "x.py").write_text("x\n")
    prov = _provenance.capture_tree(repo)
    assert prov.dirty is False, f"an out-of-scope edit set the bit: {prov.dirty_paths}"
    assert prov.scope == _provenance.CODE_SCOPE


def test_dirt_inside_the_mounted_code_still_counts(tmp_path):
    repo = _repo(tmp_path)
    (repo / _provenance.CODE_SCOPE / "thing.py").write_text("x\n")
    prov = _provenance.capture_tree(repo)
    assert prov.dirty is True
    assert prov.dirty_paths == (f"{_provenance.CODE_SCOPE}/thing.py",)


def test_the_build_stamp_answers_when_git_cannot(tmp_path, monkeypatch):
    plain = tmp_path / "no-repo"
    plain.mkdir()
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    prov = _provenance.capture_tree(plain, environ={_provenance.BUILD_COMMIT_ENV: "b" * 40})
    assert prov.commit == "b" * 40
    assert prov.unavailable is not None
    assert _provenance.BUILD_COMMIT_ENV in prov.unavailable


def test_a_live_sha_is_never_replaced_by_a_stale_baked_one(tmp_path):
    """Git answered for HEAD; only the working-tree question failed. Falling back here would
    swap a true sha for whatever an image was built from months ago."""
    repo = _repo(tmp_path)
    head = _git.git_head_sha(repo)
    (repo / ".git" / "index").write_bytes(b"\x00 not an index \xff" * 8)
    prov = _provenance.capture_tree(repo, environ={_provenance.BUILD_COMMIT_ENV: "d" * 40})
    assert prov.commit == head
    assert prov.dirty is None


def test_a_read_refuses_a_hard_link_the_write_would_refuse(tmp_path):
    real = tmp_path / "real.json"
    _provenance.write(real, RunProvenance(commit="a" * 40, dirty=False))
    link = tmp_path / "provenance.json"
    os.link(real, link)
    assert _provenance.read(link) is None, "a hard-linked stamp was read as this run's own"
    with pytest.raises(OSError, match="aliased entry"):
        _provenance.write(link, RunProvenance(commit="b" * 40, dirty=False))


def test_a_stamp_that_cannot_be_written_does_not_take_the_run_down(tmp_path, monkeypatch, capsys):
    from defender import run_common

    tenant = _set_up_tenant(tmp_path, monkeypatch)
    runs = location_path(tenant.runs)
    alert = tmp_path / "alert.json"
    alert.write_text(json.dumps({"id": "a1"}))
    # A real failure, not an authored exception: a DIRECTORY at the stamp's name is one of the
    # shapes `write_guarded` refuses. #1279 (conflict updated): setup takes no id and never
    # resumes a dir, so a crashed run's leftover can no longer be planted at a chosen id; the
    # obstruction is planted in a minted run's dir, between its creation and its stamp, and the
    # stamp step is driven directly.
    run = tenant.runs_repository().create()
    run.make_run_dir()
    (run.run_dir / PROVENANCE).mkdir()

    run_common._stamp(run, knowledge_dir=tenant.knowledge)

    assert "could not stamp" in capsys.readouterr().err
    assert (run.run_dir / PROVENANCE).is_dir(), "the refusal removed the obstruction"
    assert run.run_dir.parent == runs



def test_each_materialised_run_takes_its_own_capture(tmp_path, monkeypatch):
    from defender import run_common

    tenant = _set_up_tenant(tmp_path, monkeypatch)
    runs = location_path(tenant.runs)
    alert = tmp_path / "alert.json"
    alert.write_text(json.dumps({"id": "a1"}))
    run_dir = run_common.materialize_run(alert, tenant=tenant).run_dir
    rec = _provenance.read(RunPaths(run_dir).provenance)
    assert rec is not None
    assert rec.commit is not None or rec.unavailable is not None
    # "No seam" is a fact about the signature, pinned as one: a `provenance=` keyword is the
    # hoisted-capture path this change removed, and it is refused rather than accepted and
    # ignored. Refused BEFORE the run dir exists, so the id is not burned by the attempt.
    handed = RunProvenance(commit="e" * 40, dirty=False, scope=_provenance.CODE_SCOPE)
    before = sorted(p.name for p in runs.iterdir())
    with pytest.raises(TypeError):
        run_common.materialize_run(alert, tenant=tenant, provenance=handed)
    assert sorted(p.name for p in runs.iterdir()) == before



# The coherence rules as a CONSTRUCTOR invariant, not a parser habit.

IMPOSSIBLE = {
    "says nothing at all": (
        {"commit": None, "dirty": None}, "says nothing"),
    "clean bill of health with no sha": (
        {"commit": None, "dirty": False}, "no commit was"),
    "dirt answered for with no sha": (
        {"commit": None, "dirty": True}, "no commit was"),
    "an empty string is not a sha": (
        {"commit": "", "dirty": False}, "not a sha"),
    "a blank string is not a sha": (
        {"commit": "   ", "dirty": False}, "not a sha"),
    "a clean tree carrying dirty paths": (
        {"commit": "a" * 40, "dirty": False, "dirty_paths": ("x.md",), "dirty_path_count": 1},
        "clean tree cannot carry"),
    "a clean tree carrying a dirt count": (
        {"commit": "a" * 40, "dirty": False, "dirty_path_count": 3},
        "clean tree cannot carry"),
    "a sample larger than the total it samples": (
        {"commit": "a" * 40, "dirty": True, "dirty_paths": ("x.md", "y.md"),
         "dirty_path_count": 1},
        "larger than the count"),
    "a negative count": (
        {"commit": "a" * 40, "dirty": True, "dirty_path_count": -1},
        "larger than the count"),
}


@pytest.mark.parametrize("why", sorted(IMPOSSIBLE))
def test_nothing_can_construct_a_record_no_capture_could_produce(why):
    """THE POINT OF MOVING THESE ONTO THE CLASS."""
    kwargs, refusal = IMPOSSIBLE[why]
    with pytest.raises(ValueError, match=refusal):
        RunProvenance(**kwargs)


def test_a_truncated_sha_on_disk_reads_as_no_stamp(tmp_path):
    """`{"commit": ""}` is what a torn write leaves. It folds to absent in the parser and is
    then refused by the class for having no reason behind it — one rule, reached two ways."""
    path = tmp_path / "torn.json"
    path.write_text(json.dumps({"commit": "", "dirty": None, "unavailable": None}))
    assert _provenance.read(path) is None
