"""#747 — a tainted drain worktree is archived (inert tar + manifest, capped by refusal, never evicting) before the finally that cleans it up; the taint still propagates and nothing is pushed."""
from __future__ import annotations

import json
import os
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from defender.learning.core.faults import SYSTEMIC_FAULTS, run_or_dead_letter  # noqa: E402
from defender.box import RunTainted, scrub  # noqa: E402
from defender.tests.e2e._box665 import (  # noqa: E402
    BoxLifecycleRecorder,
    RecordingBranch,
    drive_worktree_batch,
)


PLANTED_TARGET = "/root/.ssh/id_rsa"


def _tainting_scrub(planted_name: str = "stolen.json"):
    """A scrub that plants a real symlink in the tree and then runs the REAL scrub over it."""
    def go(tree: Path) -> None:
        os.symlink(PLANTED_TARGET, tree / planted_name)
        scrub(tree)
    return go


def _drive_tainted(tmp_path, *, branch=None, do_work=None, planted="stolen.json"):
    rec = BoxLifecycleRecorder(events=[])
    if branch is None:
        branch = RecordingBranch(
            tmp_path / "wt", events=rec.events, destroy_on_cleanup=True,
        )
    rec.scrub = _tainting_scrub(planted)

    def ok_work(wt_paths, *, box=None):
        (Path(wt_paths.repo_root) / "lesson.md").write_text("a lesson\n", encoding="utf-8")

    with pytest.raises(RunTainted) as caught:
        drive_worktree_batch(
            tmp_path, rec, do_work=do_work if do_work is not None else ok_work, branch=branch,
        )
    return branch, caught.value


def test_the_tainted_tree_is_preserved_as_an_archive(tmp_path):
    """d_tainted_tree_is_preserved (#747, O1) — the drain archives the worktree before the
    `finally` destroys it, and the archive CONTAINS the planted entry."""
    branch, _ = _drive_tainted(tmp_path)

    archives = sorted(branch.quarantine_dir.glob("*.tar.gz"))
    assert len(archives) == 1, f"expected one archive, got {archives}"

    with tarfile.open(archives[0]) as tar:
        members = {Path(m.name).name: m for m in tar.getmembers()}
    assert "stolen.json" in members, f"the planted entry is not in the archive: {members}"
    planted = members["stolen.json"]
    assert planted.issym(), "the planted entry was not stored as a symlink member"
    assert planted.linkname == PLANTED_TARGET, \
        f"the archive lost where the link pointed: {planted.linkname!r}"
    assert "lesson.md" in members, \
        "the curator's uncommitted edit was not preserved — it exists nowhere else"


def test_the_archive_holds_no_live_link_and_the_tree_is_gone(tmp_path):
    """d_quarantine_is_inert (#747, O4) — the negative universal: no live symlink the box created
    survives anywhere on the host once the lane exits."""
    branch, _ = _drive_tainted(tmp_path)

    assert list(branch.quarantine_dir.glob("*.tar.gz")), \
        "nothing was preserved — the link sweep below would be vacuous"

    live = [
        Path(parent) / name
        for parent, dirs, files in os.walk(branch.quarantine_dir)
        for name in (*dirs, *files)
        if os.path.islink(Path(parent) / name)
    ]
    assert live == [], f"quarantine holds live, dereferenceable links: {live}"

    surviving = list((tmp_path / "wt").glob("lessons-*"))
    assert surviving == [], f"the worktree outlived cleanup: {surviving}"


def test_the_taint_still_propagates_and_nothing_is_pushed(tmp_path):
    """d_preserve_does_not_swallow (#747, O1 + O5) — preserving the tree must not swallow the
    signal that it is tainted, and must not disturb the supply-chain ordering."""
    branch, taint = _drive_tainted(tmp_path)

    assert isinstance(taint, RunTainted)
    assert branch.finished == [], "a tainted batch reached the commit+push+PR step"
    assert not any(e.startswith("finish_batch") for e in branch.events), \
        "the supply-chain step ran on a tainted tree"
    assert "cleanup" in branch.events, "the tree must still be destroyed (M5)"


def test_the_manifest_records_the_findings_and_the_displaced_fault(tmp_path):
    """d_manifest_records_triage_facts (#747) — the manifest sits BESIDE the archive and carries
    what triage runs on without anyone unpacking anything."""
    boom = RuntimeError("the curator exploded")

    def crashing_work(wt_paths, *, box=None):
        raise boom

    branch, _ = _drive_tainted(tmp_path, do_work=crashing_work)

    manifests = sorted(branch.quarantine_dir.glob("*.json"))
    assert len(manifests) == 1, f"expected one manifest, got {manifests}"
    doc = json.loads(manifests[0].read_text(encoding="utf-8"))

    assert doc["label"] == "author_drain", f"the manifest names the wrong lane: {doc['label']!r}"
    assert doc["branch"].endswith(doc["batch_id"]), \
        f"the manifest does not name the real branch: {doc['branch']!r}"
    assert "the curator exploded" in doc["cause"], \
        "the fault the taint displaced was not recorded"

    targets = [f["target"] for f in doc["findings"]]
    assert PLANTED_TARGET in targets, \
        f"the manifest dropped where the link pointed: {doc['findings']}"


def test_quarantine_refuses_past_the_cap_and_evicts_nothing(tmp_path, monkeypatch):
    """d_quarantine_caps_without_evicting (#747, O6 + N1) — past the cap the lane refuses to
    write a new archive, and every archive already held is untouched."""
    monkeypatch.setenv("LEARNING_TAINT_QUARANTINE_MAX", "2")
    base = tmp_path / "wt"
    qdir = base / "quarantine"
    qdir.mkdir(parents=True)
    held = {}
    for i in range(2):
        p = qdir / f"older-{i}.tar.gz"
        p.write_bytes(f"older archive {i}".encode())
        held[p] = p.read_bytes()

    branch = RecordingBranch(base, events=[], destroy_on_cleanup=True)
    _drive_tainted(tmp_path, branch=branch)

    assert sorted(qdir.glob("*.tar.gz")) == sorted(held), \
        "the cap evicted or added an archive instead of refusing"
    for p, blob in held.items():
        assert p.read_bytes() == blob, f"{p.name} was modified"

    monkeypatch.setenv("LEARNING_TAINT_QUARANTINE_MAX", "9")
    control = RecordingBranch(tmp_path / "wt2", events=[], destroy_on_cleanup=True)
    _drive_tainted(tmp_path, branch=control)
    assert list(control.quarantine_dir.glob("*.tar.gz")), \
        "the control never archived either — the refusal above was vacuous"


def test_a_failure_to_quarantine_does_not_replace_the_taint(tmp_path, capsys):
    """d_preserve_failure_never_masks_the_taint (#747) — if archiving fails, the taint still
    propagates unchanged, and the failure is LOUD."""
    branch = RecordingBranch(tmp_path / "wt", events=[], destroy_on_cleanup=True)
    branch.quarantine_dir.parent.mkdir(parents=True, exist_ok=True)
    branch.quarantine_dir.write_text("not a directory\n", encoding="utf-8")

    _, taint = _drive_tainted(tmp_path, branch=branch)

    err = capsys.readouterr().err
    assert "FAILED to quarantine" in err, \
        "the preserve step failed silently — indistinguishable from never having run"

    assert isinstance(taint, RunTainted)
    assert taint.findings, "the taint's own findings were disturbed by the failed preserve"
    assert branch.quarantine_dir.is_file(), "the blocking path was clobbered"


def test_run_tainted_is_a_systemic_fault(tmp_path):
    """d_taint_is_systemic (#747, O3 + M2) — `RunTainted` is classified with the systemic faults,
    which has two consequences and both are wanted."""
    from defender.learning.core.cli import _run_stage

    assert RunTainted in SYSTEMIC_FAULTS

    def tainting_stage() -> int:
        raise RunTainted("planted link")

    assert _run_stage(tainting_stage) == 2

    dead_lettered: list[Exception] = []
    with pytest.raises(RunTainted):
        run_or_dead_letter(tainting_stage, dead_lettered.append)
    assert dead_lettered == [], "a taint was filed as an ordinary per-item failure"
