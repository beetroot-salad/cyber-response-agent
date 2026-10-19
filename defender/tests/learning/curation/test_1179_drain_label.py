from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from defender.learning.author.branch import AuthorBranch, BranchError
from defender.learning.core import drains
from defender.learning.core.state import LEAD_QUEUE_LOCK, TRY_ONCE
from defender.learning.core.config import (
    AUTHOR_DRAIN_LABEL, LEAD_AUTHOR_DRAIN_LABEL, DrainLabel, LoopPaths,
)
from defender.learning.core.quarantine import preserve_tainted_tree
from defender.learning.leads import lead_author
from defender.learning.leads.lead_author import LeadAuthorError
from defender.box import _scrub as scrub_mod
from defender.tests.support.learning.core._state1135 import curation_run_dir, run_of, state_for_paths
from defender.tests.support.learning.curation._tree_listing_1134 import descriptors_under
from defender.tests.e2e import _box665 as B
from defender.tests.learning.curation.test_1134_mount_list import UNKNOWN_LABELS

VALUES = {AUTHOR_DRAIN_LABEL: "author_drain", LEAD_AUTHOR_DRAIN_LABEL: "lead_author_drain"}
MEMBERS = list(VALUES)
#: Non-members, as `test_1134_mount_list` spells them: values and names as strings, look-alikes,
#: `.value` carriers, near misses.
NON_MEMBERS = list(UNKNOWN_LABELS)
#: What a member's display would leak if formatted as the enum's own `str`/`repr`.
LEAKS = ("DrainLabel", "<", "AUTHOR:")


def _paths(tmp_path: Path) -> LoopPaths:
    repo = tmp_path / "repo"
    (repo / "defender").mkdir(parents=True, exist_ok=True)
    (tmp_path / "state").mkdir(parents=True, exist_ok=True)  # the root is never created lazily (#1135)
    return LoopPaths(repo_root=repo, state_dir=tmp_path / "state")


def _assert_shows_value(text: str, label: DrainLabel) -> None:
    assert VALUES[label] in text, text
    for leak in LEAKS:
        assert leak not in text, (leak, text)


@pytest.mark.parametrize("label", MEMBERS, ids=lambda m: m.value)
def test_the_pending_delivery_record_writes_the_labels_value(tmp_path: Path, label: DrainLabel):
    paths = _paths(tmp_path)
    branch = AuthorBranch(repo_root=paths.repo_root, worktree_base=tmp_path / "wts")

    drains._record_pending_delivery(state_for_paths(paths), branch, "batch-7", label=label, reason="push failed")

    [record] = sorted((paths.state_root / "_pending_delivery").glob("*.json"))
    doc = json.loads(record.read_text(encoding="utf-8"))
    assert doc["label"] == VALUES[label]
    assert type(doc["label"]) is str
    assert doc["batch_id"] == "batch-7"
    assert doc["branch"] == branch.branch_name("batch-7")
    assert doc["reason"] == "push failed"


def _tainted(tree: Path) -> scrub_mod.RunTainted:
    """A real taint: a link planted in a real tree, caught by the real scrub."""
    tree.mkdir(parents=True)
    (tree / "lesson.md").write_text("ok\n", encoding="utf-8")
    os.symlink("/etc/passwd", tree / "stolen.md")
    try:
        scrub_mod.scrub(tree)
    except scrub_mod.RunTainted as taint:
        return taint
    raise AssertionError("the planted link did not taint the tree: the drive is vacuous")


@pytest.mark.parametrize("label", MEMBERS, ids=lambda m: m.value)
def test_the_quarantine_manifest_writes_the_labels_value_and_logs_it(
        tmp_path: Path, label: DrainLabel, caplog: pytest.LogCaptureFixture):
    wt = tmp_path / "wt"
    taint = _tainted(wt)
    qdir = tmp_path / "quarantine"

    with caplog.at_level(logging.WARNING):
        archive = preserve_tainted_tree(
            wt, qdir, batch_id="batch-9", branch="lessons/batch-9", label=label, taint=taint)

    assert archive == qdir / "batch-9.tar.gz"
    assert archive.is_file()
    manifest = qdir / "batch-9.json"
    assert manifest.is_file(), f"no manifest beside the archive; logs: {caplog.text}"
    doc = json.loads(manifest.read_text(encoding="utf-8"))
    assert doc["label"] == VALUES[label]
    assert type(doc["label"]) is str
    assert doc["batch_id"] == "batch-9"
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR], caplog.text
    [preserved] = [r.getMessage() for r in caplog.records if "preserved at" in r.getMessage()]
    _assert_shows_value(preserved, label)


@pytest.mark.parametrize("label", MEMBERS, ids=lambda m: m.value)
def test_the_claim_log_shows_the_labels_value(
        tmp_path: Path, label: DrainLabel, caplog: pytest.LogCaptureFixture):
    state = state_for_paths(_paths(tmp_path))
    with caplog.at_level(logging.INFO):
        assert list(state.claim(
            "run_id", label=label, noun="authoring")) == []  # type: ignore[arg-type]
    [line] = [r.getMessage() for r in caplog.records if "queued for authoring" in r.getMessage()]
    _assert_shows_value(line, label)
    assert line.startswith(f"{VALUES[label]}: ")


def test_the_lead_author_refusal_names_the_labels_value(tmp_path: Path):
    run = run_of(curation_run_dir("run"))  # the opened run the lane is handed (#1105 PR 2)
    paths = _paths(tmp_path)

    class Reached(Exception):
        pass

    def lock(_role: object, *, wait: object) -> None:
        raise Reached

    deps = SimpleNamespace(paths=paths, state=SimpleNamespace(lock=lock))
    with pytest.raises(LeadAuthorError) as e:
        lead_author.run(run, label=AUTHOR_DRAIN_LABEL, deps=deps)  # type: ignore[arg-type]
    msg = str(e.value)
    assert "the 'author_drain' lane does not mount" in msg, msg
    _assert_shows_value(msg, AUTHOR_DRAIN_LABEL)

    with pytest.raises(Reached):
        lead_author.run(run, label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", NON_MEMBERS, ids=repr)
def test_the_lead_author_lane_raises_on_a_non_member_before_the_queue_lock(
        tmp_path: Path, value: object):
    run = run_of(curation_run_dir("run"))  # the opened run the lane is handed (#1105 PR 2)
    paths = _paths(tmp_path)

    def lock(_role: object, *, wait: object) -> None:
        raise AssertionError("a non-member got past the grant check to the queue lock")

    deps = SimpleNamespace(paths=paths, state=SimpleNamespace(lock=lock))
    with pytest.raises(AttributeError):
        lead_author.run(run, label=value, deps=deps)  # type: ignore[arg-type]

    with state_for_paths(paths).lock(LEAD_QUEUE_LOCK, wait=TRY_ONCE) as held:
        assert held, "precondition: the test holds the queue lock"
        assert lead_author.run(run, label=LEAD_AUTHOR_DRAIN_LABEL, paths=paths) == \
            lead_author.QUEUE_LOCK_SKIP_RC, "control: the held lock makes a member skip"
        with pytest.raises(AttributeError):
            lead_author.run(run, label=value, paths=paths)  # type: ignore[arg-type]


def _writable(request: Any) -> list[Path]:
    return [Path(m.source) for m in request.mounts if m.writable]


@pytest.mark.parametrize("label", NON_MEMBERS, ids=repr)
def test_a_batch_handed_a_non_member_raises_before_any_batch_work(tmp_path: Path, label: object):
    asked: list[LoopPaths] = []

    def has_work(paths: LoopPaths) -> bool:
        asked.append(paths)
        return True

    root = tmp_path / "non-member"
    root.mkdir()
    rec = B.BoxLifecycleRecorder()
    branch = _DeliveringBranch(root / "wt", events=rec.events)
    retained = _retain(root, branch)
    with pytest.raises(AttributeError):
        B.drive_worktree_batch(root, rec, do_work=lambda *_a, **_k: None, has_work=has_work,
                               branch=branch, label=label)
    assert branch.delivered == [], "a non-member's batch delivered a retained branch"
    assert retained.is_file(), "a non-member's batch dropped the retained delivery's record"
    assert asked == [], "the batch reached _open_batch with a non-member"
    assert rec.requests == []
    assert rec.events == []
    assert not (root / "wt").exists(), "a worktree was made for a non-member"
    assert descriptors_under(root) == []

    for member, rels in ((AUTHOR_DRAIN_LABEL, ("defender/lessons", "defender/lessons-questioner")),
                         (LEAD_AUTHOR_DRAIN_LABEL, ("defender/skills",))):
        asked.clear()
        root = tmp_path / member.value
        root.mkdir()
        rec = B.BoxLifecycleRecorder()
        branch = _DeliveringBranch(root / "wt", events=rec.events)
        retained = _retain(root, branch)
        B.drive_worktree_batch(root, rec, do_work=lambda *_a, **_k: None, has_work=has_work,
                               branch=branch, label=member)
        assert branch.delivered == ["retained-1"]
        assert not retained.exists()
        assert len(asked) == 1
        request = rec.only_request()
        [leaf] = [Path(m.source) for m in request.mounts if not m.writable]
        assert _writable(request) == [leaf / rel for rel in rels]


class _DeliveringBranch(B.RecordingBranch):
    """`_box665.RecordingBranch` that can deliver a retained batch (`deliver`), recording each,
    and whose `finish_batch` can fail like a rejected push."""

    def __init__(self, *a: Any, fail_push: bool = False, **kw: Any) -> None:
        super().__init__(*a, **kw)
        self.delivered: list[str] = []
        self.fail_push = fail_push

    def deliver(self, batch_id: str) -> str:
        self.delivered.append(batch_id)
        return f"https://example/pr/{batch_id}"

    def finish_batch(self, batch_id: str, wt: Path) -> str | None:
        if self.fail_push:
            self.events.append(f"finish_batch:{batch_id}")
            raise BranchError("push rejected")
        return super().finish_batch(batch_id, wt)


def _retain(root: Path, branch: Any) -> Path:
    """A retained delivery from an earlier tick, under the lane's branch prefix, as the real
    writer leaves it (the label written is irrelevant to delivery)."""
    paths = B.loop_paths(root)
    drains._record_pending_delivery(state_for_paths(paths), branch, "retained-1", label=AUTHOR_DRAIN_LABEL,
                                    reason="push rejected")
    [record] = sorted((paths.state_root / "_pending_delivery").glob("*.json"))
    return record


@pytest.mark.parametrize("label", MEMBERS, ids=lambda m: m.value)
def test_each_lanes_batch_writes_its_own_label_into_both_records(tmp_path: Path, label: DrainLabel):
    root = tmp_path / "push"
    root.mkdir()
    rec = B.BoxLifecycleRecorder()
    branch = _DeliveringBranch(root / "wt", events=rec.events, fail_push=True)
    assert B.drive_worktree_batch(root, rec, do_work=lambda *_a, **_k: None, branch=branch,
                                  label=label) == 0
    [record] = sorted((B.loop_paths(root).state_root / "_pending_delivery").glob("*.json"))
    assert json.loads(record.read_text(encoding="utf-8"))["label"] == VALUES[label]

    root = tmp_path / "taint"
    root.mkdir()
    rec = B.BoxLifecycleRecorder()
    branch = _DeliveringBranch(root / "wt", events=rec.events, destroy_on_cleanup=True)

    def tainting_scrub(tree: Path) -> None:
        os.symlink("/etc/passwd", tree / "stolen.md")
        scrub_mod.scrub(tree)

    rec.scrub = tainting_scrub
    with pytest.raises(scrub_mod.RunTainted):
        B.drive_worktree_batch(root, rec, do_work=lambda *_a, **_k: None, branch=branch,
                               label=label)
    [manifest] = sorted(branch.quarantine_dir.glob("*.json"))
    assert json.loads(manifest.read_text(encoding="utf-8"))["label"] == VALUES[label]


def test_the_paths_carry_no_label_table():
    """`LoopPaths` has no `drain_writable_trees` (#1179 M1'): the member owns its trees, so no
    second, string-keyed table can sit behind it on the paths."""
    assert not hasattr(LoopPaths, "drain_writable_trees")
