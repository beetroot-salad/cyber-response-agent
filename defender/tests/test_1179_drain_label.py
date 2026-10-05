"""#1179: the drain labels are the members of a plain `enum.Enum`, so no string is a label.

The contract is #1179's intent+design comment (2026-10-03) and its owner amendment (the same
day, after `/code-review`):

- O1', only a member names a lane. `DrainLabel.writable_trees(paths)` (`@owns
  drain_writable_trees`) is each member's own list; a non-member (a string, a member's name, a
  look-alike, an object carrying a value) has no such method and raises at its first use.
  `_run_worktree_batch` asks it first, so a non-member raises before `_open_batch`, before a
  worktree, a box, a held root or a record exists. `test_1134_mount_list.py` carries the box
  and holder rows; here are the batch entry and the lead-author lane's own grant check.
- O2, the two records that persist a label still write its value as a JSON string: the
  pending-delivery record (`drains._record_pending_delivery`) and the quarantine manifest
  (`quarantine.preserve_tainted_tree`). Each is read back from disk. The quarantine writer
  swallows its own failures (a missed `.value` would lose the manifest silently and log an
  error), so these rows assert on the written file, never on an exception.
- O3, every message that carries a label shows its value, never `DrainLabel.AUTHOR` or
  `<DrainLabel.AUTHOR: ...>`: the claim log of `markers.claim_markers`, the quarantine log, and
  the lead-author refusal (formatted with `!r` before #1179).

Real primitives throughout: a real scrub taints a real tree with a planted link, the real writers
write, and the records are read back with `json.loads`. Nothing is monkeypatched (`caplog`
only captures).
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from defender.learning.author.branch import AuthorBranch, BranchError
from defender.learning.core import drains, markers
from defender.learning.core.config import (
    AUTHOR_DRAIN_LABEL, LEAD_AUTHOR_DRAIN_LABEL, DrainLabel, LoopPaths,
)
from defender.learning.core.quarantine import preserve_tainted_tree
from defender.learning.leads import lead_author
from defender.learning.leads.lead_author import LeadAuthorError
from defender.learning.leads.lead_author._handoff import acquire_queue_lock, release_queue_lock
from defender.runtime import scrub as scrub_mod
from defender.tests._tree_listing_1134 import descriptors_under
from defender.tests.e2e import _box665 as B
from defender.tests.test_1134_mount_list import UNKNOWN_LABELS

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
    return LoopPaths(repo_root=repo, state_dir=tmp_path / "state")


def _assert_shows_value(text: str, label: DrainLabel) -> None:
    assert VALUES[label] in text, text
    for leak in LEAKS:
        assert leak not in text, (leak, text)


# ---------------------------------------------------------------------------------------
# O2: the written records carry the value
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("label", MEMBERS, ids=lambda m: m.value)
def test_the_pending_delivery_record_writes_the_labels_value(tmp_path: Path, label: DrainLabel):
    """The real `_record_pending_delivery` writes `"label": "<value>"`, a JSON string, beside
    the branch and batch it already wrote.

    Catches: the member handed to `json.dumps` (a `TypeError` out of the delivery path), its
    `str()`/`repr()` or its name written instead of its value, and a record that drops the
    label."""
    paths = _paths(tmp_path)
    branch = AuthorBranch(repo_root=paths.repo_root, worktree_base=tmp_path / "wts")

    drains._record_pending_delivery(paths, branch, "batch-7", label=label, reason="push failed")

    [record] = sorted(paths.pending_delivery_dir.glob("*.json"))
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
    """The real `preserve_tainted_tree` over a really tainted tree writes its archive and a
    manifest whose `"label"` is the value, a JSON string, and logs the preservation under the
    value.

    The manifest is read back: the writer swallows any failure (it must not mask the taint),
    so a member handed to `json.dumps` shows only as a missing manifest and an error log.

    Catches: a missed `.value` (no manifest, the archive alone), a written `str()`/`repr()`,
    and a log line that shows `DrainLabel.AUTHOR`."""
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


# ---------------------------------------------------------------------------------------
# O3: messages show the value
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("label", MEMBERS, ids=lambda m: m.value)
def test_the_claim_log_shows_the_labels_value(
        tmp_path: Path, label: DrainLabel, caplog: pytest.LogCaptureFixture):
    """`claim_markers(label=<member>)` logs its queue count under the value.

    Catches: an f-string `{label}` over a member whose `str()` is the enum's default
    (`DrainLabel.AUTHOR`)."""
    queue = tmp_path / "queue"
    queue.mkdir()
    with caplog.at_level(logging.INFO):
        assert list(markers.claim_markers(
            queue, identity_key="run_id", label=label, noun="authoring")) == []
    [line] = [r.getMessage() for r in caplog.records if "queued for authoring" in r.getMessage()]
    _assert_shows_value(line, label)
    assert line.startswith(f"{VALUES[label]}: ")


def test_the_lead_author_refusal_names_the_labels_value(tmp_path: Path):
    """`lead_author.run(deps=..., label=<member>)` whose list lacks `skills/` is refused, and the
    refusal names the lane by its value, quoted: `the 'author_drain' lane does not mount`.

    The author member is that case: its list is the two lessons corpora. The positive control,
    the lead member over the same `deps.paths`, gets past the check (to the queue lock, which
    the stub deps answers with a sentinel).

    Catches: `{label!r}` over a member, rendering `<DrainLabel.AUTHOR: 'author_drain'>`."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    paths = _paths(tmp_path)

    class Reached(Exception):
        pass

    def lock() -> None:
        raise Reached

    deps = SimpleNamespace(paths=paths, acquire_queue_lock=lock)
    with pytest.raises(LeadAuthorError) as e:
        lead_author.run(run_dir, label=AUTHOR_DRAIN_LABEL, deps=deps)  # type: ignore[arg-type]
    msg = str(e.value)
    assert "the 'author_drain' lane does not mount" in msg, msg
    _assert_shows_value(msg, AUTHOR_DRAIN_LABEL)

    with pytest.raises(Reached):
        lead_author.run(run_dir, label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------------------
# O1 through the lead-author lane's own grant check
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("value", NON_MEMBERS, ids=repr)
def test_the_lead_author_lane_raises_on_a_non_member_before_the_queue_lock(
        tmp_path: Path, value: object):
    """`lead_author.run(label=<non-member>)` raises at its first use (`AttributeError`) before
    the queue lock, on both paths:
    - with deps, the deps' lock seam is never called;
    - without deps, the real queue lock is already held by this test, so a run that took the
      lock before using the label would answer the skip code instead of raising.

    The controls: the lead member reaches the deps' lock (above), and without deps the same
    held lock makes the lead member answer the skip code.

    Catches: a `str`-mixin enum, a check that coerces a string, a name or a look-alike into a
    member (`DrainLabel(label)`, `DrainLabel[label]`, `.value` lookups), and a run that takes
    the queue lock before it uses the label."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    paths = _paths(tmp_path)

    def lock() -> None:
        raise AssertionError("a non-member got past the grant check to the queue lock")

    deps = SimpleNamespace(paths=paths, acquire_queue_lock=lock)
    with pytest.raises(AttributeError):
        lead_author.run(run_dir, label=value, deps=deps)  # type: ignore[arg-type]

    held = acquire_queue_lock(paths)
    assert held is not None, "precondition: the test holds the queue lock"
    try:
        assert lead_author.run(run_dir, label=LEAD_AUTHOR_DRAIN_LABEL, paths=paths) == \
            lead_author.QUEUE_LOCK_SKIP_RC, "control: the held lock makes a member skip"
        with pytest.raises(AttributeError):
            lead_author.run(run_dir, label=value, paths=paths)  # type: ignore[arg-type]
    finally:
        release_queue_lock(held)


# ---------------------------------------------------------------------------------------
# O1' at the batch entry: a non-member raises before any batch work
# ---------------------------------------------------------------------------------------


def _writable(request: Any) -> list[Path]:
    return [Path(m.source) for m in request.mounts if m.writable]


@pytest.mark.parametrize("label", NON_MEMBERS, ids=repr)
def test_a_batch_handed_a_non_member_raises_before_any_batch_work(tmp_path: Path, label: object):
    """The real `_run_worktree_batch(label=<non-member>)` raises `AttributeError` before
    `_open_batch`, over a lane that has a retained delivery from an earlier tick: the retained
    batch is NOT delivered (its record stays on disk, `deliver` is never called), `has_work` is
    never asked, the branch records no event and makes no worktree, no box is started, and
    nothing is held.

    The positive control, each member over a fresh drive with the same retained record: the
    batch delivers it (one `deliver`, the record removed), asks `has_work`, its work's one agent
    run starts one box (#1195: the batch itself starts none), and that box mounts the member's
    trees writable.

    Catches: a string, a name or a look-alike coerced into a member at the batch entry, and a
    batch that only meets the label late (inside `_open_batch` after the delivery pushed and
    dropped the record, at the box, or at a record writer)."""
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
        B.drive_worktree_batch(root, rec, do_work=_one_agent_run, has_work=has_work,
                               branch=branch, label=member)
        assert branch.delivered == ["retained-1"]
        assert not retained.exists()
        assert len(asked) == 1
        request = rec.only_request()
        [leaf] = [Path(m.source) for m in request.mounts if not m.writable]
        assert _writable(request) == [leaf / rel for rel in rels]


def _one_agent_run(_wt_paths: LoopPaths, *, box: Any = None) -> None:
    """A work step with one agent run of the batch's box source, as a lane's spawn site enters
    one: the lane's box request reaches `start_box=` only there (#1195)."""
    from defender.runtime.box import box_for_run

    with box_for_run(box):
        pass


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
    drains._record_pending_delivery(paths, branch, "retained-1", label=AUTHOR_DRAIN_LABEL,
                                    reason="push rejected")
    [record] = sorted(paths.pending_delivery_dir.glob("*.json"))
    return record


# ---------------------------------------------------------------------------------------
# O2 by lane: each member's own batch writes its own value into both records
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("label", MEMBERS, ids=lambda m: m.value)
def test_each_lanes_batch_writes_its_own_label_into_both_records(tmp_path: Path, label: DrainLabel):
    """Driven through the real `_run_worktree_batch` for each member: a rejected push records
    a pending delivery whose `"label"` is that member's value, and a tainted tree (a real link
    planted, the real scrub) leaves a quarantine manifest whose `"label"` is that member's value.

    Catches: a lane constant (or the other lane's label) handed to `_land_batch` or
    `preserve_tainted_tree` instead of the batch's own label: each path driven for one lane
    only would stay green."""
    root = tmp_path / "push"
    root.mkdir()
    rec = B.BoxLifecycleRecorder()
    branch = _DeliveringBranch(root / "wt", events=rec.events, fail_push=True)
    assert B.drive_worktree_batch(root, rec, do_work=lambda *_a, **_k: None, branch=branch,
                                  label=label) == 0
    [record] = sorted(B.loop_paths(root).pending_delivery_dir.glob("*.json"))
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
