"""Pre-flight gates: lock, ground-truth filter, idempotency.

#1108 P4 (O7): the author works on a batch draft (clean-scope is the draft's construction, P3)."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import json
from dataclasses import replace

import pytest

from defender.learning.core.state import FINDINGS, REPO_LOCK, TRY_ONCE

from defender.tests.support.learning.curation import _curator1134 as C


# #1108 P4 (O7, OD7): the lessons author over a git-free draft, not `tmp_repo`'s product-shaped
# repo. The config is built with the assumed `batch=` seam (`_curator1134.draft_author_cfg`) on
# first use, so a test reaches its own body before that seam's absence fails it.
class _DraftRepo:
    def __init__(self, lane):
        from defender.learning.author.lessons import run as author_mod

        self.lane = lane
        self.author = author_mod
        self.paths = lane.paths
        self.lessons_dir = lane.lessons_dir
        self.state = C.open_state(lane.paths)
        self._cfg = None

    @property
    def cfg(self):
        if self._cfg is None:
            self._cfg = C.draft_author_cfg(self.lane, state=self.state)
        return self._cfg


@pytest.fixture
def draft_repo(tmp_path):
    """The fixture tenant's batch draft (lanes `lessons`, `lessons-questioner`) and its author."""
    return _DraftRepo(C.draft_lane(tmp_path))



def test_lock_refuses_concurrent_run(draft_repo, helpers):
    """A second author tick exits cleanly while the first holds the queue lock."""
    role = draft_repo.cfg.channel.drain_role
    state = draft_repo.state
    with state.lock(role, wait=TRY_ONCE) as first:
        assert first
        with state.lock(role, wait=TRY_ONCE) as second:
            assert not second
    with state.lock(role, wait=TRY_ONCE) as third:
        assert third


def test_repo_lock_held_returns_zero(draft_repo, helpers):
    """run_batch exits cleanly when the shared repo lock is unavailable."""
    import fcntl

    a = draft_repo.author
    helpers.write_finding(location_path(draft_repo.paths.state_root) / FINDINGS.queue, finding_id="run-A/0", run_id="run-A")

    lock_file = location_path(draft_repo.paths.state_root) / REPO_LOCK.file
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    holder = lock_file.open("a+")
    fcntl.flock(holder.fileno(), fcntl.LOCK_EX)

    invoked = {"count": 0}

    def fake_invoke(findings, batch_id, cfg):
        invoked["count"] += 1
        return {"committed": [], "held_forward_bad": [], "consumed_skip": [], "commit_sha": None}

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke, repo_lock_wait_seconds=1)
    try:
        rc = a.run_batch(cfg=cfg)
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()

    assert rc == 0
    assert invoked["count"] == 0, "agent must not run while repo lock is held"

    pending = [
        json.loads(line)
        for line in (location_path(draft_repo.paths.state_root) / FINDINGS.queue).read_text().splitlines()
        if line.strip()
    ]
    assert [p["finding_id"] for p in pending] == ["run-A/0"]


# #1108 P4 OD12(i): `test_clean_scope_check_refuses_dirty_lessons` / `test_clean_scope_passes_when_clean`
# pinned `shared.assert_clean_corpus_dir`, a `git status` check over the worktree corpus. A batch's
# draft is built fresh from the export commit and re-synced by the per-claim reset, so no prior
# drift can reach a claim: P3 tenant_1108_delivery/test_batches.py::test_start_batch_makes_a_git_free_draft_of_the_export_commit_and_no_checkout
# and test_changes.py::test_a_claim_reset_resyncs_the_draft_and_never_follows_box_links.


def test_idempotency_filter_skips_already_authored(tmp_path, helpers, monkeypatch):
    # The covering lesson is published in the export commit the draft is built from (#1108 P4).
    draft_repo = _DraftRepo(C.draft_lane(tmp_path, files={"lessons/preexisting.md": (
        "---\n"
        "name: preexisting\n"
        "description: covers the same pitfall\n"
        "source_finding_ids:\n"
        "  - run-X/0\n"
        "created_at: 2026-05-09T00:00:00+00:00\n"
        "---\n\nbody\n")}))
    a = draft_repo.author
    helpers.write_finding(location_path(draft_repo.paths.state_root) / FINDINGS.queue, finding_id="run-X/0", run_id="run-X")


    invoked = {"called": False}

    def fake_invoke(findings, batch_id, cfg):
        invoked["called"] = True
        return {"committed": [], "held_forward_bad": [], "consumed_skip": [], "commit_sha": None}

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    rc = a.run_batch(cfg=cfg)
    assert rc == 0
    assert invoked["called"] is False, "agent must not be invoked when all findings are idempotent"

    assert (location_path(draft_repo.paths.state_root) / FINDINGS.queue).read_text().strip() == ""
    consumed = [
        json.loads(line)
        for line in (location_path(draft_repo.paths.state_root) / FINDINGS.consumed).read_text().splitlines()
        if line.strip()
    ]
    assert len(consumed) == 1
    assert consumed[0]["consumed_category"] == "consumed_idempotent"
    assert "consumed_at" in consumed[0]


def test_empty_queue_is_noop(draft_repo, monkeypatch):
    a = draft_repo.author
    (location_path(draft_repo.paths.state_root) / FINDINGS.queue).parent.mkdir(parents=True, exist_ok=True)
    (location_path(draft_repo.paths.state_root) / FINDINGS.queue).write_text("")
    called = {"n": 0}

    def fake_invoke(*args, **kwargs):
        called["n"] += 1
        return {}

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    assert a.run_batch(cfg=cfg) == 0
    assert called["n"] == 0
