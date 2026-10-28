"""Pre-flight gates: the drain and repo locks, the idempotency filter, an empty queue.

The author works on a batch draft, which is clean by construction."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import json
from dataclasses import replace

import pytest

from defender.learning.core.state import REPO_LOCK, TRY_ONCE

from defender.tests.support.learning.curation._author_draft import DraftRepo


@pytest.fixture
def draft_repo(tmp_path):
    return DraftRepo.over(tmp_path)



def test_lock_refuses_concurrent_run(draft_repo):
    """The drain role's lock admits one `TRY_ONCE` holder at a time and frees on release."""
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
    helpers.write_finding(draft_repo.queue, finding_id="run-A/0", run_id="run-A")

    lock_file = location_path(draft_repo.paths.state_root) / REPO_LOCK.file
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    holder = lock_file.open("a+")
    fcntl.flock(holder.fileno(), fcntl.LOCK_EX)

    invoked = {"count": 0}

    def fake_invoke(findings, batch_id, cfg):
        invoked["count"] += 1
        return {"committed": [], "consumed_skip": [], "commit_sha": None}

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
        for line in draft_repo.queue.read_text().splitlines()
        if line.strip()
    ]
    assert [p["finding_id"] for p in pending] == ["run-A/0"]


def test_idempotency_filter_skips_already_authored(tmp_path, helpers):
    # The covering lesson is published in the export commit the draft is built from.
    draft_repo = DraftRepo.over(tmp_path, files={"lessons/preexisting.md": (
        "---\n"
        "name: preexisting\n"
        "description: covers the same pitfall\n"
        "source_finding_ids:\n"
        "  - run-X/0\n"
        "created_at: 2026-05-09T00:00:00+00:00\n"
        "---\n\nbody\n")})
    a = draft_repo.author
    helpers.write_finding(draft_repo.queue, finding_id="run-X/0", run_id="run-X")


    invoked = {"called": False}

    def fake_invoke(findings, batch_id, cfg):
        invoked["called"] = True
        return {"committed": [], "consumed_skip": [], "commit_sha": None}

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    rc = a.run_batch(cfg=cfg)
    assert rc == 0
    assert invoked["called"] is False, "agent must not be invoked when all findings are idempotent"

    assert draft_repo.queue.read_text().strip() == ""
    consumed = [
        json.loads(line)
        for line in draft_repo.consumed.read_text().splitlines()
        if line.strip()
    ]
    assert len(consumed) == 1
    assert consumed[0]["consumed_category"] == "consumed_idempotent"
    assert "consumed_at" in consumed[0]


def test_empty_queue_is_noop(draft_repo):
    a = draft_repo.author
    draft_repo.queue.parent.mkdir(parents=True, exist_ok=True)
    draft_repo.queue.write_text("")
    called = {"n": 0}

    def fake_invoke(*args, **kwargs):
        called["n"] += 1
        return {}

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    assert a.run_batch(cfg=cfg) == 0
    assert called["n"] == 0
