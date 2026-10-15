"""Pre-flight gates: lock, clean-scope, ground-truth filter, idempotency."""
from __future__ import annotations

import json
from dataclasses import replace

import pytest

from defender.learning.author import shared
from defender.learning.core.state import FINDINGS, REPO_LOCK, TRY_ONCE


def test_lock_refuses_concurrent_run(tmp_repo, helpers):
    """A second author tick exits cleanly while the first holds the queue lock.

    The author drives this through the shared drain body's drain-role gate; the lock
    primitive is the handle's ``lock(role, wait=TRY_ONCE)`` on the channel's drain role."""
    role = tmp_repo.cfg.channel.drain_role
    state = tmp_repo.state
    with state.lock(role, wait=TRY_ONCE) as first:
        assert first
        with state.lock(role, wait=TRY_ONCE) as second:
            assert not second
    with state.lock(role, wait=TRY_ONCE) as third:
        assert third


def test_repo_lock_held_returns_zero(tmp_repo, helpers):
    """run_batch exits cleanly when the shared repo lock is unavailable.

    Mirrors the actor-author behavior: queue stays intact, no agent
    invocation, rc=0 so the next tick retries.
    """
    import fcntl

    a = tmp_repo.author
    helpers.write_finding(tmp_repo.paths.state_root / FINDINGS.queue, finding_id="run-A/0", run_id="run-A")

    lock_file = tmp_repo.paths.state_root / REPO_LOCK.file
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    holder = lock_file.open("a+")
    fcntl.flock(holder.fileno(), fcntl.LOCK_EX)

    invoked = {"count": 0}

    def fake_invoke(findings, batch_id, cfg):
        invoked["count"] += 1
        return {"committed": [], "held_forward_bad": [], "consumed_skip": [], "commit_sha": None}

    cfg = replace(tmp_repo.cfg, invoke_agent=fake_invoke, repo_lock_wait_seconds=1)
    try:
        rc = a.run_batch(cfg=cfg)
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()

    assert rc == 0
    assert invoked["count"] == 0, "agent must not run while repo lock is held"

    pending = [
        json.loads(line)
        for line in (tmp_repo.paths.state_root / FINDINGS.queue).read_text().splitlines()
        if line.strip()
    ]
    assert [p["finding_id"] for p in pending] == ["run-A/0"]


def test_clean_scope_check_refuses_dirty_lessons(tmp_repo):
    cfg = tmp_repo.cfg
    (tmp_repo.paths.lessons_dir / "drift.md").write_text("uncommitted\n")
    with pytest.raises(shared.AuthorError, match="uncommitted changes"):
        shared.assert_clean_corpus_dir(cfg.repo_root, cfg.corpus_dir, "defender/lessons/",
                                       corpus=cfg.corpus)


def test_clean_scope_passes_when_clean(tmp_repo):
    cfg = tmp_repo.cfg
    shared.assert_clean_corpus_dir(cfg.repo_root, cfg.corpus_dir, "defender/lessons/",
                                   corpus=cfg.corpus)


def test_idempotency_filter_skips_already_authored(tmp_repo, helpers, monkeypatch):
    a = tmp_repo.author
    helpers.write_finding(tmp_repo.paths.state_root / FINDINGS.queue, finding_id="run-X/0", run_id="run-X")

    (tmp_repo.paths.lessons_dir / "preexisting.md").write_text(
        "---\n"
        "name: preexisting\n"
        "description: covers the same pitfall\n"
        "source_finding_ids:\n"
        "  - run-X/0\n"
        "created_at: 2026-05-09T00:00:00+00:00\n"
        "---\n\nbody\n"
    )
    tmp_repo.run_git("add", "-A")
    tmp_repo.run_git("commit", "-q", "-m", "seed")

    invoked = {"called": False}

    def fake_invoke(findings, batch_id, cfg):
        invoked["called"] = True
        return {"committed": [], "held_forward_bad": [], "consumed_skip": [], "commit_sha": None}

    cfg = replace(tmp_repo.cfg, invoke_agent=fake_invoke)
    rc = a.run_batch(cfg=cfg)
    assert rc == 0
    assert invoked["called"] is False, "agent must not be invoked when all findings are idempotent"

    assert (tmp_repo.paths.state_root / FINDINGS.queue).read_text().strip() == ""
    consumed = [
        json.loads(line)
        for line in (tmp_repo.paths.state_root / FINDINGS.consumed).read_text().splitlines()
        if line.strip()
    ]
    assert len(consumed) == 1
    assert consumed[0]["consumed_category"] == "consumed_idempotent"
    assert "consumed_at" in consumed[0]


def test_empty_queue_is_noop(tmp_repo, monkeypatch):
    a = tmp_repo.author
    (tmp_repo.paths.state_root / FINDINGS.queue).parent.mkdir(parents=True, exist_ok=True)
    (tmp_repo.paths.state_root / FINDINGS.queue).write_text("")
    called = {"n": 0}

    def fake_invoke(*args, **kwargs):
        called["n"] += 1
        return {}

    cfg = replace(tmp_repo.cfg, invoke_agent=fake_invoke)
    assert a.run_batch(cfg=cfg) == 0
    assert called["n"] == 0
