"""Pre-flight gates: lock, clean-scope, ground-truth filter, idempotency."""
from __future__ import annotations

import json

import pytest


def test_lock_refuses_concurrent_run(tmp_repo, helpers):
    """A second author tick exits cleanly while the first holds the lock."""
    a = tmp_repo.author
    fh = a.acquire_lock()
    assert fh is not None
    try:
        # Simulate a concurrent invocation: acquire_lock should return None.
        second = a.acquire_lock()
        assert second is None
    finally:
        a.release_lock(fh)
    third = a.acquire_lock()
    assert third is not None
    a.release_lock(third)


def test_repo_lock_held_returns_zero(tmp_repo, helpers, monkeypatch):
    """run_batch exits cleanly when the shared repo lock is unavailable.

    Mirrors the actor-author behavior: queue stays intact, no agent
    invocation, rc=0 so the next tick retries.
    """
    import fcntl

    a = tmp_repo.author
    helpers.write_source_refs(a.RUNS_DIR, "run-A", "benign")
    helpers.write_finding(a.PENDING_FILE, finding_id="run-A/0", run_id="run-A")

    # Hold the repo lock from a separate fd.
    shared = a._shared
    shared.REPO_LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    holder = shared.REPO_LOCK_FILE.open("a+")
    fcntl.flock(holder.fileno(), fcntl.LOCK_EX)

    # Short timeout so the test doesn't sleep for half an hour.
    monkeypatch.setattr(shared, "REPO_LOCK_WAIT_SECONDS", 1)

    invoked = {"count": 0}

    def fake_invoke(findings, batch_id):
        invoked["count"] += 1
        return {"committed": [], "held_forward_bad": [], "consumed_skip": [], "commit_sha": None}

    monkeypatch.setattr(a, "invoke_agent", fake_invoke)
    try:
        rc = a.run_batch()
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()

    assert rc == 0
    assert invoked["count"] == 0, "agent must not run while repo lock is held"

    # Queue still has the original finding — nothing was rotated out.
    pending = [
        json.loads(line)
        for line in a.PENDING_FILE.read_text().splitlines()
        if line.strip()
    ]
    assert [p["finding_id"] for p in pending] == ["run-A/0"]


def test_clean_scope_check_refuses_dirty_lessons(tmp_repo):
    a = tmp_repo.author
    (a.LESSONS_DIR / "drift.md").write_text("uncommitted\n")
    with pytest.raises(a.AuthorError, match="uncommitted changes"):
        a.assert_clean_lessons_dir()


def test_clean_scope_passes_when_clean(tmp_repo):
    a = tmp_repo.author
    a.assert_clean_lessons_dir()  # no raise


def test_ground_truth_gate_holds_inconclusive(tmp_repo, helpers, monkeypatch):
    a = tmp_repo.author
    helpers.write_source_refs(a.RUNS_DIR, "run-A", "inconclusive")
    helpers.write_source_refs(a.RUNS_DIR, "run-B", "benign")
    helpers.write_finding(a.PENDING_FILE, finding_id="run-A/0", run_id="run-A")
    helpers.write_finding(a.PENDING_FILE, finding_id="run-B/0", run_id="run-B")

    captured = {}

    def fake_invoke(findings, batch_id):
        captured["findings"] = findings
        captured["batch_id"] = batch_id
        # Simulate skip — no lessons authored, no commit.
        return {
            "committed": [],
            "held_forward_bad": [],
            "consumed_skip": [
                {"finding_id": f["finding_id"], "reason": "covered"}
                for f in findings
            ],
            "commit_sha": None,
        }

    monkeypatch.setattr(a, "invoke_agent", fake_invoke)
    rc = a.run_batch()
    assert rc == 0

    # Only the benign finding reached the agent.
    assert [f["finding_id"] for f in captured["findings"]] == ["run-B/0"]

    # The inconclusive finding stayed in the queue (held).
    pending = [
        json.loads(line)
        for line in a.PENDING_FILE.read_text().splitlines()
        if line.strip()
    ]
    assert [p["finding_id"] for p in pending] == ["run-A/0"]
    assert "no_ground_truth" in pending[0]["held_reason"]


def test_idempotency_filter_skips_already_authored(tmp_repo, helpers, monkeypatch):
    a = tmp_repo.author
    helpers.write_source_refs(a.RUNS_DIR, "run-X", "benign")
    helpers.write_finding(a.PENDING_FILE, finding_id="run-X/0", run_id="run-X")

    # Pre-existing lesson cites this finding_id — must skip the agent entirely.
    (a.LESSONS_DIR / "preexisting.md").write_text(
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

    def fake_invoke(findings, batch_id):
        invoked["called"] = True
        return {"committed": [], "held_forward_bad": [], "consumed_skip": [], "commit_sha": None}

    monkeypatch.setattr(a, "invoke_agent", fake_invoke)
    rc = a.run_batch()
    assert rc == 0
    assert invoked["called"] is False, "agent must not be invoked when all findings are idempotent"

    # Queue empty (all consumed_idempotent).
    assert a.PENDING_FILE.read_text().strip() == ""
    consumed = [
        json.loads(line)
        for line in a.CONSUMED_FILE.read_text().splitlines()
        if line.strip()
    ]
    assert len(consumed) == 1
    assert consumed[0]["consumed_category"] == "consumed_idempotent"
    assert "consumed_at" in consumed[0]


def test_empty_queue_is_noop(tmp_repo, monkeypatch):
    a = tmp_repo.author
    a.PENDING_DIR.mkdir(parents=True, exist_ok=True)
    a.PENDING_FILE.write_text("")  # empty
    called = {"n": 0}

    def fake_invoke(*args, **kwargs):
        called["n"] += 1
        return {}

    monkeypatch.setattr(a, "invoke_agent", fake_invoke)
    assert a.run_batch() == 0
    assert called["n"] == 0
