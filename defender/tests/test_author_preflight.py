"""Pre-flight gates: lock, clean-scope, ground-truth filter, idempotency."""
from __future__ import annotations

import json
from dataclasses import replace

import pytest

from defender.learning.author import shared


def test_lock_refuses_concurrent_run(tmp_repo, helpers):
    """A second author tick exits cleanly while the first holds the queue lock.

    The author drives this through ``shared.run_batch_envelope``; the lock primitive
    is ``shared.acquire_flock`` on the cfg's queue lock-file."""
    lock_file = tmp_repo.cfg.lock_file
    fh = shared.acquire_flock(lock_file)
    assert fh is not None
    try:
        second = shared.acquire_flock(lock_file)
        assert second is None
    finally:
        shared.release_flock(fh)
    third = shared.acquire_flock(lock_file)
    assert third is not None
    shared.release_flock(third)


def test_repo_lock_held_returns_zero(tmp_repo, helpers):
    """run_batch exits cleanly when the shared repo lock is unavailable.

    Mirrors the actor-author behavior: queue stays intact, no agent
    invocation, rc=0 so the next tick retries.
    """
    import fcntl

    a = tmp_repo.author
    helpers.write_source_refs(tmp_repo.paths.runs_dir, "run-A", "benign")
    helpers.write_finding(tmp_repo.paths.pending_file, finding_id="run-A/0", run_id="run-A")

    lock_file = tmp_repo.cfg.repo_lock_file
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
        for line in tmp_repo.paths.pending_file.read_text().splitlines()
        if line.strip()
    ]
    assert [p["finding_id"] for p in pending] == ["run-A/0"]


def test_clean_scope_check_refuses_dirty_lessons(tmp_repo):
    cfg = tmp_repo.cfg
    (tmp_repo.paths.lessons_dir / "drift.md").write_text("uncommitted\n")
    with pytest.raises(shared.AuthorError, match="uncommitted changes"):
        shared.assert_clean_corpus_dir(cfg.repo_root, cfg.lessons_dir, "defender/lessons/")


def test_clean_scope_passes_when_clean(tmp_repo):
    cfg = tmp_repo.cfg
    shared.assert_clean_corpus_dir(cfg.repo_root, cfg.lessons_dir, "defender/lessons/")


def test_ground_truth_gate_holds_inconclusive(tmp_repo, helpers, monkeypatch):
    a = tmp_repo.author
    helpers.write_source_refs(tmp_repo.paths.runs_dir, "run-A", "inconclusive")
    helpers.write_source_refs(tmp_repo.paths.runs_dir, "run-B", "benign")
    helpers.write_finding(tmp_repo.paths.pending_file, finding_id="run-A/0", run_id="run-A")
    helpers.write_finding(tmp_repo.paths.pending_file, finding_id="run-B/0", run_id="run-B")

    captured = {}

    def fake_invoke(findings, batch_id, cfg):
        captured["findings"] = findings
        captured["batch_id"] = batch_id
        return {
            "committed": [],
            "held_forward_bad": [],
            "consumed_skip": [
                {"finding_id": f["finding_id"], "reason": "covered"}
                for f in findings
            ],
            "commit_sha": None,
        }

    cfg = replace(tmp_repo.cfg, invoke_agent=fake_invoke)
    rc = a.run_batch(cfg=cfg)
    assert rc == 0

    assert [f["finding_id"] for f in captured["findings"]] == ["run-B/0"]

    pending = [
        json.loads(line)
        for line in tmp_repo.paths.pending_file.read_text().splitlines()
        if line.strip()
    ]
    assert [p["finding_id"] for p in pending] == ["run-A/0"]
    assert "no_ground_truth" in pending[0]["held_reason"]


def test_has_confident_ground_truth_is_direction_aware(tmp_repo):
    """The two directions confirm on opposite dispositions (#317). A benign (FP)
    finding is a confident over-escalation only when the source case was `malicious`;
    an adversarial finding is a confident miss only when it was `benign`. Everything
    else (including None) is held."""
    a = tmp_repo.author
    assert a._has_confident_ground_truth("benign", "malicious") is True
    assert a._has_confident_ground_truth("benign", "benign") is False
    assert a._has_confident_ground_truth("benign", "inconclusive") is False
    assert a._has_confident_ground_truth("benign", None) is False
    assert a._has_confident_ground_truth("adversarial", "benign") is True
    assert a._has_confident_ground_truth("adversarial", "malicious") is False


def test_ground_truth_gate_benign_authors_off_malicious(tmp_repo, helpers, monkeypatch):
    """Mirror of the adversarial gate for the FP direction: a benign finding reaches the
    agent only from a `malicious` source case (the over-escalation it corrects); from a
    benign source it is held (no confident FP ground truth)."""
    a = tmp_repo.author
    helpers.write_source_refs(tmp_repo.paths.runs_dir, "run-M", "malicious")
    helpers.write_source_refs(tmp_repo.paths.runs_dir, "run-Bn", "benign")
    helpers.write_finding(
        tmp_repo.paths.pending_file, finding_id="run-M/0", run_id="run-M", direction="benign"
    )
    helpers.write_finding(
        tmp_repo.paths.pending_file, finding_id="run-Bn/0", run_id="run-Bn", direction="benign"
    )

    captured = {}

    def fake_invoke(findings, batch_id, cfg):
        captured["findings"] = findings
        return {
            "committed": [],
            "held_forward_bad": [],
            "consumed_skip": [
                {"finding_id": f["finding_id"], "reason": "covered"} for f in findings
            ],
            "commit_sha": None,
        }

    cfg = replace(tmp_repo.cfg, invoke_agent=fake_invoke)
    rc = a.run_batch(cfg=cfg)
    assert rc == 0

    assert [f["finding_id"] for f in captured["findings"]] == ["run-M/0"]

    pending = [
        json.loads(line)
        for line in tmp_repo.paths.pending_file.read_text().splitlines()
        if line.strip()
    ]
    assert [p["finding_id"] for p in pending] == ["run-Bn/0"]
    assert "no_ground_truth" in pending[0]["held_reason"]

    consumed = [
        json.loads(line)
        for line in tmp_repo.cfg.consumed_file.read_text().splitlines()
        if line.strip()
    ]
    assert [c["finding_id"] for c in consumed] == ["run-M/0"]
    assert consumed[0]["consumed_category"] == "consumed_skip"
    assert "consumed_at" in consumed[0]


def test_idempotency_filter_skips_already_authored(tmp_repo, helpers, monkeypatch):
    a = tmp_repo.author
    helpers.write_source_refs(tmp_repo.paths.runs_dir, "run-X", "benign")
    helpers.write_finding(tmp_repo.paths.pending_file, finding_id="run-X/0", run_id="run-X")

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

    assert tmp_repo.paths.pending_file.read_text().strip() == ""
    consumed = [
        json.loads(line)
        for line in tmp_repo.cfg.consumed_file.read_text().splitlines()
        if line.strip()
    ]
    assert len(consumed) == 1
    assert consumed[0]["consumed_category"] == "consumed_idempotent"
    assert "consumed_at" in consumed[0]


def test_empty_queue_is_noop(tmp_repo, monkeypatch):
    a = tmp_repo.author
    tmp_repo.paths.pending_dir.mkdir(parents=True, exist_ok=True)
    tmp_repo.paths.pending_file.write_text("")
    called = {"n": 0}

    def fake_invoke(*args, **kwargs):
        called["n"] += 1
        return {}

    cfg = replace(tmp_repo.cfg, invoke_agent=fake_invoke)
    assert a.run_batch(cfg=cfg) == 0
    assert called["n"] == 0
