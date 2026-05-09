"""Atomicity: agent crash / failure leaves queue intact, lock released."""
from __future__ import annotations

import json


def test_agent_exception_leaves_queue_intact(tmp_repo, helpers, monkeypatch):
    a = tmp_repo.author
    helpers.write_source_refs(a.RUNS_DIR, "run-K", "benign")
    helpers.write_finding(a.PENDING_FILE, finding_id="run-K/0", run_id="run-K")
    pre = a.PENDING_FILE.read_text()

    def boom(findings, batch_id):
        raise a.AuthorError("simulated agent failure")

    monkeypatch.setattr(a, "invoke_agent", boom)
    rc = a.run_batch()
    assert rc == 2
    assert a.PENDING_FILE.read_text() == pre, "queue must survive agent failure"

    # Lock must have been released — a follow-up tick can run.
    fh = a.acquire_lock()
    assert fh is not None
    a.release_lock(fh)


def test_idempotent_retry_after_partial_failure(tmp_repo, helpers, monkeypatch):
    """First tick fails inside the agent. Second tick retries cleanly."""
    a = tmp_repo.author
    helpers.write_source_refs(a.RUNS_DIR, "run-R", "benign")
    helpers.write_finding(a.PENDING_FILE, finding_id="run-R/0", run_id="run-R")

    state = {"calls": 0}

    def maybe_fail(findings, batch_id):
        state["calls"] += 1
        if state["calls"] == 1:
            raise a.AuthorError("commit failed")
        # Second call: succeed.
        body = (
            "---\n"
            "name: lessonR\n"
            "description: d\n"
            "source_finding_ids:\n"
            "  - run-R/0\n"
            "created_at: 2026-05-09T00:00:00+00:00\n"
            "---\n\nb\n"
        )
        (a.LESSONS_DIR / "lessonR.md").write_text(body)
        tmp_repo.run_git("add", "-A")
        tmp_repo.run_git("commit", "-q", "-m", "lessonR")
        sha = tmp_repo.run_git("rev-parse", "HEAD").stdout.strip()
        return {"committed": ["run-R/0"], "held_forward_bad": [], "consumed_skip": [], "commit_sha": sha}

    monkeypatch.setattr(a, "invoke_agent", maybe_fail)
    assert a.run_batch() == 2  # first tick fails
    # Findings still queued.
    assert "run-R/0" in a.PENDING_FILE.read_text()
    # Second tick succeeds.
    assert a.run_batch() == 0
    assert a.PENDING_FILE.read_text().strip() == ""
