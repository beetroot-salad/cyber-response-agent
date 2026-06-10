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


def _commit_lesson(tmp_repo, a, *, name: str, fid: str):
    """Return a fake invoke_agent that commits one lesson citing ``fid``."""
    def fake(findings, batch_id):
        body = (
            f"---\nname: {name}\ndescription: d\nsource_finding_ids:\n  - {fid}\n"
            "created_at: 2026-05-09T00:00:00+00:00\n---\n\nbody\n"
        )
        (a.LESSONS_DIR / f"{name}.md").write_text(body)
        tmp_repo.run_git("add", "-A")
        tmp_repo.run_git("commit", "-q", "-m", name)
        sha = tmp_repo.run_git("rev-parse", "HEAD").stdout.strip()
        return {"committed": [fid], "held_forward_bad": [], "consumed_skip": [],
                "commit_sha": sha}
    return fake


def test_hold_committed_keeps_findings_queued_until_corpus_covers_them(
    tmp_repo, helpers, monkeypatch
):
    """Under the drain (hold_committed), a just-committed finding STAYS queued —
    the PR isn't merged yet, so a rejected PR can't strand it. Once the lesson is
    in the corpus, the next batch filters it via existing_finding_ids (idempotent)
    and rotates it out without re-authoring."""
    a = tmp_repo.author
    helpers.write_source_refs(a.RUNS_DIR, "run-H", "benign")
    helpers.write_finding(a.PENDING_FILE, finding_id="run-H/0", run_id="run-H")

    monkeypatch.setattr(
        a, "invoke_agent", _commit_lesson(tmp_repo, a, name="lessonH", fid="run-H/0")
    )
    # Tick 1: lesson committed, finding held (not consumed), stamp stripped.
    assert a.run_batch(hold_committed=True) == 0
    assert "run-H/0" in a.PENDING_FILE.read_text()
    consumed = a.CONSUMED_FILE.read_text() if a.CONSUMED_FILE.exists() else ""
    assert "run-H/0" not in consumed
    held_row = json.loads(a.PENDING_FILE.read_text().splitlines()[0])
    assert "consumed_category" not in held_row

    # Tick 2: lesson now covers the finding → consumed_idempotent → rotates out,
    # and the agent is never re-invoked on an already-covered finding.
    def must_not_author(findings, batch_id):
        raise AssertionError("re-authored an already-covered finding")

    monkeypatch.setattr(a, "invoke_agent", must_not_author)
    assert a.run_batch(hold_committed=True) == 0
    assert a.PENDING_FILE.read_text().strip() == ""
    assert "run-H/0" in a.CONSUMED_FILE.read_text()


def test_default_rotate_consumes_committed_immediately(tmp_repo, helpers, monkeypatch):
    """Standalone (hold_committed=False, the default): a committed finding rotates
    straight to consumed.jsonl, as before this change."""
    a = tmp_repo.author
    helpers.write_source_refs(a.RUNS_DIR, "run-D", "benign")
    helpers.write_finding(a.PENDING_FILE, finding_id="run-D/0", run_id="run-D")
    monkeypatch.setattr(
        a, "invoke_agent", _commit_lesson(tmp_repo, a, name="lessonD", fid="run-D/0")
    )
    assert a.run_batch() == 0  # hold_committed defaults False
    assert a.PENDING_FILE.read_text().strip() == ""
    assert "run-D/0" in a.CONSUMED_FILE.read_text()
