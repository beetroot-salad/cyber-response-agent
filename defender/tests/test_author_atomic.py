"""Atomicity: agent crash / failure leaves queue intact, lock released."""
from __future__ import annotations

import json
from dataclasses import replace

from defender._io import read_jsonl_rows
from defender.learning.author import shared


def test_agent_exception_leaves_queue_intact(tmp_repo, helpers, monkeypatch):
    a = tmp_repo.author
    helpers.write_source_refs(tmp_repo.paths.runs_dir, "run-K", "benign")
    helpers.write_finding(tmp_repo.paths.pending_file, finding_id="run-K/0", run_id="run-K")

    def boom(findings, batch_id, cfg):
        raise a.AuthorError("simulated agent failure")

    cfg = replace(tmp_repo.cfg, invoke_agent=boom)
    rc = a.run_batch(cfg=cfg)
    assert rc == 2
    # The finding is NOT lost on an agent failure — it survives in the queue, retryable. The
    # dead-letter queue bumps its `attempts` counter (findings.jsonl gets the same batch-granular
    # quarantine as the observation curators) but 1 < LEARNING_AUTHOR_MAX_ATTEMPTS, so it is NOT
    # yet dead-lettered.
    rows = read_jsonl_rows(tmp_repo.paths.pending_file)
    assert {r["finding_id"] for r in rows} == {"run-K/0"}, "queue must survive agent failure"
    assert [r.get("attempts") for r in rows] == [1]
    assert not tmp_repo.paths.pending_file.with_suffix(".deadletter.jsonl").exists()

    # Lock must have been released — a follow-up tick can run.
    fh = shared.acquire_flock(tmp_repo.cfg.lock_file)
    assert fh is not None
    shared.release_flock(fh)


def test_dlq_quarantines_poison_findings_batch(tmp_repo, helpers, monkeypatch):
    """The findings curator (A → defender/lessons/) gets the SAME batch-granular dead-letter as
    the observation curators (spec: the ``curator_A -> dlq`` edge, findings.jsonl's NEW ``attempts``
    field): a poison findings batch that faults every tick quarantines to the ``deadletter.jsonl``
    sidecar after ``LEARNING_AUTHOR_MAX_ATTEMPTS`` instead of retrying forever and wedging the
    ``defender/lessons/`` queue."""
    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "3")  # (= the default; documents the budget)
    a = tmp_repo.author
    helpers.write_source_refs(tmp_repo.paths.runs_dir, "run-P", "benign")
    helpers.write_finding(tmp_repo.paths.pending_file, finding_id="run-P/0", run_id="run-P")

    def boom(findings, batch_id, cfg):
        raise a.AuthorError("simulated per-run authoring fault")

    fault_cfg = replace(tmp_repo.cfg, invoke_agent=boom)
    for _ in range(3):  # tick 1→attempts 1, tick 2→2, tick 3 reaches the budget
        assert a.run_batch(cfg=fault_cfg) == 2

    # Gone from the active queue, moved to the deadletter sidecar carrying its attempt count + reason.
    assert read_jsonl_rows(tmp_repo.paths.pending_file) == []
    dead = read_jsonl_rows(tmp_repo.paths.pending_file.with_suffix(".deadletter.jsonl"))
    assert {r["finding_id"] for r in dead} == {"run-P/0"}
    assert dead[0]["attempts"] == 3
    assert "simulated per-run authoring fault" in dead[0]["deadletter_reason"]


def test_idempotent_retry_after_partial_failure(tmp_repo, helpers, monkeypatch):
    """First tick fails inside the agent. Second tick retries cleanly."""
    a = tmp_repo.author
    helpers.write_source_refs(tmp_repo.paths.runs_dir, "run-R", "benign")
    helpers.write_finding(tmp_repo.paths.pending_file, finding_id="run-R/0", run_id="run-R")

    state = {"calls": 0}

    def maybe_fail(findings, batch_id, cfg):
        state["calls"] += 1
        if state["calls"] == 1:
            raise a.AuthorError("commit failed")
        # Second call: succeed. Write the lesson, run NO git (the loop commits).
        body = (
            "---\n"
            "name: lessonR\n"
            "description: d\n"
            "source_finding_ids:\n"
            "  - run-R/0\n"
            "created_at: 2026-05-09T00:00:00+00:00\n"
            "---\n\nb\n"
        )
        (tmp_repo.paths.lessons_dir / "lessonR.md").write_text(body)
        return {"committed": ["run-R/0"], "held_forward_bad": [], "consumed_skip": [],
                "commit_message": "lessonR"}

    cfg = replace(tmp_repo.cfg, invoke_agent=maybe_fail)
    assert a.run_batch(cfg=cfg) == 2  # first tick fails
    # Findings still queued.
    assert "run-R/0" in tmp_repo.paths.pending_file.read_text()
    # Second tick succeeds.
    assert a.run_batch(cfg=cfg) == 0
    assert tmp_repo.paths.pending_file.read_text().strip() == ""


def _commit_lesson(tmp_repo, a, *, name: str, fid: str):
    """Return a fake invoke_agent that writes one lesson citing ``fid`` — no git
    (the loop is the sole committer)."""
    def fake(findings, batch_id, cfg):
        body = (
            f"---\nname: {name}\ndescription: d\nsource_finding_ids:\n  - {fid}\n"
            "created_at: 2026-05-09T00:00:00+00:00\n---\n\nbody\n"
        )
        (tmp_repo.paths.lessons_dir / f"{name}.md").write_text(body)
        return {"committed": [fid], "held_forward_bad": [], "consumed_skip": [],
                "commit_message": name}
    return fake


def test_hold_committed_keeps_findings_queued_until_corpus_covers_them(
    tmp_repo, helpers, monkeypatch
):
    """Under the drain (hold_committed), a just-committed finding STAYS queued —
    the PR isn't merged yet, so a rejected PR can't strand it. Once the lesson is
    in the corpus, the next batch filters it via existing_finding_ids (idempotent)
    and rotates it out without re-authoring."""
    a = tmp_repo.author
    helpers.write_source_refs(tmp_repo.paths.runs_dir, "run-H", "benign")
    helpers.write_finding(tmp_repo.paths.pending_file, finding_id="run-H/0", run_id="run-H")

    cfg = replace(
        tmp_repo.cfg, invoke_agent=_commit_lesson(tmp_repo, a, name="lessonH", fid="run-H/0")
    )
    # Tick 1: lesson committed, finding held (not consumed), stamp stripped.
    assert a.run_batch(hold_committed=True, cfg=cfg) == 0
    assert "run-H/0" in tmp_repo.paths.pending_file.read_text()
    consumed = tmp_repo.cfg.consumed_file.read_text() if tmp_repo.cfg.consumed_file.exists() else ""
    assert "run-H/0" not in consumed
    held_row = json.loads(tmp_repo.paths.pending_file.read_text().splitlines()[0])
    assert "consumed_category" not in held_row

    # Tick 2: lesson now covers the finding → consumed_idempotent → rotates out,
    # and the agent is never re-invoked on an already-covered finding.
    def must_not_author(findings, batch_id, cfg):
        raise AssertionError("re-authored an already-covered finding")

    cfg = replace(tmp_repo.cfg, invoke_agent=must_not_author)
    assert a.run_batch(hold_committed=True, cfg=cfg) == 0
    assert tmp_repo.paths.pending_file.read_text().strip() == ""
    assert "run-H/0" in tmp_repo.cfg.consumed_file.read_text()


def test_default_rotate_consumes_committed_immediately(tmp_repo, helpers, monkeypatch):
    """Standalone (hold_committed=False, the default): a committed finding rotates
    straight to consumed.jsonl, as before this change."""
    a = tmp_repo.author
    helpers.write_source_refs(tmp_repo.paths.runs_dir, "run-D", "benign")
    helpers.write_finding(tmp_repo.paths.pending_file, finding_id="run-D/0", run_id="run-D")
    cfg = replace(
        tmp_repo.cfg, invoke_agent=_commit_lesson(tmp_repo, a, name="lessonD", fid="run-D/0")
    )
    assert a.run_batch(cfg=cfg) == 0  # hold_committed defaults False
    assert tmp_repo.paths.pending_file.read_text().strip() == ""
    assert "run-D/0" in tmp_repo.cfg.consumed_file.read_text()
