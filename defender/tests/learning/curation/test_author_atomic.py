"""Atomicity: agent crash / failure leaves queue intact, lock released."""
from __future__ import annotations

import json
from dataclasses import replace

import pytest

from defender._io import read_jsonl_rows
from defender.learning.core.state import CURATOR_DRAIN_LOCK, TRY_ONCE
from defender.tests.support.learning.curation._author_draft import DraftRepo


@pytest.fixture
def draft_repo(tmp_path):
    return DraftRepo.over(tmp_path)



def test_agent_exception_leaves_queue_intact(draft_repo, helpers):
    a = draft_repo.author
    helpers.write_finding(draft_repo.queue, finding_id="run-K/0", run_id="run-K")

    def boom(findings, batch_id, cfg):
        raise a.AuthorError("simulated agent failure")

    cfg = replace(draft_repo.cfg, invoke_agent=boom)
    rc = a.run_batch(cfg=cfg)
    assert rc == 2
    rows = read_jsonl_rows(draft_repo.queue)
    assert {r["finding_id"] for r in rows} == {"run-K/0"}, "queue must survive agent failure"
    assert [r.get("attempts") for r in rows] == [1]
    assert not draft_repo.deadletter.exists()

    with draft_repo.state.lock(CURATOR_DRAIN_LOCK, wait=TRY_ONCE) as taken:
        assert taken, "the drain lock must be free after the failed tick"


def test_dlq_quarantines_poison_findings_batch(draft_repo, helpers, monkeypatch):
    """A finding whose authoring keeps faulting is dead-lettered at the ceiling, with its attempt
    count and the fault's message."""
    # `config.author_max_attempts()` reads this key when the config is built (on first use of
    # `draft_repo.cfg`, below), so the setenv applies.
    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "3")  # lint-stale-ref: ok — the ENV
    # VAR outlives the retired module constant of the same name (#717).
    a = draft_repo.author
    helpers.write_finding(draft_repo.queue, finding_id="run-P/0", run_id="run-P")

    def boom(findings, batch_id, cfg):
        raise a.AuthorError("simulated per-run authoring fault")

    fault_cfg = replace(draft_repo.cfg, invoke_agent=boom)
    for _ in range(3):
        assert a.run_batch(cfg=fault_cfg) == 2

    assert read_jsonl_rows(draft_repo.queue) == []
    dead = read_jsonl_rows(draft_repo.deadletter)
    assert {r["finding_id"] for r in dead} == {"run-P/0"}
    assert dead[0]["attempts"] == 3
    assert "simulated per-run authoring fault" in dead[0]["deadletter_reason"]


def _commit_lesson(draft_repo, *, name: str, fid: str):
    """Return a fake invoke_agent that writes one lesson citing ``fid`` — no git (the loop is the sole committer)."""
    def fake(findings, batch_id, cfg):
        draft_repo.write_lesson(name, fid)
        return {"committed": [fid], "consumed_skip": [], "commit_message": name}
    return fake


def test_hold_committed_keeps_findings_queued_until_corpus_covers_them(draft_repo, helpers):
    """Under the drain (`hold_committed`), a committed finding stays queued until its lesson is in
    the corpus; the next tick consumes it as idempotent, without authoring or committing again."""
    a = draft_repo.author
    helpers.write_finding(draft_repo.queue, finding_id="run-H/0", run_id="run-H")

    cfg = replace(draft_repo.cfg, invoke_agent=_commit_lesson(draft_repo, name="lessonH", fid="run-H/0"))
    assert a.run_batch(hold_committed=True, cfg=cfg) == 0
    assert len(draft_repo.lane.commits()) == 1
    head_after_tick1 = draft_repo.lane.tip()
    assert "run-H/0" in draft_repo.queue.read_text()
    consumed = draft_repo.consumed.read_text() if draft_repo.consumed.exists() else ""
    assert "run-H/0" not in consumed
    held_row = json.loads(draft_repo.queue.read_text().splitlines()[0])
    assert "consumed_category" not in held_row

    def must_not_author(findings, batch_id, cfg):
        raise AssertionError("re-authored an already-covered finding")

    cfg = replace(draft_repo.cfg, invoke_agent=must_not_author)
    assert a.run_batch(hold_committed=True, cfg=cfg) == 0
    assert draft_repo.lane.tip() == head_after_tick1
    assert draft_repo.queue.read_text().strip() == ""
    assert "run-H/0" in draft_repo.consumed.read_text()
    assert "consumed_idempotent" in draft_repo.consumed.read_text()
