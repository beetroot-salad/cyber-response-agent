"""Atomicity: an agent crash / failure leaves the claim's items undecided and the draft clean.

Retired with the file queue (design r8 Locks and Items): the drain lock being free after the failed tick (`TRY_ONCE`,
no drain lock), and `test_dlq_quarantines_poison_findings_batch` (a finding whose authoring keeps faulting is
dead-lettered at the ceiling with its attempt count and the fault's message): the store counts the attempts and holds
the item at the ceiling, `tests/learning/store_1278/test_items_1278.py::test_crashes_to_the_ceiling_hold_the_item_for_a_person`.
"""
from __future__ import annotations

from dataclasses import replace

import pytest

from defender.tests.support.learning.curation._author_draft import DraftRepo


@pytest.fixture
def draft_repo(tmp_path):
    return DraftRepo.over(tmp_path)


def test_agent_exception_leaves_the_items_undecided(draft_repo):
    a = draft_repo.author
    draft_repo.add("run-K/0")

    def boom(findings, batch_id, cfg):
        raise a.AuthorError("simulated agent failure")

    assert draft_repo.run(replace(draft_repo.cfg, invoke_agent=boom)) == 2
    assert draft_repo.outcomes == {}, "an aborted claim must leave the items to the store"
    assert draft_repo.lane.landed() == []


def _commit_lesson(draft_repo, *, name: str, fid: str):
    """Return a fake invoke_agent that writes one lesson citing ``fid`` — no git (the loop is the sole committer)."""
    def fake(findings, batch_id, cfg):
        draft_repo.write_lesson(name, fid)
        return {"committed": [fid], "consumed_skip": [], "commit_message": name}
    return fake


def test_a_committed_finding_is_not_authored_again_once_the_corpus_covers_it(draft_repo):
    """A committed finding stays with its batch; the next claim over the same finding finds its lesson already in the
    corpus and publishes it as idempotent, without authoring or committing again (the pre-author idempotency gate)."""
    draft_repo.add("run-H/0")

    cfg = replace(draft_repo.cfg, invoke_agent=_commit_lesson(draft_repo, name="lessonH", fid="run-H/0"))
    assert draft_repo.run(cfg) == 0
    assert len(draft_repo.lane.commits()) == 1
    head_after_tick1 = draft_repo.lane.tip()
    assert draft_repo.fate("run-H/0") is None

    def must_not_author(findings, batch_id, cfg):
        raise AssertionError("re-authored an already-covered finding")

    assert draft_repo.run(replace(draft_repo.cfg, invoke_agent=must_not_author)) == 0
    assert draft_repo.lane.tip() == head_after_tick1
    assert draft_repo.fate("run-H/0") == ("published", None)
