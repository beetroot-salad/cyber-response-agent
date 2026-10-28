"""Post-flight: agent-state verification, queue rotation, no-commit surfacing.

The author works on a batch draft; what it committed is read off the batch branch."""
from __future__ import annotations

import json
from dataclasses import replace

import pytest
from defender.learning.core.state import FINDINGS

from defender.tests.support.learning.curation._author_draft import DraftRepo, attempts, rows_without_attempts


@pytest.fixture
def draft_repo(tmp_path):
    return DraftRepo.over(tmp_path)



def _assert_held_with_one_attempt(draft_repo, pre_pending: list[dict]) -> None:
    """The tick left the queue as it was, each row charged one attempt, and consumed nothing."""
    queued = draft_repo.queue.read_text()
    assert rows_without_attempts(queued) == pre_pending
    assert attempts(queued) == [1] * len(pre_pending)
    assert not draft_repo.consumed.exists()


def test_committed_finding_consumed(draft_repo, helpers):
    a = draft_repo.author
    helpers.write_finding(draft_repo.queue, finding_id="run-1/0", run_id="run-1")

    def fake_invoke(findings, batch_id, cfg):
        draft_repo.write_lesson("lessonA", "run-1/0")
        return {
            "committed": ["run-1/0"],
            "consumed_skip": [],
            "commit_message": "defender: lesson lessonA",
        }

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    assert a.run_batch(cfg=cfg) == 0
    # What landed on the batch branch, asked of git.
    assert draft_repo.lane.landed() == ["agent/lessons/lessonA.md"]
    assert len(draft_repo.lane.commits()) == 1
    assert draft_repo.queue.read_text().strip() == ""
    consumed = [
        json.loads(line)
        for line in draft_repo.consumed.read_text().splitlines() if line.strip()
    ]
    assert len(consumed) == 1
    assert consumed[0]["consumed_category"] == "consumed_committed"
    assert consumed[0]["consumed_commit"] == draft_repo.lane.tip()


def test_committed_finding_without_commit_message_aborts(draft_repo, helpers):
    a = draft_repo.author
    helpers.write_finding(draft_repo.queue, finding_id="run-1b/0", run_id="run-1b")
    pre_pending = rows_without_attempts(draft_repo.queue.read_text())

    def fake_invoke(findings, batch_id, cfg):
        draft_repo.write_lesson("lessonB", "run-1b/0")
        return {
            "committed": ["run-1b/0"],
            "consumed_skip": [],
        }

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    assert a.run_batch(cfg=cfg) == 2
    _assert_held_with_one_attempt(draft_repo, pre_pending)


def test_a_stray_forward_bad_bucket_key_aborts(draft_repo, helpers):
    """`held_forward_bad` is no longer a curator bucket (#773): a result still carrying it aborts
    the tick and charges the row an attempt."""
    a = draft_repo.author
    helpers.write_finding(draft_repo.queue, finding_id="run-2/0", run_id="run-2")

    def fake_invoke(findings, batch_id, cfg):
        return {
            "committed": [],
            "held_forward_bad": [{"finding_id": "run-2/0", "reason": "regresses-elsewhere"}],
            "consumed_skip": [],
            "commit_message": None,
        }

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    assert a.run_batch(cfg=cfg) == 2
    pending = [
        json.loads(line)
        for line in draft_repo.queue.read_text().splitlines() if line.strip()
    ]
    assert [p["finding_id"] for p in pending] == ["run-2/0"]
    assert pending[0].get("attempts") == 1


def test_consumed_skip_rotates_out(draft_repo, helpers):
    a = draft_repo.author
    helpers.write_finding(draft_repo.queue, finding_id="run-3/0", run_id="run-3")

    def fake_invoke(findings, batch_id, cfg):
        return {
            "committed": [],
            "consumed_skip": [{"finding_id": "run-3/0", "reason": "already covered"}],
            "commit_message": None,
        }

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    assert a.run_batch(cfg=cfg) == 0
    assert draft_repo.queue.read_text().strip() == "", "skipped findings must rotate out — never re-trigger"
    consumed = [
        json.loads(line)
        for line in draft_repo.consumed.read_text().splitlines() if line.strip()
    ]
    assert consumed[0]["consumed_category"] == "consumed_skip"
    assert "skip_reason" in consumed[0]


def test_committed_but_corpus_clean_aborts(draft_repo, helpers):
    """``committed`` non-empty but the corpus clean (a claimed commit, no edits) is inconsistent:
    the tick aborts, the row stays queued with one attempt, nothing rotates."""
    a = draft_repo.author
    helpers.write_finding(draft_repo.queue, finding_id="run-4/0", run_id="run-4")
    pre_pending = rows_without_attempts(draft_repo.queue.read_text())

    def fake_invoke(findings, batch_id, cfg):
        return {
            "committed": ["run-4/0"],
            "consumed_skip": [],
            "commit_message": "defender: lesson batch",
        }

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    assert a.run_batch(cfg=cfg) == 2
    _assert_held_with_one_attempt(draft_repo, pre_pending)


def test_no_commit_but_left_corpus_edits_aborts(draft_repo, helpers):
    """``committed`` empty but the corpus dirty is inconsistent: refuse to rotate, and reset the
    draft."""
    a = draft_repo.author
    helpers.write_finding(draft_repo.queue, finding_id="run-5/0", run_id="run-5")
    pre_pending = rows_without_attempts(draft_repo.queue.read_text())

    def fake_invoke(findings, batch_id, cfg):
        (draft_repo.lessons_dir / "orphan.md").write_text("uncommitted\n")
        return {
            "committed": [],
            "consumed_skip": [{"finding_id": "run-5/0", "reason": "x"}],
            "commit_message": None,
        }

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    assert a.run_batch(cfg=cfg) == 2
    _assert_held_with_one_attempt(draft_repo, pre_pending)
    assert draft_repo.lane.drift() == [], "the refused tick left its edit in the draft"


def test_agent_result_missing_finding_stays_queued_untouched(draft_repo, helpers):
    """A row the curator mentions in no bucket is neither a fault nor charged: it stays queued
    as it was while the rest of the tick completes."""
    a = draft_repo.author
    helpers.write_finding(draft_repo.queue, finding_id="run-6/0", run_id="run-6")
    helpers.write_finding(draft_repo.queue, finding_id="run-6/1", run_id="run-6")

    def fake_invoke(findings, batch_id, cfg):
        return {
            "committed": [],
            "consumed_skip": [{"finding_id": "run-6/0", "reason": "x"}],
            "commit_message": None,
        }

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    rc = a.run_batch(cfg=cfg)
    assert rc == 0
    remaining = rows_without_attempts(draft_repo.queue.read_text())
    assert [r["finding_id"] for r in remaining] == ["run-6/1"]
    assert "attempts" not in remaining[0]


@pytest.mark.parametrize(
    "agent_result",
    [
        # Committed and skipped at once; its lesson is written, so the commit claim itself holds.
        {
            "committed": ["run-6b/0"],
            "consumed_skip": [{"finding_id": "run-6b/0", "reason": "x"}],
            "commit_message": "defender: lesson dup",
        },
        {
            "committed": [],
            "consumed_skip": [
                {"finding_id": "run-6b/0", "reason": "x"},
                {"finding_id": "run-6b/0", "reason": "x"},
            ],
            "commit_message": None,
        },
    ],
)
def test_agent_result_duplicate_classification_aborts(draft_repo, helpers, agent_result):
    a = draft_repo.author
    helpers.write_finding(draft_repo.queue, finding_id="run-6b/0", run_id="run-6b")
    pre_pending = rows_without_attempts(draft_repo.queue.read_text())

    def fake_invoke(findings, batch_id, cfg):
        if agent_result["committed"]:
            draft_repo.write_lesson("dup", "run-6b/0")
        return agent_result

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    rc = a.run_batch(cfg=cfg)
    assert rc == 2
    _assert_held_with_one_attempt(draft_repo, pre_pending)
    [stuck] = draft_repo.state.stuck_rows(FINDINGS)
    assert "more than once" in stuck["reason"], stuck


def test_agent_writes_outside_lessons_aborts(draft_repo, helpers):
    """A change outside every lane of the draft refuses the claim whole: a refused claim, not a
    stage failure (rc 0), with the row held at one attempt, nothing landed, the draft reset."""
    a = draft_repo.author
    helpers.write_finding(draft_repo.queue, finding_id="run-7/0", run_id="run-7")
    pre_pending = rows_without_attempts(draft_repo.queue.read_text())

    def fake_invoke(findings, batch_id, cfg):
        # Outside every lane of the draft.
        (draft_repo.lane.agent / "scratch.txt").write_text("oops")
        draft_repo.write_lesson("in-scope", "run-7/0")
        return {
            "committed": ["run-7/0"],
            "consumed_skip": [],
            "commit_message": "defender: lesson in-scope",
        }

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    rc = a.run_batch(cfg=cfg)
    assert rc == 0
    _assert_held_with_one_attempt(draft_repo, pre_pending)
    assert draft_repo.lane.landed() == [], "an out-of-lane change refuses the claim whole"
    assert draft_repo.lane.drift() == [], "the refused claim's draft was not reset"
