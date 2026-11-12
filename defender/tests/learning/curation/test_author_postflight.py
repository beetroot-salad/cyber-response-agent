"""Post-flight: agent-state verification, the fates a claim writes, no-commit surfacing.

The author works on a batch draft; what it committed is read off the batch branch, and the fate each claimed row got is
the claim's `outcomes` (#1278 D1): none for a committed row (it stays in the batch) or one the curator mentioned
nowhere, `skipped` with the curator's reason, and nothing at all for an aborted tick (the claim counted the attempt).

Retired with the file queue (design r8 Items): the queue rotation itself, the `consumed_commit` sha stamped on a consumed
row (the commit record is the store's), the per-row `attempts` count, and the stuck-row record of a duplicate
classification (the reason is logged and is the claim's fault record)."""
from __future__ import annotations

from dataclasses import replace

import pytest

from defender.tests.support.learning.curation._author_draft import DraftRepo


@pytest.fixture
def draft_repo(tmp_path):
    return DraftRepo.over(tmp_path)


def _aborted(draft_repo, rc: int) -> None:
    """The tick aborted (`rc`): the rows stay as they were, given no fate, and nothing is left in the draft."""
    assert rc in (0, 2)
    assert draft_repo.outcomes == {}
    assert draft_repo.lane.drift() == []


def test_committed_finding_is_committed_and_stays_in_the_batch(draft_repo):
    draft_repo.add("run-1/0")

    def fake_invoke(findings, batch_id, cfg):
        draft_repo.write_lesson("lessonA", "run-1/0")
        return {
            "committed": ["run-1/0"],
            "consumed_skip": [],
            "commit_message": "defender: lesson lessonA",
        }

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    assert draft_repo.run(cfg) == 0
    # What landed on the batch branch, asked of git.
    assert draft_repo.lane.landed() == ["agent/lessons/lessonA.md"]
    assert len(draft_repo.lane.commits()) == 1
    assert draft_repo.fate("run-1/0") is None, "a committed finding is named nowhere: it stays in its batch"
    assert draft_repo.outcomes == {}


def test_committed_finding_without_commit_message_aborts(draft_repo):
    draft_repo.add("run-1b/0")

    def fake_invoke(findings, batch_id, cfg):
        draft_repo.write_lesson("lessonB", "run-1b/0")
        return {
            "committed": ["run-1b/0"],
            "consumed_skip": [],
        }

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    assert draft_repo.run(cfg) == 2
    _aborted(draft_repo, 2)
    assert draft_repo.lane.landed() == []


def test_a_stray_forward_bad_bucket_key_aborts(draft_repo):
    """`held_forward_bad` is no longer a curator bucket (#773): a result still carrying it aborts
    the tick and decides nothing for the row."""
    draft_repo.add("run-2/0")

    def fake_invoke(findings, batch_id, cfg):
        return {
            "committed": [],
            "held_forward_bad": [{"finding_id": "run-2/0", "reason": "regresses-elsewhere"}],
            "consumed_skip": [],
            "commit_message": None,
        }

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    assert draft_repo.run(cfg) == 2
    _aborted(draft_repo, 2)


def test_consumed_skip_is_skipped_with_the_curators_reason(draft_repo):
    draft_repo.add("run-3/0")

    def fake_invoke(findings, batch_id, cfg):
        return {
            "committed": [],
            "consumed_skip": [{"finding_id": "run-3/0", "reason": "already covered"}],
            "commit_message": None,
        }

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    assert draft_repo.run(cfg) == 0
    assert draft_repo.fate("run-3/0") == ("skipped", "already covered"), "skipped findings must leave the work — never re-trigger"


def test_committed_but_corpus_clean_aborts(draft_repo):
    """``committed`` non-empty but the corpus clean (a claimed commit, no edits) is inconsistent:
    the tick aborts and decides nothing."""
    draft_repo.add("run-4/0")

    def fake_invoke(findings, batch_id, cfg):
        return {
            "committed": ["run-4/0"],
            "consumed_skip": [],
            "commit_message": "defender: lesson batch",
        }

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    assert draft_repo.run(cfg) == 2
    _aborted(draft_repo, 2)


def test_no_commit_but_left_corpus_edits_aborts(draft_repo):
    """``committed`` empty but the corpus dirty is inconsistent: refuse to decide, and reset the
    draft."""
    draft_repo.add("run-5/0")

    def fake_invoke(findings, batch_id, cfg):
        (draft_repo.lessons_dir / "orphan.md").write_text("uncommitted\n")
        return {
            "committed": [],
            "consumed_skip": [{"finding_id": "run-5/0", "reason": "x"}],
            "commit_message": None,
        }

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    assert draft_repo.run(cfg) == 2
    _aborted(draft_repo, 2)
    assert draft_repo.lane.landed() == []


def test_agent_result_missing_finding_is_decided_nothing(draft_repo):
    """A row the curator mentions in no bucket is neither a fault nor decided: it keeps no fate
    while the rest of the tick completes."""
    draft_repo.add("run-6/0")
    draft_repo.add("run-6/1")

    def fake_invoke(findings, batch_id, cfg):
        return {
            "committed": [],
            "consumed_skip": [{"finding_id": "run-6/0", "reason": "x"}],
            "commit_message": None,
        }

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    assert draft_repo.run(cfg) == 0
    assert draft_repo.fate("run-6/0") == ("skipped", "x")
    assert draft_repo.fate("run-6/1") is None


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
def test_agent_result_duplicate_classification_aborts(draft_repo, agent_result, caplog):
    draft_repo.add("run-6b/0")

    def fake_invoke(findings, batch_id, cfg):
        if agent_result["committed"]:
            draft_repo.write_lesson("dup", "run-6b/0")
        return agent_result

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    assert draft_repo.run(cfg) == 2
    _aborted(draft_repo, 2)
    assert "more than once" in caplog.text


def test_agent_writes_outside_lessons_aborts(draft_repo):
    """A change outside every lane of the draft refuses the claim whole: a refused claim, not a
    stage failure (rc 0), nothing decided, nothing landed, the draft reset."""
    draft_repo.add("run-7/0")

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
    assert draft_repo.run(cfg) == 0
    _aborted(draft_repo, 0)
    assert draft_repo.lane.landed() == [], "an out-of-lane change refuses the claim whole"
