"""Post-flight: agent-state verification, queue rotation, no-commit surfacing.

The author works on a batch draft; what it committed is read off the batch branch."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import json
from dataclasses import replace

import pytest
from defender.learning.core.state import FINDINGS

from defender.tests.support.learning.curation import _curator1134 as C


# The lessons author over a batch's git-free draft; its config (`_curator1134.draft_author_cfg`)
# is built on first use of `cfg`.
class _DraftRepo:
    def __init__(self, lane):
        from defender.learning.author.lessons import run as author_mod

        self.lane = lane
        self.author = author_mod
        self.paths = lane.paths
        self.lessons_dir = lane.lessons_dir
        self.state = C.open_state(lane.paths)
        self._cfg = None

    @property
    def cfg(self):
        if self._cfg is None:
            self._cfg = C.draft_author_cfg(self.lane, state=self.state)
        return self._cfg


@pytest.fixture
def draft_repo(tmp_path):
    """The fixture tenant's batch draft (lanes `lessons`, `lessons-questioner`) and its author."""
    return _DraftRepo(C.draft_lane(tmp_path))



def _rows_without_attempts(text: str) -> list[dict]:
    """The queue's rows with the retirement counter dropped."""
    import json as _json

    return [
        {k: v for k, v in _json.loads(line).items() if k != "attempts"}
        for line in text.splitlines() if line.strip()
    ]


def _attempts(text: str) -> list[int]:
    import json as _json

    return [_json.loads(line).get("attempts") for line in text.splitlines() if line.strip()]


def _write_lesson(draft_repo, name: str, finding_id: str) -> None:
    """Write a lesson into the working tree — no git (the loop commits)."""
    body = (
        "---\n"
        f"name: {name}\n"
        "description: a teachable pitfall\n"
        "source_finding_ids:\n"
        f"  - {finding_id}\n"
        "created_at: 2026-05-09T00:00:00+00:00\n"
        "---\n\nbody\n"
    )
    (draft_repo.lessons_dir / f"{name}.md").write_text(body)


def test_committed_finding_consumed(draft_repo, helpers, monkeypatch):
    a = draft_repo.author
    helpers.write_finding(location_path(draft_repo.paths.state_root) / FINDINGS.queue, finding_id="run-1/0", run_id="run-1")

    def fake_invoke(findings, batch_id, cfg):
        _write_lesson(draft_repo, "lessonA", "run-1/0")
        return {
            "committed": ["run-1/0"],
            "held_forward_bad": [],
            "consumed_skip": [],
            "commit_message": "defender: lesson lessonA",
        }

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    assert a.run_batch(cfg=cfg) == 0
    # What landed on the batch branch, asked of git.
    assert draft_repo.lane.landed() == ["agent/lessons/lessonA.md"]
    assert len(draft_repo.lane.commits()) == 1
    assert (location_path(draft_repo.paths.state_root) / FINDINGS.queue).read_text().strip() == ""
    consumed = [
        json.loads(line)
        for line in (location_path(draft_repo.paths.state_root) / FINDINGS.consumed).read_text().splitlines() if line.strip()
    ]
    assert len(consumed) == 1
    assert consumed[0]["consumed_category"] == "consumed_committed"
    assert consumed[0]["consumed_commit"] == draft_repo.lane.tip()


def test_committed_finding_without_commit_message_aborts(draft_repo, helpers, monkeypatch):
    a = draft_repo.author
    helpers.write_finding(location_path(draft_repo.paths.state_root) / FINDINGS.queue, finding_id="run-1b/0", run_id="run-1b")
    pre_pending = _rows_without_attempts((location_path(draft_repo.paths.state_root) / FINDINGS.queue).read_text())

    def fake_invoke(findings, batch_id, cfg):
        _write_lesson(draft_repo, "lessonB", "run-1b/0")
        return {
            "committed": ["run-1b/0"],
            "held_forward_bad": [],
            "consumed_skip": [],
        }

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    assert a.run_batch(cfg=cfg) == 2
    assert _rows_without_attempts((location_path(draft_repo.paths.state_root) / FINDINGS.queue).read_text()) == pre_pending
    assert _attempts((location_path(draft_repo.paths.state_root) / FINDINGS.queue).read_text()) == [1] * len(pre_pending)
    assert not (location_path(draft_repo.paths.state_root) / FINDINGS.consumed).exists()


def test_a_stray_forward_bad_bucket_key_aborts(draft_repo, helpers, monkeypatch):
    """`held_forward_bad` is no longer a curator bucket (#773): a result still carrying it aborts
    the tick and charges the row an attempt."""
    a = draft_repo.author
    helpers.write_finding(location_path(draft_repo.paths.state_root) / FINDINGS.queue, finding_id="run-2/0", run_id="run-2")

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
        for line in (location_path(draft_repo.paths.state_root) / FINDINGS.queue).read_text().splitlines() if line.strip()
    ]
    assert [p["finding_id"] for p in pending] == ["run-2/0"]
    assert pending[0].get("attempts") == 1


def test_consumed_skip_rotates_out(draft_repo, helpers, monkeypatch):
    a = draft_repo.author
    helpers.write_finding(location_path(draft_repo.paths.state_root) / FINDINGS.queue, finding_id="run-3/0", run_id="run-3")

    def fake_invoke(findings, batch_id, cfg):
        return {
            "committed": [],
            "held_forward_bad": [],
            "consumed_skip": [{"finding_id": "run-3/0", "reason": "already covered"}],
            "commit_message": None,
        }

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    assert a.run_batch(cfg=cfg) == 0
    assert (location_path(draft_repo.paths.state_root) / FINDINGS.queue).read_text().strip() == "", "skipped findings must rotate out — never re-trigger"
    consumed = [
        json.loads(line)
        for line in (location_path(draft_repo.paths.state_root) / FINDINGS.consumed).read_text().splitlines() if line.strip()
    ]
    assert consumed[0]["consumed_category"] == "consumed_skip"
    assert "skip_reason" in consumed[0]


def test_committed_but_corpus_clean_aborts(draft_repo, helpers, monkeypatch):
    """``committed`` non-empty but the corpus clean (a claimed commit, no edits) is inconsistent:
    the tick aborts, the row stays queued with one attempt, nothing rotates."""
    a = draft_repo.author
    helpers.write_finding(location_path(draft_repo.paths.state_root) / FINDINGS.queue, finding_id="run-4/0", run_id="run-4")
    pre_pending = _rows_without_attempts((location_path(draft_repo.paths.state_root) / FINDINGS.queue).read_text())

    def fake_invoke(findings, batch_id, cfg):
        return {
            "committed": ["run-4/0"],
            "held_forward_bad": [],
            "consumed_skip": [],
            "commit_message": "defender: lesson batch",
        }

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    assert a.run_batch(cfg=cfg) == 2
    assert _rows_without_attempts((location_path(draft_repo.paths.state_root) / FINDINGS.queue).read_text()) == pre_pending
    assert _attempts((location_path(draft_repo.paths.state_root) / FINDINGS.queue).read_text()) == [1] * len(pre_pending)
    assert not (location_path(draft_repo.paths.state_root) / FINDINGS.consumed).exists()


def test_no_commit_but_left_corpus_edits_aborts(draft_repo, helpers, monkeypatch):
    """``committed`` empty but the corpus dirty is inconsistent: refuse to rotate, and reset the
    draft."""
    a = draft_repo.author
    helpers.write_finding(location_path(draft_repo.paths.state_root) / FINDINGS.queue, finding_id="run-5/0", run_id="run-5")
    pre_pending = _rows_without_attempts((location_path(draft_repo.paths.state_root) / FINDINGS.queue).read_text())

    def fake_invoke(findings, batch_id, cfg):
        (draft_repo.lessons_dir / "orphan.md").write_text("uncommitted\n")
        return {
            "committed": [],
            "held_forward_bad": [],
            "consumed_skip": [{"finding_id": "run-5/0", "reason": "x"}],
            "commit_message": None,
        }

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    assert a.run_batch(cfg=cfg) == 2
    assert _rows_without_attempts((location_path(draft_repo.paths.state_root) / FINDINGS.queue).read_text()) == pre_pending
    assert _attempts((location_path(draft_repo.paths.state_root) / FINDINGS.queue).read_text()) == [1] * len(pre_pending)
    assert not (location_path(draft_repo.paths.state_root) / FINDINGS.consumed).exists()
    assert draft_repo.lane.drift() == [], "the refused tick left its edit in the draft"


def test_agent_result_missing_finding_stays_queued_untouched(draft_repo, helpers, monkeypatch):
    """A row the curator mentions in no bucket is neither a fault nor charged: it stays queued
    as it was while the rest of the tick completes."""
    a = draft_repo.author
    helpers.write_finding(location_path(draft_repo.paths.state_root) / FINDINGS.queue, finding_id="run-6/0", run_id="run-6")
    helpers.write_finding(location_path(draft_repo.paths.state_root) / FINDINGS.queue, finding_id="run-6/1", run_id="run-6")

    def fake_invoke(findings, batch_id, cfg):
        return {
            "committed": [],
            "consumed_skip": [{"finding_id": "run-6/0", "reason": "x"}],
            "commit_message": None,
        }

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    rc = a.run_batch(cfg=cfg)
    assert rc == 0
    remaining = _rows_without_attempts((location_path(draft_repo.paths.state_root) / FINDINGS.queue).read_text())
    assert [r["finding_id"] for r in remaining] == ["run-6/1"]
    assert "attempts" not in remaining[0]


@pytest.mark.parametrize(
    "agent_result",
    [
        {
            "committed": [],
            "held_forward_bad": [{"finding_id": "run-6b/0", "reason": "x"}],
            "consumed_skip": [{"finding_id": "run-6b/0", "reason": "x"}],
            "commit_message": None,
        },
        {
            "committed": [],
            "held_forward_bad": [],
            "consumed_skip": [
                {"finding_id": "run-6b/0", "reason": "x"},
                {"finding_id": "run-6b/0", "reason": "x"},
            ],
            "commit_message": None,
        },
    ],
)
def test_agent_result_duplicate_classification_aborts(
    draft_repo, helpers, monkeypatch, agent_result
):
    a = draft_repo.author
    helpers.write_finding(location_path(draft_repo.paths.state_root) / FINDINGS.queue, finding_id="run-6b/0", run_id="run-6b")
    pre_pending = _rows_without_attempts((location_path(draft_repo.paths.state_root) / FINDINGS.queue).read_text())

    def fake_invoke(findings, batch_id, cfg):
        return agent_result

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    rc = a.run_batch(cfg=cfg)
    assert rc == 2
    assert _rows_without_attempts((location_path(draft_repo.paths.state_root) / FINDINGS.queue).read_text()) == pre_pending
    assert _attempts((location_path(draft_repo.paths.state_root) / FINDINGS.queue).read_text()) == [1] * len(pre_pending)
    assert not (location_path(draft_repo.paths.state_root) / FINDINGS.consumed).exists()


def test_agent_writes_outside_lessons_aborts(draft_repo, helpers, monkeypatch):
    """A change outside every lane of the draft refuses the claim whole: a refused claim, not a
    stage failure (rc 0), with the row held at one attempt, nothing landed, the draft reset."""
    a = draft_repo.author
    helpers.write_finding(location_path(draft_repo.paths.state_root) / FINDINGS.queue, finding_id="run-7/0", run_id="run-7")
    pre_pending = _rows_without_attempts((location_path(draft_repo.paths.state_root) / FINDINGS.queue).read_text())

    def fake_invoke(findings, batch_id, cfg):
        # Outside every lane of the draft.
        (draft_repo.lane.agent / "scratch.txt").write_text("oops")
        _write_lesson(draft_repo, "in-scope", "run-7/0")
        return {
            "committed": ["run-7/0"],
            "held_forward_bad": [],
            "consumed_skip": [],
            "commit_message": "defender: lesson in-scope",
        }

    cfg = replace(draft_repo.cfg, invoke_agent=fake_invoke)
    rc = a.run_batch(cfg=cfg)
    assert rc == 0
    assert _rows_without_attempts((location_path(draft_repo.paths.state_root) / FINDINGS.queue).read_text()) == pre_pending
    assert _attempts((location_path(draft_repo.paths.state_root) / FINDINGS.queue).read_text()) == [1] * len(pre_pending)
    assert not (location_path(draft_repo.paths.state_root) / FINDINGS.consumed).exists()
    assert draft_repo.lane.landed() == [], "an out-of-lane change refuses the claim whole"
    assert draft_repo.lane.drift() == [], "the refused claim's draft was not reset"
