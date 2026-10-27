"""Atomicity: agent crash / failure leaves queue intact, lock released."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import json
from dataclasses import replace

import pytest

from defender._io import read_jsonl_rows
from defender.learning.core.state import CURATOR_DRAIN_LOCK, FINDINGS, TRY_ONCE
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



def test_agent_exception_leaves_queue_intact(draft_repo, helpers, monkeypatch):
    a = draft_repo.author
    helpers.write_finding(location_path(draft_repo.paths.state_root) / FINDINGS.queue, finding_id="run-K/0", run_id="run-K")

    def boom(findings, batch_id, cfg):
        raise a.AuthorError("simulated agent failure")

    cfg = replace(draft_repo.cfg, invoke_agent=boom)
    rc = a.run_batch(cfg=cfg)
    assert rc == 2
    rows = read_jsonl_rows(location_path(draft_repo.paths.state_root) / FINDINGS.queue)
    assert {r["finding_id"] for r in rows} == {"run-K/0"}, "queue must survive agent failure"
    assert [r.get("attempts") for r in rows] == [1]
    assert not (location_path(draft_repo.paths.state_root) / FINDINGS.deadletter).exists()

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
    helpers.write_finding(location_path(draft_repo.paths.state_root) / FINDINGS.queue, finding_id="run-P/0", run_id="run-P")

    def boom(findings, batch_id, cfg):
        raise a.AuthorError("simulated per-run authoring fault")

    fault_cfg = replace(draft_repo.cfg, invoke_agent=boom)
    for _ in range(3):
        assert a.run_batch(cfg=fault_cfg) == 2

    assert read_jsonl_rows(location_path(draft_repo.paths.state_root) / FINDINGS.queue) == []
    dead = read_jsonl_rows(location_path(draft_repo.paths.state_root) / FINDINGS.deadletter)
    assert {r["finding_id"] for r in dead} == {"run-P/0"}
    assert dead[0]["attempts"] == 3
    assert "simulated per-run authoring fault" in dead[0]["deadletter_reason"]


def _commit_lesson(draft_repo, a, *, name: str, fid: str):
    """Return a fake invoke_agent that writes one lesson citing ``fid`` — no git (the loop is the sole committer)."""
    def fake(findings, batch_id, cfg):
        body = (
            f"---\nname: {name}\ndescription: d\nsource_finding_ids:\n  - {fid}\n"
            "created_at: 2026-05-09T00:00:00+00:00\n---\n\nbody\n"
        )
        (draft_repo.lessons_dir / f"{name}.md").write_text(body)
        return {"committed": [fid], "held_forward_bad": [], "consumed_skip": [],
                "commit_message": name}
    return fake


def test_hold_committed_keeps_findings_queued_until_corpus_covers_them(
    draft_repo, helpers, monkeypatch
):
    """Under the drain (`hold_committed`), a committed finding stays queued until its lesson is in
    the corpus; the next tick consumes it as idempotent, without authoring or committing again."""
    a = draft_repo.author
    helpers.write_finding(location_path(draft_repo.paths.state_root) / FINDINGS.queue, finding_id="run-H/0", run_id="run-H")

    cfg = replace(
        draft_repo.cfg, invoke_agent=_commit_lesson(draft_repo, a, name="lessonH", fid="run-H/0")
    )
    assert a.run_batch(hold_committed=True, cfg=cfg) == 0
    assert len(draft_repo.lane.commits()) == 1
    head_after_tick1 = draft_repo.lane.tip()
    assert "run-H/0" in (location_path(draft_repo.paths.state_root) / FINDINGS.queue).read_text()
    consumed = (location_path(draft_repo.paths.state_root) / FINDINGS.consumed).read_text() if (location_path(draft_repo.paths.state_root) / FINDINGS.consumed).exists() else ""
    assert "run-H/0" not in consumed
    held_row = json.loads((location_path(draft_repo.paths.state_root) / FINDINGS.queue).read_text().splitlines()[0])
    assert "consumed_category" not in held_row

    def must_not_author(findings, batch_id, cfg):
        raise AssertionError("re-authored an already-covered finding")

    cfg = replace(draft_repo.cfg, invoke_agent=must_not_author)
    assert a.run_batch(hold_committed=True, cfg=cfg) == 0
    assert draft_repo.lane.tip() == head_after_tick1
    assert (location_path(draft_repo.paths.state_root) / FINDINGS.queue).read_text().strip() == ""
    assert "run-H/0" in (location_path(draft_repo.paths.state_root) / FINDINGS.consumed).read_text()
    assert "consumed_idempotent" in (location_path(draft_repo.paths.state_root) / FINDINGS.consumed).read_text()
