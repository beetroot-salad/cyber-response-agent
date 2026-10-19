from __future__ import annotations

from defender.tests.support.learning.branch import _triplet_947 as T

import pytest

from defender.tests.support.learning.curation import _drain719 as D
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.learning.core import _state1135
from defender.tests.support.learning.core._state1135 import env_state


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def _family_row(fid: str, **over) -> dict:
    """A well-formed defender row as the judge appends it (#1234 shape)."""
    row = dict(D.finding_row(fid, run_id="ep-1", direction="family"),
               type="decision-discipline", subject="defender",
               subject_anchor="l-001", subject_topic="holding-system coverage",
               source_run_dir="episodes/ep-1/worlds/b",
               contrast_evidence=[f"worlds/{T.fixture_world_id('b')}/report.md", f"worlds/{T.fixture_world_id('a')}/report.md"],
               on_verdict_path=True, world_label_doubted=False)
    row.pop("judge_outcome", None)
    row.update(over)
    return row


@pytest.mark.parametrize("direction", ["benign", "adversarial"])
def test_1166_the_appender_refuses_a_defender_row_that_is_not_family(tmp_path, direction):
    ep = tmp_path / "ep"
    ep.mkdir()
    row = _family_row("ep-1/b/0/0", direction=direction)
    with pytest.raises(J.refusals()) as raised:
        J.mod("learning.judge.enqueue").append_rows(ep, [row], state=env_state())
    assert direction in str(raised.value)


@pytest.mark.parametrize("direction", ["benign", "adversarial", None])
def test_1166_a_queued_non_family_row_is_held_by_name_and_the_batch_still_authors(
        tmp_path, direction):
    paths = D.make_paths(tmp_path)
    channel = D.channel_of("findings")
    legacy = _family_row("old/0", run_id="fresh-01")
    if direction is None:
        legacy.pop("direction")
    else:
        legacy["direction"] = direction
    D.seed(paths, channel, [legacy, _family_row("ep-1/b/0/0")])
    agent = D.recording(D.committing("family-lesson"))
    cfg = D.cfg_for(paths, "findings", invoke_agent=agent)

    assert J.mod("learning.author.drain").run_batch(cfg=cfg) == 0
    assert [r["finding_id"] for r in agent.calls[0]["rows"]] == ["ep-1/b/0/0"]
    assert [r["finding_id"] for r in D.consumed(paths, channel)] == ["ep-1/b/0/0"]
    pending = D.pending_by_id(paths, channel)
    assert list(pending) == ["old/0"]
    assert pending["old/0"]["held_reason"] == f"retired_direction({direction!r})"
    assert D.stuck_records(paths, channel) == []
