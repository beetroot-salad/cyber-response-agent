from __future__ import annotations

from defender.tests.support.learning.branch import _triplet_947 as T

import pytest

from defender.tests.support.learning.curation import _drain719 as D
from defender.tests.support.learning.judge import _gate_1278 as G
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.learning.judge._memory_store import MemoryStore


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))


def _family_row(fid: str, **over) -> dict:
    """A well-formed defender row as the judge appends it."""
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
        J.mod("learning.judge.enqueue").append_rows(ep, [row], state=J.findings_sink(MemoryStore()))
    assert direction in str(raised.value)


@pytest.mark.parametrize("direction", ["benign", "adversarial", None])
def test_1166_a_queued_non_family_row_is_held_by_name_and_the_batch_still_authors(
        tmp_path, direction):
    # The REAL lessons claim over a batch's git-free draft; the fates are read off its outcomes (#1278 D1).
    legacy = _family_row("old/0", run_id="fresh-01")
    if direction is None:
        legacy.pop("direction")
    else:
        legacy["direction"] = direction
    agent = D.recording(D.committing("family-lesson"))
    lane = G.gate_lane(tmp_path)

    rc, outcomes = G.claim(G.lessons_cfg(lane, invoke_agent=agent), [legacy, _family_row("ep-1/b/0/0")])

    assert rc == 0
    assert [r["finding_id"] for r in agent.calls[0]["rows"]] == ["ep-1/b/0/0"]
    # Held by name; the authored row is cited, so it is named no fate and stays in its batch.
    assert G.fates(outcomes) == {"old/0": ("held", f"retired_direction({direction!r})")}
