"""PR #1232 — the family-stamp gate, the judge's and the episode readers'.

Seventh round (finding 3): `verify_family` withholds the family stamp (`provenance.json`) when
the siblings ran other code or knowledge than the source, on unverified or dirty trees, or
under mixed tenants, and only logged why. Before #1224 such a family was recorded `incomplete`
and the judge refused it; M05=A retired `incomplete` and nothing replaced the gate, so a
non-comparable family was graded and its findings queued. What holds now (human decision
2026-10-10): `verify_family` records its reason (`not_comparable.yaml`), and an accepted family
with no readable family stamp is stamped not-graded `not comparable` naming that reason — no
model call, nothing queued. A torn stamp counts as absent. `episode.verdicts` and
`episode.delta_o` refuse the same family through the same predicate
(`outcome.not_comparable_reason`).
"""
from __future__ import annotations

import json
import os

import pytest

from defender._episode_handle import Episode
from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T
from defender.tests import _state1135
from defender.tests._state1135 import env_state
from defender.tests.live_oracle_1224 import _spec1224 as S
from defender.learning.core.state import FINDINGS, QUESTIONER_FINDINGS

WITHHELD = "sibling 'b' ran commit cafef00, not the source's deadbee"


@pytest.fixture(autouse=True)
def _roots(tmp_path, monkeypatch):
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def _judge():
    """A judge double that would grade every world with a queueable finding if asked."""
    finding = J.finding_doc(bucket="lead-quality", subject="defender",
                            topic="the lead was never revisited",
                            evidence=["investigation.md#l-001"])
    world = J.reply_doc(findings=[finding])
    world.update(bucket="lead-quality", systems=["idp"])
    family = J.reply_doc(findings=[])
    family["verdict_word"] = "survived"
    return J.scripted_judge(default=S.as_reply_text(world),
                            family_default=S.as_reply_text(family))


def _grade(tmp_path, ep, judge):
    return J.grade(ep, judge=judge, state=env_state())


def _queued() -> list[dict]:
    state = env_state()
    return state.rows(FINDINGS) + state.rows(QUESTIONER_FINDINGS)


def _not_graded(ep) -> dict:
    return J.judge_record(ep).get("not_graded") or {}


def _withhold(ep, reason: str = WITHHELD) -> None:
    """What `verify_family` leaves when it withholds the stamp: its reason, through the
    production writer."""
    with Episode.open(ep) as episode:
        T.mod("learning.branch.outcome").write_not_comparable(episode, reason)


def _container(ep):
    """The siblings' container `<ep>/runs`, made with the tenant's record as the launcher makes
    it before the first sibling (#1105 PR 2: `verify_family` opens each arm by id through the
    episode's view, so the arms live there)."""
    with Episode.open(ep) as episode:
        T.episode_view(episode)
    return ep / "runs"


def _stampless(tmp_path):
    ep = S.judged_episode(tmp_path, outcome=None)
    S.outcome_record(ep, "accepted", family_stamp=False)
    return ep


def test_an_accepted_family_with_no_family_stamp_is_stamped_not_comparable(tmp_path):
    """Seventh round (finding 3): an accepted family whose stamp `verify_family` withheld was
    graded and its findings queued. Now it is stamped not-graded `not comparable`, the reason
    naming the missing stamp and `verify_family`'s own reason; the model is never called and
    nothing is queued."""
    ep = _stampless(tmp_path)
    _withhold(ep)
    judge = _judge()
    _grade(tmp_path, ep, judge)

    stamp = _not_graded(ep)
    assert stamp.get("outcome") == "not comparable", J.judge_record(ep)
    assert "provenance.json" in stamp.get("reason", ""), stamp
    assert WITHHELD in stamp["reason"], stamp
    assert J.judge_record(ep).get("episode_outcome") == "not-graded"
    assert judge.calls == 0, f"a not-comparable family bought model calls: {judge.agent_ids}"
    assert not any(J.draw_files(ep, label) for label in S.WORLDS), "draws were written"
    assert _queued() == [], "a not-comparable family queued findings"


def test_a_family_with_the_stamp_is_graded(tmp_path):
    """Seventh round (finding 3), the control: the same family carrying the family stamp is
    graded — the model is called and its finding queued."""
    ep = _stampless(tmp_path)
    J.comparable_family_stamp(ep)
    judge = _judge()
    _grade(tmp_path, ep, judge)

    assert not _not_graded(ep), J.judge_record(ep)
    assert judge.calls > 0, "a stamped family was never graded"
    assert _queued(), "a stamped family's finding was never queued"


@pytest.mark.parametrize("torn", ["not json {", '{"agreed": "no", "allow_dirty": false}', "link"])
def test_a_torn_family_stamp_counts_as_absent(tmp_path, torn):
    """Seventh round (finding 3): an unreadable stamp certifies nothing — a torn file, the
    wrong shape, or a link at its name is refused like an absent one (never graded, never a
    refused pass), the reason naming the unreadable stamp."""
    ep = _stampless(tmp_path)
    _withhold(ep)
    stamp_path = ep / "provenance.json"
    if torn == "link":
        target = tmp_path / "elsewhere.json"
        target.write_text('{"agreed": {"commit": "deadbee"}, "allow_dirty": false}\n')
        os.symlink(target, stamp_path)
    else:
        stamp_path.write_text(torn, encoding="utf-8")
    judge = _judge()
    _grade(tmp_path, ep, judge)

    stamp = _not_graded(ep)
    assert stamp.get("outcome") == "not comparable", J.judge_record(ep)
    assert "unreadable" in stamp.get("reason", ""), stamp
    assert WITHHELD in stamp["reason"], stamp
    assert judge.calls == 0
    assert _queued() == []


def test_a_stampless_family_with_no_recorded_reason_still_is_not_comparable(tmp_path):
    """Seventh round (finding 3): with no `not_comparable.yaml` (an episode archived before
    the record existed) the family is still refused, and the reason says no record says
    why."""
    ep = _stampless(tmp_path)
    judge = _judge()
    _grade(tmp_path, ep, judge)

    stamp = _not_graded(ep)
    assert stamp.get("outcome") == "not comparable", J.judge_record(ep)
    assert "no record says why" in stamp.get("reason", ""), stamp
    assert judge.calls == 0


def test_verify_family_records_why_it_withheld_the_stamp_and_the_judge_names_it(tmp_path):
    """Seventh round (finding 3): `verify_family`'s reason was only logged. Now a family whose
    sibling ran another commit has no stamp, its reason is in `not_comparable.yaml`, and the
    judge's stamp names it."""
    T.runs_base(tmp_path)
    ep = S.judged_episode(tmp_path, outcome=None)
    S.outcome_record(ep, "accepted", family_stamp=False)
    base = _container(ep)
    for w in ("a", "b"):
        T.sibling_run_dir(base, w, commit="cafef00" if w == "b" else "deadbee")
    with Episode.open(ep) as episode:
        report = T.mod("learning.branch.cli").verify_family(
            episode, T.family_arms(episode, ("a", "b")), source=T.provenance_record())
    assert report["comparable"] is False
    assert not (ep / "provenance.json").exists()
    recorded = (ep / "not_comparable.yaml").read_text(encoding="utf-8")
    assert "cafef00" in recorded, recorded

    judge = _judge()
    _grade(tmp_path, ep, judge)
    stamp = _not_graded(ep)
    assert stamp.get("outcome") == "not comparable", J.judge_record(ep)
    assert "cafef00" in stamp.get("reason", ""), stamp
    assert judge.calls == 0


def test_the_episode_readers_refuse_a_stampless_family(tmp_path):
    """Seventh round (finding 3): `verdicts` and `delta_o` compare worlds, so the same
    comparability argument holds — an accepted family with no family stamp is refused, naming
    `not comparable`; with the stamp both answer."""
    readers = T.mod("learning.branch.episode")
    ep = T.episode(tmp_path)
    with Episode.open(ep) as episode:
        T.mod("learning.branch.outcome").write_outcome(episode, "accepted", reason="calibrated")
    for w in ("a", "b"):
        T.archived_world(ep, w)
    _withhold(ep)
    for reader in (readers.delta_o, readers.verdicts):
        with pytest.raises(T.refusals()) as bad:
            reader(ep)
        assert "not comparable" in str(bad.value), reader.__name__
        assert WITHHELD in str(bad.value), reader.__name__

    J.comparable_family_stamp(ep)
    assert set(readers.verdicts(ep)) == {"a", "b"}
    readers.delta_o(ep)


def test_a_per_world_fault_leaves_the_family_stamp_to_the_verified_siblings(tmp_path):
    """Seventh round (finding 3), FORK-1 as amended: a finished sibling with no scrub verdict
    withheld the family stamp, so with the judge's gate the whole family would have gone
    ungraded for one world's fault. Now it is that world's own `not archived` record (S10,
    counted by O5): the stamp is written over the verified, archived siblings — the unwalked
    sibling's other commit is no part of it — nothing records the family not comparable, and
    the judge grades the rest."""

    T.runs_base(tmp_path)
    ep = S.judged_episode(tmp_path, outcome=None, labels=("b",))
    S.outcome_record(ep, "accepted", family_stamp=False)
    base = _container(ep)
    T.sibling_run_dir(base, "b")
    T.sibling_run_dir(base, "c", scrub_ran=None, commit="cafef00")
    with Episode.open(ep) as episode:
        report = T.mod("learning.branch.cli").verify_family(
            episode, T.family_arms(episode, ("b", "c")), source=T.provenance_record())
    assert report["comparable"] is True, report
    assert "'c'" in report["reason"]
    assert report["not_comparable"] == ""
    assert report["archived"] == ["b"]
    stamp = json.loads((ep / "provenance.json").read_text(encoding="utf-8"))
    assert stamp["agreed"]["commit"] == "deadbee", stamp
    assert not (ep / "not_comparable.yaml").exists()
    assert (ep / "world_records" / "c.yaml").exists(), "the unwalked world has no record of its own"

    judge = _judge()
    _grade(tmp_path, ep, judge)
    assert not _not_graded(ep), J.judge_record(ep)
    assert S.judge_called_for(judge, "b"), judge.agent_ids
    assert not S.judge_called_for(judge, "c"), judge.agent_ids
