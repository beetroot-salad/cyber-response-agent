"""#1234 judge contrast: multi-draw agreement and world measurement predicates."""
from __future__ import annotations

from collections import Counter
from typing import Any

import pytest

from defender.tests.judge_contrast_1234 import _spec1234 as S

#: A world row's measurement (d00a), spelled once through the shared vocabulary.
MEASURED = S.COINED["row.measured"]
NOT_MEASURED_REASON = S.COINED["row.not_measured_reason"]
DISAGREE = S.COINED["row.draws_disagree"]
ROW_DRAWS = S.COINED["row.draws"]
COMPLETED = S.RULED["row.completed_draws"]
BUCKET = S.RULED["reply.bucket"]
ROW_SYSTEMS = S.RULED["row.systems"]


#: Not YAML: refused by any reply validator, so the draw asks again (N22) and, refused on every
#: ask, completes nothing.
MALFORMED = "bucket: [unterminated"

LQ = "lead-quality"


def _inv(label: str, bucket: str = LQ) -> dict:
    """An investigator finding whose contrast pair resolves for world `label`: a conduct pointer
    in the focus run (its report) and one in a reference run (the control's)."""
    return S.inv(bucket, contrast=[S.conduct(label), S.conduct("a")])


def _design(label: str, bucket: str = "mislabelled", *,
            systems: tuple[str, ...] = ("idp",)) -> dict:
    """A world finding citing the plan at `label`'s entry only: not gap-only, with a resolving
    plan pointer, so design — it routes to the questioner queue (A1, A15)."""
    return S.wf(bucket, systems=systems, evidence=[S.plan_ptr(label)])


def _lq(label: str, *world: dict, systems: list[str] | None = None) -> dict:
    """A `lead-quality` world reply carrying one resolving investigator finding (index 0) and
    `world` findings after it (indices 1, 2, ...)."""
    return S.world_reply(LQ, systems if systems is not None else ["idp"],
                         investigator=[_inv(label)], world=list(world))


def _none(label: str) -> dict:
    """A `none` world reply that still lists one resolving investigator finding."""
    return S.world_reply(S.NO_BUCKET, [], investigator=[_inv(label)])


def _gap_reply(built: S.Built, label: str, call: int, *, kept_facts: bool) -> dict:
    """A `lead-quality` reply with one investigator finding (index 0) and one deployment gap
    (index 1) citing world `label`'s `call`-th own call's served-ledger row — a `refused` row,
    so the gap names a blocked call (A2, A14) — and F-14's flag. The gap's `what` carries
    `S.marker(label, "gap")`, so a reason naming the gap is observable."""
    pointer = built.served(label, built.served_row(label, call))
    return S.world_reply(LQ, ["idp"], investigator=[_inv(label)],
                         gaps=[S.gap(S.marker(label, "gap"), evidence=[pointer],
                                     kept_facts=kept_facts)])


def _draws(label: str, *replies: Any) -> dict:
    """`{(label, n): reply_n}` — one routed reply per draw."""
    return {(label, n): reply for n, reply in enumerate(replies)}


def _b_calls(*extra: S.CallRow) -> list[S.CallRow]:
    """World b's default calls (an ordinary call and the oracle's altered answer: b is shown its
    facts), then `extra`."""
    return [S.CallRow(), S.oracle_call(fact_id="f-b", forged_id="fg-b-1"), *extra]


def _c_calls(*extra: S.CallRow) -> list[S.CallRow]:
    """World c's default call (an ordinary passthrough on edr), then `extra`."""
    return [S.CallRow(system="edr", params=S.query_params("host:db-1")), *extra]


def _shown(label: str, role: str) -> dict:
    """An extra planted world shown its facts: an oracle answer adding its forged row."""
    return {"role": role, "calls": [
        S.CallRow(), S.oracle_call(fact_id=f"f-{label}", forged_id=f"fg-{label}-1")]}


def _plain(role: str) -> dict:
    """An extra planted world with one ordinary call."""
    return {"role": role, "calls": [S.CallRow()]}


def _ids(rows: list[dict]) -> set[Any]:
    return {r.get("finding_id") for r in rows}


def _defender_ids(label: str) -> set[Any]:
    """Finding ids of the defender queue's rows from world `label`."""
    return _ids(S.from_world(S.defender_queue(), label))


def _questioner_ids(label: str) -> set[Any]:
    """Finding ids of the questioner queue's rows from world `label`."""
    return _ids(S.from_world(S.questioner_queue(), label))


def _every_draw(built: S.Built, label: str, index: int, draws: int = 3) -> set[str]:
    """`<episode>/<label>/<n>/<index>` for every draw `n`."""
    return {built.finding_id(label, n, index) for n in range(draws)}


def _draw_buckets(row: dict) -> Counter:
    """Every recorded draw's bucket on a world row, as a multiset."""
    return Counter(d.get(BUCKET) for d in row.get(ROW_DRAWS) or [] if isinstance(d, dict))


def test_1234_world_bucket_counts_only_when_every_completed_draw_agrees(tmp_path):
    ad = "analyze-discipline"
    built = S.family(tmp_path, S.triad(d=_shown("d", "D")))
    agree = S.world_reply(ad, ["idp"], investigator=[_inv("b", ad)])
    split = [S.world_reply(ad, ["idp"], investigator=[_inv("d", ad)]),
             S.world_reply(ad, ["idp"], investigator=[_inv("d", ad)]),
             S.world_reply(S.NO_BUCKET, [], investigator=[_inv("d", ad)])]
    judge = S.judge({**_draws("b", agree, agree, agree), **_draws("d", *split)})

    S.grade(built, judge, draws=3)

    b, d = S.row(built, "b"), S.row(built, "d")
    assert b.get(COMPLETED) == 3, b
    assert b.get(BUCKET) == ad, b
    assert not b.get(DISAGREE), b
    assert _defender_ids("b") == _every_draw(built, "b", 0)
    assert d.get(COMPLETED) == 3, d
    assert d.get(BUCKET) is None, d
    assert _draw_buckets(d) == Counter([ad, ad, S.NO_BUCKET]), d
    assert d.get(DISAGREE) is True, d
    assert _defender_ids("d") == set()


def test_1234_world_whose_draws_disagree_queues_no_defender_row(tmp_path):
    built = S.family(tmp_path)
    judge = S.judge({
        **_draws("b", _lq("b", _design("b")),
                 S.world_reply(S.NO_BUCKET, [], investigator=[_inv("b")], world=[_design("b")])),
        **_draws("c", _lq("c"), _lq("c"))})

    S.grade(built, judge, draws=2)

    b = S.row(built, "b")
    assert b.get(COMPLETED) == 2, b
    assert b.get(DISAGREE) is True, b
    assert _defender_ids("b") == set()
    assert _questioner_ids("b") == {built.finding_id("b", 0, 1), built.finding_id("b", 1, 1)}
    assert _defender_ids("c") == _every_draw(built, "c", 0, draws=2)


def test_1234_not_measured_needs_unanimity_and_the_doubt_mark_needs_any_draw(tmp_path):
    built = S.family(tmp_path, S.triad(d=_plain("D"), e=_plain("E")))
    judge = S.judge({
        **_draws("b", _lq("b"), _lq("b"), _lq("b", _design("b", "unreachable"))),
        **_draws("c", *[_lq("c", _design("c", "unreachable"))] * 3),
        **_draws("d", _lq("d"), _lq("d"), _lq("d", _design("d", "mislabelled"))),
        **_draws("e", _lq("e"), _lq("e"), _lq("e"))})

    S.grade(built, judge, draws=3)

    b, c = S.row(built, "b"), S.row(built, "c")
    assert b.get(COMPLETED) == 3, b
    assert b.get(DISAGREE) is True, b
    assert b.get(MEASURED) is not False, b
    assert not b.get(NOT_MEASURED_REASON), b
    assert _defender_ids("b") == set()
    assert c.get(MEASURED) is False, c
    assert "unreachable" in str(c.get(NOT_MEASURED_REASON)), c
    assert not c.get(DISAGREE), c
    assert _defender_ids("c") == set()
    doubted = S.from_world(S.defender_queue(), "d")
    assert _ids(doubted) == _every_draw(built, "d", 0)
    assert all(r.get(S.DOUBT) is True for r in doubted), doubted
    plain = S.from_world(S.defender_queue(), "e")
    assert _ids(plain) == _every_draw(built, "e", 0)
    assert all(r.get(S.DOUBT) is False for r in plain), plain


def test_1234_unreachable_world_is_not_measured_and_queues_no_defender_row(tmp_path):
    built = S.family(tmp_path)
    judge = S.judge({**_draws("b", *[_lq("b", _design("b", "unreachable"))] * 3),
                     **_draws("c", *[_lq("c")] * 3)})

    S.grade(built, judge, draws=3)

    b = S.row(built, "b")
    assert b.get(COMPLETED) == 3, b
    assert b.get(MEASURED) is False, b
    assert "unreachable" in str(b.get(NOT_MEASURED_REASON)), b
    assert _defender_ids("b") == set()
    assert _questioner_ids("b") == _every_draw(built, "b", 1)
    assert _defender_ids("c") == _every_draw(built, "c", 0)


def test_1234_world_whose_facts_a_gap_kept_back_is_not_measured(tmp_path):
    built = S.family(tmp_path, S.triad(
        b={"calls": _b_calls(S.refused_call(params={"entity": "b-blocked"}))},
        c={"calls": _c_calls(S.refused_call(params={"entity": "c-blocked"}))}))
    judge = S.judge({**_draws("b", *[_gap_reply(built, "b", 2, kept_facts=True)] * 3),
                     **_draws("c", *[_gap_reply(built, "c", 1, kept_facts=False)] * 3)})

    S.grade(built, judge, draws=3)

    b, c = S.row(built, "b"), S.row(built, "c")
    assert b.get(COMPLETED) == 3, b
    assert b.get(MEASURED) is False, b
    assert S.marker("b", "gap") in str(b.get(NOT_MEASURED_REASON)), (
        f"b's not-measured reason does not name the gap: {b}")
    assert _defender_ids("b") == set()
    assert c.get(MEASURED) is True, c
    assert _defender_ids("c") == _every_draw(built, "c", 0)


def test_1234_world_bucketed_none_queues_none_of_its_investigator_findings(tmp_path):
    built = S.family(tmp_path)
    judge = S.judge({**_draws("b", *[_none("b")] * 3), **_draws("c", *[_lq("c")] * 3)})

    S.grade(built, judge, draws=3)

    b = S.row(built, "b")
    assert b.get(COMPLETED) == 3, b
    assert b.get(BUCKET) == S.NO_BUCKET, b
    assert _defender_ids("b") == set()
    assert _defender_ids("c") == _every_draw(built, "c", 0)


@pytest.mark.parametrize("knob", ["0", "-1"])
def test_1234_judge_draws_zero_or_negative(tmp_path, monkeypatch, knob):
    built = S.family(tmp_path)
    monkeypatch.setenv(S.DRAWS_KNOB, knob)
    judge = S.judge()

    raised: BaseException | None = None
    try:
        S.grade(built, judge, draws=None)
    except Exception as refused:  # classified below; a bare Exception is never accepted
        raised = refused

    assert raised is not None, f"{S.DRAWS_KNOB}={knob} was graded, not refused"
    assert isinstance(raised, S.refusals()), repr(raised)
    assert S.DRAWS_KNOB in str(raised), str(raised)
    assert judge.calls == 0, judge.agent_ids
    assert S.draw_files(built, "b") == []
    assert S.draw_files(built, "c") == []
    assert [r for r in S.rows(built).values() if COMPLETED in r] == []
    assert S.defender_queue() == []
    assert S.questioner_queue() == []
    monkeypatch.setenv(S.DRAWS_KNOB, "1")
    S.grade(built, judge, draws=None)
    assert S.row(built, "b").get(COMPLETED) == 1


def test_1234_am_world_with_completed_draws_that_queues_nothing(tmp_path, monkeypatch):
    built = S.family(tmp_path, S.triad(d=_plain("D"), e=_plain("E")))
    serving = S.wf("unreachable", evidence=[S.conduct("b")])
    lost = S.inv(LQ, contrast=[S.conduct("d", "missing.md"), S.conduct("a", "missing.md")])
    judge = S.judge({
        **_draws("b", *[_lq("b", serving)] * 3),
        **_draws("c", *[_none("c")] * 3),
        **_draws("d", *[S.world_reply(LQ, ["idp"], investigator=[lost])] * 3),
        **_draws("e", _lq("e"), _lq("e"), _none("e"))})
    labels = ("b", "c", "d", "e")

    S.grade(built, judge, draws=3)

    assert {x: S.row(built, x).get(COMPLETED) for x in labels} == dict.fromkeys(labels, 3)
    assert {x: S.row(built, x).get(S.STATE_KEY) for x in labels} == \
        dict.fromkeys(labels, S.QUEUED)
    assert S.family_row(built).get(S.STATE_KEY) == S.QUEUED, S.family_row(built)
    assert S.family_row(built).get(COMPLETED) == 3, S.family_row(built)
    assert S.defender_queue() == []
    assert S.questioner_queue() == []
    queues = S.queue_bytes()

    rerun = S.judge()
    S.grade(built, rerun, draws=3)
    assert rerun.calls == 0, rerun.agent_ids
    monkeypatch.setenv(S.DRAWS_KNOB, "5")
    later = S.judge()
    S.grade(built, later, draws=None)
    assert later.calls == 0, later.agent_ids

    assert {x: S.row(built, x).get(COMPLETED) for x in labels} == dict.fromkeys(labels, 3)
    assert {x: S.row(built, x).get(S.STATE_KEY) for x in labels} == \
        dict.fromkeys(labels, S.QUEUED)
    assert S.queue_bytes() == queues


def test_1234_world_with_some_malformed_draws_and_some_completed(tmp_path):
    built = S.family(tmp_path)
    judge = S.judge({("b", 0): _lq("b"), ("b", 1): MALFORMED, ("b", 2): MALFORMED,
                     ("c", 0): _lq("c"), ("c", 1): _none("c"), ("c", 2): MALFORMED})

    S.grade(built, judge, draws=3)

    b, c = S.row(built, "b"), S.row(built, "c")
    assert b.get(COMPLETED) == 1, b
    assert b.get(BUCKET) == LQ, b
    assert b.get(ROW_SYSTEMS) == ["idp"], b
    assert not b.get(DISAGREE), b
    assert _defender_ids("b") == {built.finding_id("b", 0, 0)}
    assert c.get(COMPLETED) == 2, c
    assert c.get(DISAGREE) is True, c
    assert _defender_ids("c") == set()

    rerun = S.judge()
    S.grade(built, rerun, draws=3)
    assert not rerun.called("b"), rerun.agent_ids
    assert not rerun.called("c"), rerun.agent_ids
    assert S.row(built, "b").get(COMPLETED) == 1
    assert S.row(built, "c").get(COMPLETED) == 2
