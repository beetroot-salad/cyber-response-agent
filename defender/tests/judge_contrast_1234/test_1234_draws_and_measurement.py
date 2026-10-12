"""#1234 slice 7 — draws and measurement: how a world's completed draws combine (A7, unanimity)
into its row's outcome, systems, measured state, doubt mark and named gaps, and what that lets
each queue carry (A13: findings route per draw under their own ids; withholding stops only
defender rows).

Every scenario is a HAND-BUILT archived family (`S.family`, the control `a` plus planted worlds)
graded through the judge's one entry point (`S.grade` -> `grade_episode`) with a routed,
recording judge (`S.RoutedJudge`, keyed `(label, draw[, attempt])`). Every A7/A13 scenario asks
for more than one draw (45-dispositions-final I-7: A7 is inert at the default of one); d05m pins
that default itself.

Faults, per the hierarchy:
  * a MALFORMED reply is real text through the real `validate_reply` (`MALFORMED` is not YAML,
    so any reply validator refuses it and the draw asks again within `_REPLY_ATTEMPTS`, N22);
    s_AM23's repeated system and case variant, and s_A47's unserved lead-set systems, are real
    replies the design rules refused at validation (A5, X12, K12, M20=A);
  * a FAILED draw is `RoutedJudge(fail=...)` raising `RunUnprocessable` — #921's P9 claim
    (`spec_graph_921-family-judge.yaml`), carried by the shared fake, not re-observed here;
  * a non-positive `JUDGE_DRAWS` is the real knob, set in the environment (s_A50).

Every "queues no defender row" assertion stands beside a world in the SAME pass whose
investigator findings do queue, so an empty queue is never the only evidence. Coined row keys
come from `S.COINED` / `S.RULED`; nothing here spells one.

None of this exists at base 463833df: the amended reply shape (three filed lists, no
`episode_outcome`) is refused by main's validator, so most tests are red there on their first
row assertion (`completed_draws` is 0). The exceptions: s_A50 fails on its refusal assertion
(main grades a non-positive knob), d05m on its one-ask assertion (main re-asks the refused
reply), and s_L15 on its found-gaps assertion (main has no user section).
"""
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
#: A draw document's systems (the reply's own, d00b).
DRAW_SYSTEMS = S.RULED["reply.systems"]
#: The questioner row's `systems` — the same name `build_finding_row` writes on main.
QUESTIONER_SYSTEMS = S.RULED["row.systems"]

#: main's existing world-row count of refused asks (`S.EXISTING`).
_MALFORMED_REPLIES = S.EXISTING["row.malformed_replies"]

#: Not YAML: refused by any reply validator, so the draw asks again (N22) and, refused on every
#: ask, completes nothing.
MALFORMED = "bucket: [unterminated"

LQ = "lead-quality"


# --------------------------------------------------------------------------------------
# Scenario data: replies and worlds, a few lines each.
# --------------------------------------------------------------------------------------


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


# --------------------------------------------------------------------------------------
# Reading what the pass left.
# --------------------------------------------------------------------------------------


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


def _call_key(call: S.CallRow) -> tuple[str, str, str]:
    """A blocked call's key, run aside: (system, verb, canonical params)."""
    return (call.system, call.verb, S.canonical(call.the_params))


def _gap_keys(entries: list[dict]) -> list[tuple[Any, ...]]:
    """Each gap entry's blocked-call key, run aside."""
    return [S.gap_key(e)[1:] for e in entries]


# --------------------------------------------------------------------------------------
# The tests — one per demand, named by its `discharged_by`.
# --------------------------------------------------------------------------------------


def test_1234_world_bucket_counts_only_when_every_completed_draw_agrees(tmp_path):
    """With three completed draws answering analyze-discipline, analyze-discipline and
    analyze-discipline, the world row's bucket is analyze-discipline; with analyze-discipline,
    analyze-discipline and none, the row's bucket is None, every draw's bucket is still recorded,
    the row says the draws disagree and the world is withheld (A7).

    Both worlds are shown their facts (a discipline bucket is refused for a world that never
    was, A5), and each draw lists one resolving investigator finding, so withholding is seen
    on the defender queue: the unanimous world's findings queue from every draw, the split
    world's from none."""
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
    """With two completed draws answering lead-quality and none, the world is withheld: it
    queues no defender row and its row says the draws disagree (A7); its design world findings
    from either draw still reach the questioner queue under their own finding ids (A13).

    The design finding is `mislabelled` (it does not change a draw's outcome); world c, judged
    in the same pass with two agreeing draws, queues its investigator findings from both."""
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
    """A world in which one of three completed draws files unreachable and the other two do not
    has draws disagreeing on the outcome and is withheld (A7), never recorded not measured; one
    in which all three file unreachable is recorded not measured; a world in which any one draw
    files mislabelled queues its rows with world_label_doubted true (A7, A13).

    World b is the one-in-three unreachable world, c the three-in-three, d the one-in-three
    mislabelled; e (no mislabelled draw) queues its rows unmarked, so the mark is seen to
    discriminate."""
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


def test_1234_single_draw_decides_every_world_predicate(tmp_path, monkeypatch):
    """With JUDGE_DRAWS at its default of one, the single completed draw decides the world's
    outcome, systems, doubt mark and named gaps (A7 is inert at one draw, I-6).

    The knob is unset and the pass passes no draw count. World b's one draw buckets
    lead-quality on idp, files a mislabelled design finding and names b's refused call as a
    gap; world c's one draw files unreachable."""
    monkeypatch.delenv(S.DRAWS_KNOB, raising=False)
    blocked = S.refused_call(params={"entity": "b-blocked"})
    built = S.family(tmp_path, S.triad(b={"calls": _b_calls(blocked)}))
    gap = S.gap(evidence=[built.served("b", built.served_row("b", 2))], kept_facts=False)
    judge = S.judge({
        ("b", 0): S.world_reply(LQ, ["idp"], investigator=[_inv("b")], world=[_design("b")],
                                gaps=[gap]),
        ("c", 0): _lq("c", _design("c", "unreachable"))})

    S.grade(built, judge, draws=None)

    assert [S.parse_agent_id(a) for a in judge.calls_for("b")] == [("b", 0, 0)]
    b, c = S.row(built, "b"), S.row(built, "c")
    assert b.get(COMPLETED) == 1, b
    assert b.get(BUCKET) == LQ, b
    assert b.get(ROW_SYSTEMS) == ["idp"], b
    assert b.get(MEASURED) is True, b
    rows_b = S.from_world(S.defender_queue(), "b")
    assert _ids(rows_b) == {built.finding_id("b", 0, 0)}
    assert rows_b[0].get(S.DOUBT) is True, rows_b
    assert _gap_keys(S.named_gaps(built)) == [_call_key(blocked)]
    assert c.get(MEASURED) is False, c
    assert "unreachable" in str(c.get(NOT_MEASURED_REASON)), c
    assert _defender_ids("c") == set()


def test_1234_unreachable_world_is_not_measured_and_queues_no_defender_row(tmp_path):
    """A world whose every completed draw files an unreachable finding is recorded not measured
    with that reason (A7), and none of its investigator findings is queued; its design world
    findings still reach the questioner queue (I4).

    Each of b's three draws lists a resolving investigator finding (index 0) beside the design
    unreachable finding (index 1); world c, measured in the same pass, queues its investigator
    findings."""
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


def test_1234_incoherent_world_is_not_measured_and_queues_no_defender_row(tmp_path):
    """A world whose every completed draw files an incoherent finding is recorded not measured
    with that reason (A7), and none of its investigator findings is queued; its design world
    findings still reach the questioner queue (I4).

    Each of b's three draws lists a resolving investigator finding (index 0) beside the design
    incoherent finding (index 1); world c, measured in the same pass, queues its investigator
    findings."""
    built = S.family(tmp_path)
    judge = S.judge({**_draws("b", *[_lq("b", _design("b", "incoherent"))] * 3),
                     **_draws("c", *[_lq("c")] * 3)})

    S.grade(built, judge, draws=3)

    b = S.row(built, "b")
    assert b.get(COMPLETED) == 3, b
    assert b.get(MEASURED) is False, b
    assert "incoherent" in str(b.get(NOT_MEASURED_REASON)), b
    assert _defender_ids("b") == set()
    assert _questioner_ids("b") == _every_draw(built, "b", 1)
    assert _defender_ids("c") == _every_draw(built, "c", 0)


def test_1234_world_whose_facts_a_gap_kept_back_is_not_measured(tmp_path):
    """A world whose every completed draw names a deployment gap as the reason its facts did not
    reach the investigator is recorded not measured with that reason (A7), and none of its
    investigator findings is queued.

    F-14 (78-gate-resolutions): the gap carries kept_facts_from_investigator true in every one
    of b's draws, citing b's refused call. World c's draws name its own refused call with the
    flag false in every draw: c stays measured and queues its investigator findings."""
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
    """A world whose every completed draw buckets none queues none of the investigator findings
    its replies list (today they are queued, E-02/C14).

    Each of b's three `none` draws lists a resolving investigator finding; world c, bucketed
    lead-quality in the same pass, queues the same kind of finding from every draw."""
    built = S.family(tmp_path)
    judge = S.judge({**_draws("b", *[_none("b")] * 3), **_draws("c", *[_lq("c")] * 3)})

    S.grade(built, judge, draws=3)

    b = S.row(built, "b")
    assert b.get(COMPLETED) == 3, b
    assert b.get(BUCKET) == S.NO_BUCKET, b
    assert _defender_ids("b") == set()
    assert _defender_ids("c") == _every_draw(built, "c", 0)


def test_1234_draws_split_across_unreachable_and_incoherent(tmp_path):
    """One draw files unreachable, one incoherent, one neither. The first two agree on the
    outcome `not measured` (A7 lists not measured as one outcome), but the third draw's outcome
    differs, so the draws disagree and the world is withheld: its row says the draws disagree
    and it queues no defender row. Whether the draws' unreachable and incoherent world findings
    route is MA05.

    MA05 deferral closed by A13: each draw's unreachable and incoherent world findings route
    per draw by class under their own finding_id (design when not gap-only with a resolving
    plan pointer, else serving to the user record); withholding stops only defender rows.
    World c's draws file unreachable, incoherent and unreachable: three not-measured draws
    through different buckets agree, so c is recorded not measured, not withheld."""
    built = S.family(tmp_path)
    judge = S.judge({
        **_draws("b", _lq("b", _design("b", "unreachable")),
                 _lq("b", _design("b", "incoherent")), _lq("b")),
        **_draws("c", _lq("c", _design("c", "unreachable")),
                 _lq("c", _design("c", "incoherent")), _lq("c", _design("c", "unreachable")))})

    S.grade(built, judge, draws=3)

    b, c = S.row(built, "b"), S.row(built, "c")
    assert b.get(COMPLETED) == 3, b
    assert b.get(DISAGREE) is True, b
    assert b.get(MEASURED) is not False, b
    assert _defender_ids("b") == set()
    assert _questioner_ids("b") == {built.finding_id("b", 0, 1), built.finding_id("b", 1, 1)}
    assert c.get(MEASURED) is False, c
    assert not c.get(DISAGREE), c
    assert _questioner_ids("c") == _every_draw(built, "c", 1)


def test_1234_draws_name_different_fact_blocking_gaps(tmp_path):
    """Two draws name a gap as the reason (outcome not measured) and the third does not, so the
    draws disagree on the outcome and the world is withheld (A7). A named gap is listed only
    when every draw names the same blocked call (key: run, system, verb, params); draws naming
    different calls list no named gap. The found gaps still list each blocked call from the
    ledgers (A2).

    World b holds two refused calls: draw 0 names the first with the flag true, draw 1 the
    second with the flag true, draw 2 the first with the flag false — every draw names a gap,
    no call is named by all three. World c's three draws name its one refused call: that named
    gap is listed."""
    first = S.refused_call(params={"entity": "b-first"})
    second = S.refused_call(system="siem-x", params={"entity": "b-second"})
    c_blocked = S.refused_call(params={"entity": "c-blocked"})
    built = S.family(tmp_path, S.triad(b={"calls": _b_calls(first, second)},
                                       c={"calls": _c_calls(c_blocked)}))
    judge = S.judge({
        **_draws("b", _gap_reply(built, "b", 2, kept_facts=True),
                 _gap_reply(built, "b", 3, kept_facts=True),
                 _gap_reply(built, "b", 2, kept_facts=False)),
        **_draws("c", *[_gap_reply(built, "c", 1, kept_facts=False)] * 3)})

    S.grade(built, judge, draws=3)

    b = S.row(built, "b")
    assert b.get(COMPLETED) == 3, b
    assert b.get(DISAGREE) is True, b
    assert b.get(MEASURED) is not False, b
    assert _defender_ids("b") == set()
    assert _gap_keys(S.named_gaps(built)) == [_call_key(c_blocked)]
    found = _gap_keys(S.found_gaps(built))
    assert _call_key(first) in found, found
    assert _call_key(second) in found, found


def _lead_set(systems: list[str]) -> dict:
    """A `lead-set` reply for world b: one investigator finding (index 0) and one design
    finding on its OWN systems, siem-x (index 1) — no draw's world-level systems name siem-x."""
    return S.world_reply("lead-set", systems, investigator=[_inv("b", "lead-set")],
                         world=[_design("b", systems=("siem-x",))])


def test_1234_draws_agree_on_bucket_disagree_on_systems(tmp_path):
    """Systems count only when every completed draw agrees (A7): three draws naming different
    sets of systems withhold the world (row says draws disagree, no defender row). M20=A's
    served-system rule for lead-set applies to each draw's systems at validation. The world's
    design rows carry their own findings' systems (A5). (One set spelled in a different order
    or with a repeat: NA02.)

    Every draw buckets lead-set; draw 1's first ask names only an unserved system, is refused
    and asked again, and its second ask names edr. World c's three draws name idp alike."""
    built = S.family(tmp_path)
    judge = S.judge({
        ("b", 0): _lead_set(["idp"]),
        ("b", 1): [_lead_set(["vault"]), _lead_set(["edr"])],
        ("b", 2): _lead_set(["edr", "idp"]),
        **_draws("c", *[S.world_reply("lead-set", ["idp"],
                                      investigator=[_inv("c", "lead-set")])] * 3)})

    S.grade(built, judge, draws=3)

    b = S.row(built, "b")
    assert b.get(COMPLETED) == 3, b
    assert b.get(DISAGREE) is True, b
    assert b.get(ROW_SYSTEMS) is None, b
    assert _defender_ids("b") == set()
    assert ("b", 1, 1) in [S.parse_agent_id(a) for a in judge.calls_for("b")]
    assert S.draw_doc(built, "b", 1).get(DRAW_SYSTEMS) == ["edr"]
    design = S.from_world(S.questioner_queue(), "b")
    assert _ids(design) == _every_draw(built, "b", 1)
    assert all(r.get(QUESTIONER_SYSTEMS) == ["siem-x"] for r in design), design
    c = S.row(built, "c")
    assert c.get(ROW_SYSTEMS) == ["idp"], c
    assert not c.get(DISAGREE), c
    assert _defender_ids("c") == _every_draw(built, "c", 0)


def test_1234_world_whose_only_unreachable_finding_is_dropped_for_its_evidence(tmp_path):
    """A finding dropped for unresolvable evidence is not a finding: the per-world predicates
    read kept findings only, so the world is not marked not measured and nothing is queued.

    A13 drop-lane note: 'dropped' means the finding keeps its filed index
    (`<episode>/<world>/<draw>/<index>`, counted before any drop) and carries exactly one drop
    lane, precedence pointers unresolved, then names only another run, then no two-run pair.
    Every one of b's three draws files the same unreachable finding citing only pointers A1
    says never resolve. Positive control (d06c's shape, same pass): world c's draws file the
    unreachable finding citing the plan at c's entry, and c is not measured."""
    built = S.family(tmp_path)
    lost = S.wf("unreachable", evidence=S.never_resolving("b"))
    judge = S.judge({
        **_draws("b", *[S.world_reply(LQ, ["idp"], world=[lost])] * 3),
        **_draws("c", *[S.world_reply(LQ, ["idp"], world=[_design("c", "unreachable")])] * 3)})

    S.grade(built, judge, draws=3)

    b, c = S.row(built, "b"), S.row(built, "c")
    assert b.get(COMPLETED) == 3, b
    assert b.get(MEASURED) is True, b
    assert not b.get(NOT_MEASURED_REASON), b
    assert not b.get(DISAGREE), b
    assert [S.lane_of(built, f) for f in sorted(_every_draw(built, "b", 0))] == \
        [S.LANES["dropped_unresolved"]] * 3
    assert _questioner_ids("b") == set()
    assert _defender_ids("b") == set()
    assert S.serving_findings(built) == []
    assert c.get(MEASURED) is False, c
    assert _questioner_ids("c") == _every_draw(built, "c", 0)


@pytest.mark.parametrize("knob", ["0", "-1"])
def test_1234_judge_draws_zero_or_negative(tmp_path, monkeypatch, knob):
    """A non-positive JUDGE_DRAWS is refused loudly before any world is graded (principle 2);
    no world is silently recorded as graded with zero draws.

    The knob is set in the environment and the pass passes no draw count. The refusal is one of
    the design's refusal classes and names the knob; no model call is made, no draw file is
    written, no world row records completed draws and nothing is queued. Control: the same
    episode, with the knob at one, grades."""
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


def test_1234_two_passes_with_different_draw_counts(tmp_path):
    """judge.yaml records each world's completed_draws as that world's pass produced it; each
    world's outcome and systems are decided by unanimity over its own recorded completed draws
    (A7), not over the current knob.

    Pass one asks one draw: b completes it; every call for c fails (P9), so c completes none.
    The re-run asks three: it grades c only, whose three draws name edr, edr and idp. b keeps
    its one draw's bucket and systems, unmarked; c's systems disagree."""
    built = S.family(tmp_path)
    first = S.judge({("b", 0): _lq("b")}, fail={"c"})
    S.grade(built, first, draws=1)
    assert S.row(built, "b").get(COMPLETED) == 1, S.row(built, "b")
    assert not S.row(built, "c").get(COMPLETED), S.row(built, "c")

    second = S.judge(_draws("c", _lq("c", systems=["edr"]), _lq("c", systems=["edr"]),
                            _lq("c", systems=["idp"])))
    S.grade(built, second, draws=3)

    b, c = S.row(built, "b"), S.row(built, "c")
    assert not second.called("b"), second.agent_ids
    assert b.get(COMPLETED) == 1, b
    assert c.get(COMPLETED) == 3, c
    assert b.get(BUCKET) == LQ, b
    assert b.get(ROW_SYSTEMS) == ["idp"], b
    assert not b.get(DISAGREE), b
    assert c.get(ROW_SYSTEMS) is None, c
    assert c.get(DISAGREE) is True, c
    assert _defender_ids("b") == {built.finding_id("b", 0, 0)}
    assert _defender_ids("c") == set()


def test_1234_am_world_with_completed_draws_that_queues_nothing(tmp_path, monkeypatch):
    """A world whose draws complete and route nothing (not measured, bucket none, every finding
    dropped, or withheld for disagreeing draws) flips to `queued` with nothing appended and is
    final: a bare re-run skips it (I8), and a later JUDGE_DRAWS change never revisits it (I-8);
    the family row commits the same way (NA01).

    b is not measured (its unreachable finding is serving: the user record, no queue), c
    buckets none, d's only finding cites nothing that resolves, e's draws disagree; the family
    call files nothing. A bare re-run, then a pass under a changed knob, make no model call
    and leave both queues byte-identical."""
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


def test_1234_am_withheld_worlds_world_findings_and_named_gaps(tmp_path):
    """A withheld world queues no defender row (A7); its design world finding from every draw
    reaches the questioner queue under its own finding_id (A13, no cross-draw matching), its
    serving finding goes to the user record, and an unanimous named gap (same blocked-call key
    in every draw) reaches the user record.

    b's draws answer lead-quality, lead-quality and none; each files one investigator finding
    (index 0), the same design finding citing the plan (index 1), the same serving finding
    citing only b's report (index 2) and the same gap naming b's refused call (index 3)."""
    blocked = S.refused_call(params={"entity": "b-blocked"})
    built = S.family(tmp_path, S.triad(b={"calls": _b_calls(blocked)}))
    claim = S.marker("b", "serving-finding")
    serving = S.wf("mislabelled", evidence=[S.conduct("b")], claim=claim)
    gap = S.gap(evidence=[built.served("b", built.served_row("b", 2))], kept_facts=False)

    def reply(bucket: str, systems: list[str]) -> dict:
        return S.world_reply(bucket, systems, investigator=[_inv("b")],
                             world=[_design("b"), serving], gaps=[gap])

    judge = S.judge(_draws("b", reply(LQ, ["idp"]), reply(LQ, ["idp"]),
                           reply(S.NO_BUCKET, [])))

    S.grade(built, judge, draws=3)

    b = S.row(built, "b")
    assert b.get(COMPLETED) == 3, b
    assert b.get(DISAGREE) is True, b
    assert _defender_ids("b") == set()
    assert _questioner_ids("b") == _every_draw(built, "b", 1)
    assert [S.lane_of(built, f) for f in sorted(_every_draw(built, "b", 2))] == \
        [S.LANES["user_record"]] * 3
    assert any(claim in str(entry) for entry in S.serving_findings(built)), \
        S.serving_findings(built)
    assert _gap_keys(S.named_gaps(built)) == [_call_key(blocked)]


def test_1234_am_unanimous_systems_spelled_differently(tmp_path):
    """Systems count by the set the draws name: the same set in a different order agrees, and
    the row carries the set sorted; a reply naming one system twice is refused at validation and
    re-asked within `_REPLY_ATTEMPTS` (A5, X12), not silently de-duplicated, so a repeat never
    reaches the comparison; case variants are refused at validation (K12).

    Draw 0 names idp and edr, draw 1 edr and idp. Draw 2's first ask names idp twice, its
    second names IDP, its third edr and idp — the third is the one that completes."""
    built = S.family(tmp_path)
    judge = S.judge({
        ("b", 0): _lq("b", systems=["idp", "edr"]),
        ("b", 1): _lq("b", systems=["edr", "idp"]),
        ("b", 2): [_lq("b", systems=["idp", "idp", "edr"]), _lq("b", systems=["IDP", "edr"]),
                   _lq("b", systems=["edr", "idp"])]})

    S.grade(built, judge, draws=3)

    b = S.row(built, "b")
    assert b.get(COMPLETED) == 3, b
    assert not b.get(DISAGREE), b
    assert b.get(ROW_SYSTEMS) == ["edr", "idp"], b
    assert sorted(S.parse_agent_id(a) for a in judge.calls_for("b")) == \
        [("b", 0, 0), ("b", 1, 0), ("b", 2, 0), ("b", 2, 1), ("b", 2, 2)]
    assert S.draw_doc(built, "b", 2).get(DRAW_SYSTEMS) == ["edr", "idp"]
    assert _defender_ids("b") == _every_draw(built, "b", 0)


def test_1234_world_with_some_malformed_draws_and_some_completed(tmp_path):
    """A world with some completed draws and some malformed is judged on the completed draws:
    outcome and systems count only when every completed draw agrees (A7). A bare re-run does not
    top up.

    b's draw 0 completes (lead-quality on idp); every ask of draws 1 and 2 is malformed. c's
    draws 0 and 1 complete (lead-quality, then none) and draw 2 is malformed. The re-run asks
    neither world again."""
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


def test_1234_world_whose_every_draw_is_malformed_across_two_passes(tmp_path):
    """Each pass records the world as not graded with the reason; nothing queued; the user
    record carries the world's gaps.

    Every ask about b is malformed, in pass one and in the bare re-run; b's ledger holds one
    refused call. World c completes in pass one and queues its investigator findings (the queue
    is live), and the re-run does not ask it again. "Not graded with the reason" is read on
    d00a's row contract, as AM28 reads it: no completed draw, not measured, a non-empty reason
    in the row's one reason slot, the refused asks counted."""
    blocked = S.refused_call(params={"entity": "b-blocked"})
    built = S.family(tmp_path, S.triad(b={"calls": _b_calls(blocked)}))
    first = S.judge({"b": MALFORMED, **_draws("c", _lq("c"), _lq("c"))})

    S.grade(built, first, draws=2)

    b = S.row(built, "b")
    assert first.called("b"), first.agent_ids
    assert b.get(COMPLETED) == 0, b
    assert b.get(MEASURED) is False, b
    assert b.get(NOT_MEASURED_REASON), b
    assert (b.get(_MALFORMED_REPLIES) or 0) > 0, b
    assert b.get(S.STATE_KEY) != S.QUEUED, b
    assert _defender_ids("b") == set()
    assert _questioner_ids("b") == set()
    assert _gap_keys(S.found_gaps(built)).count(_call_key(blocked)) == 1
    assert _defender_ids("c") == _every_draw(built, "c", 0, draws=2)

    second = S.judge({"b": MALFORMED})
    S.grade(built, second, draws=2)

    b = S.row(built, "b")
    assert second.called("b"), second.agent_ids
    assert not second.called("c"), second.agent_ids
    assert b.get(COMPLETED) == 0, b
    assert b.get(MEASURED) is False, b
    assert b.get(NOT_MEASURED_REASON), b
    assert (b.get(_MALFORMED_REPLIES) or 0) > 0, b
    assert b.get(S.STATE_KEY) != S.QUEUED, b
    assert _defender_ids("b") == set()
    assert _questioner_ids("b") == set()
    assert _gap_keys(S.found_gaps(built)).count(_call_key(blocked)) == 1
