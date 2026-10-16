"""#1234 judge contrast: routing of judge findings to the defender/user-record queues."""
from __future__ import annotations

import ast
import inspect
import textwrap
from pathlib import Path
from typing import Any


from defender import _yaml
from defender.tests.judge_contrast_1234 import _spec1234 as S

LQ = "lead-quality"
LS = "lead-set"
MISLABELLED = "mislabelled"
UNREACHABLE = "unreachable"
MEASURED = S.COINED["row.measured"]
CITATIONS = S.RULED["row.citations"]


#: The family words and the per-world reply word the change retires (`_vocab.JUDGE_OUTCOME_ENUM`
#: and `run._REPLY_OUTCOME_ENUM` at 463833df; design C2, C3, C3b), and the names that carried them.
OUTCOME_WORDS = frozenset({"caught", "corpus-contradiction", "discard", "survived",
                           "undecidable", "gradable"})
RETIRED_NAMES = frozenset({*S.RETIRED_RECORD_FIELDS, *S.RETIRED_ENUMS,
                           "normalized_judge_outcome", "_UNQUEUEABLE_VERDICTS"})



# --------------------------------------------------------------------------------------
# Local readers and builders (scenario data only; every observation goes through `S`).
# --------------------------------------------------------------------------------------


def _ids(rows: list[dict]) -> list[str]:
    return [str(r.get("finding_id")) for r in rows]


def _defender(label: str, state: Any = None) -> list[str]:
    """Finding ids of world `label`'s rows on the defender channel, in queue order."""
    return _ids(S.from_world(S.defender_queue(state), label))


def _questioner(label: str, state: Any = None) -> list[str]:
    return _ids(S.from_world(S.questioner_queue(state), label))


def _defender_rows(label: str, state: Any = None) -> dict[str, dict]:
    return {str(r.get("finding_id")): r for r in S.from_world(S.defender_queue(state), label)}


def _queues_text(state: Any = None) -> str:
    """Both channels' raw text — every surface a queued finding's content could reach."""
    return "\n".join(S.queue_bytes(state))


def _user_mentions(where: Any, finding_id: str, claim: str) -> bool:
    """Does judge.yaml's user section carry this finding (its id or its claim)? Which list it
    sits in is F2's; that it is there is the demand (`S.in_user_record`)."""
    return S.in_user_record(where, finding_id, claim)


def _calls(label: str, *extra: S.CallRow) -> list[S.CallRow]:
    """The triad's own calls for the control `a` or world `b` (b keeps its altered answer, so
    it was shown its facts), then `extra`: `a`'s extras start at call 1, `b`'s at call 2."""
    base = {"a": [S.CallRow()],
            "b": [S.CallRow(), S.oracle_call(fact_id="f-b", forged_id="fg-b-1")]}[label]
    return [*base, *extra]


def _served(built: S.Built, label: str, call: int) -> str:
    """A1's served pointer at world `label`'s `call`-th own call's ledger row."""
    return built.served(label, built.served_row(label, call))


def _table(built: S.Built, label: str, call: int) -> str:
    """A table pointer at world `label`'s `call`-th own call's query-table row."""
    return built.table(label, built.own_row(label, call))


def _pair_with_control(label: str) -> list[str]:
    """A resolving two-run conduct pair for focus `label`: its report against the control's."""
    return [S.conduct(label), S.conduct("a")]


def _first_row(rows: list[dict], *, query_id: str | None = None, exit_code: int | None = None,
               without_call_id: bool = False) -> int:
    """The line index of the first real-path table row matching the given columns."""
    for i, r in enumerate(rows):
        if query_id is not None and r.get("query_id") != query_id:
            continue
        if exit_code is not None and r.get("exit_code") != exit_code:
            continue
        if without_call_id and r.get(S.CALL_ID) is not None:
            continue
        return i
    raise AssertionError(f"fixture: no table row with query_id={query_id!r}, "
                         f"exit_code={exit_code!r} in {rows!r}")




# --------------------------------------------------------------------------------------
# A13 / A7: every completed draw routes its own findings.
# --------------------------------------------------------------------------------------


def test_1234_every_completed_draws_findings_route_by_class_under_their_own_ids(
        tmp_path: Path) -> None:
    """Every completed draw's kept findings route by class under their own finding_id, for
    worlds and the family (A13): when every draw of a measured world agrees on an investigator
    bucket, the investigator findings of every completed draw are queued on the defender
    channel; design findings reach the questioner queue from every draw; withholding stops only
    defender rows (F-09 kept).

    Three draws. World b agrees on lead-quality in every draw; world c's draws disagree (draw 1
    files lead-set), so c is withheld; each world files one investigator and one design finding
    per draw, and every family draw files one family-scope design finding."""
    draws = 3
    built = S.family(tmp_path, S.triad())
    replies: dict[Any, Any] = {}
    for n in range(draws):
        replies[("b", n)] = S.world_reply(LQ, investigator=[
            S.inv(claim=S.marker("b", f"inv-{n}"))], world=[
            S.wf(MISLABELLED, evidence=[S.plan_ptr("b")], claim=S.marker("b", f"design-{n}"))])
        replies[("c", n)] = S.world_reply(LS if n == 1 else LQ, investigator=[
            S.inv(contrast=_pair_with_control("c"), claim=S.marker("c", f"inv-{n}"))], world=[
            S.wf(MISLABELLED, evidence=[S.plan_ptr("c")], claim=S.marker("c", f"design-{n}"))])
        replies[(S.FAMILY, n)] = S.family_reply(world=[S.wf(
            UNREACHABLE, evidence=[S.plan_ptr(None)], claim=S.marker("family", f"design-{n}"))])

    S.grade(built, S.judge(replies), draws=draws)

    every = range(draws)
    b_rows = _defender_rows("b")
    assert sorted(b_rows) == sorted(built.finding_id("b", n, 0) for n in every), (
        "a measured, unanimous world queues the investigator finding of EVERY completed draw, "
        f"each under its own draw's id; defender ids from b: {sorted(b_rows)}")
    for n in every:
        text = str(b_rows.get(built.finding_id("b", n, 0), {}).get("finding"))
        assert S.marker("b", f"inv-{n}") in text, (
            f"b/{n}/0 must carry draw {n}'s own finding, not another draw's: {text!r}")
    assert _defender("c") == [], "withholding (draws disagree) stops c's defender rows"
    for n in every:
        assert S.lane_of(built, built.finding_id("c", n, 0)) == S.LANES["draws_disagree"]
    assert sorted(_questioner("b")) == sorted(built.finding_id("b", n, 1) for n in every)
    assert sorted(_questioner("c")) == sorted(built.finding_id("c", n, 1) for n in every), (
        "withholding stops only defender rows: the withheld world's design finding of every "
        "draw still reaches the questioner queue")
    assert sorted(_questioner(S.FAMILY)) == sorted(
        built.finding_id(S.FAMILY, n, 0) for n in every), (
        "the family's draws combine by union: every family draw's design finding is queued")


# --------------------------------------------------------------------------------------
# M5 / M7: measured worlds queue; the doubt mark.
# --------------------------------------------------------------------------------------




def test_1234_mislabelled_world_still_queues_with_the_doubt_mark(tmp_path: Path) -> None:
    """A measured world any of whose completed draws files mislabelled still queues its
    investigator findings, each with world_label_doubted true; a world none of whose draws files
    mislabelled queues rows with world_label_doubted false (A7, A13).

    Two draws: b's draw 0 files mislabelled and its draw 1 does not; c files it in neither."""
    built = S.family(tmp_path, S.triad())
    replies = {
        ("b", 0): S.world_reply(LQ, investigator=[S.inv(claim=S.marker("b", "inv-0"))],
                                world=[S.wf(MISLABELLED, evidence=[S.plan_ptr("b")])]),
        ("b", 1): S.world_reply(LQ, investigator=[S.inv(claim=S.marker("b", "inv-1"))]),
        "c": S.world_reply(LQ, investigator=[S.inv(contrast=_pair_with_control("c"))]),
    }

    S.grade(built, S.judge(replies), draws=2)

    b_rows, c_rows = _defender_rows("b"), _defender_rows("c")
    assert sorted(b_rows) == [built.finding_id("b", 0, 0), built.finding_id("b", 1, 0)], (
        "mislabelled does not block investigator findings (N-b): both draws' rows queue")
    assert sorted(c_rows) == [built.finding_id("c", 0, 0), built.finding_id("c", 1, 0)]
    for fid, row in b_rows.items():
        assert row.get(S.DOUBT) is True, (
            f"{fid}: a draw of b filed mislabelled, so every b row carries the doubt mark")
    for fid, row in c_rows.items():
        assert row.get(S.DOUBT) is False, f"{fid}: no draw of c filed mislabelled"


def test_1234_family_call_mislabelled_finding_never_marks_world_rows(tmp_path: Path) -> None:
    """A family-call finding bucketed mislabelled leaves every per-world row's
    world_label_doubted as that world's own replies set it.

    Two draws. Every family draw files mislabelled at b's manifest entry and at the
    family-level part; b's own draws never file it, so b's rows stay false. The positive
    control: c's own draw 1 files mislabelled, so c's rows are true — the mark's channel is
    live and only a world's own replies drive it."""
    built = S.family(tmp_path, S.triad())
    family_mislabelled = S.family_reply(world=[
        S.wf(MISLABELLED, evidence=[S.plan_ptr("b")], claim=S.marker("family", "about-b")),
        S.wf(MISLABELLED, evidence=[S.plan_ptr(None)], claim=S.marker("family", "family"))])
    c_pair = _pair_with_control("c")
    replies = {
        "b": S.world_reply(LQ, investigator=[S.inv()]),
        ("c", 0): S.world_reply(LQ, investigator=[S.inv(contrast=c_pair)]),
        ("c", 1): S.world_reply(LQ, investigator=[S.inv(contrast=c_pair)],
                                world=[S.wf(MISLABELLED, evidence=[S.plan_ptr("c")])]),
        S.FAMILY: family_mislabelled,
    }

    S.grade(built, S.judge(replies), draws=2)

    assert _questioner(S.FAMILY), (
        "the family's mislabelled findings were filed and routed (questioner queue), so their "
        "absence from b's rows is not an unread reply")
    b_rows, c_rows = _defender_rows("b"), _defender_rows("c")
    assert sorted(b_rows) == [built.finding_id("b", 0, 0), built.finding_id("b", 1, 0)]
    for fid, row in b_rows.items():
        assert row.get(S.DOUBT) is False, (
            f"{fid}: the family call's mislabelled finding must never mark a per-world row")
    assert sorted(c_rows) == [built.finding_id("c", 0, 0), built.finding_id("c", 1, 0)]
    for fid, row in c_rows.items():
        assert row.get(S.DOUBT) is True, f"{fid}: c's own draw filed mislabelled"


# --------------------------------------------------------------------------------------
# P-c / I2: one world's eligibility never reads another's reply.
# --------------------------------------------------------------------------------------




# --------------------------------------------------------------------------------------
# M8 / N-f: nothing combined or ranked before enqueue.
# --------------------------------------------------------------------------------------




# --------------------------------------------------------------------------------------
# I3 / P-a: gap-only evidence goes to the user record, never a queue.
# --------------------------------------------------------------------------------------


def test_1234_defender_finding_resting_only_on_external_refusals_goes_to_the_user_record(
        tmp_path: Path) -> None:
    """An investigator finding with at least one resolving conduct pointer, every resolving
    conduct pointer (context set aside) being a blocked-call row (a ledger refused/fault row,
    or J3's inherited ∅.denied row; outage real-error rows are not blocked), is not queued on
    the defender channel and appears in the user record instead (A1, A2, A14, A15).

    The control and b each carry a refused call, a fault and an outage, and both inherit J3's
    pre-branch denial. b's reply pairs b's row with the control's for each: the refused pair
    (served-ledger rows, and again as the query-table ∅.denied rows their ledger rows join),
    the fault pair and J3's pair go to the user record; the outage pair is ordinary conduct and
    queues — the in-test control that the defender channel is live."""
    extra = (S.refused_call(), S.fault_call(), S.error_call())
    built = S.family(tmp_path, S.triad(a={"calls": _calls("a", *extra)},
                                        b={"calls": _calls("b", *extra)}),
                     inherited=[S.inherited_denial()])
    pairs = {
        "refused-served": [_served(built, "b", 2), _served(built, "a", 1)],
        "fault-served": [_served(built, "b", 3), _served(built, "a", 2)],
        "j3-table": [built.table("b", 0), built.table("a", 0)],
        "refused-table": [_table(built, "b", 2), _table(built, "a", 1)],
        "outage-served": [_served(built, "b", 4), _served(built, "a", 3)],
    }
    findings = [S.inv(contrast=ptrs, claim=S.marker("b", name)) for name, ptrs in pairs.items()]

    S.grade(built, S.judge({"b": S.world_reply(LQ, investigator=findings)}), draws=1)

    gap_only = ["refused-served", "fault-served", "j3-table", "refused-table"]
    control_id = built.finding_id("b", 0, list(pairs).index("outage-served"))
    assert _defender("b") == [control_id], (
        f"only the outage pair queues; defender ids from b: {_defender('b')}")
    queued = _queues_text()
    for name in gap_only:
        fid = built.finding_id("b", 0, list(pairs).index(name))
        assert S.lane_of(built, fid) == S.LANES["user_record"], f"{name} ({fid})"
        assert S.marker("b", name) not in queued, f"{name} reached a queue"
        assert _user_mentions(built, fid, S.marker("b", name)), (
            f"{name} ({fid}) is absent from judge.yaml's user section")
    assert S.lane_of(built, control_id) == S.LANES["defender"]


def test_1234_a_deployment_gap_reaches_neither_queue(tmp_path: Path) -> None:
    """A deployment gap, whether named as a gap, filed under an investigator bucket with only
    blocked-call conduct evidence (J3's inherited ∅.denied row cited in b and in the control
    included), or filed as a world finding citing only blocked-call rows, reaches neither the
    defender nor the questioner channel.

    One draw of b files all three shapes beside an ordinary investigator finding and a design
    world finding, which reach the defender and questioner channels (both channels are live).
    The gap content is looked for on every surface of both channels (their raw text); its
    sanctioned destination, the user record, is checked to hold it."""
    built = S.family(tmp_path, S.triad(a={"calls": _calls("a", S.refused_call())},
                                        b={"calls": _calls("b", S.refused_call())}),
                     inherited=[S.inherited_denial()])
    refused_b, refused_a = _served(built, "b", 2), _served(built, "a", 1)
    m = {k: S.marker("b", k) for k in ("inv-ok", "inv-refused", "inv-j3", "design-ok",
                                        "world-refused", "named-gap")}
    reply = S.world_reply(
        LQ,
        investigator=[S.inv(claim=m["inv-ok"]),
                      S.inv(contrast=[refused_b, refused_a], claim=m["inv-refused"]),
                      S.inv(contrast=[built.table("b", 0), built.table("a", 0)],
                            claim=m["inv-j3"])],
        world=[S.wf(MISLABELLED, evidence=[S.plan_ptr("b")], claim=m["design-ok"]),
               S.wf(MISLABELLED, systems=["edr"], evidence=[refused_b],
                    claim=m["world-refused"])],
        gaps=[S.gap(what=m["named-gap"], evidence=[refused_b], kept_facts=False)])

    S.grade(built, S.judge({"b": reply}), draws=1)

    fid = {name: built.finding_id("b", 0, i) for i, name in enumerate(
        ["inv-ok", "inv-refused", "inv-j3", "design-ok", "world-refused", "named-gap"])}
    assert _defender("b") == [fid["inv-ok"]], "positive control: the defender channel is live"
    assert _questioner("b") == [fid["design-ok"]], (
        "positive control: the questioner channel is live")
    queued = _queues_text()
    for name in ("inv-refused", "inv-j3", "world-refused", "named-gap"):
        assert m[name] not in queued, f"the gap filed as {name} reached a queue"
        assert fid[name] not in queued, f"the gap filed as {name} reached a queue by id"
    for name in ("inv-refused", "inv-j3", "world-refused"):
        assert S.lane_of(built, fid[name]) == S.LANES["user_record"], name
        assert _user_mentions(built, fid[name], m[name]), f"{name} missing from the user record"
    assert S.named_gaps(built), "the named gap is listed in the user record (A2, A7)"






# --------------------------------------------------------------------------------------
# I4 / I9: not-measured and none worlds; design findings still route.
# --------------------------------------------------------------------------------------






# --------------------------------------------------------------------------------------
# A12 / A14 on the real path: J3's row and the exit-64 reject.
# --------------------------------------------------------------------------------------


def test_1234_am_finding_resting_on_a_table_sentinel_with_no_ledger_partner(
        tmp_path: Path) -> None:
    """J3's row, a `∅.denied` table row carrying no id of this run and present identically in
    every readable run's table, the control's included (A12), is a blocked call (A14). A
    finding whose every resolving conduct pointer is that row (or another blocked-call row) is
    gap-only and goes to the user record: a world finding whose only conduct pointer is that
    row in b, and an investigator pair whose halves are that row in b and in the control,
    never reach the defender queue (I3, P-a). A refused call whose ledger row was never
    written cannot occur silently (A12: a failed write ends the run). A call the query tool
    rejected before any system was reached (exit-64 sentinel) is not a blocked call: it is an
    ordinary conduct row of the run and does not make a finding gap-only.

    The REAL path: the source run's table carries the pre-branch denial, which the real
    `_inherit_evidence` seeds into every sibling; b's gather also calls an unresolvable verb,
    which the real query tool rejects with exit 64 and no ledger row. The pair of b's reject
    with the control's J3 row is the positive control: it queues. On the refused-call clause:
    every refused call in the archive the judge reads has its ledger row, joined to its table
    row by the call id; the failed-write path itself is
    test_1234_failed_served_ledger_write_ends_the_run's."""
    turns_b = [*S.default_turns()[:-1], S.query_turn("idp", "bogus_verb", {"q": "x"}),
               S.done_turn()]
    built = S.real_family(tmp_path, {"b": S.RealWorld("b", oracle=S.altering_oracle(),
                                                      turns=turns_b)},
                          after_source=S.capture_sentinel)
    tables = {label: built.table_rows(label) for label in "abc"}
    j3 = {label: _first_row(rows, query_id=S.DENIED_QUERY_ID, without_call_id=True)
          for label, rows in tables.items()}
    assert tables["a"][j3["a"]] == tables["b"][j3["b"]] == tables["c"][j3["c"]], (
        "fixture: J3's row is present identically in every run's table")
    reject_b = _first_row(tables["b"], exit_code=S.REJECT_EXIT)
    j3_b, j3_a = S.table_ptr("b", j3["b"]), S.table_ptr("a", j3["a"])
    m = {k: S.marker("b", k) for k in ("j3-pair", "reject-pair", "j3-world")}
    reply = S.world_reply(
        LQ,
        investigator=[S.inv(contrast=[j3_b, j3_a], claim=m["j3-pair"]),
                      S.inv(contrast=[S.table_ptr("b", reject_b), j3_a],
                            claim=m["reject-pair"])],
        world=[S.wf(MISLABELLED, systems=["edr"], evidence=[S.plan_ptr("b"), j3_b],
                    claim=m["j3-world"])])

    S.grade(built, S.judge({"b": reply}), draws=1)

    fid = {name: built.finding_id("b", 0, i) for i, name in enumerate(m)}
    assert _defender("b") == [fid["reject-pair"]], (
        "the exit-64 reject is ordinary conduct, so its pair queues; neither J3 finding does: "
        f"defender ids from b: {_defender('b')}")
    assert _questioner("b") == [], "the J3 world finding is gap-only, not design"
    for name in ("j3-pair", "j3-world"):
        assert S.lane_of(built, fid[name]) == S.LANES["user_record"], name
        assert _user_mentions(built, fid[name], m[name]), name
    for label, rows in tables.items():
        own_denials = [r for i, r in enumerate(rows)
                       if r.get("query_id") == S.DENIED_QUERY_ID and i != j3[label]]
        refused_ids = {r.get(S.CALL_ID) for r in built.ledger_rows(label)
                       if r.get("source") == "refused"}
        assert own_denials, f"fixture: world {label}'s withheld call was refused at run time"
        for r in own_denials:
            assert r.get(S.CALL_ID) is not None, (
                f"world {label}: a refused call's table row carries no call id: {r!r}")
            assert r.get(S.CALL_ID) in refused_ids, (
                f"world {label}: a refused call's table row has no ledger row joined by its "
                f"call id: {r!r}")


def test_1234_served_system_with_unavailable_samples_refused_at_run_time(
        tmp_path: Path) -> None:
    """The run-time refusals are ledger `refused` rows, so they are blocked calls and appear in
    the user record's found gaps either way (A2). The judge's finding that the planted fact
    could not be seen is `unreachable` (M4: the samples showed the system unavailable, so the
    questioner could have known), and it routes by A1's rules over its pointers: design when
    it cites the plan and is not gap-only.

    The REAL path: the source run's captured edr answer cannot be read back, so pre-flight's
    samples record marks edr unavailable; edr lookup is withheld by the grant, so every
    sibling's call to it is refused at run time. b files unreachable citing its manifest entry
    (design: the questioner queue); c files unreachable citing its entry and its own refused
    row (gap-only: the user record) — routing reads the pointers, not the bucket."""

    def unreadable_edr_answer(src: Path) -> None:
        for r in S.read_jsonl(src / "executed_queries.jsonl"):
            if r.get("system") == "edr":
                (src / r["payload_path"]).write_text("{not json", encoding="utf-8")

    built = S.real_family(tmp_path, after_source=unreadable_edr_answer)
    samples = _yaml.safe_load((built.ep / "samples.yaml").read_text(encoding="utf-8")) or {}
    assert "unavailable" in (samples.get("edr") or {}), f"fixture: samples {samples!r}"
    refused_rows = [i for i, r in enumerate(built.ledger_rows("c"))
                    if r.get("source") == "refused" and r.get("system") == "edr"]
    assert refused_rows, "fixture: c's withheld edr lookup was refused at run time"
    refused_c = refused_rows[0]
    m_b, m_c = S.marker("b", "unreachable"), S.marker("c", "unreachable")
    replies = {
        "b": S.world_reply(LQ, world=[S.wf(UNREACHABLE, systems=["edr"],
                                           evidence=[S.plan_ptr("b")], claim=m_b)]),
        "c": S.world_reply(LQ, world=[S.wf(UNREACHABLE, systems=["edr"], claim=m_c,
                                           evidence=[S.plan_ptr("c"),
                                                     built.served("c", refused_c)])]),
    }

    S.grade(built, S.judge(replies), draws=1)

    refused_key = ("edr", "lookup", S.canonical(S.DENIED_LOOKUP))
    runs = {S.gap_key(e)[0] for e in S.found_gaps(built) if S.gap_key(e)[1:] == refused_key}
    assert len(runs) == 3, (
        "each run's refused edr lookup is a found gap of the user record, the control's "
        f"included: {S.found_gaps(built)!r}")
    assert _questioner("b") == [built.finding_id("b", 0, 0)], (
        "b's unreachable finding cites the plan and is not gap-only: design")
    assert S.lane_of(built, built.finding_id("b", 0, 0)) == S.LANES["questioner"]
    assert _questioner("c") == [], "c's unreachable finding rests only on a refused row"
    assert S.lane_of(built, built.finding_id("c", 0, 0)) == S.LANES["user_record"]
    assert _user_mentions(built, built.finding_id("c", 0, 0), m_c)


# --------------------------------------------------------------------------------------
# The defender row's contents (A1, OB13) and the lesson writer's view of them.
# --------------------------------------------------------------------------------------


def test_1234_defender_row_cites_the_manifest_or_the_oracle_store(tmp_path: Path) -> None:
    """Defender rows come from investigator findings, whose `citations` are
    `contrast_evidence`'s resolving pointers (A1). Manifest and oracle-store pointers listed in
    `contrast_evidence` beside the pair ride along (T1 rule 1) and, when they resolve, are among
    `citations` (rule 2): they are carried onto the defender row as inert strings the lesson
    author cannot open (OB13) and never count as a half of the pair. A world finding with a
    resolving plan pointer that is not gap-only (gap-only needs at least one resolving conduct
    pointer, every one blocked, A15) is design and goes to the questioner queue, never the
    defender queue.

    b files: the pair plus b's manifest entry and b's oracle store (queued, all four among
    citations); one conduct pointer of b beside b's entry and c's oracle store (no two-run
    pair: dropped); a design world finding citing b's entry and b's report. The row and the
    lesson writer's prompt over it carry the pointer strings, never the content they name
    (the planted fact, the forged row, the story)."""
    built = S.family(tmp_path, S.triad())
    plan_b, store_b = S.plan_ptr("b"), S.oracle_ptr("b")
    reply = S.world_reply(
        LQ,
        investigator=[S.inv(contrast=[*_pair_with_control("b"), plan_b, store_b]),
                      S.inv(contrast=[S.conduct("b"), plan_b, S.oracle_ptr("c")])],
        world=[S.wf(MISLABELLED, evidence=[plan_b, S.conduct("b")])])

    S.grade(built, S.judge({"b": reply}), draws=1)

    queued, kept_off, design = (built.finding_id("b", 0, i) for i in range(3))
    rows = _defender_rows("b")
    assert sorted(rows) == [queued], f"defender ids from b: {sorted(rows)}"
    citations = rows[queued].get(CITATIONS) or []
    for pointer in (*_pair_with_control("b"), plan_b, store_b):
        assert pointer in citations, f"{pointer} must be among the row's citations: {citations}"
    assert S.lane_of(built, kept_off) == S.LANES["dropped_no_pair"], (
        "manifest and oracle-store pointers never count as a half of the pair")
    assert _questioner("b") == [design], "the design world finding reaches the questioner"
    assert design not in _defender("b")

    content = (S.marker("b", "fact-f-b"), S.marker("b", "forged-f-b"), S.marker("b", "story"))
    queued_text = _queues_text()
    shared = S.mod("learning.author.shared")
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    with S.mod("_io").bind(corpus_dir) as corpus:
        prompt = shared.build_curator_user_prompt(
            [rows[queued]], "batch-1", corpus=corpus, corpus_dir=corpus_dir,
            corpus_dir_rel="lessons", label="findings", salt="s1234")
    for pointer in (plan_b, store_b):
        assert pointer in prompt, f"the lesson writer is handed the pointer {pointer} as text"
    for marker in content:
        assert marker not in queued_text, f"{marker}: archive content reached a queue row"
        assert marker not in prompt, f"{marker}: archive content reached the lesson writer"






# --------------------------------------------------------------------------------------
# R5 survival: the defender lane decision without a verdict word.
# --------------------------------------------------------------------------------------


def test_1234_defender_lane_decision_rests_on_world_state_not_a_verdict_word(
        tmp_path: Path) -> None:
    """The defender-lane block decision (enqueue.defender_lane_blocked, today keyed on the
    verdict word) completes without any outcome word: an investigator finding of a measured,
    unanimous, non-none world passes the lane; a finding of a not-measured, withheld or none
    world, and a gap-only finding, does not; and no outcome literal is read. The control is the
    measured world's finding reaching the defender queue.

    Two draws over four planted worlds: b measured and unanimous (an ordinary finding and a
    gap-only one), c not measured (unreachable), d withheld (draws disagree), e none. The lane
    decision's own code holds no outcome word, literal or name, and takes no outcome word;
    neither judge.yaml nor any queued row carries one."""
    built = S.family(tmp_path, S.triad(
        a={"calls": _calls("a", S.refused_call())}, b={"calls": _calls("b", S.refused_call())},
        d={"role": "D", "calls": [S.CallRow()]}, e={"role": "E", "calls": [S.CallRow()]}))
    gap_pair = [_served(built, "b", 2), _served(built, "a", 1)]

    def inv_of(label: str) -> dict:
        return S.inv(contrast=_pair_with_control(label), claim=S.marker(label, "inv"))

    replies = {
        "b": S.world_reply(LQ, investigator=[inv_of("b"), S.inv(contrast=gap_pair)]),
        "c": S.world_reply(LQ, investigator=[inv_of("c")], world=[
            S.wf(UNREACHABLE, evidence=[S.plan_ptr("c")])]),
        ("d", 0): S.world_reply(LQ, investigator=[inv_of("d")]),
        ("d", 1): S.world_reply(LS, investigator=[inv_of("d")]),
        "e": S.world_reply(S.NO_BUCKET, [], investigator=[inv_of("e")]),
    }

    S.grade(built, S.judge(replies), draws=2)

    assert sorted(_defender("b")) == [built.finding_id("b", 0, 0), built.finding_id("b", 1, 0)], (
        "control: the measured, unanimous, non-none world's finding passes the lane")
    blocked = {"c": S.LANES["not_measured"], "d": S.LANES["draws_disagree"],
               "e": S.LANES["unauthored"]}
    for label, lane in blocked.items():
        assert _defender(label) == [], f"world {label}'s finding must not pass the lane"
        for n in range(2):
            assert S.lane_of(built, built.finding_id(label, n, 0)) == lane, f"{label}/{n}/0"
    for n in range(2):
        assert S.lane_of(built, built.finding_id("b", n, 1)) == S.LANES["user_record"], (
            f"b/{n}/1 is gap-only and must not pass the lane")

    lane_rule = S.sym(S.JUDGE_ENQUEUE, "defender_lane_blocked")
    fn = ast.parse(textwrap.dedent(inspect.getsource(lane_rule))).body[0]
    assert isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
    assert fn.name == "defender_lane_blocked", f"the walk read {fn.name!r}, not the lane rule"
    body = fn.body[1:] if ast.get_docstring(fn) is not None else fn.body
    nodes = [n for stmt in body for n in ast.walk(stmt)]
    assert body, "the walk found no statement in the lane rule's body"
    assert nodes, "the walk found no node in the lane rule's body"
    literals = {n.value for n in nodes if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    names = ({n.id for n in nodes if isinstance(n, ast.Name)}
             | {n.attr for n in nodes if isinstance(n, ast.Attribute)})
    params = {a.arg for a in (*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs)}
    assert not literals & OUTCOME_WORDS, f"the lane decision reads {literals & OUTCOME_WORDS}"
    assert not (names | params) & RETIRED_NAMES, (
        f"the lane decision names {(names | params) & RETIRED_NAMES}")
    assert not set(S.record(built)) & set(S.RETIRED_RECORD_FIELDS)
    for row in S.defender_queue():
        assert not set(row) & set(S.RETIRED_RECORD_FIELDS), row


# --------------------------------------------------------------------------------------
# OB14: each row's own world's alert.
# --------------------------------------------------------------------------------------


