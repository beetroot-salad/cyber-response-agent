from __future__ import annotations

from defender.tests.support.learning.branch import _triplet_947 as T

from defender.tests.support.shared._fixture_uuid import fixture_uuid

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _run_handle_1165

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from defender.integrations import faults
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.storage._alert_plant import plant_alert
from defender.tests.support.learning.core._state1135 import state_over
from defender.tests.learning.oracle.live_contracts import _spec1224 as S

SUBMIT = S.COINED["tool.submit"]
CHECK = S.COINED["tool.check"]
PYTHON = S.COINED["tool.python"]

TS_BASE = "2026-07-28T15:00:00Z"
TS_FACT = "2026-07-28T15:22:00Z"

ALICE = S.query_params("user:alice")
BOB = S.query_params("user:bob")
DB1 = S.query_params("host:db-1")
SIEM_ALICE = {"entity": "alice"}

#: A real idp row (the base answer to `idp query user:alice`).
BASE_ROW = {"user": "alice", "event_id": "e-100", "action": "logon", "host": "web-1",
            "ts": TS_BASE}
#: The row world b's fact f1 implies, with the source's real columns and types and a fresh id.
FORGED_ROW = {"user": "alice", "event_id": "e-9f01", "action": "tgt", "host": "db-1",
              "ts": TS_FACT}
BASE = {"rows": [BASE_ROW]}
SERVED = {"rows": [BASE_ROW, FORGED_ROW]}

#: World b's fact for the check-4 scenarios: it fixes a field of an entity.
DEPT_FACT = S.fact("f1", "alice moved to the finance department and logged on to db-1 at 15:22Z",
                   ("alice", "db-1"))
#: World c's fact (another world's fact_id for world b's scenarios).
C_FACT = S.fact("f2", "bob reset carol's password from 10.0.0.9", ("bob", "carol", "10.0.0.9"))


def _doc(*b_facts: dict, source_run_dir: str | None = None) -> dict:
    """A v2 family whose world b carries `b_facts` (default: the one default fact f1)."""
    worlds = [S.control_world("a"),
              S.world_v2("b", facts=list(b_facts) if b_facts else None),
              S.world_v2("c", facts=[C_FACT])]
    kw: dict[str, Any] = {} if source_run_dir is None else {"source_run_dir": source_run_dir}
    return S.family_v2(worlds=worlds, **kw)


@dataclass
class _Scene:
    tmp: Path
    est: S.Estate
    ep: Path
    ctx: Any
    #: The source run's folder the sibling hands its registry (`None`: no source alert).
    source_run_dir: Path | None = None

    def registry(self, o: S.ScriptedModel, v: S.ScriptedModel | None = None, *,
                 label: str = "b", **knobs: Any) -> Any:
        """World `label`'s registry with the oracle / verifier doubles and a sandboxed box."""
        box, _log = S.sandboxed_box()
        knobs.setdefault("retry_cap", 3)
        verifier = v if v is not None else S.passing_verifier()
        if self.source_run_dir is None:
            return S.world_registry(self.ep, label, self.est, oracle=o, verifier=verifier,
                                    box=box, **knobs)
        # The registry receives the opened source Run; the
        # manifest's recorded `source_run_dir` is never read. Otherwise `world_registry`'s.
        rt = self.est.run_tenant()
        world, ledger = S.load_world(self.ep, label), S.world_ledger(self.ep, label)
        return S.sym(S.REGISTRY, "WorldRegistry")(
            self.est.roster(), rt.grants.gather, world=world, ledger=ledger, as_of=S.AS_OF_DT,
            tenant=rt, grant_home=rt.table_pointer, source_run=_run_handle_1165(self.source_run_dir),
            **S.registry_seams(world, ledger, oracle=o.model, verifier=verifier.model, box=box,
                               oracle_dir=S.oracle_dir(self.ep, label), **knobs))

    def call(self, reg: Any, system: str, verb: str, **params: Any) -> Any:
        """One investigator call through the registry's wrapped verb (what the query tool
        receives)."""
        return S.call(reg, system, verb, self.ctx, **params)

    def rows(self, name: str, label: str = "b") -> list[dict]:
        return S.oracle_rows(self.ep, label, name)

    def ledger(self, label: str = "b") -> list[dict]:
        return S.ledger_rows(self.ep, label)


def _scene(tmp_path: Path, *, live: tuple = (), recorded: tuple = (),
           doc: dict | None = None, source_run_dir: Path | None = None) -> _Scene:
    """`live`: `(system, verb, params, payload)` the real system answers; `recorded`: the same
    shape, captured in the family's base recording; `source_run_dir`: the source run's folder
    the registry is handed."""
    est = S.estate(tmp_path)
    for system, verb, params, payload in live:
        est.answer(system, verb, params, payload)
    ep = S.episode_v2(tmp_path, doc=doc,
                      base_rows=[S.captured(s, v, p, pl) for s, v, p, pl in recorded])
    return _Scene(tmp_path, est, ep, est.ctx(tmp_path / "run"), source_run_dir)


def _forged(**over: Any) -> dict:
    row = dict(FORGED_ROW)
    row.update(over)
    return row


def _honest(fid: str = "fg-1", *, row: dict = FORGED_ROW, base_rows: tuple = (BASE_ROW,),
            system: str = "idp", fact_id: str = "f1", **claim_kw: Any) -> list[S.Move]:
    """Forge one row for a fact and submit the base plus that row, claiming exactly it."""
    return [S.forge(fid, fact_id, system, row),
            S.submit({"rows": [*base_rows, row]},
                     S.claim(added=[S.added(fid, fact_id)], **claim_kw))]


def _move_index(o: S.ScriptedModel, tool: str, k: int) -> int:
    n = 0
    for i, move in enumerate(o.consumed):
        if move.tool == tool:
            n += 1
            if n == k:
                return i
    raise AssertionError(f"the oracle never made a #{k} `{tool}` move "
                         f"(consumed: {[m.tool for m in o.consumed]})")


def _after(o: S.ScriptedModel, tool: str, k: int = 1) -> str:
    """What the host appended to the oracle's conversation in reply to its k-th `tool` move."""
    i = _move_index(o, tool, k)
    assert i + 1 < len(o.messages), (
        f"the oracle was never asked again after its #{k} `{tool}` move — no verdict reached it")
    return S.host_tail(o.messages[i + 1])


def _named(text: str) -> set[int]:
    """The host checks (1-5) a verdict names."""
    return {n for n in range(1, 6) if S.verdict_names(text, f"check {n}")}


def _assert_verdict(o: S.ScriptedModel, k: int, what: str) -> str:
    """The k-th submission failed and its verdict — naming `what` ("check <n>" or "verifier") —
    reached the oracle's next request."""
    text = _after(o, SUBMIT, k)
    assert S.verdict_names(text, what), (
        f"submission #{k} should have failed naming {what!r}, and that verdict should be in "
        f"the oracle's next request; the host appended: {text!r}")
    return text


def _assert_some_check(o: S.ScriptedModel, k: int) -> str:
    text = _after(o, SUBMIT, k)
    assert _named(text) or S.verdict_names(text, "verifier"), (
        f"submission #{k} should have failed with a verdict naming a host check or the "
        f"verifier in the oracle's next request; the host appended: {text!r}")
    return text


def _spent(o: S.ScriptedModel) -> None:
    """The oracle answered every scripted move and was never asked for one more."""
    assert not o.overrun, "the oracle was asked for a move past its script"
    assert not o.moves, f"the oracle left {len(o.moves)} scripted move(s) unasked: {o.moves}"


def _has_row(rows: list[dict], **want: Any) -> bool:
    return any(all(r.get(k) == v for k, v in want.items()) for r in rows)


def _payload(row: dict) -> Any:
    return json.loads(row["payload_text"])


def _only_oracle_row(sc: _Scene, *, attempts: int, served: Any) -> dict:
    """The world ledger holds exactly one row for the one investigator call: an `oracle` row
    carrying the served answer and its attempt count."""
    rows = sc.ledger()
    assert len(rows) == 1, f"one investigator call, one world-ledger row; got {rows}"
    row = rows[0]
    assert row["source"] == S.ORACLE_DECISION, row
    assert _payload(row) == served, row
    assert row.get("attempts") == attempts, row
    return row


#: World b's default fact (f1), as the verifier must be handed it.
F1_STATEMENT = S.fact()["statement"]

SCRATCH = "ORACLE-SCRATCH-7e3a"


def _scratch() -> S.Move:
    return S.python(f"# {SCRATCH}: does this answer hold the fact's row?\nprint('checked')")


def _assert_handed(v: S.ScriptedModel, k: int, *, framed: dict[str, str] | None = None,
                   never: tuple[str, ...] = (SCRATCH,)) -> None:
    """The verifier's k-th request (one per pass here: each pass answers with a lone
    `verdict`) carried each `framed` token (input name -> token) inside an untrusted frame and
    nowhere outside one (M26: the call, the answers, the facts and the frozen rows are none of
    them host-authored), and none of `never` ANYWHERE in its context, history included."""
    assert len(v.seen) > k, f"the verifier was asked {len(v.seen)} time(s), never pass #{k + 1}"
    for what, token in (framed or {}).items():
        S.assert_wrapped_untrusted(v.seen[k], token, f"verifier pass #{k + 1}, {what}")
    shown = v.seen[k] + "\n" + S.all_parts_text(v.messages[k])
    for token in never:
        assert token not in shown, (
            f"verifier pass #{k + 1} was handed {token!r}: the oracle's own transcript, or an "
            "earlier pass's verdict (each pass is cold, M17=A)")


def _assert_scratched(o: S.ScriptedModel) -> None:
    """Positive control for the `SCRATCH` negative: the oracle's python move was made and the
    host answered it inside the turn, so the sentinel IS in the oracle's transcript."""
    assert any(m.tool == PYTHON and SCRATCH in m.args.get("code", "") for m in o.consumed), (
        "the oracle never made its scratch move")
    _after(o, PYTHON, 1)


def _control(tmp_path: Path, **scene_kw: Any) -> _Scene:
    """An independent scene — its own estate, episode and world stores — for the F-01
    control: the refused submission replayed under a PASSING verifier."""
    return _scene(tmp_path / "control", **scene_kw)


def test_1224_answer_differing_exactly_by_its_claim_is_served_as_oracle(tmp_path):
    vpn = {"user": "alice", "event_id": "e-101", "action": "vpn", "host": "vpn-1", "ts": TS_BASE}
    side = S.query_params("event_id:e-101")
    siem = {"entity": "alice", "risk": "low", "record_id": "r-0001"}
    sc = _scene(tmp_path, live=[("idp", "query", ALICE, {"rows": [BASE_ROW, vpn]}),
                                ("idp", "query", side, {"rows": [vpn]}),
                                ("siem-x", "lookup", SIEM_ALICE, siem)])
    rows_claim = S.claim(added=[S.added("fg-1", "f1")],
                         removed=[S.removed(vpn, system="idp", verb="query", params=side,
                                            count=1)])
    rows_served = {"rows": [BASE_ROW, FORGED_ROW]}
    change_claim = S.claim(changed=[S.changed("alice", "risk", "low", "high")])
    siem_served = {**siem, "risk": "high"}
    o = S.oracle(S.forge("fg-1", "f1", "idp", FORGED_ROW), S.submit(rows_served, rows_claim),
                 S.submit(siem_served, change_claim))
    v = S.passing_verifier()
    reg = sc.registry(o, v)

    assert sc.call(reg, "idp", "query", **ALICE) == rows_served
    assert sc.call(reg, "siem-x", "lookup", **SIEM_ALICE) == siem_served
    _spent(o)
    assert o.submissions() == 2, "each call served on its first attempt"
    assert v.requests == 2, "one verifier pass per served call"

    ledger = sc.ledger()
    assert [r["source"] for r in ledger] == [S.ORACLE_DECISION, S.ORACLE_DECISION], ledger
    for row, served, claim_ in ((ledger[0], rows_served, rows_claim),
                                (ledger[1], siem_served, change_claim)):
        assert _payload(row) == served, row
        assert row.get("attempts") == 1, row
        assert row.get("base_digest"), f"an oracle row carries the base answer's digest: {row}"
        assert row.get("verifier_verdict") is not None, row
        recorded = row.get("claim") or {}
        for key, value in claim_.items():
            assert recorded.get(key) == value, (key, recorded)
    # The removal's side query reached the tenant through the oracle-side door, at the clock.
    side_calls = [c for c in sc.est.calls("idp", "query") if c["params"] == side]
    assert side_calls, "check 5 re-ran the removal's side query against the real system"
    assert all(c["as_of"] == S.AS_OF_DT.isoformat() for c in side_calls), side_calls
    assert _has_row(sc.rows("ledger"), actor="host-check", system="idp", verb="query",
                    params=side), sc.rows("ledger")
    # Committed with the verified answer: the forged row and both stored answers.
    assert _has_row(sc.rows("forged"), forged_id="fg-1", fact_id="f1", system="idp",
                    row=FORGED_ROW), sc.rows("forged")
    assert len(sc.rows("answers")) == 2, sc.rows("answers")


def test_1224_answer_contradicting_a_recorded_fact_fails_check_4_and_retries(tmp_path):
    siem = {"entity": "alice", "risk": "low", "record_id": "r-0001", "department": "sales"}
    sc = _scene(tmp_path, doc=_doc(DEPT_FACT),
                live=[("idp", "query", ALICE, BASE), ("siem-x", "lookup", SIEM_ALICE, siem)])
    contradicting = {**siem, "department": "marketing"}
    consistent = {**siem, "department": "finance"}
    o = S.oracle(
        S.record_fact("alice", "department", "finance"), *_honest(),
        # call 2 (another system), attempt 1: alice's department claimed to a value the record
        # does not hold.
        S.submit(contradicting, S.claim(changed=[
            S.changed("alice", "department", "sales", "marketing")])),
        # attempt 2: the recorded value.
        S.submit(consistent, S.claim(changed=[
            S.changed("alice", "department", "sales", "finance")])))
    reg = sc.registry(o)

    assert sc.call(reg, "idp", "query", **ALICE) == SERVED
    facts = sc.rows("facts")
    assert _has_row(facts, entity="alice", field="department", value="finance"), facts

    answer = sc.call(reg, "siem-x", "lookup", **SIEM_ALICE)
    assert answer == consistent, "the contradicting answer must never reach the caller"
    _assert_verdict(o, 2, "check 4")
    _spent(o)
    assert all("marketing" not in r["payload_text"] for r in sc.ledger()), sc.ledger()
    assert sc.rows("facts") == facts, "the recorded fact is unchanged by the refused attempt"


def test_1224_forged_row_is_written_once_and_never_rewritten(tmp_path):
    sc = _scene(tmp_path, live=[("idp", "query", ALICE, BASE),
                                ("idp", "query", DB1, {"rows": []})])
    rewritten = _forged(action="tgs", host="db-2")
    o = S.oracle(
        *_honest(),
        # call 2, attempt 1: rewrite the frozen fg-1 and serve the rewrite.
        S.forge("fg-1", "f1", "idp", rewritten),
        S.submit({"rows": [rewritten]}, S.claim(added=[S.added("fg-1", "f1")])),
        # attempt 2: the frozen row, reused.
        S.submit({"rows": [FORGED_ROW]}, S.claim(added=[S.added("fg-1", "f1")])))
    reg = sc.registry(o)

    assert sc.call(reg, "idp", "query", **ALICE) == SERVED
    frozen = sc.rows("forged")
    assert frozen == [{"forged_id": "fg-1", "fact_id": "f1", "system": "idp",
                       "row": FORGED_ROW}], frozen

    assert sc.call(reg, "idp", "query", **DB1) == {"rows": [FORGED_ROW]}
    _assert_verdict(o, 2, "check 4")
    _spent(o)
    assert sc.rows("forged") == frozen, "the second write of fg-1 was refused; one row, unchanged"
    assert all("db-2" not in r["payload_text"] for r in sc.ledger()), sc.ledger()


def test_1224_forged_store_and_recorded_facts_live_under_the_world_dir(tmp_path):
    siem = {"entity": "alice", "risk": "low", "record_id": "r-0001"}
    sc = _scene(tmp_path, live=[("idp", "query", ALICE, BASE),
                                ("siem-x", "lookup", SIEM_ALICE, siem)])
    o1 = S.oracle(S.record_fact("alice", "cost_center", "cc-4417"), *_honest())
    assert sc.call(sc.registry(o1), "idp", "query", **ALICE) == SERVED
    _spent(o1)

    world_dir = S.oracle_dir(sc.ep, "b")
    forged_file, facts_file = world_dir / "forged.jsonl", world_dir / "facts.jsonl"
    listing = sorted(p.name for p in world_dir.glob("*")) if world_dir.is_dir() else world_dir
    assert forged_file.is_file(), listing
    assert facts_file.is_file(), listing
    for outside in (sc.ctx.run_dir, sc.ep / "worlds"):
        assert not world_dir.resolve().is_relative_to(Path(outside).resolve()), (
            f"the oracle-side store must live outside {outside}")
    before = (forged_file.read_bytes(), facts_file.read_bytes())
    assert b"fg-1" in before[0], before
    assert b"cc-4417" in before[1], before

    # The conversation restarts: a fresh oracle, nothing of the first conversation in it.
    o2 = S.oracle(S.submit(siem, S.EMPTY_CLAIM))
    reg2 = sc.registry(o2)
    assert (forged_file.read_bytes(), facts_file.read_bytes()) == before
    assert sc.call(reg2, "siem-x", "lookup", **SIEM_ALICE) == siem
    _spent(o2)
    assert "cc-4417" in o2.seen[0], (
        "the restarted conversation's prefix carries the recorded facts from the store")
    assert forged_file.read_bytes().startswith(before[0]), "the frozen rows are unchanged"
    assert facts_file.read_bytes().startswith(before[1]), "the recorded facts are unchanged"


def test_1224_undeclared_added_row_fails_check_1_and_is_not_served(tmp_path):
    sc = _scene(tmp_path, live=[("idp", "query", ALICE, BASE)])
    undeclared = _forged(event_id="e-bad1", action="tgs")
    o = S.oracle(S.submit({"rows": [BASE_ROW, undeclared]}, S.EMPTY_CLAIM), *_honest())
    reg = sc.registry(o)

    _run_dir, gather = S.drive_gather(
        tmp_path, verbs=reg, tenant=sc.est.place(),
        gather_turns=[S.query_turn("idp", "query", ALICE), S.done_turn()])
    seen = "\n".join(gather.seen)
    assert "e-9f01" in seen, "the honest retry reached the investigator (positive control)"
    assert "e-bad1" not in seen, "the undeclared row reached the investigator"
    _assert_verdict(o, 1, "check 1")
    _spent(o)
    row = _only_oracle_row(sc, attempts=2, served=SERVED)
    assert "e-bad1" not in json.dumps(row), row


def test_1224_silent_edit_of_a_base_row_fails_check_1(tmp_path):
    sc = _scene(tmp_path, live=[("idp", "query", ALICE, BASE)])
    edited = {**BASE_ROW, "host": "db-9"}
    o = S.oracle(S.forge("fg-1", "f1", "idp", FORGED_ROW),
                 S.submit({"rows": [edited, FORGED_ROW]}, S.claim(added=[S.added("fg-1", "f1")])),
                 *_honest())
    reg = sc.registry(o)

    assert sc.call(reg, "idp", "query", **ALICE) == SERVED
    _assert_verdict(o, 1, "check 1")
    _spent(o)
    row = _only_oracle_row(sc, attempts=2, served=SERVED)
    assert "db-9" not in row["payload_text"], row


def test_1224_wrong_count_or_unreproducible_removal_fails_check_5(tmp_path):
    count_q = S.query_params("count by host")
    counts = {"counts": [{"host": "web-1", "count": 3}, {"host": "db-1", "count": 1}]}
    vpn = {"user": "alice", "event_id": "e-101", "action": "vpn", "host": "vpn-1", "ts": TS_BASE}
    vpn2 = {**vpn, "event_id": "e-102"}
    loose = S.query_params("user:alice action:vpn")
    tight = S.query_params("event_id:e-101")
    sc = _scene(tmp_path, live=[("siem-x", "query", count_q, counts),
                                ("idp", "query", ALICE, {"rows": [BASE_ROW, vpn]}),
                                ("idp", "query", loose, {"rows": [vpn, vpn2]}),
                                ("idp", "query", tight, {"rows": [vpn]})])
    event = {"host": "db-1", "user": "alice", "event_id": "s-9f03", "ts": TS_FACT}

    def counted_answer(n: int) -> dict:
        return {"counts": [{"host": "web-1", "count": 3}, {"host": "db-1", "count": n}]}

    def removal(params: dict) -> dict:
        return S.claim(removed=[S.removed(vpn, system="idp", verb="query", params=params,
                                          count=1)])

    o = S.oracle(
        # call 1, attempt 1: 1 + 1 claimed as 3, and 3 served.
        S.forge("fg-1", "f1", "siem-x", event),
        S.submit(counted_answer(3), S.claim(added=[S.added("fg-1", "f1")], counts=[
            S.counted("db-1", base=1, added_=1, served=3)])),
        # attempt 2: the arithmetic holds.
        S.forge("fg-1", "f1", "siem-x", event),
        S.submit(counted_answer(2), S.claim(added=[S.added("fg-1", "f1")], counts=[
            S.counted("db-1", base=1, added_=1)])),
        # call 2, attempt 1: one row removed, but its side query selects two.
        S.submit(BASE, removal(loose)),
        # attempt 2: a side query that selects exactly the removed row.
        S.submit(BASE, removal(tight)))
    reg = sc.registry(o)

    assert sc.call(reg, "siem-x", "query", **count_q) == counted_answer(2)
    _assert_verdict(o, 1, "check 5")
    assert sc.call(reg, "idp", "query", **ALICE) == BASE
    _assert_verdict(o, 3, "check 5")
    _spent(o)

    reruns = [c for c in sc.est.calls("idp", "query") if c["params"] in (loose, tight)]
    assert {json.dumps(c["params"], sort_keys=True) for c in reruns} == {
        json.dumps(loose, sort_keys=True), json.dumps(tight, sort_keys=True)}, reruns
    assert all(c["as_of"] == S.AS_OF_DT.isoformat() for c in reruns), reruns
    oracle_ledger = sc.rows("ledger")
    assert _has_row(oracle_ledger, actor="host-check", params=loose), oracle_ledger
    ledger = sc.ledger()
    assert len(ledger) == 2, f"one world-ledger row per investigator call, none for a re-run: {ledger}"
    assert [_payload(r) for r in ledger] == [counted_answer(2), BASE], ledger


def test_1224_check_tool_and_host_return_one_verdict(tmp_path):
    sc = _scene(tmp_path, live=[("idp", "query", ALICE, BASE)])
    bad = {"rows": [BASE_ROW, _forged(event_id="e-bad1")]}
    honest_claim = S.claim(added=[S.added("fg-1", "f1")])
    o = S.oracle(S.check(bad, S.EMPTY_CLAIM), S.submit(bad, S.EMPTY_CLAIM),
                 S.forge("fg-1", "f1", "idp", FORGED_ROW),
                 S.check(SERVED, honest_claim), S.submit(SERVED, honest_claim))
    reg = sc.registry(o)

    assert sc.call(reg, "idp", "query", **ALICE) == SERVED
    _spent(o)
    tool_bad, host_bad = _after(o, CHECK, 1), _after(o, SUBMIT, 1)
    assert 1 in _named(host_bad), f"the host's gate failed check 1: {host_bad!r}"
    assert _named(tool_bad) == _named(host_bad), (
        f"the check tool's verdict {tool_bad!r} differs from the host's {host_bad!r}")
    tool_ok = _after(o, CHECK, 2)
    assert _named(tool_ok) == set(), (
        f"the check tool failed an answer the host then served: {tool_ok!r}")
    _only_oracle_row(sc, attempts=2, served=SERVED)


def test_1224_forged_row_with_missing_extra_or_mistyped_column_fails_check_2(tmp_path):
    with_null = {"user": "alice", "event_id": "e-099", "action": "logoff", "host": None,
                 "ts": "2026-07-28T14:55:00Z"}
    base = {"rows": [BASE_ROW, with_null]}
    edr_row = {"event_id": "x-9f02", "host": "db-1", "process": "kinit", "ts": TS_FACT}
    sc = _scene(tmp_path, live=[("idp", "query", ALICE, base),
                                ("edr", "query", DB1, {"events": []})])
    missing = {k: v for k, v in FORGED_ROW.items() if k != "host"}
    extra = _forged(event_id="e-9f0b", note="forged for f1")
    mistyped = _forged(event_id="e-9f0c", ts=1785252120)

    def attempt(fid: str, row: dict) -> list[S.Move]:
        return _honest(fid, row=row, base_rows=(BASE_ROW, with_null))

    o = S.oracle(*attempt("fg-m", {**missing, "event_id": "e-9f0a"}), *attempt("fg-x", extra),
                 *attempt("fg-t", mistyped), *attempt("fg-1", FORGED_ROW),
                 S.forge("fg-2", "f1", "edr", edr_row),
                 S.submit({"events": [edr_row]}, S.claim(added=[S.added("fg-2", "f1")])))
    reg = sc.registry(o, retry_cap=5)

    assert sc.call(reg, "idp", "query", **ALICE) == {"rows": [BASE_ROW, with_null, FORGED_ROW]}
    for k in (1, 2, 3):
        _assert_verdict(o, k, "check 2")
    # No real edr example exists anywhere in this world: forged from the oracle's knowledge and
    # served on the first attempt (D2), never refused for want of an exemplar.
    assert sc.call(reg, "edr", "query", **DB1) == {"events": [edr_row]}
    _spent(o)
    ledger = sc.ledger()
    assert [(r["source"], r.get("attempts")) for r in ledger] == [
        (S.ORACLE_DECISION, 4), (S.ORACLE_DECISION, 1)], ledger


SID = "S-1-5-21-1004"
SID_ROW = {"user": "alice", "user_id": SID, "event_id": "e-100", "action": "logon",
           "host": "web-1", "ts": TS_BASE}
ALERT = {"alert_id": "a-31337", "rule": "kerberos ticket anomaly", "host": "db-1"}


def _sid_row(event_id: str) -> dict:
    return {**SID_ROW, "event_id": event_id, "action": "tgt", "host": "db-1", "ts": TS_FACT}


def _sid_attempt(fid: str, event_id: str, *, base_rows: tuple = (SID_ROW,),
                 declare: bool = True) -> list[S.Move]:
    """Forge alice's row (carrying her real SID, declared as a reference to her when
    `declare`) under `event_id`, and submit the base plus it."""
    refs = [S.entity_ref(fid, "user_id", "alice")] if declare else []
    row = _sid_row(event_id)
    return [S.forge(fid, "f1", "idp", row),
            S.submit({"rows": [*base_rows, row]},
                     S.claim(added=[S.added(fid, "f1")], entity_refs=refs))]


def _plant_alert(tmp_path: Path) -> Path:
    """The source run's alert and its record (#1222), in the source run dir the manifest names
    and in the sibling's run dir, which resumes from it."""
    src = tmp_path / fixture_uuid("1224-source-run")
    for where in (src, tmp_path / "run"):
        where.mkdir(parents=True, exist_ok=True)
        plant_alert(where, json.dumps(ALERT).encode("utf-8"))
    return src


def test_1224_forged_id_occurring_in_any_real_answer_fails_check_3(tmp_path):
    src = _plant_alert(tmp_path)
    bob = {"user": "bob", "user_id": "S-1-5-21-2002", "event_id": "e-555", "action": "logon",
           "host": "web-2", "ts": TS_BASE}
    siem = {"entity": "alice", "risk": "low", "record_id": "r-0042"}
    sc = _scene(tmp_path, doc=_doc(), source_run_dir=src,
                recorded=[("edr", "query", DB1, {"events": [
                    {"event_id": "x-rec-7", "host": "db-1", "process": "sshd"}]})],
                live=[("idp", "query", ALICE, {"rows": [SID_ROW]}),
                      ("idp", "query", DB1, {"rows": []}),
                      ("idp", "query", BOB, {"rows": [bob]}),
                      ("siem-x", "lookup", SIEM_ALICE, siem)])
    o = S.oracle(
        # call 1 (idp query user:alice; live base)
        *_sid_attempt("fg-a", "x-rec-7"),              # the base recording
        *_sid_attempt("fg-b", "e-100"),                # this world's live base answer
        *_sid_attempt("fg-1", "e-9f01"),               # fresh: served
        # call 2 (idp query host:db-1; live base empty)
        S.run_query("idp", "query", BOB),
        *_sid_attempt("fg-c", "e-555", base_rows=()),  # this world's exploration result
        *_sid_attempt("fg-d", "r-0042", base_rows=()),  # the verifier's run_query result
        *_sid_attempt("fg-e", "a-31337", base_rows=()),  # the source alert
        *_sid_attempt("fg-f", "e-9f02", base_rows=(), declare=False),  # undeclared SID
        *_sid_attempt("fg-2", "e-9f02", base_rows=()))  # declared reference: exempt
    v = S.verifier(S.run_query("siem-x", "lookup", SIEM_ALICE), S.verdict(True),
                   then=S.verdict(True))
    reg = sc.registry(o, v, retry_cap=6)

    assert sc.call(reg, "idp", "query", **ALICE) == {"rows": [SID_ROW, _sid_row("e-9f01")]}
    assert sc.call(reg, "idp", "query", **DB1) == {"rows": [_sid_row("e-9f02")]}
    _spent(o)
    for k, source in enumerate(("base recording", "live base answer", None,
                                "exploration result", "verifier run_query result",
                                "source alert", "undeclared entity identifier"), start=1):
        if source is None:
            continue
        text = _after(o, SUBMIT, k)
        assert S.verdict_names(text, "check 3"), (
            f"a forged id equal to a value in the {source} must fail check 3; "
            f"the host appended: {text!r}")
    ledger = sc.ledger()
    assert [r.get("attempts") for r in ledger] == [3, 5], ledger
    for colliding in ("x-rec-7", '"e-100"', "e-555", "r-0042", "a-31337"):
        assert colliding not in ledger[1]["payload_text"], (colliding, ledger[1])
    forged_ids = {r["forged_id"] for r in sc.rows("forged")}
    assert forged_ids == {"fg-1", "fg-2"}, f"only the served attempts' rows froze: {forged_ids}"


def test_input_record_fact_value_is_null_empty_or_typed_differently(tmp_path):
    siem = {"entity": "alice", "mfa": "true", "display": "Alice", "logons": 5, "manager": None,
            "record_id": "r-0001"}
    sc = _scene(tmp_path, live=[("idp", "query", ALICE, BASE),
                                ("siem-x", "lookup", SIEM_ALICE, siem)])
    records = (("mfa", "true"), ("display", "Alice"), ("logons", 5), ("manager", None))
    retyped = (("mfa", True), ("display", "alice"), ("logons", "5"), ("manager", ""))
    o = S.oracle(
        *(S.record_fact("alice", f, value) for f, value in records), *_honest(),
        *(S.submit({**siem, f: new}, S.claim(changed=[S.changed("alice", f, siem[f], new)]))
          for f, new in retyped),
        S.submit(siem, S.EMPTY_CLAIM))
    reg = sc.registry(o, retry_cap=6)

    assert sc.call(reg, "idp", "query", **ALICE) == SERVED
    facts = sc.rows("facts")
    for f, value in records:
        assert any(r.get("entity") == "alice" and r.get("field") == f and "value" in r
                   and r["value"] == value and type(r["value"]) is type(value)
                   for r in facts), (f, value, facts)
    assert sc.call(reg, "siem-x", "lookup", **SIEM_ALICE) == siem
    for k in range(2, 6):
        _assert_verdict(o, k, "check 4")
    _spent(o)


def test_input_record_fact_conflicts_with_itself_or_names_a_stranger(tmp_path):
    siem = {"entity": "alice", "risk": "low", "record_id": "r-0001", "department": "sales"}
    sc = _scene(tmp_path, doc=_doc(DEPT_FACT),
                live=[("idp", "query", ALICE, BASE), ("siem-x", "lookup", SIEM_ALICE, siem)])
    o = S.oracle(
        S.record_fact("alice", "department", "finance"),
        S.record_fact("alice", "department", "legal"),          # refused
        S.record_fact("mallory-pc", "os", "linux"),             # a stranger: accepted
        *_honest(),
        # call 2: record the refused value again, and serve it.
        S.record_fact("alice", "department", "legal"),
        S.submit({**siem, "department": "legal"}, S.claim(changed=[
            S.changed("alice", "department", "sales", "legal")])),
        S.submit({**siem, "department": "finance"}, S.claim(changed=[
            S.changed("alice", "department", "sales", "finance")])))
    reg = sc.registry(o)

    assert sc.call(reg, "idp", "query", **ALICE) == SERVED
    facts = sc.rows("facts")
    dept = [r.get("value") for r in facts
            if r.get("entity") == "alice" and r.get("field") == "department"]
    assert dept == ["finance"], f"one value for (alice, department): {facts}"
    assert _has_row(facts, entity="mallory-pc", field="os", value="linux"), facts
    assert sc.call(reg, "siem-x", "lookup", **SIEM_ALICE)["department"] == "finance"
    _assert_verdict(o, 2, "check 4")
    _spent(o)
    assert [r.get("value") for r in sc.rows("facts")
            if r.get("entity") == "alice" and r.get("field") == "department"] == ["finance"]


def test_input_oracle_forges_for_a_fact_the_call_does_not_cover_or_that_does_not_exist(tmp_path):
    bob_base = {"rows": [{"user": "bob", "event_id": "e-200", "action": "logon",
                          "host": "web-2", "ts": TS_BASE}]}
    bob_rows = tuple(bob_base["rows"])
    sc = _scene(tmp_path, live=[("idp", "query", BOB, bob_base)])
    reason = "f1 is about alice; this call reads bob's events"
    o = S.oracle(*_honest("fg-c", fact_id="f2", base_rows=bob_rows),
                 *_honest("fg-n", fact_id="f9", base_rows=bob_rows),
                 _scratch(), *_honest("fg-1", fact_id="f1", base_rows=bob_rows),
                 S.submit(bob_base, S.EMPTY_CLAIM))
    v = S.verifier(S.verdict(False, reason), S.verdict(True))
    reg = sc.registry(o, v, retry_cap=5)

    assert sc.call(reg, "idp", "query", **BOB) == bob_base
    _spent(o)
    assert _named(_after(o, SUBMIT, 1)), "another world's fact_id fails a host check"
    assert _named(_after(o, SUBMIT, 2)), "a fact_id that exists nowhere fails a host check"
    _assert_verdict(o, 3, "verifier")
    assert not v.overrun
    assert v.requests == 2, "the verifier judged only what passed 1-5"
    _assert_handed(v, 0, framed={"the call's filter": "user:bob", "the base answer": "e-200",
                                 "the served answer's forged row": "e-9f01",
                                 "the world's fact": F1_STATEMENT})
    _assert_handed(v, 1, never=(SCRATCH, reason))
    _assert_scratched(o)
    assert sc.rows("forged") == [], "no row of a failed attempt is frozen (M15=B)"
    assert [_payload(r) for r in sc.ledger()] == [bob_base], sc.ledger()

    # Control: the verifier-refused (third) submission, alone, under a passing verifier.
    ctl = _control(tmp_path, live=[("idp", "query", BOB, bob_base)])
    oc = S.oracle(*_honest("fg-1", fact_id="f1", base_rows=bob_rows))
    with_f1 = {"rows": [*bob_rows, FORGED_ROW]}
    assert ctl.call(ctl.registry(oc, S.passing_verifier()), "idp", "query", **BOB) == with_f1, (
        "under a passing verdict the f1 row is served on bob's call: no host rule refuses it")
    _spent(oc)
    _only_oracle_row(ctl, attempts=1, served=with_f1)


def test_input_two_forged_rows_get_one_forged_id(tmp_path):
    """s_p070 — two different rows under one forged_id in a call, or a frozen forged_id reused for another fact's row, are refused; forged_id names one frozen row of one fact."""
    carol_fact = S.fact("f3", "carol ran a credential dumper on web-1 at 15:40Z",
                        ("carol", "web-1"))
    carol = S.query_params("user:carol")
    carol_row = {"user": "carol", "event_id": "e-9f03", "action": "dump", "host": "web-1",
                 "ts": "2026-07-28T15:40:00Z"}
    other = _forged(event_id="e-9f0d", action="tgs")
    sc = _scene(tmp_path, doc=_doc(S.fact("f1"), carol_fact),
                live=[("idp", "query", ALICE, BASE), ("idp", "query", carol, {"rows": []})])
    o = S.oracle(
        # call 1, attempt 1: two different rows under fg-1.
        S.forge("fg-1", "f1", "idp", FORGED_ROW), S.forge("fg-1", "f1", "idp", other),
        S.submit({"rows": [BASE_ROW, FORGED_ROW, other]}, S.claim(
            added=[S.added("fg-1", "f1"), S.added("fg-1", "f1")])),
        *_honest(),
        # call 2, attempt 1: the frozen fg-1 reused for carol's fact.
        S.forge("fg-1", "f3", "idp", carol_row),
        S.submit({"rows": [carol_row]}, S.claim(added=[S.added("fg-1", "f3")])),
        *_honest("fg-3", row=carol_row, base_rows=(), fact_id="f3"))
    reg = sc.registry(o)

    assert sc.call(reg, "idp", "query", **ALICE) == SERVED
    assert sc.call(reg, "idp", "query", **carol) == {"rows": [carol_row]}
    _spent(o)
    _assert_some_check(o, 1)
    _assert_some_check(o, 3)
    forged = sc.rows("forged")
    assert sorted((r["forged_id"], r["fact_id"]) for r in forged) == [
        ("fg-1", "f1"), ("fg-3", "f3")], forged
    assert _has_row(forged, forged_id="fg-1", row=FORGED_ROW), forged


def test_input_base_answer_is_a_scalar_or_a_count(tmp_path):
    scalar_q = S.query_params("count user:alice")
    grouped_q = S.query_params("count by host")
    big = 2 ** 53 + 1   # a float cannot hold it, nor big + 1
    grouped = {"counts": [{"host": "web-1", "count": big}]}
    sc = _scene(tmp_path, live=[("siem-x", "query", scalar_q, 0),
                                ("siem-x", "query", grouped_q, grouped)])

    def event(eid: str, host: str) -> dict:
        return {"user": "alice", "event_id": eid, "host": host, "ts": TS_FACT}

    grouped_served = {"counts": [{"host": "web-1", "count": big + 1},
                                 {"host": "db-1", "count": 1}]}
    o = S.oracle(
        S.forge("fg-1", "f1", "siem-x", event("s-9f01", "db-1")),
        S.submit(2, S.claim(added=[S.added("fg-1", "f1")], counts=[
            S.counted("*", base=0, added_=1, served=2)])),
        S.forge("fg-1", "f1", "siem-x", event("s-9f01", "db-1")),
        S.submit(1, S.claim(added=[S.added("fg-1", "f1")], counts=[
            S.counted("*", base=0, added_=1)])),
        S.forge("fg-2", "f1", "siem-x", event("s-9f02", "web-1")),
        S.forge("fg-3", "f1", "siem-x", event("s-9f03", "db-1")),
        S.submit(grouped_served, S.claim(
            added=[S.added("fg-2", "f1"), S.added("fg-3", "f1")],
            counts=[S.counted("web-1", base=big, added_=1), S.counted("db-1", base=0,
                                                                     added_=1)])))
    reg = sc.registry(o)

    assert sc.call(reg, "siem-x", "query", **scalar_q) == 1
    _assert_verdict(o, 1, "check 5")
    served = sc.call(reg, "siem-x", "query", **grouped_q)
    _spent(o)
    assert served == grouped_served
    assert served["counts"][0]["count"] == big + 1
    assert [r.get("attempts") for r in sc.ledger()] == [2, 1], sc.ledger()


def test_input_base_rows_are_heterogeneous(tmp_path):
    r1 = dict(BASE_ROW)
    r2 = {"user": "alice", "event_id": "e-101", "action": "vpn", "ts": TS_BASE,
          "src_ip": "10.0.0.9", "parent": None}
    base = {"rows": [r1, r2]}
    r2_shaped = {"user": "alice", "event_id": "e-9f01", "action": "vpn", "ts": TS_FACT,
                 "src_ip": "10.0.0.7", "parent": None}
    union = {**FORGED_ROW, "event_id": "e-9f0b", "src_ip": "10.0.0.7", "parent": None}
    sc = _scene(tmp_path, live=[("idp", "query", ALICE, base)])
    no_parent = {k: v for k, v in r2_shaped.items() if k != "parent"}
    o = S.oracle(*_honest("fg-p", row={**no_parent, "event_id": "e-9f0a"}, base_rows=(r1, r2)),
                 *_honest("fg-u", row=union, base_rows=(r1, r2)),
                 *_honest("fg-x", row={**r2_shaped, "event_id": "e-9f0c", "note": "x"},
                          base_rows=(r1, r2)),
                 *_honest(row=r2_shaped, base_rows=(r1, r2)))
    reg = sc.registry(o, retry_cap=5)

    assert sc.call(reg, "idp", "query", **ALICE) == {"rows": [r1, r2, r2_shaped]}
    for k in (1, 2, 3):
        _assert_verdict(o, k, "check 2")
    _spent(o)
    _only_oracle_row(sc, attempts=4, served={"rows": [r1, r2, r2_shaped]})


def test_input_forged_id_is_a_substring_of_a_real_id_or_contains_one(tmp_path):
    real = {**BASE_ROW, "event_id": "e-100200", "message": "logon ok"}
    sc = _scene(tmp_path, live=[("idp", "query", ALICE, {"rows": [real]})])
    rows = [_forged(event_id="e-100", message="tgt issued"),
            _forged(event_id="e-1002001", message="tgt issued"),
            _forged(event_id="e-9f01", message="saw e-100200 in /tmp/e-100200.log")]
    o = S.oracle(
        *_honest("fg-x", row=_forged(event_id="e-100200", message="tgt issued"),
                 base_rows=(real,)),
        *(S.forge(f"fg-{i}", "f1", "idp", row) for i, row in enumerate(rows)),
        S.submit({"rows": [real, *rows]},
                 S.claim(added=[S.added(f"fg-{i}", "f1") for i in range(len(rows))])))
    reg = sc.registry(o)

    assert sc.call(reg, "idp", "query", **ALICE) == {"rows": [real, *rows]}
    _assert_verdict(o, 1, "check 3")
    _spent(o)
    _only_oracle_row(sc, attempts=2, served={"rows": [real, *rows]})


_JUDGE_REPLY = S.as_reply_text(J.reply_doc(findings=[], bucket="none", systems=[]))


def _judged_in_place(ep: Path) -> None:
    """Make the registry-written episode `ep` (built on the default `S.family_v2()` manifest) a
    judged one IN PLACE: exactly what `S.judged_episode` adds to the episode it creates (every
    world's #921 archive, the samples and outcome records), plus an empty ledger for each world
    that has none — without re-creating the episode, so the ledgers and oracle-side stores the
    registry wrote stay as they are."""
    doc = S.family_v2()
    for world in doc["worlds"]:
        label = world["label"]
        S.archived_judge_world(ep, label,
                               disposition=world.get("disposition_declared", "malicious"))
        if not S.ledger_path(ep, label).is_file():
            S.write_ledger(ep, label, [])
        # Direct registry calls have no query-tool host to mint ids. Complete this synthetic
        # archive with the shared ledger fixture's ids and the matching query-table rows.
        ledger = S.ledger_rows(ep, label)
        for row in ledger:
            if row.get(J.CALL_ID) is None:
                row.pop(J.CALL_ID, None)
        S.write_ledger(ep, label, ledger)
        S.write_call_table(ep, label, S.ledger_rows(ep, label))
        if world.get("role") != "A":
            S.oracle_dir(ep, label).mkdir(parents=True, exist_ok=True)
    S.samples_record(ep, {system: {"verbs": {"query": [json.dumps({"rows": []})]}}
                          for system in doc.get("served_systems") or []})
    S.outcome_record(ep)


def _grade(ep: Path, judge: Any, where: Path) -> BaseException | None:
    """The real `grade_episode` over `ep`, with a learning-state root and runs base of its own.
    A failure AFTER the judge was asked is returned (the demand reads the prompts); one before
    it is raised."""
    try:
        J.grade_at(ep, judge=judge, git_show=J.FakeGitShow(),
                   state=state_over(where / "judge-state"), draws=1)
    except Exception as exc:  # noqa: BLE001 — re-raised unless the prompts were captured
        if not judge.prompts:
            raise
        return exc
    return None


def test_input_real_id_appears_in_family_data_after_the_forged_id_was_frozen(tmp_path):
    dave = {"user": "dave", "event_id": "e-9f01", "action": "logon", "host": "web-3",
            "ts": TS_BASE}
    dave_q = S.query_params("user:dave")
    sc = _scene(tmp_path, live=[("idp", "query", ALICE, BASE),
                                ("idp", "query", dave_q, {"rows": [dave]}),
                                ("idp", "query", BOB, {"rows": []}),
                                ("idp", "query", DB1, {"rows": []})])
    o = S.oracle(*_honest(),
                 S.run_query("idp", "query", dave_q), S.submit({"rows": []}, S.EMPTY_CLAIM),
                 S.submit({"rows": [FORGED_ROW]}, S.claim(added=[S.added("fg-1", "f1")])))
    reg = sc.registry(o)

    assert sc.call(reg, "idp", "query", **ALICE) == SERVED
    frozen = sc.rows("forged")
    assert sc.call(reg, "idp", "query", **BOB) == {"rows": []}
    assert [c for c in sc.est.calls("idp", "query") if c["params"] == dave_q], (
        "the colliding real row was read (positive control)")
    assert sc.call(reg, "idp", "query", **DB1) == {"rows": [FORGED_ROW]}, (
        "the frozen row is still reused after real data collided with its id")
    _spent(o)
    assert o.submissions() == 3, "no attempt failed on the frozen row's id"
    assert sc.rows("forged") == frozen, "the frozen row is not rewritten or dropped"
    assert all("dave" not in r["payload_text"] for r in sc.ledger()), (
        "the exploration's row reached the sibling's ledger (O9)")

    # The collision, recorded for the judge: grade THIS episode and read world b's prompt.
    _judged_in_place(sc.ep)
    judge = S.FakeJudge(default=_JUDGE_REPLY)
    _grade(sc.ep, judge, tmp_path)
    world_b = "\n".join(p for p, a in zip(judge.prompts, judge.agent_ids, strict=True)
                        if a.startswith(f"judge:{T.fixture_world_id('b')}:"))
    assert world_b, f"world b was never graded (agent ids: {judge.agent_ids})"
    assert S.ORACLE_DECISION in world_b, (
        "world b's ledger rows (two `oracle` rows) reached the judge (positive control, PCO-08)")
    assert "e-9f01" in world_b or "fg-1" in world_b, (
        "M12=A: world b's judge prompt names neither the frozen row's colliding id e-9f01 nor "
        "its forged_id fg-1: the collision was not recorded for the judge")
    assert "dave" in world_b, (
        "M12=A: the collision of the frozen row's id e-9f01 with this world's real row (dave's, "
        "read by the oracle's exploration) was not recorded for the judge: world b's judge "
        "prompt does not carry the colliding real row")


def test_1224_id_occurs_only_in_a_verifier_query_result_or_the_source_alert(tmp_path):
    src = _plant_alert(tmp_path)
    siem = {"entity": "alice", "risk": "low", "record_id": "r-0042"}
    sc = _scene(tmp_path, doc=_doc(), source_run_dir=src,
                live=[("idp", "query", ALICE, BASE), ("idp", "query", DB1, {"rows": []}),
                      ("siem-x", "lookup", SIEM_ALICE, siem)])
    o = S.oracle(*_honest(),
                 *_honest("fg-v", row=_forged(event_id="r-0042"), base_rows=()),
                 *_honest("fg-a", row=_forged(event_id="a-31337"), base_rows=()),
                 *_honest("fg-2", row=_forged(event_id="e-9f02"), base_rows=()))
    v = S.verifier(S.run_query("siem-x", "lookup", SIEM_ALICE), S.verdict(True),
                   then=S.verdict(True))
    reg = sc.registry(o, v, retry_cap=4)

    assert sc.call(reg, "idp", "query", **ALICE) == SERVED
    assert [c for c in sc.est.calls("siem-x", "lookup")], "the verifier's query ran (control)"
    assert sc.call(reg, "idp", "query", **DB1) == {"rows": [_forged(event_id="e-9f02")]}
    _spent(o)
    _assert_verdict(o, 2, "check 3")
    _assert_verdict(o, 3, "check 3")
    assert [r.get("attempts") for r in sc.ledger()] == [1, 3], sc.ledger()


def test_1224_forged_row_must_reuse_a_real_entitys_identifier(tmp_path):
    bob_row = {**SID_ROW, "user": "bob", "user_id": "S-1-5-21-2002", "event_id": "e-101"}
    base_rows = (SID_ROW, bob_row)
    sc = _scene(tmp_path, live=[("idp", "query", ALICE, {"rows": list(base_rows)})])
    bob_sid_row = {**_sid_row("e-9f0b"), "user_id": "S-1-5-21-2002"}
    o = S.oracle(
        *_sid_attempt("fg-u", "e-9f0a", base_rows=base_rows, declare=False),
        S.forge("fg-w", "f1", "idp", bob_sid_row),
        S.submit({"rows": [*base_rows, bob_sid_row]}, S.claim(
            added=[S.added("fg-w", "f1")],
            entity_refs=[S.entity_ref("fg-w", "user_id", "alice")])),
        *_sid_attempt("fg-1", "e-9f01", base_rows=base_rows))
    reg = sc.registry(o, retry_cap=4)

    served = {"rows": [*base_rows, _sid_row("e-9f01")]}
    assert sc.call(reg, "idp", "query", **ALICE) == served
    _assert_verdict(o, 1, "check 3")
    _assert_verdict(o, 2, "check 3")
    _spent(o)
    _only_oracle_row(sc, attempts=3, served=served)


def test_input_served_answer_differs_only_in_row_order_or_spacing(tmp_path):
    r1 = {"action": "logon", "host": "web-1"}
    r2 = {"action": "logoff", "host": "web-1"}
    base = {"rows": [r1, r2]}
    sc = _scene(tmp_path, live=[("idp", "query", ALICE, base)])
    o = S.oracle(S.submit({"rows": [r2, r1]}, S.EMPTY_CLAIM),
                 S.submit({"rows": [{"host": "web-1", "action": "logon"}, r2]}, S.EMPTY_CLAIM))
    reg = sc.registry(o)

    assert sc.call(reg, "idp", "query", **ALICE) == base
    _assert_verdict(o, 1, "check 1")
    _spent(o)
    ledger = sc.ledger()
    assert [(r["source"], _payload(r)) for r in ledger] == [(S.PASSTHROUGH, base)], ledger


def test_p040_served_answer_changes_a_value_to_a_textually_equal_value_of_another_type(tmp_path):
    """s_p111 — a value served as the same text but another JSON type, with no claimed change, is an unclaimed difference refused at check 1."""
    base = {"rows": [{**BASE_ROW, "port": 22}]}
    sc = _scene(tmp_path, live=[("idp", "query", ALICE, base)])
    o = S.oracle(S.submit({"rows": [{**BASE_ROW, "port": "22"}]}, S.EMPTY_CLAIM),
                 S.submit(base, S.EMPTY_CLAIM))
    reg = sc.registry(o)

    assert sc.call(reg, "idp", "query", **ALICE) == base
    _assert_verdict(o, 1, "check 1")
    _spent(o)
    assert [_payload(r) for r in sc.ledger()] == [base], sc.ledger()


def test_1224_claim_arithmetic_arrives_as_an_expression(tmp_path):
    count_q = S.query_params("count user:alice")
    canary = tmp_path / "evaluated-on-the-host"
    code = f"__import__('pathlib').Path({str(canary)!r}).write_text('ran')"
    sc = _scene(tmp_path, live=[("siem-x", "query", count_q, {"count": 1})])
    event = {"user": "alice", "event_id": "s-9f01", "host": "db-1", "ts": TS_FACT}

    def attempt(served_expr: Any) -> list[S.Move]:
        return [S.forge("fg-1", "f1", "siem-x", event),
                S.submit({"count": 2}, S.claim(added=[S.added("fg-1", "f1")], counts=[
                    {"group": "*", "base": 1, "added": 1, "removed": 0,
                     "served": served_expr}]))]

    o = S.oracle(*attempt("1+1"), *attempt(code), *attempt(2))
    reg = sc.registry(o, retry_cap=4)

    assert sc.call(reg, "siem-x", "query", **count_q) == {"count": 2}
    _spent(o)
    assert not canary.exists(), "the claim's text was evaluated on the host"
    for k in (1, 2):
        assert _after(o, SUBMIT, k).strip(), f"attempt {k}'s refusal reached the oracle"
    _only_oracle_row(sc, attempts=3, served={"count": 2})


class _StoreWitness(S.ScriptedModel):
    """A verifier double that also RECORDS the world's committed stores as they stand on disk
    at the moment it is consulted — after the attempt forged and recorded, before the verified
    answer is stored. It decides nothing; it reads `S.oracle_rows` and answers its script."""

    def __init__(self, ep: Path, *moves: S.Move, then: S.Move | None = None) -> None:
        super().__init__(*moves, then=then, name="verifier")
        self.ep = ep
        self.stores: list[dict[str, list[dict]]] = []

    def __call__(self, messages: list[Any], info: Any) -> Any:
        self.stores.append({name: S.oracle_rows(self.ep, "b", name)
                            for name in ("forged", "facts", "answers")})
        return super().__call__(messages, info)


def test_sibling_dies_after_forging_a_row_before_storing_the_served_answer(tmp_path):
    sc = _scene(tmp_path, doc=_doc(DEPT_FACT), live=[("idp", "query", ALICE, BASE)])
    o1 = S.oracle(S.record_fact("alice", "department", "finance"), *_honest())
    witness = _StoreWitness(sc.ep, then=S.verdict(True))
    assert sc.call(sc.registry(o1, witness), "idp", "query", **ALICE) == SERVED
    _spent(o1)
    assert witness.stores == [{"forged": [], "facts": [], "answers": []}], (
        f"rows were frozen before the verified answer was stored: {witness.stores}")
    committed = {name: sc.rows(name) for name in ("forged", "facts", "answers")}
    assert len(committed["forged"]) == 1, committed
    assert len(committed["answers"]) == 1, committed
    assert _has_row(committed["facts"], entity="alice", value="finance"), committed

    # Resumed: a fresh registry and oracle; the same call is served what was stored.
    o2 = S.oracle()
    again = sc.call(sc.registry(o2), "idp", "query", **ALICE)
    assert again == SERVED
    assert o2.requests == 0, "a stored answer is served without a turn"
    assert sc.rows("forged") == committed["forged"], "the fact's row is never duplicated"
    ledger = sc.ledger()
    assert [r["payload_text"] for r in ledger] == [ledger[0]["payload_text"]] * 2, ledger


def test_failed_attempt_forged_rows_and_facts_when_the_next_attempt_differs(tmp_path):
    siem = {"entity": "alice", "risk": "low", "record_id": "r-0001", "department": "sales"}
    sc = _scene(tmp_path, doc=_doc(DEPT_FACT),
                live=[("idp", "query", ALICE, BASE), ("idp", "query", DB1, {"rows": []}),
                      ("siem-x", "lookup", SIEM_ALICE, siem)])
    edited = {**BASE_ROW, "host": "db-9"}
    o = S.oracle(
        S.record_fact("alice", "department", "finance"),
        S.forge("fg-1", "f1", "idp", FORGED_ROW),
        S.submit({"rows": [edited, FORGED_ROW]}, S.claim(added=[S.added("fg-1", "f1")])),
        S.submit(BASE, S.EMPTY_CLAIM),
        # later calls: neither the uncommitted fg-1 nor the uncommitted record binds them.
        *_honest(row=_forged(action="tgs"), base_rows=()),
        S.submit(siem, S.EMPTY_CLAIM))
    reg = sc.registry(o)

    assert sc.call(reg, "idp", "query", **ALICE) == BASE
    _assert_verdict(o, 1, "check 1")
    assert sc.rows("forged") == [], "the failed attempt's row was committed"
    assert sc.rows("facts") == [], "the failed attempt's record was committed"
    assert sc.call(reg, "idp", "query", **DB1) == {"rows": [_forged(action="tgs")]}
    assert sc.call(reg, "siem-x", "lookup", **SIEM_ALICE) == siem
    _spent(o)
    assert o.submissions() == 4, "neither later call failed against the failed attempt's state"
    assert all("db-9" not in r["payload_text"] for r in sc.ledger()), sc.ledger()


def test_1224_sibling_reissues_an_original_call_after_recording_a_conflicting_value(tmp_path):
    original = {"entity": "alice", "risk": "low", "record_id": "r-0001", "department": "sales"}
    sc = _scene(tmp_path, doc=_doc(DEPT_FACT),
                recorded=[("siem-x", "lookup", SIEM_ALICE, original)],
                live=[("idp", "query", ALICE, BASE)])
    held = {**original, "department": "finance"}
    o = S.oracle(S.record_fact("alice", "department", "finance"), *_honest(),
                 S.submit(original, S.EMPTY_CLAIM),
                 S.submit(held, S.claim(changed=[
                     S.changed("alice", "department", "sales", "finance")])))
    reg = sc.registry(o)

    assert sc.call(reg, "idp", "query", **ALICE) == SERVED
    assert sc.call(reg, "siem-x", "lookup", **SIEM_ALICE) == held
    _assert_verdict(o, 2, "check 4")
    _spent(o)
    assert sc.est.calls("siem-x") == [], "the original call's base came from the recording"


def test_1224_collision_check_while_the_tenant_system_is_unreachable(tmp_path):
    sc = _scene(tmp_path, recorded=[("idp", "query", ALICE, BASE)])
    for system in S.SYSTEMS:
        for verb in S.READ_VERBS:
            sc.est.fail(system, verb, None, fault="TransportFault", detail="connection refused")
    o = S.oracle(*_honest("fg-x", row=_forged(event_id="e-100")), *_honest())
    reg = sc.registry(o)

    assert sc.call(reg, "idp", "query", **ALICE) == SERVED
    _assert_verdict(o, 1, "check 3")
    assert sc.est.calls() == [], "no tenant query was sent for the check"
    _only_oracle_row(sc, attempts=2, served=SERVED)

    with pytest.raises(faults.TransportFault):
        sc.call(reg, "edr", "query", **DB1)
    assert len(sc.est.calls("edr", "query")) == 1, "the outage is real (positive control)"
    _spent(o)
