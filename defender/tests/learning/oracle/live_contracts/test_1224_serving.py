from __future__ import annotations

import concurrent.futures
import json
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.configuration._env import FatalConfigError  # noqa: E402
from defender._io import read_jsonl_rows  # noqa: E402
from defender.integrations import faults  # noqa: E402
from defender.tests.learning.oracle.live_contracts import _spec1224 as S  # noqa: E402


ALICE = S.query_params("user:alice")
BOB = S.query_params("user:bob")
DB1 = S.query_params("host:db-1")
WEB1 = S.query_params("host:web-1")
SIEM_ALICE = {"entity": "alice"}

ALICE_ROW = {"action": "logon", "event_id": "e-100", "user": "alice"}
BASE_ALICE = {"rows": [ALICE_ROW]}
#: Fact f1's telemetry: the base rows' own columns (check 2) and an id no real answer holds
#: (check 3).
FORGED = {"action": "tgt-issued", "event_id": "e-9001", "user": "alice"}
SERVED_ALICE = {"rows": [ALICE_ROW, FORGED]}
CLAIM_ALICE = S.claim(added=[S.added("fg-1", "f1")])
#: A submission that adds a row its claim does not declare — O3's own example of a bad answer.
UNDECLARED = {"rows": [ALICE_ROW, {"action": "logon", "event_id": "e-7777", "user": "alice"}]}

BOB_BASE = {"rows": [{"action": "logon", "event_id": "e-200", "user": "bob"}]}
EDR_BASE = {"events": [{"event_id": "x-7", "host": "db-1", "process": "sshd",
                        "ts": "2026-07-28T15:10:00Z"}]}
SIEM_BASE = {"entity": "alice", "record_id": "r-0001", "risk": "low"}

TOKEN_B = S.fixture_world_id("b")


def _text(payload: Any) -> str:
    """A payload's canonical bytes — the spelling the world ledger and the base recording use."""
    return json.dumps(payload, sort_keys=True, default=str)


def _forged_moves(fid: str = "fg-1", fact_id: str = "f1", *, system: str = "idp",
                  row: dict | None = None, served: Any = None) -> list:
    """One oracle turn that forges fact telemetry and submits the base plus that row."""
    row = FORGED if row is None else row  # lint-default: ok — a test builder's fresh per-call double or fixture, never a shared instance
    served = SERVED_ALICE if served is None else served  # lint-default: ok — a test builder's fresh per-call double or fixture, never a shared instance
    return [S.forge(fid, fact_id, system, row),
            S.submit(served, S.claim(added=[S.added(fid, fact_id)]))]


def _episode(tmp_path: Path, *, doc: dict | None = None,
             captured: list[tuple[str, str, dict, Any]] | None = None) -> Path:
    """A v2 episode whose base recording holds `captured` (default: the idp alice call)."""
    rows = [("idp", "query", ALICE, BASE_ALICE)] if captured is None else captured
    return S.episode_v2(tmp_path, doc=doc, base_rows=[S.captured(*c) for c in rows])


def _decisions(ep: Path, label: str = "b") -> list[str]:
    return [row.get("source") for row in S.ledger_rows(ep, label)]


def _asked(row: dict) -> Any:
    asked = row.get("asked_params")
    return asked if isinstance(asked, dict) else row.get("params")


def _rows_for(ep: Path, label: str, system: str, verb: str, params: dict) -> list[dict]:
    """The world-ledger rows for one investigator call (read raw off disk)."""
    return [r for r in S.ledger_rows(ep, label)
            if (r.get("system"), r.get("verb")) == (system, verb) and _asked(r) == params]


def _complete_rows(path: Path) -> list[dict]:
    """Every line of a JSONL store that parses; a torn line is skipped, never repaired."""
    path = Path(path)
    if not path.is_file():
        return []
    out = []
    for line in path.read_bytes().split(b"\n"):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            out.append(row)
    return out


def _stored(ep: Path, label: str, system: str, verb: str, params: dict) -> list[dict]:
    """The world's served-answer cache rows for one call (`answers.jsonl`, read raw)."""
    return [r for r in _complete_rows(S.oracle_dir(ep, label) / "answers.jsonl")
            if (r.get("system"), r.get("verb")) == (system, verb) and r.get("params") == params]


def _mentions(rows: list[dict], needle: str) -> bool:
    return any(needle in json.dumps(r, sort_keys=True) for r in rows)


RUN_ID = "run-1224"


def _evidence(run_dir: Path) -> list[dict]:
    """The lead's rows in the run's queries table (the investigator's evidence)."""
    return [r for r in read_jsonl_rows(Path(run_dir) / "executed_queries.jsonl")
            if r.get("lead_id") == S.LEAD]


def _evidence_payload(run_dir: Path, row: dict) -> str:
    rel = row.get("payload_path")
    return (Path(run_dir) / rel).read_text(encoding="utf-8") if rel else ""


#: The columns of an evidence row that say what the investigator was handed (the rest — seq,
#: payload path — are allocation, not content).
_ROW_VIEW = ("system", "verb", "query_id", "params", "exit_code", "error_class",
             "payload_status", "payload_digest", "payload_sha256")


def _row_view(row: dict) -> dict:
    return {k: row.get(k) for k in _ROW_VIEW}


def _breaker(state: Any) -> dict:
    """The run's circuit-breaker state, read off the run's one `RunState` (#1235: never a file
    in the run dir)."""
    return state.breaker_snapshot()


def _parallel_turn(*calls: tuple[str, str, dict]) -> Any:
    """One gather turn issuing several `query` calls at once (they run on worker threads)."""
    H = S.replay_harness()
    return H.Turn(tool_calls=[("query", {"system": s, "verb": v, "params": dict(p)})
                              for s, v, p in calls])


class _CallRouted:
    """An oracle double answering each request with the scripted double of the CALL the request
    is about (R-01), told apart by a marker in that call's params. The oracle's context runs
    stable to volatile (design: static instructions, family block, world block, then the
    per-call turns), so the call a request is about is the one whose marker occurs LAST in the
    request's inbound text — whether each call opens a fresh conversation or extends the
    sibling's one. Markers must not contain one another."""

    __name__ = "CallRouted"

    def __init__(self, routes: Mapping[str, S.ScriptedModel]) -> None:
        self.routes = dict(routes)
        self.unrouted: list[str] = []
        self._lock = threading.Lock()
        self._model: Any = None

    @property
    def model(self) -> Any:
        if self._model is None:
            from pydantic_ai.models.function import FunctionModel
            self._model = FunctionModel(self, model_name=S.double_model_name("oracle"))
        return self._model

    @property
    def requests(self) -> int:
        return sum(d.requests for d in self.routes.values()) + len(self.unrouted)

    def __call__(self, messages: list[Any], info: Any) -> Any:
        text = S._messages_text(messages)
        last = {marker: text.rfind(marker) for marker in self.routes}
        marker = max(last, key=last.__getitem__)
        if last[marker] >= 0:
            return self.routes[marker](messages, info)
        with self._lock:
            self.unrouted.append(text)
        from pydantic_ai.messages import ModelResponse, TextPart
        return ModelResponse(parts=[TextPart(content="(no scripted double for this request)")])


def _run_alone(fn: Any, *, timeout: float) -> tuple[bool, Any, BaseException | None]:
    """Run `fn` on a thread; `(finished, result, raised)` — `finished` False means it hung."""
    box: dict[str, Any] = {}

    def target() -> None:
        try:
            box["result"] = fn()
        except BaseException as e:  # noqa: BLE001 — handed back to the asserting thread whole
            box["raised"] = e

    worker = threading.Thread(target=target, daemon=True)
    worker.start()
    worker.join(timeout)
    return (not worker.is_alive()), box.get("result"), box.get("raised")


# --- a tenant that also serves a ticket store (the query tool's self-reference screen) -------

_TICKET_ADAPTER = '''\
"""Stub ticket store for the #1224 serving suite: the query tool screens `list-tickets`."""
from __future__ import annotations

import json
import time
from pathlib import Path

from defender.runtime.verbs import VerbContext, verb

_STATE = Path({state!r})
SYSTEM = "ticket"


def check_settings(*_a, **_k):
    """A fixture store needs no settings (#1256 O-5: every adapter declares its check)."""
    return None


def _answer(ctx: VerbContext, name: str, params: dict):
    as_of = getattr(ctx, "as_of", None)
    row = {{"system": SYSTEM, "verb": name, "params": params,
           "as_of": None if as_of is None else as_of.isoformat(),
           "world_id": getattr(ctx, "world_id", None),
           "run_dir": str(getattr(ctx, "run_dir", "")), "t": time.time()}}
    with (_STATE / "calls.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, sort_keys=True) + "\\n")
    table = json.loads((_STATE / "answers.json").read_text(encoding="utf-8"))
    key = SYSTEM + "|" + name + "|" + json.dumps(params, sort_keys=True, separators=(",", ":"))
    entry = table.get(key)
    if entry is None:
        return {{"tickets": [], "total": 0}}
    return entry["payload"]


@verb()
def list_tickets(ctx: VerbContext, *, q: str = "*") -> dict:
    return _answer(ctx, "list-tickets", {{"q": q}})


VERBS = {{"list-tickets": list_tickets}}
'''


@dataclass
class _TicketEstate(S.Estate):
    """The fixture estate plus a `ticket` store whose `list-tickets` the gather grant reads."""

    def __post_init__(self) -> None:
        super().__post_init__()
        (self.adapters / "ticket_adapter.py").write_text(
            _TICKET_ADAPTER.format(state=str(self.state)), encoding="utf-8")

    def table(self) -> str:
        return super().table() + "  ticket:\n    list-tickets: {roles: [gather]}\n"


TICKETS = {"q": "*"}
SELF_TICKET = {"key": RUN_ID, "status": "open", "summary": "this investigation's own case"}
OTHER_TICKET = {"key": "INC-7", "status": "closed", "summary": "an older logon case"}
TICKETS_BASE = {"tickets": [SELF_TICKET, OTHER_TICKET], "total": 2}


def _ticket_episode(tmp_path: Path) -> Path:
    doc = S.family_v2(served_systems=(*S.SYSTEMS, "ticket"))
    return _episode(tmp_path, doc=doc, captured=[])


def _ticket_drive(tmp_path: Path, est: S.Estate, verbs: Any) -> tuple[Path, Any]:
    return S.drive_gather(tmp_path, verbs=verbs, tenant=est.place(), system="ticket",
                          run_id=RUN_ID, gather_turns=[
                              S.query_turn("ticket", "list-tickets", TICKETS), S.done_turn()])


def test_1224_served_verb_returns_the_verified_answer_and_rows_it(tmp_path):
    """a verified oracle answer is returned to the caller and rowed `oracle`; a submission equal to the base returns the base's canonical bytes, rowed …"""
    est = S.estate(tmp_path)
    ep = _episode(tmp_path, captured=[("idp", "query", ALICE, BASE_ALICE),
                                      ("siem-x", "lookup", SIEM_ALICE, SIEM_BASE)])
    oracle = S.oracle(*_forged_moves(), S.submit(SIEM_BASE, S.EMPTY_CLAIM))
    verifier = S.passing_verifier()
    reg = S.sandboxed_registry(ep, "b", est, oracle=oracle, verifier=verifier)
    ctx = est.ctx(tmp_path / "run")

    served = S.call(reg, "idp", "query", ctx, **ALICE)
    rows = S.ledger_rows(ep, "b")
    assert served == SERVED_ALICE, "the verified served answer is what the caller gets"
    assert [r["source"] for r in rows] == [S.ORACLE_DECISION]
    assert json.loads(rows[0]["payload_text"]) == SERVED_ALICE

    unchanged = S.call(reg, "siem-x", "lookup", ctx, **SIEM_ALICE)
    rows = S.ledger_rows(ep, "b")
    assert _text(unchanged) == S.captured("siem-x", "lookup", SIEM_ALICE,
                                          SIEM_BASE)["payload_text"], (
        "a base-equal submission must hand back the base answer's canonical bytes")
    assert [r["source"] for r in rows] == [S.ORACLE_DECISION, S.PASSTHROUGH]
    assert rows[1]["payload_text"] == _text(SIEM_BASE)
    assert verifier.requests >= 2, "both calls went through a verifier pass (M01=A)"
    assert not oracle.overrun


def test_1224_real_system_error_reraises_unchanged_without_an_oracle_turn(tmp_path):
    """a real-system error on the original query re-raises unchanged, costs no oracle or verifier turn, reads the adapter once and leaves one `real-error` …"""
    est = S.estate(tmp_path)
    ep = _episode(tmp_path)
    detail = "idp: directory shard 3 unavailable"
    est.fail("idp", "query", BOB, fault="UpstreamFault", detail=detail)  # GA-40: a real AdapterFault
    oracle, verifier = S.oracle(*_forged_moves()), S.passing_verifier()
    reg = S.sandboxed_registry(ep, "b", est, oracle=oracle, verifier=verifier)
    ctx = est.ctx(tmp_path / "run")

    with pytest.raises(faults.UpstreamFault) as raised:
        S.call(reg, "idp", "query", ctx, **BOB)
    assert type(raised.value) is faults.UpstreamFault
    assert str(raised.value) == str(faults.UpstreamFault(detail))
    assert oracle.requests == 0
    assert verifier.requests == 0
    assert len(est.calls("idp", "query")) == 1
    rows = S.ledger_rows(ep, "b")
    assert [r["source"] for r in rows] == [S.REAL_ERROR]
    assert (rows[0]["system"], rows[0]["verb"], _asked(rows[0])) == ("idp", "query", BOB)

    # Positive control: the oracle seam is wired — a call that answers does get a turn.
    assert S.call(reg, "idp", "query", ctx, **ALICE) == SERVED_ALICE
    assert oracle.requests >= 1
    assert verifier.requests >= 1


@pytest.mark.parametrize("failing", ["host-check", "verifier"])
def test_1224_n_failed_attempts_raise_oracle_unservable(tmp_path, failing):
    """with a retry cap of N, an oracle failing every attempt is consulted exactly N times for the call and the served verb raises `OracleUnservable`; …"""
    est = S.estate(tmp_path)
    ep = _episode(tmp_path, captured=[("idp", "query", ALICE, BASE_ALICE),
                                      ("siem-x", "lookup", SIEM_ALICE, SIEM_BASE)])
    if failing == "host-check":
        oracle = S.oracle(S.submit(SIEM_BASE, S.EMPTY_CLAIM),
                          then=S.submit(UNDECLARED, S.EMPTY_CLAIM))
        verifier = S.passing_verifier()
    else:
        oracle = S.oracle(S.submit(SIEM_BASE, S.EMPTY_CLAIM),
                          then=S.submit(BASE_ALICE, S.EMPTY_CLAIM))
        verifier = S.verifier(S.verdict(True),
                              then=S.verdict(False, "fact f1's TGT for alice is missing"))
    reg = S.sandboxed_registry(ep, "b", est, oracle=oracle, verifier=verifier, retry_cap=3)
    ctx = est.ctx(tmp_path / "run")

    # Positive control: the cache and the ledger do record a call that is served.
    S.call(reg, "siem-x", "lookup", ctx, **SIEM_ALICE)
    assert len(_stored(ep, "b", "siem-x", "lookup", SIEM_ALICE)) == 1
    assert len(S.ledger_rows(ep, "b")) == 1

    with pytest.raises(S.unservable_cls()) as raised:
        S.call(reg, "idp", "query", ctx, **ALICE)
    assert oracle.submissions() - 1 == 3, "consulted exactly N times for the failing call"
    if failing == "verifier":
        assert verifier.requests - 1 == 3
    assert isinstance(raised.value.reason, str)
    assert raised.value.reason
    system, verb, params = raised.value.call
    assert (system, verb, dict(params)) == ("idp", "query", ALICE)
    assert _stored(ep, "b", "idp", "query", ALICE) == []
    assert _rows_for(ep, "b", "idp", "query", ALICE) == []
    assert len(S.ledger_rows(ep, "b")) == 1


def test_1224_same_call_same_world_returns_identical_bytes_from_the_cache(tmp_path):
    """the same call twice in one world returns byte-identical answers, and the repeat costs no oracle turn, no verifier pass and no base query."""
    est = S.estate(tmp_path)
    ep = _episode(tmp_path, captured=[])
    est.answer("idp", "query", ALICE, BASE_ALICE)
    oracle, verifier = S.oracle(*_forged_moves()), S.passing_verifier()
    reg = S.sandboxed_registry(ep, "b", est, oracle=oracle, verifier=verifier)
    ctx = est.ctx(tmp_path / "run")

    first = S.call(reg, "idp", "query", ctx, **ALICE)
    turns, checks, reads = oracle.requests, verifier.requests, len(est.calls("idp", "query"))
    assert turns >= 1
    assert checks >= 1
    assert reads == 1, "the first call was a real served call"

    second = S.call(reg, "idp", "query", ctx, **ALICE)
    assert _text(second) == _text(first)
    assert second == first
    assert (oracle.requests, verifier.requests) == (turns, checks)
    assert len(est.calls("idp", "query")) == reads
    rows = S.ledger_rows(ep, "b")
    assert len(rows) == 2
    assert rows[0]["payload_text"] == rows[1]["payload_text"]


def test_1224_oracle_row_carries_call_digest_answer_claim_verdict_and_attempts(tmp_path):
    """the `oracle` row carries the call, the base answer's digest, the served answer, the submitted claim, the verifier's verdict and the attempt count."""
    est = S.estate(tmp_path)
    ep = _episode(tmp_path)
    est.answer("idp", "query", BOB, BOB_BASE)
    reason = "fact f1's TGT for alice at 15:22Z is present and plausible"
    forged_bob = {"action": "tgt-issued", "event_id": "e-9002", "user": "bob"}
    oracle = S.oracle(S.submit(UNDECLARED, S.EMPTY_CLAIM), *_forged_moves(),
                      *_forged_moves("fg-2", row=forged_bob,
                                     served={"rows": [*BOB_BASE["rows"], forged_bob]}))
    verifier = S.verifier(S.verdict(True, reason), then=S.verdict(True))
    reg = S.sandboxed_registry(ep, "b", est, oracle=oracle, verifier=verifier)

    S.call(reg, "idp", "query", est.ctx(tmp_path / "run"), **ALICE)
    rows = S.ledger_rows(ep, "b")
    assert len(rows) == 1
    row = rows[0]
    assert row["source"] == S.ORACLE_DECISION
    assert (row["system"], row["verb"], _asked(row)) == ("idp", "query", ALICE)
    assert json.loads(row["payload_text"]) == SERVED_ALICE
    assert {"forged_id": "fg-1", "fact_id": "f1"} in row["claim"]["added"]
    assert reason in json.dumps(row["verifier_verdict"])
    assert row["attempts"] == 2, "one failed check-1 attempt, then the verified one"

    # `base_digest` (R-11, no algorithm): present, equal over the same base answer, different
    # over a different one.
    digest = row.get("base_digest")
    assert digest not in (None, "", [], {}), f"the oracle row carries no base digest: {row}"
    forged_c = {"action": "password-reset", "event_id": "e-9101", "user": "bob"}
    world_c = S.sandboxed_registry(ep, "c", est, verifier=S.passing_verifier(), oracle=S.oracle(
        *_forged_moves("fg-c1", "f2", row=forged_c, served={"rows": [ALICE_ROW, forged_c]})))
    S.call(world_c, "idp", "query", est.ctx(tmp_path / "run-c"), **ALICE)
    rows_c = _rows_for(ep, "c", "idp", "query", ALICE)
    assert [r["source"] for r in rows_c] == [S.ORACLE_DECISION]
    assert rows_c[0].get("base_digest") == digest, (
        "two oracle rows over the same base answer carry different base digests")
    S.call(reg, "idp", "query", est.ctx(tmp_path / "run"), **BOB)
    rows_bob = _rows_for(ep, "b", "idp", "query", BOB)
    assert [r["source"] for r in rows_bob] == [S.ORACLE_DECISION]
    assert rows_bob[0].get("base_digest") not in (None, "", [], {})
    assert rows_bob[0].get("base_digest") != digest, (
        "an oracle row over a different base answer carries the same base digest")
    assert not oracle.overrun


def test_1224_world_with_no_facts_serves_base_with_no_oracle_turn(tmp_path):
    """a world whose facts list is empty serves every call's base unchanged with no oracle or verifier turn, each row `passthrough`."""
    est = S.estate(tmp_path)
    ep = _episode(tmp_path)
    est.answer("idp", "query", BOB, BOB_BASE)
    control_oracle = S.oracle(S.submit(BOB_BASE, S.EMPTY_CLAIM))
    control = S.sandboxed_registry(ep, "a", est, oracle=control_oracle,
                                   verifier=S.passing_verifier())
    ctx = est.ctx(tmp_path / "run")

    captured_call = S.call(control, "idp", "query", ctx, **ALICE)
    assert _text(captured_call) == _text(BASE_ALICE)
    assert control_oracle.requests == 0, "a recorded answer cost the control world an oracle turn"
    live_call = S.call(control, "idp", "query", ctx, **BOB)
    assert _text(live_call) == _text(BOB_BASE)
    assert control_oracle.requests >= 1, (
        "the control world served a question the source never asked as a raw live read (D3)")
    assert "user:bob" in control_oracle.all_seen(), "the oracle was not handed the live call"
    assert _decisions(ep, "a") == [S.PASSTHROUGH, S.PASSTHROUGH]
    assert not control_oracle.overrun

    # Positive control: a world with facts takes a turn for the recorded call too.
    oracle, verifier = S.oracle(*_forged_moves()), S.passing_verifier()
    fact_world = S.sandboxed_registry(ep, "b", est, oracle=oracle, verifier=verifier)
    assert S.call(fact_world, "idp", "query", ctx, **ALICE) == SERVED_ALICE
    assert oracle.requests >= 1
    assert verifier.requests >= 1


def test_1224_unchanged_answer_in_a_fact_world_still_passes_the_verifier(tmp_path):
    """in a world with facts an unchanged submission is still put to the verifier and recorded `passthrough` only once it passes; a failing verdict sends …"""
    est = S.estate(tmp_path)
    ep = _episode(tmp_path)
    oracle = S.oracle(S.submit(BASE_ALICE, S.EMPTY_CLAIM), S.submit(BASE_ALICE, S.EMPTY_CLAIM))
    verifier = S.verifier(S.verdict(False, "fact f1's TGT logon should show in this window"),
                          S.verdict(True))
    reg = S.sandboxed_registry(ep, "b", est, oracle=oracle, verifier=verifier)

    served = S.call(reg, "idp", "query", est.ctx(tmp_path / "run"), **ALICE)
    assert _text(served) == _text(BASE_ALICE)
    assert verifier.requests == 2
    assert oracle.submissions() == 2
    assert S.verdict_names(oracle.seen[1], "verifier"), (
        "the failing verdict reached the oracle's next request")
    assert _decisions(ep, "b") == [S.PASSTHROUGH]
    assert not oracle.overrun


def test_1224_served_answer_is_recorded_and_screened_as_real_data(tmp_path):
    """an oracle-served answer reaches the investigator through the query tool as one exit-0 evidence row carrying the served payload, with the ticket …"""
    est = _TicketEstate(tmp_path / "estate")
    est.answer("ticket", "list-tickets", TICKETS, TICKETS_BASE)
    forged = {"key": "INC-9001", "status": "open", "summary": "alice TGT anomaly on db-1"}
    served = {"tickets": [SELF_TICKET, OTHER_TICKET, forged], "total": 3}
    claim = S.claim(added=[S.added("fg-t1", "f1")], counts=[S.counted("total", base=2, added_=1)])
    ep = _ticket_episode(tmp_path)
    oracle = S.oracle(S.forge("fg-t1", "f1", "ticket", forged), S.submit(served, claim))
    reg = S.sandboxed_registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier())

    run_dir, _gather = _ticket_drive(tmp_path / "branch", est, reg)
    rows = _evidence(run_dir)
    assert len(rows) == 1
    assert rows[0]["exit_code"] == 0
    shown = json.loads(_evidence_payload(run_dir, rows[0]))
    assert [t["key"] for t in shown["tickets"]] == [RUN_ID, "INC-7", "INC-9001"], (
        "the served (forged) ticket reaches the investigator whole, as a real answer would")
    assert shown["total"] == 3
    assert _decisions(ep, "b") == [S.ORACLE_DECISION]


def test_1224_two_worlds_asking_one_call_get_their_own_served_answers(tmp_path):
    """worlds b and c asking one call each get their own oracle turn and their own cached served answer; neither cache returns the other's."""
    est = S.estate(tmp_path)
    ep = _episode(tmp_path)
    forged_c = {"action": "password-reset", "event_id": "e-9002", "user": "alice"}
    served_c = {"rows": [ALICE_ROW, forged_c]}
    oracle_b = S.oracle(*_forged_moves())
    oracle_c = S.oracle(*_forged_moves("fg-c1", "f2", row=forged_c, served=served_c))
    reg_b = S.sandboxed_registry(ep, "b", est, oracle=oracle_b, verifier=S.passing_verifier())
    reg_c = S.sandboxed_registry(ep, "c", est, oracle=oracle_c, verifier=S.passing_verifier())
    ctx_b, ctx_c = est.ctx(tmp_path / "run-b"), est.ctx(tmp_path / "run-c")

    got_b = S.call(reg_b, "idp", "query", ctx_b, **ALICE)
    got_c = S.call(reg_c, "idp", "query", ctx_c, **ALICE)
    assert oracle_b.requests >= 1
    assert oracle_c.requests >= 1
    assert got_b == SERVED_ALICE
    assert got_c == served_c
    assert S.call(reg_b, "idp", "query", ctx_b, **ALICE) == SERVED_ALICE
    assert S.call(reg_c, "idp", "query", ctx_c, **ALICE) == served_c
    assert [json.loads(r["payload_text"]) for r in S.ledger_rows(ep, "b")] == [SERVED_ALICE] * 2
    assert [json.loads(r["payload_text"]) for r in S.ledger_rows(ep, "c")] == [served_c] * 2
    assert not _mentions(_complete_rows(S.oracle_dir(ep, "b") / "answers.jsonl"), "e-9002")
    assert not _mentions(_complete_rows(S.oracle_dir(ep, "c") / "answers.jsonl"), "e-9001")


def test_1224_fact_names_an_entity_no_real_answer_contains(tmp_path):
    """an invented entity named by a fact reads the same on every served system that knows it: each system's call gets an oracle turn and a verifier pass, …"""
    est = S.estate(tmp_path)
    ep = _episode(tmp_path, captured=[])
    ghost = {"entity": "ghost-7"}
    est.answer("idp", "lookup", ghost, {"entity": "ghost-7", "found": False})
    est.answer("edr", "lookup", ghost, {"entity": "ghost-7", "found": False})
    exists = {"entity": "ghost-7", "found": True}
    found = S.claim(changed=[S.changed("ghost-7", "found", False, True)])
    oracle = S.oracle(
        S.record_fact("ghost-7", "found", True), S.submit(exists, found),       # idp
        S.submit({"entity": "ghost-7", "found": "no"},                          # edr, attempt 1
                 S.claim(changed=[S.changed("ghost-7", "found", False, "no")])),
        S.submit(exists, found))                                                # edr, attempt 2
    verifier = S.passing_verifier()
    reg = S.sandboxed_registry(ep, "b", est, oracle=oracle, verifier=verifier)
    ctx = est.ctx(tmp_path / "run")

    on_idp = S.call(reg, "idp", "lookup", ctx, **ghost)
    on_edr = S.call(reg, "edr", "lookup", ctx, **ghost)
    assert on_idp == exists
    assert on_edr == exists, "the entity reads the same on both systems"
    assert S.verdict_names(oracle.seen[-1], "check 4"), (
        "the contradicting submission was refused by check 4 and the refusal fed back")
    recorded = [r for r in S.oracle_rows(ep, "b", "facts")
                if (r.get("entity"), r.get("field")) == ("ghost-7", "found")]
    assert [r.get("value") for r in recorded] == [True]
    assert _decisions(ep, "b") == [S.ORACLE_DECISION, S.ORACLE_DECISION]
    assert verifier.requests >= 2
    assert not oracle.overrun


def test_p098_real_error_on_a_call_the_worlds_facts_cover(tmp_path):
    """a real error on a call the world's facts cover passes through the query tool unchanged, exactly as on a real run (same evidence row, same …"""
    est = S.estate(tmp_path)
    est.fail("idp", "query", ALICE, fault="TransportFault", detail="idp: connection reset by peer")
    est.answer("idp", "query", BOB, BOB_BASE)

    def turns() -> list:
        return [S.query_turn("idp", "query", ALICE), S.query_turn("idp", "query", BOB),
                S.done_turn()]

    real_dir, _, real_state = S.drive_gather_run(tmp_path / "real", verbs=S.plain_registry(est),
                                                 tenant=est.place(), gather_turns=turns())
    ep = _episode(tmp_path / "branch", captured=[])
    oracle = S.oracle(S.submit(BOB_BASE, S.EMPTY_CLAIM))
    reg = S.sandboxed_registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier())
    branch_dir, _, branch_state = S.drive_gather_run(tmp_path / "branch", verbs=reg,
                                                     tenant=est.place(), gather_turns=turns())

    real_rows, branch_rows = _evidence(real_dir), _evidence(branch_dir)
    assert len(branch_rows) == len(real_rows) == 2
    assert _row_view(branch_rows[0]) == _row_view(real_rows[0])
    assert branch_rows[0]["exit_code"] != 0
    assert _breaker(branch_state).get("systems", {}).get("idp", {}).get("failures") == 1
    assert _breaker(branch_state).get("systems") == _breaker(real_state).get("systems")
    assert "user:alice" not in oracle.all_seen(), "the oracle was never asked about the error"
    assert "user:bob" in oracle.all_seen(), "positive control: the answering call got a turn"
    assert _decisions(ep, "b") == [S.REAL_ERROR, S.PASSTHROUGH]
    assert _stored(ep, "b", "idp", "query", ALICE) == []
    assert S.oracle_rows(ep, "b", "forged") == []


def test_input_same_call_with_params_in_a_different_key_order(tmp_path):
    """a re-issued call with its params in another key order is the same call (same bytes, no new turn); a respelling (an omitted default) is a distinct …"""
    est = S.estate(tmp_path)
    ep = _episode(tmp_path)
    est.answer("idp", "query", ALICE, BASE_ALICE)  # what a live read of the respelled call gets
    oracle = S.oracle(*_forged_moves(), S.submit(SERVED_ALICE, CLAIM_ALICE))
    reg = S.sandboxed_registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier())
    ctx = est.ctx(tmp_path / "run")

    first = S.call(reg, "idp", "query", ctx, **ALICE)
    turns, reads = oracle.requests, len(est.calls())
    reordered = dict(reversed(list(ALICE.items())))
    assert list(reordered) != list(ALICE)
    second = S.call(reg, "idp", "query", ctx, **reordered)
    assert _text(second) == _text(first)
    assert oracle.requests == turns
    assert len(est.calls()) == reads

    respelled = {k: v for k, v in ALICE.items() if k != "limit"}
    third = S.call(reg, "idp", "query", ctx, **respelled)
    assert oracle.requests > turns, "an omitted default is a distinct call with its own turn"
    assert third == SERVED_ALICE
    frozen = [r for r in S.oracle_rows(ep, "b", "forged") if r.get("forged_id") == "fg-1"]
    assert len(frozen) == 1
    assert frozen[0].get("row") == FORGED
    assert len(S.ledger_rows(ep, "b")) == 3
    assert not oracle.overrun


@pytest.mark.parametrize("body", ["html", "truncated", "empty", "null", "error-like",
                                  "undecodable"])
def test_base_answer_is_a_non_answer_body(tmp_path, body):
    """a non-answer body with a success signal is the base answer: framed untrusted to the oracle, served unchanged by a world with no covering fact, and …"""
    payloads: dict[str, tuple[Any, str | None]] = {
        "html": ("<html><body><h1>502 Bad Gateway</h1></body></html>", "502 Bad Gateway"),
        "truncated": ('{"rows": [{"note": "TRUNC-MARK-41', "TRUNC-MARK-41"),
        "empty": ("", None),
        "null": (None, None),
        "error-like": ({"message": "ERRBODY-MARK-7: index not found"}, "ERRBODY-MARK-7"),
        "undecodable": ("��BIN-MARK-3�", "BIN-MARK-3"),
    }
    payload, marker = payloads[body]
    est = S.estate(tmp_path)
    ep = _episode(tmp_path, captured=[])
    est.answer("idp", "query", BOB, payload)
    ctx = est.ctx(tmp_path / "run")

    # #1255 D3: the control world's live base goes through its oracle too, framed the same way
    # (was M07=A: served with no turn).
    control_oracle = S.oracle(S.submit(payload, S.EMPTY_CLAIM))
    control = S.sandboxed_registry(ep, "a", est, oracle=control_oracle,
                                   verifier=S.passing_verifier())
    assert _text(S.call(control, "idp", "query", ctx, **BOB)) == _text(payload)
    assert control_oracle.requests >= 1
    assert _decisions(ep, "a") == [S.PASSTHROUGH]
    if marker is not None:
        S.assert_wrapped_untrusted(control_oracle.seen[0], marker, f"the {body} base body")

    oracle = S.oracle(S.submit(payload, S.EMPTY_CLAIM))
    reg = S.sandboxed_registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier())
    assert _text(S.call(reg, "idp", "query", ctx, **BOB)) == _text(payload)
    assert _decisions(ep, "b") == [S.PASSTHROUGH]
    assert oracle.requests >= 1
    if marker is not None:
        S.assert_wrapped_untrusted(oracle.seen[0], marker, f"the {body} base body")


def test_input_base_answer_is_larger_than_the_oracle_context(tmp_path):
    """a base answer larger than one oracle turn is worked over a handle (the oracle's request does not carry it whole) and is served whole; a call whose …"""
    est = S.estate(tmp_path)
    ep = _episode(tmp_path, captured=[])
    everyone = S.query_params("*")
    # Past the most one request carries (`_CONTEXT_CAP`), so working over a handle is the only
    # way the oracle can take it whole; 5,000 rows clear the cap by a third.
    big = {"rows": [{"action": "logon", "event_id": f"e-{i:06d}", "user": f"u{i:05d}"}
                    for i in range(5000)]}
    hosts = S.query_params("host:*")
    big_hosts = {"rows": [{"action": "logon", "event_id": f"h-{i:06d}", "user": f"h{i:05d}"}
                          for i in range(5000)]}
    cap = S.sym("learning.branch.estate.oracle", "_CONTEXT_CAP")
    for answer in (big, big_hosts):
        assert len(_text(answer)) > cap, "the base answer fits one request: nothing to test"
    est.answer("idp", "query", everyone, big)
    est.answer("idp", "query", hosts, big_hosts)
    truncated = {"rows": big_hosts["rows"][:10]}
    oracle = S.oracle(S.submit(big, S.EMPTY_CLAIM), then=S.submit(truncated, S.EMPTY_CLAIM))
    reg = S.sandboxed_registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier(), retry_cap=2)
    ctx = est.ctx(tmp_path / "run")

    served = S.call(reg, "idp", "query", ctx, **everyone)
    assert _text(served) == _text(big), "served whole"
    assert len(oracle.seen[0]) < len(_text(big)), "the oracle works over a handle"

    with pytest.raises(S.unservable_cls()):
        S.call(reg, "idp", "query", ctx, **hosts)
    assert _rows_for(ep, "b", "idp", "query", hosts) == []
    assert _stored(ep, "b", "idp", "query", hosts) == []
    assert [r["source"] for r in S.ledger_rows(ep, "b")] == [S.PASSTHROUGH]


@pytest.mark.parametrize("shape", ["huge-string", "deep-nesting"])
def test_p019_base_answer_has_a_single_enormous_string_value(tmp_path, shape):
    """a multi-megabyte string value or a very deeply nested base answer neither crashes nor hangs the call, and either admitted outcome leaves the records …"""
    if shape == "huge-string":
        base: Any = {"rows": [{"blob": "A" * (3 * 1024 * 1024), "event_id": "e-1",
                               "user": "alice"}]}
    else:
        base = {"leaf": "bottom"}
        for depth in range(120):
            base = {"level": depth, "nested": base}
    est = S.estate(tmp_path)
    ep = _episode(tmp_path, captured=[])
    est.answer("idp", "query", BOB, base)
    oracle = S.oracle(S.submit(base, S.EMPTY_CLAIM))
    reg = S.sandboxed_registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier())
    ctx = est.ctx(tmp_path / "run")

    finished, served, raised = _run_alone(lambda: S.call(reg, "idp", "query", ctx, **BOB),
                                          timeout=180)
    assert finished, "the call hung"
    if raised is not None:
        assert isinstance(raised, S.unservable_cls()), f"crashed: {raised!r}"
        assert _rows_for(ep, "b", "idp", "query", BOB) == []
        assert _stored(ep, "b", "idp", "query", BOB) == []
    else:
        assert _text(served) == _text(base)
        rows = read_jsonl_rows(S.ledger_path(ep, "b"))
        assert len(rows) == 1
        assert rows[0]["source"] == S.PASSTHROUGH
        assert json.loads(rows[0]["payload_text"]) == base
        assert len(_stored(ep, "b", "idp", "query", BOB)) == 1
    # The ledger's own reader still reads the world's file.
    S.sym(S.LEDGER, "Ledger").for_world(S.mod("episodes._episode_handle").Episode.create(ep), TOKEN_B)


def test_p021_base_answer_values_with_control_characters_nul_bidi_and_zero_width(tmp_path):
    """NUL, a bidi override, zero-width characters, ANSI escapes, U+2028, raw newlines and an unpaired surrogate in a base answer are carried …"""
    hostile = "nul\x00 bidi‮ zw​ ansi\x1b[31m ls  nl\n lone\ud800 end"
    base = {"rows": [{"event_id": "e-100", "note": hostile, "user": "alice"}]}
    est = S.estate(tmp_path)
    ep = _episode(tmp_path, captured=[])
    est.answer("idp", "query", BOB, base)
    oracle = S.oracle(S.submit(base, S.EMPTY_CLAIM))
    reg = S.sandboxed_registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier())

    served = S.call(reg, "idp", "query", est.ctx(tmp_path / "run"), **BOB)
    assert served["rows"][0]["note"] == hostile
    raw = S.ledger_path(ep, "b").read_bytes()
    assert raw.count(b"\n") == 1, "exactly one record line for the call"
    rows = read_jsonl_rows(S.ledger_path(ep, "b"))
    assert len(rows) == 1
    assert rows[0]["source"] == S.PASSTHROUGH
    assert json.loads(rows[0]["payload_text"])["rows"][0]["note"] == hostile
    S.sym(S.LEDGER, "Ledger").for_world(S.mod("episodes._episode_handle").Episode.create(ep), TOKEN_B)


def test_input_call_params_cannot_be_stored(tmp_path):
    """a call whose params no record can store is refused by the query tool exactly as on a real run: no oracle turn, no cache entry, no ledger row, and the …"""
    deep: dict = {"leaf": "x"}
    for _ in range(40):
        deep = {"n": deep}
    params = {"q": "user:alice", "filter": deep}
    est = S.estate(tmp_path)

    def turns() -> list:
        return [S.query_turn("idp", "query", params), S.done_turn()]

    real_dir, real_gather = S.drive_gather(tmp_path / "real", verbs=S.plain_registry(est),
                                           tenant=est.place(), gather_turns=turns())
    ep = _episode(tmp_path / "branch")
    oracle = S.oracle(S.submit(BASE_ALICE, S.EMPTY_CLAIM))
    verifier = S.passing_verifier()
    reg = S.sandboxed_registry(ep, "b", est, oracle=oracle, verifier=verifier)
    branch_dir, branch_gather = S.drive_gather(tmp_path / "branch", verbs=reg,
                                               tenant=est.place(), gather_turns=turns())

    refusal = S.sym(S.QUERY_TOOL, "PARAMS_TOO_DEEP")
    assert refusal in "\n".join(real_gather.seen)
    assert refusal in "\n".join(branch_gather.seen)
    assert ([_row_view(r) for r in _evidence(branch_dir)]
            == [_row_view(r) for r in _evidence(real_dir)])
    assert oracle.requests == 0
    assert verifier.requests == 0
    assert S.ledger_rows(ep, "b") == []
    assert _complete_rows(S.oracle_dir(ep, "b") / "answers.jsonl") == []
    assert est.calls() == []

    # Positive control (R-12): the same registry, a granted call, the same query-tool path.
    S.drive_gather(tmp_path / "control", verbs=reg, tenant=est.place(),
                   gather_turns=[S.query_turn("idp", "query", ALICE), S.done_turn()])
    assert oracle.requests >= 1, "a granted call never reached this registry's oracle"
    assert verifier.requests >= 1
    assert _decisions(ep, "b") == [S.PASSTHROUGH]
    assert len(_stored(ep, "b", "idp", "query", ALICE)) == 1
    assert not oracle.overrun


def test_input_denied_or_undeclared_call_in_a_fact_world(tmp_path):
    """a call the grant denies, and one naming a system the tenant does not serve, are refused by the grant decision before serving exactly as on a real …"""
    est = S.estate(tmp_path)

    def turns() -> list:
        return [S.query_turn("idp", S.WRITE_VERB, {"host": "db-1"}),
                S.query_turn("crm", "query", {"q": "*"}), S.done_turn()]

    real_dir, _ = S.drive_gather(tmp_path / "real", verbs=S.plain_registry(est),
                                 tenant=est.place(), gather_turns=turns())
    ep = _episode(tmp_path / "branch")
    oracle = S.oracle(S.submit(BASE_ALICE, S.EMPTY_CLAIM))
    verifier = S.passing_verifier()
    reg = S.sandboxed_registry(ep, "b", est, oracle=oracle, verifier=verifier)
    branch_dir, _ = S.drive_gather(tmp_path / "branch", verbs=reg, tenant=est.place(),
                                   gather_turns=turns())

    real_rows, branch_rows = _evidence(real_dir), _evidence(branch_dir)
    assert len(real_rows) == 2
    assert [_row_view(r) for r in branch_rows] == [_row_view(r) for r in real_rows]
    assert all(r["exit_code"] != 0 for r in branch_rows)
    assert oracle.requests == 0
    assert verifier.requests == 0
    assert _complete_rows(S.oracle_dir(ep, "b") / "answers.jsonl") == []
    refused_rows = S.ledger_rows(ep, "b")
    assert all(row.get("source") == S.REFUSED for row in refused_rows)
    assert est.calls() == [], "nothing reached a tenant system"

    # Positive control (R-12): the same registry, a granted call, the same query-tool path.
    S.drive_gather(tmp_path / "control", verbs=reg, tenant=est.place(),
                   gather_turns=[S.query_turn("idp", "query", ALICE), S.done_turn()])
    assert oracle.requests >= 1, "a granted call never reached this registry's oracle"
    assert verifier.requests >= 1
    assert _decisions(ep, "b") == [S.REFUSED] * len(refused_rows) + [S.PASSTHROUGH]
    assert len(_stored(ep, "b", "idp", "query", ALICE)) == 1
    assert not oracle.overrun


def test_conc_19_oracle_side_query_beside_investigator_calls(tmp_path):
    """with cached, oracle-served, passthrough and real-error calls running at once in one sibling, the world ledger and evidence hold one complete, …"""
    est = S.estate(tmp_path)
    ep = _episode(tmp_path)
    explored = WEB1
    checked = {"entity": "carol"}
    est.answer("edr", "query", DB1, EDR_BASE)
    est.answer("edr", "query", explored, {"events": []})
    est.answer("idp", "lookup", checked, {"entity": "carol", "found": True})
    est.fail("siem-x", "lookup", SIEM_ALICE, fault="UpstreamFault", detail="siem-x: 503")
    oracle = S.oracle(S.run_query("edr", "query", explored), *_forged_moves(),   # alice
                      S.submit(EDR_BASE, S.EMPTY_CLAIM))                          # edr db-1
    verifier = S.verifier(S.run_query("idp", "lookup", checked), S.verdict(True),
                          then=S.verdict(True))
    reg = S.sandboxed_registry(ep, "b", est, oracle=oracle, verifier=verifier)

    run_dir, _ = S.drive_gather(tmp_path, verbs=reg, tenant=est.place(), gather_turns=[
        S.query_turn("idp", "query", ALICE),
        _parallel_turn(("idp", "query", ALICE), ("edr", "query", DB1),
                       ("siem-x", "lookup", SIEM_ALICE)),
        S.done_turn()])

    evidence = _evidence(run_dir)
    ledger = S.ledger_rows(ep, "b")
    calls = [("idp", "query", ALICE), ("idp", "query", ALICE), ("edr", "query", DB1),
             ("siem-x", "lookup", SIEM_ALICE)]

    def key(system: str, verb: str, params: Any) -> str:
        return f"{system}|{verb}|{S.canonical(params if isinstance(params, dict) else {})}"

    assert sorted(key(r["system"], r["verb"], r["params"]) for r in evidence) == sorted(
        key(*c) for c in calls)
    assert sorted(key(r["system"], r["verb"], _asked(r)) for r in ledger) == sorted(
        key(*c) for c in calls)
    for row in ledger:
        assert row.get("world_id") == TOKEN_B
        assert isinstance(row.get("payload_text"), str)
        assert row.get("source")
    by_call = {key(r["system"], r["verb"], _asked(r)): r["source"] for r in ledger}
    assert by_call[key("edr", "query", DB1)] == S.PASSTHROUGH
    assert by_call[key("siem-x", "lookup", SIEM_ALICE)] == S.REAL_ERROR
    assert [r["source"] for r in ledger if _asked(r) == ALICE][0] == S.ORACLE_DECISION

    side = S.oracle_rows(ep, "b", "ledger")
    assert any(r.get("actor") == "oracle" and r.get("params") == explored for r in side)
    assert any(r.get("actor") == "verifier" and r.get("params") == checked for r in side)
    for params in (explored, checked):
        assert not any(r.get("params") == params for r in evidence)
        assert not any(_asked(r) == params for r in ledger)
    assert not oracle.overrun


def test_sibling_dies_after_the_answer_is_stored_before_its_ledger_row(tmp_path):
    """after a crash between storing a served answer and recording its ledger row, the resumed sibling's re-issued call gets the identical stored answer …"""
    est = S.estate(tmp_path)
    ep = _episode(tmp_path)
    first_run = S.sandboxed_registry(ep, "b", est, oracle=S.oracle(*_forged_moves()),
                          verifier=S.passing_verifier())
    first = S.call(first_run, "idp", "query", est.ctx(tmp_path / "run"), **ALICE)
    assert len(_stored(ep, "b", "idp", "query", ALICE)) == 1

    path = S.ledger_path(ep, "b")
    kept = [r for r in S.ledger_rows(ep, "b") if _asked(r) != ALICE]
    path.write_text("".join(json.dumps(r) + "\n" for r in kept), encoding="utf-8")

    oracle, verifier = S.oracle(), S.verifier()
    resumed = S.sandboxed_registry(ep, "b", est, oracle=oracle, verifier=verifier)
    again = S.call(resumed, "idp", "query", est.ctx(tmp_path / "run"), **ALICE)
    assert _text(again) == _text(first)
    assert oracle.requests == 0
    assert verifier.requests == 0
    assert len(_rows_for(ep, "b", "idp", "query", ALICE)) == 1


def test_torn_last_line_in_the_forged_store_at_resume(tmp_path):
    """a half-written trailing record in the forged store, the served-answer store or the oracle-side ledger is never read as a valid row, answer or fact, …"""
    est = S.estate(tmp_path)
    ep = _episode(tmp_path)
    window = S.query_params("user:alice", start="2026-07-28T15:00:00Z",
                            end="2026-07-28T16:00:00Z")
    est.answer("idp", "query", window, BASE_ALICE)
    store = S.oracle_dir(ep, "b")
    store.mkdir(parents=True, exist_ok=True)
    (store / "answers.jsonl").write_text(
        json.dumps({"system": "idp", "verb": "query", "params": ALICE, "served": SERVED_ALICE})
        + "\n" + '{"system": "idp", "verb": "query", "params": {"q": "user:alice", "st',
        encoding="utf-8")
    (store / "forged.jsonl").write_text(
        json.dumps({"forged_id": "fg-1", "fact_id": "f1", "system": "idp", "row": FORGED})
        + "\n" + '{"forged_id": "fg-2", "fact_id": "f1", "system": "id', encoding="utf-8")
    (store / "facts.jsonl").write_text('{"entity": "alice", "field": "dep', encoding="utf-8")
    (store / "ledger.jsonl").write_text(
        json.dumps({"actor": "oracle", "system": "edr", "verb": "query", "params": WEB1})
        + "\n" + '{"actor": "verif', encoding="utf-8")
    forged_2 = {"action": "tgt-renewed", "event_id": "e-9002", "user": "alice"}
    served_2 = {"rows": [ALICE_ROW, forged_2]}
    oracle = S.oracle(*_forged_moves("fg-2", row=forged_2, served=served_2))
    reg = S.sandboxed_registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier())
    ctx = est.ctx(tmp_path / "run")

    assert S.call(reg, "idp", "query", ctx, **ALICE) == SERVED_ALICE
    assert oracle.requests == 0, "the complete stored answer is served from the store"
    assert S.call(reg, "idp", "query", ctx, **window) == served_2
    assert oracle.requests >= 1, "the torn answer was treated as not written"
    complete = [r for r in _complete_rows(store / "forged.jsonl") if r.get("forged_id") == "fg-2"]
    assert [r.get("row") for r in complete] == [forged_2]

    later = S.oracle()
    resumed = S.sandboxed_registry(ep, "b", est, oracle=later, verifier=S.verifier())
    assert S.call(resumed, "idp", "query", ctx, **window) == served_2
    assert later.requests == 0, "the answer written after the torn line reads back whole"


def test_input_oracle_budget_is_zero_or_unreadable(tmp_path, monkeypatch):
    """with a zero oracle budget a world with facts is unservable (reason `budget`) at its first call that needs the oracle and fails pre-flight, a …"""
    est = S.estate(tmp_path / "serving")
    ep = _episode(tmp_path / "serving")
    ctx = est.ctx(tmp_path / "run")
    control_oracle = S.oracle()
    control = S.sandboxed_registry(ep, "a", est, oracle=control_oracle, verifier=S.verifier(), budget=0)
    assert _text(S.call(control, "idp", "query", ctx, **ALICE)) == _text(BASE_ALICE)
    assert control_oracle.requests == 0
    assert _decisions(ep, "a") == [S.PASSTHROUGH]

    fact_world = S.sandboxed_registry(ep, "b", est, oracle=S.oracle(*_forged_moves()),
                           verifier=S.passing_verifier(), budget=0)
    with pytest.raises(S.unservable_cls()) as raised:
        S.call(fact_world, "idp", "query", ctx, **ALICE)
    assert raised.value.reason == S.REASON_BUDGET
    assert S.ledger_rows(ep, "b") == []

    settings = S.sym(S.ORACLE, "oracle_settings")
    settings({S.KNOB_BUDGET: "5"})  # positive control: a positive budget is read
    for bad in ("-1", "lots"):
        with pytest.raises(FatalConfigError, match=S.KNOB_BUDGET):
            settings({S.KNOB_BUDGET: bad})

    monkeypatch.setenv(S.KNOB_BUDGET, "0")
    launch = S.launch(tmp_path / "launch", S.estate(tmp_path / "launch"),
                      calls=[S.Call("idp", "query", ALICE, BASE_ALICE)],
                      oracle=S.oracle(then=S.submit(BASE_ALICE, S.EMPTY_CLAIM)),
                      verifier=S.passing_verifier(), judge=S.FakeJudge(default=S.judge_reply()))
    outcome = S.read_outcome(launch.ep)
    assert outcome is not None
    assert outcome["outcome"] == "unusable"
    by_world = {w["world"]: w for w in outcome["unservable_worlds"]}
    assert set(by_world) == {"b", "c"}
    assert all(S.REASON_BUDGET in str(w.get("reason")) for w in by_world.values())


def test_conc_25_one_worlds_served_answer_beside_another_worlds_base_read(tmp_path):
    """RE-PINNED (S20): a world's served answer never reaches another world's base; the only cross-world store, the base recording, is never written by a …"""
    est = S.estate(tmp_path)
    ep = _episode(tmp_path)
    family_before = (ep / "served" / "base.jsonl").read_bytes()
    oracle_c, verifier_c = S.oracle(S.submit(BASE_ALICE, S.EMPTY_CLAIM)), S.passing_verifier()
    regs = {"b": S.sandboxed_registry(ep, "b", est, oracle=S.oracle(*_forged_moves()),
                           verifier=S.passing_verifier()),
            "c": S.sandboxed_registry(ep, "c", est, oracle=oracle_c, verifier=verifier_c)}
    gate = threading.Barrier(2)

    def snapshot() -> dict[Path, bytes]:
        return {p: p.read_bytes() for p in ep.rglob("*") if p.is_file()}

    def own(label: str, path: Path) -> bool:
        return path == S.ledger_path(ep, label) or S.oracle_dir(ep, label) in path.parents

    def ask(label: str) -> Any:
        gate.wait(timeout=30)
        return S.call(regs[label], "idp", "query", est.ctx(tmp_path / f"run-{label}"), **ALICE)

    before = snapshot()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        got = dict(zip(("b", "c"), pool.map(ask, ("b", "c")), strict=True))
    after = snapshot()

    assert got == {"b": SERVED_ALICE, "c": BASE_ALICE}
    assert "e-9001" not in oracle_c.all_seen() + verifier_c.all_seen()
    assert (ep / "served" / "base.jsonl").read_bytes() == family_before
    changed = {p for p in after if before.get(p) != after[p]}
    for label in ("b", "c"):
        assert any(own(label, p) for p in changed), (
            f"positive control: serving wrote world {label}'s own records")
    foreign = sorted(str(p.relative_to(ep)) for p in changed
                     if not (own("b", p) or own("c", p)))
    assert foreign == [], f"serving wrote outside the worlds' own state: {foreign}"
    leaked = sorted(str(p.relative_to(ep)) for p in after
                    if own("c", p) and b"e-9001" in after[p])
    assert leaked == [], f"world b's forged row reached world c's files: {leaked}"


#: R-01: the post-branch call's params marker. Neither it nor the pre-branch call's marker
#: (`user:alice`) contains the other, so `_CallRouted` tells the two replayed calls apart.
POST_Q = "tgt:alice"
POST_BASE = {"rows": [{"action": "logon", "event_id": "e-300", "user": "alice"}]}


@pytest.mark.parametrize("edited_call", ["pre-branch", "neither", "post-branch"])
def test_1224_world_fact_covers_a_call_the_investigator_made_before_the_branch_point(
        tmp_path, monkeypatch, edited_call):
    """a pre-branch call is fixed: a world whose oracle would change the answer to a call the original run made before the branch point fails pre-flight, …"""
    monkeypatch.setenv(S.KNOB_RETRY_CAP, "1")
    est = S.estate(tmp_path)
    claim = S.claim(changed=[S.changed("alice", "action", "logon", "tgt-issued")])

    def answering(base: dict, *, edit: bool) -> S.ScriptedModel:
        if not edit:
            return S.oracle(then=S.submit(base, S.EMPTY_CLAIM))
        edited = {"rows": [dict(row, action="tgt-issued") for row in base["rows"]]}
        return S.oracle(then=S.submit(edited, claim))

    pre = answering(BASE_ALICE, edit=edited_call == "pre-branch")
    post = answering(POST_BASE, edit=edited_call == "post-branch")
    oracle = _CallRouted({"user:alice": pre, POST_Q: post})
    launch = S.launch(tmp_path, est,
                      calls=[S.Call("idp", "query", ALICE, BASE_ALICE),
                             S.post_branch_call(q=POST_Q, payload=POST_BASE)],
                      oracle=oracle, verifier=S.passing_verifier(),
                      judge=S.FakeJudge(default=S.judge_reply()))

    outcome = S.read_outcome(launch.ep)
    assert outcome is not None
    assert not oracle.unrouted, "a replayed call reached the oracle carrying neither marker"
    assert pre.requests >= 2, "pre-flight replayed the pre-branch call through each fact world"
    failed = {w["world"]: w for w in outcome["unservable_worlds"]}
    if edited_call == "pre-branch":
        assert set(failed) == {"b", "c"}
        assert outcome["outcome"] == "unusable"
        assert launch.spawn.launches == []
        for label, record in failed.items():
            named = json.dumps(record.get("call"), sort_keys=True, default=str)
            assert "user:alice" in named, f"world {label} failed on another call: {named}"
            assert POST_Q not in named, f"world {label} failed on the post-branch call: {named}"
    else:
        assert post.requests >= 2, (
            "pre-flight replayed the post-branch call through each fact world")
        assert failed == {}, f"a world failed pre-flight: {sorted(failed)}"
        assert outcome["outcome"] == "accepted"
        assert set(launch.spawn.worlds) >= {"b", "c"}


@pytest.mark.parametrize("cause", ["checks", "exception", "budget"])
def test_1224_unservable_call_and_the_world_ledger(tmp_path, cause):
    """whatever makes a call unservable (N failed checks, an oracle-side exception on every attempt, the budget running out mid-call), the world ledger …"""
    est = S.estate(tmp_path)
    ep = _episode(tmp_path)
    est.fail("siem-x", "lookup", SIEM_ALICE, fault="UpstreamFault", detail="siem-x: 503")
    knobs: dict[str, Any] = {"retry_cap": 2}
    if cause == "checks":
        oracle = S.oracle(then=S.submit(UNDECLARED, S.EMPTY_CLAIM))
    elif cause == "exception":
        # GPR-01: every oracle request fails as the provider client fails after its retries.
        oracle = S.oracle(then=S.raising(S.OUTAGE))
    else:
        oracle = S.oracle(*_forged_moves(), then=S.text_only())
        # D1 / R-08: a priced double's request costs more than this in any unit; none is pinned.
        knobs["budget"] = 1e-9
    reg = S.sandboxed_registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier(), **knobs)
    ctx = est.ctx(tmp_path / "run")

    # Positive control: the ledger records this world's calls (a real error costs no oracle).
    with pytest.raises(faults.UpstreamFault):
        S.call(reg, "siem-x", "lookup", ctx, **SIEM_ALICE)
    assert _decisions(ep, "b") == [S.REAL_ERROR]

    with pytest.raises(S.unservable_cls()) as raised:
        S.call(reg, "idp", "query", ctx, **ALICE)
    if cause == "budget":
        assert raised.value.reason == S.REASON_BUDGET
    if cause == "exception":
        assert oracle.requests >= 2, "the provider failure was not retried up to the cap"
    rows = S.ledger_rows(ep, "b")
    assert _rows_for(ep, "b", "idp", "query", ALICE) == []
    assert not any(r.get("source") == S.FAULT for r in rows)
    assert not _mentions(rows, "e-7777")
    assert not _mentions(rows, str(raised.value))
    assert _decisions(ep, "b") == [S.REAL_ERROR]
    assert _stored(ep, "b", "idp", "query", ALICE) == []


def test_1224_ledger_records_oracle_and_real_error_at_the_world_tier_only(tmp_path):
    """`Ledger.record` records `oracle` and `real-error` at the world tier and refuses them at the family tier; `staged` and `patched` are refused; …"""
    ep = S.episode_v2(tmp_path / "unit")
    ledger = S.world_ledger(ep, "b")
    served_call = S.sym(S.LEDGER, "ServedCall")
    ledger_error = S.sym(S.LEDGER, "LedgerError")

    def row(source: str, q: str, world_id: str | None) -> Any:
        return served_call(system="idp", verb="query", params=S.query_params(q),
                           payload_text=_text(BASE_ALICE), source=source, world_id=world_id)

    for word in (S.PASSTHROUGH, S.ORACLE_DECISION, S.REAL_ERROR, S.REFUSED):
        ledger.record(row(word, f"user:{word}", TOKEN_B))
    for word in (S.ORACLE_DECISION, S.REAL_ERROR):
        with pytest.raises(ledger_error):
            ledger.record(row(word, f"user:{word}-family", None))
    for word in S.RETIRED_DECISIONS:
        with pytest.raises(ledger_error):
            ledger.record(row(word, f"user:{word}", TOKEN_B))
    for world_id in (None, TOKEN_B):
        with pytest.raises(ledger_error):
            ledger.record(row("captured", "user:captured", world_id))
    ledger.record(row("base", "user:family", None))
    assert _decisions(ep, "b") == [S.PASSTHROUGH, S.ORACLE_DECISION, S.REAL_ERROR, S.REFUSED,
                                   "base"]

    est = S.estate(tmp_path)
    serving = _episode(tmp_path / "serving", captured=[])
    est.answer("idp", "query", ALICE, BASE_ALICE)
    reg = S.sandboxed_registry(serving, "b", est, oracle=S.oracle(*_forged_moves()),
                    verifier=S.passing_verifier())
    S.call(reg, "idp", "query", est.ctx(tmp_path / "run"), **ALICE)
    assert _decisions(serving, "b") == [S.ORACLE_DECISION], "no live-miss base row"
    assert _mentions(S.oracle_rows(serving, "b", "base"), "e-100")
