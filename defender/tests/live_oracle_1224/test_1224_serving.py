"""#1224 — the sibling's serving path through the live oracle: `serve_one` / `WorldRegistry`, the
query tool's handling of what the registry returns or raises, and the world ledger.

What this file owns (one test per slice entry of `w01_serving`):
  * the served-answer contract — an uncached call in a world with facts gets an oracle turn and a
    verifier pass and the oracle decides `passthrough` (M01=A); a facts-free world serves the base
    with no oracle turn (M07=A); N failed attempts raise `OracleUnservable` (M03=A);
  * the world ledger's vocabulary and row count — one row per investigator call, `passthrough`,
    `oracle`, `real-error` or `refused`; `staged` / `patched` refused; a live base answer lives
    in the world's own oracle-side `base.jsonl`, never as a ledger row; an unservable call leaves
    no row (M16=A, F-02=A, PCO-05);
  * real-system errors — passed through unchanged, recorded `real-error`, never cached, and still
    charged to the circuit breaker by the query tool as on a real run (M08=A, F-02=A);
  * the cache — keyed on the canonical JSON of params (N08), a repeat returns the world's own
    stored answer byte for byte (S5), nothing crosses worlds but the base recording (S20, S22);
  * the hostile and degenerate inputs the premises name (non-answer bodies, huge or control-laden
    values, unstorable params, denied calls, torn stores, crashes between writes).

Faults are real inputs through real primitives (the fixture estate's stub adapters raise the real
`AdapterFault` subclasses; the files a crash leaves behind are written on disk), or scripted
model content the design names (O3). Every model double enters through the coined seams; nothing
here uses `monkeypatch.setattr`.
"""
from __future__ import annotations

import concurrent.futures
import importlib
import json
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender._env import FatalConfigError  # noqa: E402
from defender._io import read_jsonl_rows  # noqa: E402
from defender.scripts.adapters import faults  # noqa: E402
from defender.tests import _judge_921 as J  # noqa: E402
from defender.tests._state1135 import state_over  # noqa: E402
from defender.tests.live_oracle_1224 import _spec1224 as S  # noqa: E402

# --------------------------------------------------------------------------------------------
# The fixture's answers. Every literal keeps its keys sorted, so a payload compares byte for
# byte whether it came back from the stub adapter (whose table is dumped sorted) or from a
# scripted submission.
# --------------------------------------------------------------------------------------------

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

TOKEN_B = S.world_token("b")


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


def _registry(ep: Path, label: str, est: S.Estate, *, oracle: Any = None, verifier: Any = None,
              **knobs: Any) -> Any:
    """The world's `WorldRegistry` with the doubles injected and a sandboxed, recording box (so
    no scenario here can start a real one)."""
    knobs.setdefault("retry_cap", 3)
    box, _log = S.sandboxed_box()
    return S.world_registry(ep, label, est, oracle=oracle, verifier=verifier, box=box, **knobs)


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


def _real_registry(est: S.Estate) -> Any:
    """The registry an ordinary (non-branched) run queries through — the "as on a real run"
    control every query-tool scenario compares against."""
    rt = est.run_tenant()
    return S.sym(S.VERBS, "ModuleVerbRegistry")(est.roster(), rt.grants.gather,
                                                grant_home=rt.table_pointer)


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


def _breaker(run_dir: Path) -> dict:
    path = Path(run_dir) / "circuit_breaker.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def _parallel_turn(*calls: tuple[str, str, dict]) -> Any:
    """One gather turn issuing several `query` calls at once (they run on worker threads)."""
    H = importlib.import_module("defender.tests.e2e._replay_harness")
    return H.Turn(tool_calls=[("query", {"system": s, "verb": v, "params": dict(p)})
                              for s, v, p in calls])


def _judge_reply(*, systems: tuple[str, ...] = ("idp",), bucket: str = "lead-set") -> str:
    """A judge reply in the coined v2 shape: a world-scope `bucket` and `systems`, plus the
    family-scope `verdict_word`, so one default answers both scopes."""
    return S.as_reply_text(J.reply_doc(findings=[], bucket=bucket, systems=list(systems),
                                       verdict_word="caught"))


def _grade(ep: Path, judge: Any) -> Any:
    """Grade `ep` once, against a learning-state root of its own (so no other grade of the same
    episode id in the environment's state can stand in for this one)."""
    return S.sym(S.JUDGE, "grade_episode")(ep, judge=judge, runs_base=ep.parent / "runs-base",
                                           state=state_over(ep.parent.parent / "judge-state"), draws=1)


def _judged_label(agent_id: str) -> str | None:
    """The world a judge call is about, from its agent id: `judge:<label>:<n>` -> `<label>`
    (the family-scope call is `judge:family:<n>`; the spelling `grade_episode` uses today)."""
    parts = str(agent_id).split(":")
    return parts[1] if len(parts) >= 3 and parts[0] == "judge" else None


class _CallRouted:
    """An oracle double answering each request with the scripted double of the CALL the request
    is about (R-01), told apart by a marker in that call's params. The oracle's context runs
    stable to volatile (design: static instructions, family block, world block, then the
    per-call turns), so the call a request is about is the one whose marker occurs LAST in the
    request's inbound text — whether each call opens a fresh conversation or extends the
    sibling's one. Markers must not contain one another.

    Tier 2: it routes a script and decides nothing. Each route is a `S.ScriptedModel`, which
    records what it was handed; a request carrying no marker is answered text-only and recorded
    in `unrouted`, which the scenario asserts empty. Named after a priced model
    (`S.double_model_name`, R-08) like every double."""

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


# ============================================================================================
# The served-answer contract.
# ============================================================================================


def test_1224_served_verb_returns_the_verified_answer_and_rows_it(tmp_path):
    """d00a_served_answer_contract — a verified oracle answer is returned to the caller and rowed
    `oracle`; a submission equal to the base returns the base's canonical bytes, rowed
    `passthrough`.

    Through WorldRegistry.verbs(system)[verb](ctx, **params) in a world with facts, a scripted
    oracle double whose submission passes host checks 1-5 and the verifier gets its served answer
    returned to the caller and one world-ledger row with decision `oracle`; a call whose
    submission equals the base answer gets the base answer's canonical bytes back and one row
    with decision `passthrough`. Rests on M01=A (the oracle decides passthrough) and F-08.
    """
    est = S.estate(tmp_path)
    ep = _episode(tmp_path, captured=[("idp", "query", ALICE, BASE_ALICE),
                                      ("siem-x", "lookup", SIEM_ALICE, SIEM_BASE)])
    oracle = S.oracle(*_forged_moves(), S.submit(SIEM_BASE, S.EMPTY_CLAIM))
    verifier = S.passing_verifier()
    reg = _registry(ep, "b", est, oracle=oracle, verifier=verifier)
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
    """d00b_real_error_passes_through — a real-system error on the original query re-raises
    unchanged, costs no oracle or verifier turn, reads the adapter once and leaves one
    `real-error` row.

    When the adapter (or the live base read) raises on the original query, the served verb
    re-raises that same exception, same class and message, the oracle and verifier doubles record
    zero turns, the adapter was called exactly once, and the world ledger holds exactly one row
    with decision `real-error`. F-02=A (`real-error` replaces `fault` for an error on the original
    query); RF-1 (the registry's fault-row writer must not turn it into anything else).
    """
    est = S.estate(tmp_path)
    ep = _episode(tmp_path)
    detail = "idp: directory shard 3 unavailable"
    est.fail("idp", "query", BOB, fault="UpstreamFault", detail=detail)  # GA-40: a real AdapterFault
    oracle, verifier = S.oracle(*_forged_moves()), S.passing_verifier()
    reg = _registry(ep, "b", est, oracle=oracle, verifier=verifier)
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
    """d00c_unservable_after_n — with a retry cap of N, an oracle failing every attempt is
    consulted exactly N times for the call and the served verb raises `OracleUnservable`; nothing
    is stored or rowed for that call.

    With the retry cap set to N, an oracle double that fails a host check (or the verifier) on
    every attempt is consulted exactly N times for the call, after which the served verb raises
    OracleUnservable carrying an unservable reason, and no served answer for that call is stored
    in the world's cache or ledger as `oracle`. M03=A (a failed host check or verifier verdict is
    one attempt); M16=A (an unservable call leaves no ledger row).
    """
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
    reg = _registry(ep, "b", est, oracle=oracle, verifier=verifier, retry_cap=3)
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
    """d00d_cache_hit_identical — the same call twice in one world returns byte-identical
    answers, and the repeat costs no oracle turn, no verifier pass and no base query.

    Issuing the same (system, verb, params) twice in one world returns byte-identical answers,
    and the second call makes no oracle turn, no verifier call and no base query (adapter call
    count unchanged). S5.
    """
    est = S.estate(tmp_path)
    ep = _episode(tmp_path, captured=[])
    est.answer("idp", "query", ALICE, BASE_ALICE)
    oracle, verifier = S.oracle(*_forged_moves()), S.passing_verifier()
    reg = _registry(ep, "b", est, oracle=oracle, verifier=verifier)
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


def test_1224_ledger_refuses_staged_and_patched_decisions(tmp_path):
    """d00e_ledger_vocabulary — `Ledger.record` accepts `passthrough`, `oracle` and `real-error`
    served rows and refuses `staged` and `patched`; `base`, `captured` and `refused` behave as
    today.

    Ledger.record accepts a served row whose decision is `passthrough`, `oracle` or
    `real-error` and refuses one whose decision is `staged` or `patched` with LedgerError;
    `base`, `captured` and `refused` rows are written as today. F-02=A, M16=A.
    """
    ep = S.episode_v2(tmp_path)
    ledger = S.world_ledger(ep, "b")
    served_call = S.sym(S.LEDGER, "ServedCall")
    ledger_error = S.sym(S.LEDGER, "LedgerError")

    def row(source: str, q: str, world_id: str | None = TOKEN_B) -> Any:
        return served_call(system="idp", verb="query", params=S.query_params(q),
                           payload_text=_text(BASE_ALICE), source=source, world_id=world_id)

    for i, word in enumerate((S.PASSTHROUGH, S.ORACLE_DECISION, S.REAL_ERROR, S.REFUSED)):
        ledger.record(row(word, f"user:accepted-{i}"))
    for i, word in enumerate(S.RETIRED_DECISIONS):
        with pytest.raises(ledger_error):
            ledger.record(row(word, f"user:retired-{i}"))
    ledger.record(row("base", "user:family", world_id=None))
    with pytest.raises(ledger_error):
        ledger.record(row("captured", "user:primer-only", world_id=None))

    assert _decisions(ep, "b") == [S.PASSTHROUGH, S.ORACLE_DECISION, S.REAL_ERROR, S.REFUSED,
                                   "base"]


def test_1224_oracle_row_carries_call_digest_answer_claim_verdict_and_attempts(tmp_path):
    """d00f_served_answer_record_shape — the `oracle` row carries the call, the base answer's
    digest, the served answer, the submitted claim, the verifier's verdict and the attempt count.

    The world-ledger row for an `oracle` decision carries the call (system, verb, params), the
    base answer's digest, the served answer, the submitted claim, the verifier's verdict and the
    attempt count that produced it. M16=A. The claim's exact schema is the implementer's; only
    the added-row entry the submission declared is checked. The digest's algorithm is the
    implementer's too (R-11: the design says only "the base answer digest" and no reader
    recomputes it), so `base_digest` is pinned by what a digest must do: present, equal for two
    `oracle` rows over the same base answer (world b's and world c's answers to one captured
    call), different for a row over a different base answer (world b's live-read bob call).
    """
    est = S.estate(tmp_path)
    ep = _episode(tmp_path)
    est.answer("idp", "query", BOB, BOB_BASE)
    reason = "fact f1's TGT for alice at 15:22Z is present and plausible"
    forged_bob = {"action": "tgt-issued", "event_id": "e-9002", "user": "bob"}
    oracle = S.oracle(S.submit(UNDECLARED, S.EMPTY_CLAIM), *_forged_moves(),
                      *_forged_moves("fg-2", row=forged_bob,
                                     served={"rows": [*BOB_BASE["rows"], forged_bob]}))
    verifier = S.verifier(S.verdict(True, reason), then=S.verdict(True))
    reg = _registry(ep, "b", est, oracle=oracle, verifier=verifier)

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
    world_c = _registry(ep, "c", est, verifier=S.passing_verifier(), oracle=S.oracle(
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


def test_1224_oracle_and_verifier_enter_through_injection_seams(tmp_path):
    """d00g_oracle_and_verifier_seams — scripted oracle and verifier doubles handed to
    `WorldRegistry` and to the launcher are driven by the real serving path and by pre-flight,
    and what those paths produce is reached through the doubles.

    A test hands a scripted oracle and a scripted verifier to WorldRegistry and to the launcher's
    main, and the real serving path and pre-flight drive those doubles without monkeypatching.
    F-01. Product observables reached through the seams, serving side: the double is offered
    the coined tools; a submission failing host check 1 sends the turn back to it with the
    failure named (the host checks and the retry loop drive it); its `forge` lands in the
    world's frozen store; the verifier double is handed the served answer; the caller gets the
    verified answer, rowed `oracle` with two attempts; a repeat is answered from the world's
    cache with no further turn. Pre-flight side: the captured call and each fact world's
    statement reach the oracle double, the call's base answer reaches the verifier double, and
    the launch is `accepted`. The base-answer read itself is pinned by d00a / d00d, not here.
    """
    est = S.estate(tmp_path / "serving")
    ep = _episode(tmp_path / "serving")
    oracle = S.oracle(S.submit(UNDECLARED, S.EMPTY_CLAIM), *_forged_moves())
    verifier = S.passing_verifier()
    reg = _registry(ep, "b", est, oracle=oracle, verifier=verifier)
    ctx = est.ctx(tmp_path / "run")
    assert S.call(reg, "idp", "query", ctx, **ALICE) == SERVED_ALICE
    assert "submit" in oracle.tools[0]
    assert "forge" in oracle.tools[0]
    assert "verdict" in verifier.tools[0]
    assert len(oracle.seen) >= 2, "the failed submission was not followed by another request"
    assert S.verdict_names(oracle.seen[1], "check 1"), (
        "the host's check-1 failure did not reach the oracle double's next request")
    assert [(r.get("forged_id"), r.get("row")) for r in S.oracle_rows(ep, "b", "forged")] == [
        ("fg-1", FORGED)], "the double's forge did not land in the world's frozen store"
    assert "e-9001" in verifier.all_seen(), "the verifier double was not handed the served answer"
    rows = S.ledger_rows(ep, "b")
    assert [r["source"] for r in rows] == [S.ORACLE_DECISION]
    assert rows[0]["attempts"] == 2
    turns, checks = oracle.requests, verifier.requests
    assert S.call(reg, "idp", "query", ctx, **ALICE) == SERVED_ALICE
    assert (oracle.requests, verifier.requests) == (turns, checks), (
        "a repeat of a served call reached the doubles instead of the world's cache")
    assert not oracle.overrun

    launch_est = S.estate(tmp_path / "launch")
    pre_oracle = S.oracle(then=S.submit(BASE_ALICE, S.EMPTY_CLAIM))
    pre_verifier = S.passing_verifier()
    launch = S.launch(tmp_path / "launch", launch_est,
                      calls=[S.Call("idp", "query", ALICE, BASE_ALICE)],
                      oracle=pre_oracle, verifier=pre_verifier,
                      judge=S.FakeJudge(default=_judge_reply()))
    assert pre_oracle.requests >= 2, "pre-flight replayed the call through each fact world"
    assert pre_verifier.requests >= 2
    seen = pre_oracle.all_seen()
    assert "user:alice" in seen, "the captured call never reached the pre-flight oracle double"
    for world in S.family_v2()["worlds"]:
        for fact in world["facts"]:
            assert fact["statement"] in seen, (
                f"world {world['world_id']}'s replay never reached the oracle double")
    assert "e-100" in pre_verifier.all_seen(), (
        "the replayed call's base answer never reached the verifier double")
    outcome = S.read_outcome(launch.ep)
    assert outcome is not None
    assert outcome["outcome"] == "accepted"


def test_1224_world_with_no_facts_serves_base_with_no_oracle_turn(tmp_path):
    """d00h_world_without_facts_is_passthrough — a world whose facts list is empty serves every
    call's base unchanged with no oracle or verifier turn, each row `passthrough`.

    In a world whose manifest entry has an explicit empty facts list (today's control world),
    every call returns the base answer unchanged, the oracle and verifier doubles record zero
    turns, and each row's decision is `passthrough`. M07=A.
    """
    est = S.estate(tmp_path)
    ep = _episode(tmp_path)
    est.answer("idp", "query", BOB, BOB_BASE)
    oracle, verifier = S.oracle(*_forged_moves()), S.passing_verifier()
    control = _registry(ep, "a", est, oracle=oracle, verifier=verifier)
    ctx = est.ctx(tmp_path / "run")

    captured_call = S.call(control, "idp", "query", ctx, **ALICE)
    live_call = S.call(control, "idp", "query", ctx, **BOB)
    assert _text(captured_call) == _text(BASE_ALICE)
    assert _text(live_call) == _text(BOB_BASE)
    assert oracle.requests == 0
    assert verifier.requests == 0
    assert _decisions(ep, "a") == [S.PASSTHROUGH, S.PASSTHROUGH]

    # Positive control: the same doubles ARE driven for a world with facts.
    fact_world = _registry(ep, "b", est, oracle=oracle, verifier=verifier)
    assert S.call(fact_world, "idp", "query", ctx, **ALICE) == SERVED_ALICE
    assert oracle.requests >= 1
    assert verifier.requests >= 1


def test_1224_unchanged_answer_in_a_fact_world_still_passes_the_verifier(tmp_path):
    """d00i_unchanged_answer_still_verified — in a world with facts an unchanged submission is
    still put to the verifier and recorded `passthrough` only once it passes; a failing verdict
    sends the turn back to the oracle.

    In a world with facts, a call for which the oracle submits the base answer unchanged with an
    empty claim is still put to the verifier, and is recorded `passthrough` only after the
    verifier passes it; a verifier that fails it sends the turn back to the oracle. M01=A, F-08.
    """
    est = S.estate(tmp_path)
    ep = _episode(tmp_path)
    oracle = S.oracle(S.submit(BASE_ALICE, S.EMPTY_CLAIM), S.submit(BASE_ALICE, S.EMPTY_CLAIM))
    verifier = S.verifier(S.verdict(False, "fact f1's TGT logon should show in this window"),
                          S.verdict(True))
    reg = _registry(ep, "b", est, oracle=oracle, verifier=verifier)

    served = S.call(reg, "idp", "query", est.ctx(tmp_path / "run"), **ALICE)
    assert _text(served) == _text(BASE_ALICE)
    assert verifier.requests == 2
    assert oracle.submissions() == 2
    assert S.verdict_names(oracle.seen[1], "verifier"), (
        "the failing verdict reached the oracle's next request")
    assert _decisions(ep, "b") == [S.PASSTHROUGH]
    assert not oracle.overrun


def test_1224_served_answer_is_recorded_and_screened_as_real_data(tmp_path):
    """d00j_answer_screened_as_real_data — an oracle-served answer reaches the investigator
    through the query tool as one exit-0 evidence row carrying the served payload, with the
    ticket self-reference screen applied as to a real answer.

    An oracle-served answer reaches the investigator through the query tool as real data does:
    one evidence row in the run's queries table carrying the served payload with exit code 0,
    and the query tool's screens (the ticket self-reference screen) applied to it exactly as to a
    real answer.
    """
    est = _TicketEstate(tmp_path / "estate")
    est.answer("ticket", "list-tickets", TICKETS, TICKETS_BASE)
    forged = {"key": "INC-9001", "status": "open", "summary": "alice TGT anomaly on db-1"}
    served = {"tickets": [SELF_TICKET, OTHER_TICKET, forged], "total": 3}
    claim = S.claim(added=[S.added("fg-t1", "f1")], counts=[S.counted("total", base=2, added_=1)])
    ep = _ticket_episode(tmp_path)
    oracle = S.oracle(S.forge("fg-t1", "f1", "ticket", forged), S.submit(served, claim))
    reg = _registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier())

    run_dir, _gather = _ticket_drive(tmp_path / "branch", est, reg)
    rows = _evidence(run_dir)
    assert len(rows) == 1
    assert rows[0]["exit_code"] == 0
    shown = json.loads(_evidence_payload(run_dir, rows[0]))
    assert [t["key"] for t in shown["tickets"]] == ["INC-7", "INC-9001"], (
        "the served (forged) ticket reaches the investigator; its own case is screened out")
    assert shown["total"] == 2
    assert _decisions(ep, "b") == [S.ORACLE_DECISION]


# ============================================================================================
# Worlds do not share served answers or live base reads (S20, S22).
# ============================================================================================


def test_1224_two_worlds_asking_one_call_get_their_own_served_answers(tmp_path):
    """d17b_served_answers_not_shared — worlds b and c asking one call each get their own oracle
    turn and their own cached served answer; neither cache returns the other's.

    When worlds b and c of one episode issue the same (system, verb, params), each gets its own
    oracle turn and its own cached served answer; neither world's cache returns the other's.
    """
    est = S.estate(tmp_path)
    ep = _episode(tmp_path)
    forged_c = {"action": "password-reset", "event_id": "e-9002", "user": "alice"}
    served_c = {"rows": [ALICE_ROW, forged_c]}
    oracle_b = S.oracle(*_forged_moves())
    oracle_c = S.oracle(*_forged_moves("fg-c1", "f2", row=forged_c, served=served_c))
    reg_b = _registry(ep, "b", est, oracle=oracle_b, verifier=S.passing_verifier())
    reg_c = _registry(ep, "c", est, oracle=oracle_c, verifier=S.passing_verifier())
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


def test_1224_uncaptured_call_is_read_live_by_each_world_for_itself(tmp_path):
    """d17c_live_base_answer_shared_per_family — INVERTED (S20, S22): two worlds asking one
    uncaptured call each read it live for themselves; no live base answer crosses worlds.

    When two worlds of one episode issue the same call the capture never recorded, each world
    reads it live for itself (two adapter calls, one per world); no live base answer crosses
    worlds, and each world's served answer differs from its own base only by its own facts.
    Neither world's live read lands in the family's shared base recording; each lands in that
    world's own oracle-side base store (M16=A).
    """
    est = S.estate(tmp_path)
    ep = _episode(tmp_path, captured=[])
    est.answer("idp", "query", BOB, BOB_BASE)
    family_before = (ep / "served" / "base.jsonl").read_bytes()
    reg_b = _registry(ep, "b", est, oracle=S.oracle(S.submit(BOB_BASE, S.EMPTY_CLAIM)),
                      verifier=S.passing_verifier())
    reg_c = _registry(ep, "c", est, oracle=S.oracle(S.submit(BOB_BASE, S.EMPTY_CLAIM)),
                      verifier=S.passing_verifier())

    assert S.call(reg_b, "idp", "query", est.ctx(tmp_path / "run-b"), **BOB) == BOB_BASE
    assert len(est.calls("idp", "query")) == 1
    assert S.call(reg_c, "idp", "query", est.ctx(tmp_path / "run-c"), **BOB) == BOB_BASE
    assert len(est.calls("idp", "query")) == 2, "world c read the call live for itself"
    assert (ep / "served" / "base.jsonl").read_bytes() == family_before
    for label in ("b", "c"):
        assert _mentions(S.oracle_rows(ep, label, "base"), "e-200"), (
            f"world {label}'s own base store holds its live read")
        assert _decisions(ep, label) == [S.PASSTHROUGH]


# ============================================================================================
# Premises (silent branches, forks, settled).
# ============================================================================================


@pytest.mark.parametrize("facts", ["absent", "null", "empty"])
def test_input_world_facts_key_absent_null_or_empty(tmp_path, facts):
    """b_p009 — a world whose `facts` key is absent or null is refused at load naming `facts`; a
    world with an empty facts list serves every call's base unchanged as `passthrough` with no
    oracle or verifier turn.

    M07=A: the control world has no oracle and an explicit empty facts list is required; a
    facts-free world serves base answers (ledger `passthrough`) with no oracle or verifier turn;
    an absent or null `facts` key is refused at load. Settled regardless: a world with an empty
    facts list serves every call with the base answer unchanged and its ledger decision is
    passthrough.
    """
    doc = S.family_v2()
    world_b = next(w for w in doc["worlds"] if w["world_id"] == "b")
    if facts == "absent":
        del world_b["facts"]
    else:
        world_b["facts"] = None if facts == "null" else []
    ep = _episode(tmp_path, doc=doc)

    if facts != "empty":
        with pytest.raises(S.sym(S.FAMILY, "FamilyError"), match="facts"):
            S.load_world(ep, "b")
        # Positive control: the same manifest with an explicit empty list loads.
        world_b["facts"] = []
        S.write_manifest(ep, doc)
        assert S.load_world(ep, "b") is not None
        return

    est = S.estate(tmp_path)
    est.answer("idp", "query", BOB, BOB_BASE)
    oracle, verifier = S.oracle(), S.verifier()
    reg = _registry(ep, "b", est, oracle=oracle, verifier=verifier)
    ctx = est.ctx(tmp_path / "run")
    assert _text(S.call(reg, "idp", "query", ctx, **ALICE)) == _text(BASE_ALICE)
    assert _text(S.call(reg, "idp", "query", ctx, **BOB)) == _text(BOB_BASE)
    assert oracle.requests == 0
    assert verifier.requests == 0
    assert _decisions(ep, "b") == [S.PASSTHROUGH, S.PASSTHROUGH]


def test_1224_fact_names_an_entity_no_real_answer_contains(tmp_path):
    """b_p021 — an invented entity named by a fact reads the same on every served system that
    knows it: each system's call gets an oracle turn and a verifier pass, the entity's recorded
    field is held, and a submission contradicting it is refused (check 4) before any answer is
    served.

    M01=A: every uncached call in a world with facts gets an oracle turn plus a verifier pass; an
    invented entity reads as existing on every served system that would know it. M13=A: check 4
    is host-exact on the recorded (entity, field). Settled regardless: whatever the world says
    about the entity reads the same in every system and on every call (O2).
    """
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
    reg = _registry(ep, "b", est, oracle=oracle, verifier=verifier)
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


def test_base_query_fails_once_then_the_identical_call_succeeds(tmp_path):
    """b_p050 — a real-system error is not the world's answer: the failing call passes through
    unchanged as `real-error`, the repeat after recovery reads live and is served, and a third
    repeat returns that served answer, not the error.

    M08=A: a real-system error is not cached as the world's answer; a repeat of that call reads
    live, as on a real run; O2's identical-bytes rule applies to answers, not errors. Settled
    regardless: the first error reaches the investigator unchanged (O4), and an oracle failure is
    never recorded as, or confused with, a real-system error.
    """
    est = S.estate(tmp_path)
    ep = _episode(tmp_path, captured=[])
    detail = "idp: token service timed out"
    est.fail("idp", "query", ALICE, fault="UpstreamFault", detail=detail)
    oracle, verifier = S.oracle(*_forged_moves()), S.passing_verifier()
    reg = _registry(ep, "b", est, oracle=oracle, verifier=verifier)
    ctx = est.ctx(tmp_path / "run")

    with pytest.raises(faults.UpstreamFault) as raised:
        S.call(reg, "idp", "query", ctx, **ALICE)
    assert str(raised.value) == str(faults.UpstreamFault(detail))
    assert oracle.requests == 0

    est.answer("idp", "query", ALICE, BASE_ALICE)  # the system recovers
    second = S.call(reg, "idp", "query", ctx, **ALICE)
    assert len(est.calls("idp", "query")) == 2, "the repeat after the error read live"
    assert second == SERVED_ALICE
    turns = oracle.requests
    third = S.call(reg, "idp", "query", ctx, **ALICE)
    assert _text(third) == _text(second)
    assert len(est.calls("idp", "query")) == 2
    assert oracle.requests == turns
    assert _decisions(ep, "b")[:2] == [S.REAL_ERROR, S.ORACLE_DECISION]
    assert len(_decisions(ep, "b")) == 3
    assert not _mentions(_stored(ep, "b", "idp", "query", ALICE), detail)


def test_p098_real_error_on_a_call_the_worlds_facts_cover(tmp_path):
    """s_p052 — a real error on a call the world's facts cover passes through the query tool
    unchanged, exactly as on a real run (same evidence row, same circuit-breaker charge), with no
    oracle turn and nothing stored as the world's answer.

    When the original query errors on the real system for a call that a world's facts would have
    produced telemetry for, the system's error passes through unchanged (O4); the oracle is not
    asked to forge telemetry on top of an error, and nothing is stored as the world's answer
    built from it. F-02=A: the query tool files the re-raised real error exactly as on a real
    run, charging the circuit breaker (the positive control for O4's never-charged rule).
    """
    est = S.estate(tmp_path)
    est.fail("idp", "query", ALICE, fault="TransportFault", detail="idp: connection reset by peer")
    est.answer("idp", "query", BOB, BOB_BASE)

    def turns() -> list:
        return [S.query_turn("idp", "query", ALICE), S.query_turn("idp", "query", BOB),
                S.done_turn()]

    real_dir, _ = S.drive_gather(tmp_path / "real", verbs=_real_registry(est),
                                 tenant=est.place(), gather_turns=turns())
    ep = _episode(tmp_path / "branch", captured=[])
    oracle = S.oracle(S.submit(BOB_BASE, S.EMPTY_CLAIM))
    reg = _registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier())
    branch_dir, _ = S.drive_gather(tmp_path / "branch", verbs=reg, tenant=est.place(),
                                   gather_turns=turns())

    real_rows, branch_rows = _evidence(real_dir), _evidence(branch_dir)
    assert len(branch_rows) == len(real_rows) == 2
    assert _row_view(branch_rows[0]) == _row_view(real_rows[0])
    assert branch_rows[0]["exit_code"] != 0
    assert _breaker(branch_dir).get("systems", {}).get("idp", {}).get("failures") == 1
    assert _breaker(branch_dir).get("systems") == _breaker(real_dir).get("systems")
    assert "user:alice" not in oracle.all_seen(), "the oracle was never asked about the error"
    assert "user:bob" in oracle.all_seen(), "positive control: the answering call got a turn"
    assert _decisions(ep, "b") == [S.REAL_ERROR, S.PASSTHROUGH]
    assert _stored(ep, "b", "idp", "query", ALICE) == []
    assert S.oracle_rows(ep, "b", "forged") == []


def test_first_sibling_live_read_of_an_uncaptured_call_errors_while_the_second_succeeds(
        tmp_path):
    """b_p053 — the first world's live read errors and its investigator gets the error unchanged
    (`real-error`); the second world reads the call for itself and starts from its own
    successful answer; the error never becomes anyone's base.

    Settled by S20, S22: each sibling reads the uncaptured call live for itself; the first
    sibling's investigator gets its error unchanged (`real-error`), and the second sibling's read
    is its own. Settled regardless: the error is world telemetry passed through unchanged (O4),
    never converted into an oracle failure.
    """
    est = S.estate(tmp_path)
    ep = _episode(tmp_path, captured=[])
    detail = "idp: replica lagging behind primary"
    est.fail("idp", "query", ALICE, fault="UpstreamFault", detail=detail)
    family_before = (ep / "served" / "base.jsonl").read_bytes()
    oracle_b, oracle_c = S.oracle(), S.oracle(S.submit(BASE_ALICE, S.EMPTY_CLAIM))
    verifier_c = S.passing_verifier()
    reg_b = _registry(ep, "b", est, oracle=oracle_b, verifier=S.verifier())
    reg_c = _registry(ep, "c", est, oracle=oracle_c, verifier=verifier_c)

    with pytest.raises(faults.UpstreamFault) as raised:
        S.call(reg_b, "idp", "query", est.ctx(tmp_path / "run-b"), **ALICE)
    assert type(raised.value) is faults.UpstreamFault
    assert detail in str(raised.value)
    assert oracle_b.requests == 0
    assert _decisions(ep, "b") == [S.REAL_ERROR]

    est.answer("idp", "query", ALICE, BASE_ALICE)
    assert S.call(reg_c, "idp", "query", est.ctx(tmp_path / "run-c"), **ALICE) == BASE_ALICE
    assert len(est.calls("idp", "query")) == 2, "world c read the call for itself"
    assert "e-100" in verifier_c.all_seen(), "world c's turn started from its own answer"
    assert detail not in oracle_c.all_seen() + verifier_c.all_seen()
    assert _decisions(ep, "c") == [S.PASSTHROUGH]
    assert _mentions(S.oracle_rows(ep, "c", "base"), "e-100")
    assert not _mentions(S.oracle_rows(ep, "b", "base"), "e-100")
    assert (ep / "served" / "base.jsonl").read_bytes() == family_before


def test_live_base_answer_for_an_uncaptured_call_changes_between_two_siblings_reads(tmp_path):
    """s_p054 — RE-PINNED (S22): each world's base for an uncaptured call is its own read; a
    change in the tenant's data shows in a later world's base, and within one world a repeat
    returns the stored answer (S5).

    S22: each world's base is its own read; a change in the tenant's data can show in a later
    world's base; within one world a repeat returns the stored answer (S5). The pre-Amendment-2
    assertion (one family-cached base for every world) is retired.
    """
    est = S.estate(tmp_path)
    ep = _episode(tmp_path, captured=[])
    first = {"rows": [{"action": "logon", "event_id": "e-301", "user": "bob"}]}
    later = {"rows": [{"action": "logon", "event_id": "e-302", "user": "bob"}]}
    est.answer("idp", "query", BOB, first)
    oracle_b = S.oracle(S.submit(first, S.EMPTY_CLAIM))
    oracle_c = S.oracle(S.submit(later, S.EMPTY_CLAIM))
    verifier_c = S.passing_verifier()
    reg_b = _registry(ep, "b", est, oracle=oracle_b, verifier=S.passing_verifier())
    reg_c = _registry(ep, "c", est, oracle=oracle_c, verifier=verifier_c)
    ctx_b = est.ctx(tmp_path / "run-b")

    got_b = S.call(reg_b, "idp", "query", ctx_b, **BOB)
    est.answer("idp", "query", BOB, later)  # the tenant's data moves between the two reads
    got_c = S.call(reg_c, "idp", "query", est.ctx(tmp_path / "run-c"), **BOB)
    assert got_b == first
    assert got_c == later
    assert "e-302" in verifier_c.all_seen()
    assert "e-301" not in verifier_c.all_seen()

    reads = len(est.calls("idp", "query"))
    assert reads == 2
    again = S.call(reg_b, "idp", "query", ctx_b, **BOB)
    assert _text(again) == _text(got_b), "within one world the stored answer is returned"
    assert len(est.calls("idp", "query")) == reads
    assert _mentions(S.oracle_rows(ep, "b", "base"), "e-301")
    assert _mentions(S.oracle_rows(ep, "c", "base"), "e-302")
    assert not _mentions(S.oracle_rows(ep, "c", "base"), "e-301")


def test_conc_23_two_siblings_ask_one_uncaptured_call_together(tmp_path):
    """b_p055 — two siblings in different worlds asking one uncaptured call at the same moment
    send two tenant reads, one per world, and each world starts from its own read.

    Settled by S20, S22: two siblings asking at once send two tenant reads, one per world, each
    counted against its own sibling's slice (S18). The pre-Amendment-2 bound ("the family holds
    exactly one base answer") is refuted by S20: no family-wide live-base cache exists.
    """
    est = S.estate(tmp_path)
    ep = _episode(tmp_path, captured=[])
    est.answer("idp", "query", BOB, BOB_BASE)
    family_before = (ep / "served" / "base.jsonl").read_bytes()
    regs = {label: _registry(ep, label, est,
                             oracle=S.oracle(S.submit(BOB_BASE, S.EMPTY_CLAIM)),
                             verifier=S.passing_verifier()) for label in ("b", "c")}
    ctxs = {label: est.ctx(tmp_path / f"run-{label}") for label in ("b", "c")}
    gate = threading.Barrier(2)

    def ask(label: str) -> Any:
        gate.wait(timeout=30)
        return S.call(regs[label], "idp", "query", ctxs[label], **BOB)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        answers = dict(zip(("b", "c"), pool.map(ask, ("b", "c")), strict=True))

    assert answers == {"b": BOB_BASE, "c": BOB_BASE}
    assert len(est.calls("idp", "query")) == 2, "one live read per world"
    for label in ("b", "c"):
        assert _mentions(S.oracle_rows(ep, label, "base"), "e-200")
        assert _decisions(ep, label) == [S.PASSTHROUGH]
    assert (ep / "served" / "base.jsonl").read_bytes() == family_before


def test_input_same_call_with_params_in_a_different_key_order(tmp_path):
    """b_p062 — a re-issued call with its params in another key order is the same call (same
    bytes, no new turn); a respelling (an omitted default) is a distinct call that gets its own
    turn and reuses the frozen forged row rather than forging a second one.

    N08: the cache key uses canonical JSON of params; every other respelling is a distinct call,
    held consistent by recorded facts and frozen rows. Settled regardless: whichever call counts
    as new, any entity field it reveals reads the same as in the earlier answers (O2); S4: frozen
    rows are reused (same forged_id, same values), no second row.
    """
    est = S.estate(tmp_path)
    ep = _episode(tmp_path)
    est.answer("idp", "query", ALICE, BASE_ALICE)  # what a live read of the respelled call gets
    oracle = S.oracle(*_forged_moves(), S.submit(SERVED_ALICE, CLAIM_ALICE))
    reg = _registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier())
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


def test_input_fact_lies_outside_every_window_the_investigator_asks_for(tmp_path):
    """s_p072 — a fact outside every window the investigator asks for leaves every call a
    verified passthrough, and the judge is shown the world (its fact and the passthrough rows)
    as a world to grade, not a withheld one.

    A fact outside the window of every call the investigator makes leaves every call a
    passthrough: all served answers equal their base answers, the ledger decisions are
    passthrough, and the judge's input shows the fact never reached the investigator, which is a
    finding and not a withheld case (no mechanical bucket). M01=A (each call still gets a
    verifier pass), O11, M19=A (the bucket is the judge model's).

    Judge side, as asserted: world b's own world-scope draw (the judge double's call naming
    world b) is handed the fact's statement and the `passthrough` decisions, and `judge.yaml`
    records for world b exactly the bucket the judge model replied (`analyze-discipline`) —
    graded from the reply, neither withheld (no bucket) nor given a host-computed one. What
    the judge model concludes about an unreached fact is its judgement and is not pinned.
    """
    est = S.estate(tmp_path)
    ep = _episode(tmp_path, captured=[])
    early = S.query_params("user:alice", start="2026-07-27T00:00:00Z",
                           end="2026-07-27T06:00:00Z")
    morning = S.query_params("host:db-1", start="2026-07-28T09:00:00Z",
                             end="2026-07-28T10:00:00Z")
    early_base = {"rows": [{"action": "logon", "event_id": "e-050", "user": "alice"}]}
    morning_base = {"rows": [{"action": "ssh", "event_id": "e-060", "user": "carol"}]}
    est.answer("idp", "query", early, early_base)
    est.answer("idp", "query", morning, morning_base)
    oracle = S.oracle(S.submit(early_base, S.EMPTY_CLAIM), S.submit(morning_base, S.EMPTY_CLAIM))
    verifier = S.passing_verifier()
    reg = _registry(ep, "b", est, oracle=oracle, verifier=verifier)
    ctx = est.ctx(tmp_path / "run")

    assert S.call(reg, "idp", "query", ctx, **early) == early_base
    assert S.call(reg, "idp", "query", ctx, **morning) == morning_base
    assert _decisions(ep, "b") == [S.PASSTHROUGH, S.PASSTHROUGH]
    assert verifier.requests == 2
    statement = S.fact()["statement"]
    assert statement in verifier.seen[0]
    assert "2026-07-27T06:00:00Z" in verifier.seen[0]

    judged = S.judged_episode(tmp_path / "judged", ledgers={"b": S.ledger_rows(ep, "b")})
    judge = S.FakeJudge(default=_judge_reply(bucket="analyze-discipline"))
    _grade(judged, judge)
    world_b = [p for p, agent in zip(judge.prompts, judge.agent_ids, strict=True)
               if _judged_label(agent) == "b"]
    assert world_b, "world b got no world-scope draw: it was withheld from the judge"
    assert any(statement in p and S.PASSTHROUGH in p for p in world_b), (
        "world b's draw was not handed its fact and its passthrough decisions")
    row_b = J.world_rows(J.judge_record(judged)).get("b") or {}
    assert row_b.get("bucket") == "analyze-discipline", (
        f"judge.yaml does not record the judge model's bucket for world b: {row_b!r}")


@pytest.mark.parametrize("body", ["html", "truncated", "empty", "null", "error-like",
                                  "undecodable"])
def test_base_answer_is_a_non_answer_body(tmp_path, body):
    """s_p073 — a non-answer body with a success signal is the base answer: framed untrusted to
    the oracle, served unchanged by a world with no covering fact, and never reclassified as an
    oracle failure or a real-system error.

    That body is the base answer: it is handed to the oracle framed as untrusted (O7), a world
    with no covering fact serves it unchanged, a covering fact changes it only by claimed
    differences (O3), and an undecodable body causes no crash; it is not reclassified as an
    oracle failure or as a real-system error.
    """
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

    control_oracle = S.oracle()
    control = _registry(ep, "a", est, oracle=control_oracle, verifier=S.verifier())
    assert _text(S.call(control, "idp", "query", ctx, **BOB)) == _text(payload)
    assert control_oracle.requests == 0
    assert _decisions(ep, "a") == [S.PASSTHROUGH]

    oracle = S.oracle(S.submit(payload, S.EMPTY_CLAIM))
    reg = _registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier())
    assert _text(S.call(reg, "idp", "query", ctx, **BOB)) == _text(payload)
    assert _decisions(ep, "b") == [S.PASSTHROUGH]
    assert oracle.requests >= 1
    if marker is not None:
        S.assert_wrapped_untrusted(oracle.seen[0], marker, f"the {body} base body")


def test_1224_metadata_call_after_forging_introduced_a_new_source(tmp_path):
    """b_p080 — in a world with facts, a metadata call made after the oracle forged telemetry
    still gets its own oracle turn and verifier pass, so the oracle can hold it consistent with
    the forged rows.

    M01=A: every uncached call in a world with facts gets an oracle turn plus a verifier pass
    (the oracle decides `passthrough`); metadata calls are held consistent with forged sources.
    Settled regardless: the answer differs from base only by what the facts imply (O3), and its
    served answer never contradicts a frozen forged row or recorded fact (O2).
    """
    est = S.estate(tmp_path)
    ep = _episode(tmp_path, captured=[])
    forged = {"event_id": "x-9001", "host": "db-1", "process": "kinit",
              "ts": "2026-07-28T15:22:00Z"}
    served = {"events": [*EDR_BASE["events"], forged]}
    health = {"indices": ["edr-events"], "status": "green"}
    est.answer("edr", "query", DB1, EDR_BASE)
    est.answer("edr", "health-check", {}, health)
    oracle = S.oracle(*_forged_moves("fg-e1", system="edr", row=forged, served=served),
                      S.submit(health, S.EMPTY_CLAIM))
    verifier = S.passing_verifier()
    reg = _registry(ep, "b", est, oracle=oracle, verifier=verifier)
    ctx = est.ctx(tmp_path / "run")

    assert S.call(reg, "edr", "query", ctx, **DB1) == served
    turns, checks = oracle.requests, verifier.requests
    assert S.call(reg, "edr", "health-check", ctx) == health
    assert oracle.requests > turns, "the metadata call cost an oracle turn"
    assert verifier.requests > checks, "and a verifier pass"
    assert _decisions(ep, "b") == [S.ORACLE_DECISION, S.PASSTHROUGH]
    assert not oracle.overrun


def test_input_base_answer_is_larger_than_the_oracle_context(tmp_path):
    """b_p081 — a base answer larger than one oracle turn is worked over a handle (the oracle's
    request does not carry it whole) and is served whole; a call whose every submission silently
    drops base rows ends unservable, never served truncated.

    N10: the oracle works over a handle with Python; if no verified answer can be produced the
    call ends unservable; no silently truncated answer is served. Settled regardless: the
    investigator is never served an answer that silently dropped base rows (O3: nothing missing),
    and no failure of this kind reaches the investigator as an oracle error (O4).
    """
    est = S.estate(tmp_path)
    ep = _episode(tmp_path, captured=[])
    everyone = S.query_params("*")
    # Several megabytes: past any single turn's context, so working over a handle is the only
    # way the oracle can take it.
    big = {"rows": [{"action": "logon", "event_id": f"e-{i:06d}", "user": f"u{i:05d}"}
                    for i in range(60000)]}
    hosts = S.query_params("host:*")
    big_hosts = {"rows": [{"action": "logon", "event_id": f"h-{i:06d}", "user": f"h{i:05d}"}
                          for i in range(60000)]}
    est.answer("idp", "query", everyone, big)
    est.answer("idp", "query", hosts, big_hosts)
    truncated = {"rows": big_hosts["rows"][:10]}
    oracle = S.oracle(S.submit(big, S.EMPTY_CLAIM), then=S.submit(truncated, S.EMPTY_CLAIM))
    reg = _registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier(), retry_cap=2)
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
    """s_p083 — a multi-megabyte string value or a very deeply nested base answer neither
    crashes nor hangs the call, and either admitted outcome leaves the records consistent.

    Settled (P083): the sibling neither crashes nor hangs: the call is served within bounds as a
    base-equal answer or fails as an oracle-side failure that never reaches the investigator
    (O4), and whatever is stored and recorded stays readable by the ledger and page readers.

    BOTH outcomes are admitted because the settled assertion itself admits both: whether the
    oracle can take such an answer is a question of its handle and context (N10) and of its own
    judgement, not a host rule, so no ruling picks one. Asserted: the call returns within the
    bound; if it raises, it raises `OracleUnservable` only, with no ledger row and no stored
    answer for the call; if it is served, the answer is the base byte for byte, rowed once
    `passthrough` and stored once. Either way the world's file is still read by the ledger's own
    reader (`Ledger.for_world` absorbs it) and raw off disk. The page-reader half is not driven
    here: this registry-level scenario builds no archived episode for the page to render.
    """
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
    reg = _registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier())
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
    S.sym(S.LEDGER, "Ledger").for_world(S.mod("_episode_handle").Episode.create(ep), TOKEN_B)


def test_p021_base_answer_values_with_control_characters_nul_bidi_and_zero_width(tmp_path):
    """s_p084 — NUL, a bidi override, zero-width characters, ANSI escapes, U+2028, raw newlines
    and an unpaired surrogate in a base answer are carried byte-faithfully; the ledger holds
    exactly one readable row for the call.

    The value is carried through byte-faithfully in the served answer, and the ledger still holds
    exactly one row for the call and stays readable; no reader splits one record into several or
    fails.
    """
    hostile = "nul\x00 bidi‮ zw​ ansi\x1b[31m ls  nl\n lone\ud800 end"
    base = {"rows": [{"event_id": "e-100", "note": hostile, "user": "alice"}]}
    est = S.estate(tmp_path)
    ep = _episode(tmp_path, captured=[])
    est.answer("idp", "query", BOB, base)
    oracle = S.oracle(S.submit(base, S.EMPTY_CLAIM))
    reg = _registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier())

    served = S.call(reg, "idp", "query", est.ctx(tmp_path / "run"), **BOB)
    assert served["rows"][0]["note"] == hostile
    raw = S.ledger_path(ep, "b").read_bytes()
    assert raw.count(b"\n") == 1, "exactly one record line for the call"
    rows = read_jsonl_rows(S.ledger_path(ep, "b"))
    assert len(rows) == 1
    assert rows[0]["source"] == S.PASSTHROUGH
    assert json.loads(rows[0]["payload_text"])["rows"][0]["note"] == hostile
    S.sym(S.LEDGER, "Ledger").for_world(S.mod("_episode_handle").Episode.create(ep), TOKEN_B)


def test_input_base_answer_would_trip_a_query_tool_screen(tmp_path):
    """s_p088 — a base answer carrying the investigation's own ticket, re-served unchanged by
    the oracle, gets exactly the evidence row and screen outcome a real run gets.

    A base answer carrying content the query tool screens specially on real data (a ticket
    citing the investigation's own alert) re-served unchanged by the oracle gets exactly the
    same evidence row and screen outcome as on a real run, because the served answer goes back
    through the query tool exactly as real data does.
    """
    est = _TicketEstate(tmp_path / "estate")
    est.answer("ticket", "list-tickets", TICKETS, TICKETS_BASE)
    real_dir, _ = _ticket_drive(tmp_path / "real", est, _real_registry(est))

    ep = _ticket_episode(tmp_path)
    oracle = S.oracle(S.submit(TICKETS_BASE, S.EMPTY_CLAIM))
    reg = _registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier())
    branch_dir, _ = _ticket_drive(tmp_path / "branch", est, reg)

    real_rows, branch_rows = _evidence(real_dir), _evidence(branch_dir)
    assert len(real_rows) == len(branch_rows) == 1
    assert _row_view(branch_rows[0]) == _row_view(real_rows[0])
    shown = json.loads(_evidence_payload(branch_dir, branch_rows[0]))
    assert json.loads(_evidence_payload(real_dir, real_rows[0])) == shown
    assert RUN_ID not in json.dumps(shown), "the screen withheld the investigation's own ticket"
    assert oracle.requests >= 1
    assert _decisions(ep, "b") == [S.PASSTHROUGH]


def test_input_call_params_cannot_be_stored(tmp_path):
    """s_p089 — a call whose params no record can store is refused by the query tool exactly as
    on a real run: no oracle turn, no cache entry, no ledger row, and the same refusal shown.

    A call whose params cannot be stored or hashed (non-finite number, non-JSON type, enormous
    string) is refused by the query tool as on a real run: no oracle turn, cache entry, ledger
    row or oracle spend results, and the investigator sees the same refusal as in an ordinary
    run. The unstorable shape the code refuses today is params nested past the stored-call
    bound (`PARAMS_NESTING_LIMIT`).

    Paired positive control (R-12), in the SAME registry: a granted, storable call driven
    through the query tool afterwards does reach the oracle and verifier doubles and is rowed
    and stored — so the zero counts above are the refusal's doing, not a registry that never
    consults its oracle.
    """
    deep: dict = {"leaf": "x"}
    for _ in range(40):
        deep = {"n": deep}
    params = {"q": "user:alice", "filter": deep}
    est = S.estate(tmp_path)

    def turns() -> list:
        return [S.query_turn("idp", "query", params), S.done_turn()]

    real_dir, real_gather = S.drive_gather(tmp_path / "real", verbs=_real_registry(est),
                                           tenant=est.place(), gather_turns=turns())
    ep = _episode(tmp_path / "branch")
    oracle = S.oracle(S.submit(BASE_ALICE, S.EMPTY_CLAIM))
    verifier = S.passing_verifier()
    reg = _registry(ep, "b", est, oracle=oracle, verifier=verifier)
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
    """s_p090 — a call the grant denies, and one naming a system the tenant does not serve, are
    refused by the grant decision before serving exactly as on a real run: no oracle turn, no
    cache entry, and the same refusal record.

    A call the investigator's grant denies, or one naming a system the tenant does not serve, is
    refused by the grant decision before serving exactly as on a real run: no oracle turn, no
    cache entry, no oracle budget spent, and the refusal record is as on a real run (O6).

    Paired positive control (R-12), in the SAME registry: a granted call driven through the
    query tool afterwards does reach the oracle and verifier doubles and is rowed and stored —
    so the zero counts above are the grant decision's doing, not a registry that never consults
    its oracle.
    """
    est = S.estate(tmp_path)

    def turns() -> list:
        return [S.query_turn("idp", S.WRITE_VERB, {"host": "db-1"}),
                S.query_turn("crm", "query", {"q": "*"}), S.done_turn()]

    real_dir, _ = S.drive_gather(tmp_path / "real", verbs=_real_registry(est),
                                 tenant=est.place(), gather_turns=turns())
    ep = _episode(tmp_path / "branch")
    oracle = S.oracle(S.submit(BASE_ALICE, S.EMPTY_CLAIM))
    verifier = S.passing_verifier()
    reg = _registry(ep, "b", est, oracle=oracle, verifier=verifier)
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


def test_oracle_conversation_hits_the_model_context_limit_inside_one_call(tmp_path):
    """b_p128 — when the oracle's conversation restarts between attempts of one call, the
    restarted context keeps the prefix, the recorded facts and the recent failure, and the
    attempt count carries on: the call still ends unservable after exactly N attempts.

    N10: if no verified answer can be produced the call ends unservable; no silently truncated
    answer is served. Settled regardless: a restart keeps the same prefix plus the recorded facts
    and recent failures, so the attempt count, the failure history and every frozen row and
    recorded fact still bind the call after it. The restart is forced with the smallest restart
    threshold.
    """
    est = S.estate(tmp_path)
    ep = _episode(tmp_path)
    est.answer("idp", "query", BOB, BOB_BASE)
    oracle = S.oracle(S.record_fact("alice", "department", "finance-ops-7"), *_forged_moves(),
                      then=S.submit({"rows": [*BOB_BASE["rows"], ALICE_ROW]}, S.EMPTY_CLAIM))
    reg = _registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier(), retry_cap=2,
                    restart_after=1)
    ctx = est.ctx(tmp_path / "run")

    assert S.call(reg, "idp", "query", ctx, **ALICE) == SERVED_ALICE
    before = oracle.submissions()
    with pytest.raises(S.unservable_cls()):
        S.call(reg, "idp", "query", ctx, **BOB)
    assert oracle.submissions() - before == 2, "restarts do not reset the attempt count"
    restarted = [i for i in range(1, len(oracle.messages))
                 if len(oracle.messages[i]) < len(oracle.messages[i - 1])]
    assert restarted, "the conversation restarted"
    last = oracle.seen[-1]
    assert S.fact()["statement"] in last, "the restarted context keeps the world block"
    assert "finance-ops-7" in last, "and the recorded facts"
    assert S.verdict_names(last, "check 1"), "and the recent failure"
    assert [r.get("forged_id") for r in S.oracle_rows(ep, "b", "forged")] == ["fg-1"]


def test_conc_19_oracle_side_query_beside_investigator_calls(tmp_path):
    """b_p162 — with cached, oracle-served, passthrough and real-error calls running at once in
    one sibling, the world ledger and evidence hold one complete, correctly attributed row per
    investigator call, and oracle and verifier queries appear only in the oracle-side ledger.

    With many leads in one sibling making cached, oracle-served, passthrough and real-error
    calls concurrently, the world ledger and evidence hold exactly one complete, correctly
    attributed row per investigator call, and exploration, run_query and verifier traffic
    appears only in the oracle-side ledger (O9). The concurrent calls are one gather turn's
    parallel `query` calls, which run on worker threads as parallel leads do (GD-33).
    """
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
    reg = _registry(ep, "b", est, oracle=oracle, verifier=verifier)

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


def test_1224_uncaptured_investigator_call_and_the_world_ledger_row_count(tmp_path):
    """b_p163 — an uncaptured investigator call read live in a world with facts leaves exactly
    one world-ledger row (its decision) and no base row; its live base answer lives in the
    world's own base store.

    M16=A: one ledger row per investigator call (decision `passthrough`, `oracle`, `real-error`
    or `refused`); a world's live base answers live in that world's own per-world base store,
    not as world-ledger rows. Settled regardless: the ledger holds one row per investigator call
    (O9: row count equals the sibling's own calls).
    """
    est = S.estate(tmp_path)
    ep = _episode(tmp_path, captured=[])
    est.answer("idp", "query", ALICE, BASE_ALICE)
    family_before = (ep / "served" / "base.jsonl").read_bytes()
    reg = _registry(ep, "b", est, oracle=S.oracle(*_forged_moves()),
                    verifier=S.passing_verifier())

    S.call(reg, "idp", "query", est.ctx(tmp_path / "run"), **ALICE)
    rows = S.ledger_rows(ep, "b")
    assert [r["source"] for r in rows] == [S.ORACLE_DECISION]
    assert not any(r.get("world_id") is None for r in rows)
    assert _mentions(S.oracle_rows(ep, "b", "base"), "e-100")
    assert (ep / "served" / "base.jsonl").read_bytes() == family_before


def test_sibling_dies_after_the_answer_is_stored_before_its_ledger_row(tmp_path):
    """s_p166 — after a crash between storing a served answer and recording its ledger row, the
    resumed sibling's re-issued call gets the identical stored answer with no new turn, and the
    ledger ends with exactly one row for the call.

    After a crash between storing a served answer and recording the call, a resumed sibling's
    re-issued call is served the identical stored answer (O2) and the ledger ends with exactly
    one row for that call, neither zero nor two (O9). The crash is the state it leaves on disk:
    the answer is in the world's store and the call's ledger row never landed.
    """
    est = S.estate(tmp_path)
    ep = _episode(tmp_path)
    first_run = _registry(ep, "b", est, oracle=S.oracle(*_forged_moves()),
                          verifier=S.passing_verifier())
    first = S.call(first_run, "idp", "query", est.ctx(tmp_path / "run"), **ALICE)
    assert len(_stored(ep, "b", "idp", "query", ALICE)) == 1

    path = S.ledger_path(ep, "b")
    kept = [r for r in S.ledger_rows(ep, "b") if _asked(r) != ALICE]
    path.write_text("".join(json.dumps(r) + "\n" for r in kept), encoding="utf-8")

    oracle, verifier = S.oracle(), S.verifier()
    resumed = _registry(ep, "b", est, oracle=oracle, verifier=verifier)
    again = S.call(resumed, "idp", "query", est.ctx(tmp_path / "run"), **ALICE)
    assert _text(again) == _text(first)
    assert oracle.requests == 0
    assert verifier.requests == 0
    assert len(_rows_for(ep, "b", "idp", "query", ALICE)) == 1


def test_torn_last_line_in_the_forged_store_at_resume(tmp_path):
    """s_p167 — a half-written trailing record in the forged store, the served-answer store or
    the oracle-side ledger is never read as a valid row, answer or fact, is not served, and does
    not crash the resume; it is treated as not written.

    A half-written trailing record in the forged store, served-answer store or oracle-side
    ledger after a crash is never read as a valid row, answer or fact, is not served, and does
    not crash the resume; it is treated as not written. A complete record before it is read as
    written (the positive control).
    """
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
    reg = _registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier())
    ctx = est.ctx(tmp_path / "run")

    assert S.call(reg, "idp", "query", ctx, **ALICE) == SERVED_ALICE
    assert oracle.requests == 0, "the complete stored answer is served from the store"
    assert S.call(reg, "idp", "query", ctx, **window) == served_2
    assert oracle.requests >= 1, "the torn answer was treated as not written"
    complete = [r for r in _complete_rows(store / "forged.jsonl") if r.get("forged_id") == "fg-2"]
    assert [r.get("row") for r in complete] == [forged_2]

    later = S.oracle()
    resumed = _registry(ep, "b", est, oracle=later, verifier=S.verifier())
    assert S.call(resumed, "idp", "query", ctx, **window) == served_2
    assert later.requests == 0, "the answer written after the torn line reads back whole"


def test_sibling_resumed_twice_the_second_resume_crashes_mid_call(tmp_path):
    """s_p169 — across two crashes and resumes (the second mid-turn), every repeated call is
    served the same stored answer and the stores and ledger match a run that never crashed in
    the number and attribution of rows.

    After any number of crashes and resumes, every call repeated by the investigator is served
    the same stored answer as before (O2), and the stores, ledger and evidence match a run that
    never crashed in the number and attribution of rows (O9). The mid-turn crash is the state it
    leaves on disk: the turn's exploration trace in the oracle-side ledger and nothing committed
    for the call (M15=B: forged rows and facts commit with the verified answer).
    """
    est = S.estate(tmp_path)
    for system, verb, params, payload in (("edr", "query", DB1, EDR_BASE),
                                          ("siem-x", "lookup", SIEM_ALICE, SIEM_BASE)):
        est.answer(system, verb, params, payload)
    a, b, c = ("idp", "query", ALICE), ("edr", "query", DB1), ("siem-x", "lookup", SIEM_ALICE)

    def ask(reg: Any, call: tuple[str, str, dict], run: Path) -> str:
        system, verb, params = call
        return _text(S.call(reg, system, verb, est.ctx(run), **params))

    ref_ep = _episode(tmp_path / "ref")
    ref_oracle = S.oracle(*_forged_moves(), S.submit(EDR_BASE, S.EMPTY_CLAIM),
                          S.submit(SIEM_BASE, S.EMPTY_CLAIM))
    ref = _registry(ref_ep, "b", est, oracle=ref_oracle, verifier=S.passing_verifier())
    ref_answers = [ask(ref, call, tmp_path / "ref-run") for call in (a, b, a, c, b)]

    ep = _episode(tmp_path / "crash")
    run = tmp_path / "crash-run"
    first = _registry(ep, "b", est, oracle=S.oracle(*_forged_moves(),
                                                    S.submit(EDR_BASE, S.EMPTY_CLAIM)),
                      verifier=S.passing_verifier())
    got = [ask(first, a, run), ask(first, b, run)]
    second_oracle = S.oracle()
    second = _registry(ep, "b", est, oracle=second_oracle, verifier=S.verifier())
    got.append(ask(second, a, run))
    assert second_oracle.requests == 0
    with (S.oracle_dir(ep, "b") / "ledger.jsonl").open("a", encoding="utf-8") as side:
        side.write(json.dumps({"actor": "oracle", "system": "siem-x", "verb": "query",
                               "params": S.query_params("entity:alice")}) + "\n")
    third = _registry(ep, "b", est, oracle=S.oracle(S.submit(SIEM_BASE, S.EMPTY_CLAIM)),
                      verifier=S.passing_verifier())
    got += [ask(third, c, run), ask(third, b, run)]

    assert got == ref_answers, "every repeat is served the same stored answer"

    def attribution(rows: list[dict]) -> list[tuple]:
        return [(r.get("system"), r.get("verb"), r.get("source"), r.get("world_id"))
                for r in rows]

    assert attribution(S.ledger_rows(ep, "b")) == attribution(S.ledger_rows(ref_ep, "b"))
    for store in ("answers", "forged"):
        assert len(S.oracle_rows(ep, "b", store)) == len(S.oracle_rows(ref_ep, "b", store)), (
            store)


def test_control_world_when_every_other_world_is_unservable(tmp_path, monkeypatch):
    """b_p194 — when every world with facts fails pre-flight and only the control world is
    left, the outcome record says `unusable` naming both failed worlds, no sibling starts and no
    findings are graded.

    M07=A: the control world has no oracle; it can be unservable only through a non-oracle cause
    and then counts toward O5 like any world. Settled regardless: with two or more unservable
    worlds the family is unusable (O5). Every fact-world turn here ends without a valid
    submission (M03=A), one attempt allowed.
    """
    monkeypatch.setenv(S.KNOB_RETRY_CAP, "1")
    est = S.estate(tmp_path)
    oracle = S.oracle(then=S.text_only())
    judge = S.FakeJudge(default=_judge_reply())
    launch = S.launch(tmp_path, est, calls=[S.Call("idp", "query", ALICE, BASE_ALICE)],
                      oracle=oracle, verifier=S.passing_verifier(), judge=judge)

    outcome = S.read_outcome(launch.ep)
    assert outcome is not None
    assert outcome["outcome"] == "unusable"
    failed = {w["world"] for w in outcome["unservable_worlds"]}
    assert failed == {"b", "c"}, "the control world is not unservable through the oracle"
    assert oracle.requests >= 2
    assert launch.spawn.launches == [], "no sibling starts for an unusable family"
    assert judge.calls == 0


def test_input_oracle_budget_is_zero_or_unreadable(tmp_path, monkeypatch):
    """b_p209 — with a zero oracle budget a world with facts is unservable (reason `budget`) at
    its first call that needs the oracle and fails pre-flight, a facts-free world still serves,
    and a negative or non-numeric budget is refused naming the knob.

    M07=A: a facts-free world spends no oracle budget. D1 (M10): exhaustion makes the world
    unservable with reason `budget`; no unit is pinned. Settled regardless: with a budget of
    zero a world with facts is unservable at its first call that needs the oracle (O14), and a
    negative or non-numeric budget is refused with a named reason and never read as unlimited.
    """
    est = S.estate(tmp_path / "serving")
    ep = _episode(tmp_path / "serving")
    ctx = est.ctx(tmp_path / "run")
    control_oracle = S.oracle()
    control = _registry(ep, "a", est, oracle=control_oracle, verifier=S.verifier(), budget=0)
    assert _text(S.call(control, "idp", "query", ctx, **ALICE)) == _text(BASE_ALICE)
    assert control_oracle.requests == 0
    assert _decisions(ep, "a") == [S.PASSTHROUGH]

    fact_world = _registry(ep, "b", est, oracle=S.oracle(*_forged_moves()),
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
                      verifier=S.passing_verifier(), judge=S.FakeJudge(default=_judge_reply()))
    outcome = S.read_outcome(launch.ep)
    assert outcome is not None
    assert outcome["outcome"] == "unusable"
    by_world = {w["world"]: w for w in outcome["unservable_worlds"]}
    assert set(by_world) == {"b", "c"}
    assert all(S.REASON_BUDGET in str(w.get("reason")) for w in by_world.values())


def test_conc_25_one_worlds_served_answer_beside_another_worlds_base_read(tmp_path):
    """s_p220 — RE-PINNED (S20): a world's served answer never reaches another world's base; the
    only cross-world store, the base recording, is never written by a sibling.

    A world's served answer never reaches another world's base. The only cross-world store is
    the base recording, which the launcher writes once before any sibling starts and no sibling
    ever writes (S20). Driven with world b storing its served answer while world c reads the same
    call.
    """
    est = S.estate(tmp_path)
    ep = _episode(tmp_path)
    family_before = (ep / "served" / "base.jsonl").read_bytes()
    oracle_c, verifier_c = S.oracle(S.submit(BASE_ALICE, S.EMPTY_CLAIM)), S.passing_verifier()
    regs = {"b": _registry(ep, "b", est, oracle=S.oracle(*_forged_moves()),
                           verifier=S.passing_verifier()),
            "c": _registry(ep, "c", est, oracle=oracle_c, verifier=verifier_c)}
    gate = threading.Barrier(2)

    def ask(label: str) -> Any:
        gate.wait(timeout=30)
        return S.call(regs[label], "idp", "query", est.ctx(tmp_path / f"run-{label}"), **ALICE)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        got = dict(zip(("b", "c"), pool.map(ask, ("b", "c")), strict=True))

    assert got == {"b": SERVED_ALICE, "c": BASE_ALICE}
    assert "e-9001" not in oracle_c.all_seen() + verifier_c.all_seen()
    assert (ep / "served" / "base.jsonl").read_bytes() == family_before
    assert not _mentions(_complete_rows(S.oracle_dir(ep, "c") / "base.jsonl"), "e-9001")
    assert not _mentions(S.ledger_rows(ep, "c"), "e-9001")


def test_conc_31_reader_meets_a_half_written_shared_entry(tmp_path):
    """s_p222 — RE-PINNED (S19, S20): no sibling writes a store another sibling reads; serving a
    world changes only that world's own ledger and oracle-side state, never the base recording or
    another world's files.

    No sibling writes a store another sibling reads. The base recording is complete before any
    sibling starts, so no sibling ever reads a partial shared entry (S19, S20).
    """
    est = S.estate(tmp_path)
    ep = _episode(tmp_path)
    est.answer("idp", "query", BOB, BOB_BASE)

    def snapshot() -> dict[Path, bytes]:
        return {p: p.read_bytes() for p in ep.rglob("*") if p.is_file()}

    def own(label: str, path: Path) -> bool:
        return path == S.ledger_path(ep, label) or S.oracle_dir(ep, label) in path.parents

    for label, other in (("b", "c"), ("c", "b")):
        reg = _registry(ep, label, est, oracle=S.oracle(
            S.submit(BASE_ALICE, S.EMPTY_CLAIM), S.submit(BOB_BASE, S.EMPTY_CLAIM)),
            verifier=S.passing_verifier())
        before = snapshot()
        ctx = est.ctx(tmp_path / f"run-{label}")
        S.call(reg, "idp", "query", ctx, **ALICE)
        S.call(reg, "idp", "query", ctx, **BOB)
        after = snapshot()
        changed = {p for p in after if before.get(p) != after[p]}
        assert any(own(label, p) for p in changed), (
            "positive control: serving wrote this world's own records")
        foreign = sorted(str(p.relative_to(ep)) for p in changed if not own(label, p))
        assert foreign == [], f"world {label} wrote outside its own state: {foreign}"
        assert not any(own(other, p) for p in changed)


#: R-01: the post-branch call's params marker. Neither it nor the pre-branch call's marker
#: (`user:alice`) contains the other, so `_CallRouted` tells the two replayed calls apart.
POST_Q = "tgt:alice"
POST_BASE = {"rows": [{"action": "logon", "event_id": "e-300", "user": "alice"}]}


@pytest.mark.parametrize("edited_call", ["pre-branch", "neither", "post-branch"])
def test_1224_world_fact_covers_a_call_the_investigator_made_before_the_branch_point(
        tmp_path, monkeypatch, edited_call):
    """b_p227 — a pre-branch call is fixed: a world whose oracle would change the answer to a
    call the original run made before the branch point fails pre-flight, while the same claimed
    edit to a call made after the branch point is accepted, and serving both unchanged passes.

    M01=A: pre-branch calls are fixed (served unchanged), so a world whose facts would change a
    pre-branch answer fails pre-flight (the prefix is fixed, a contradicting world is
    unservable); a world may change only a post-branch call.

    One launch shape for every arm (R-01): the source run holds one captured idp call on each
    side of the branch point — `user:alice` under the inherited lead, `tgt:alice` under a lead
    dispatched after the branch message (`S.post_branch_call`). The oracle double answers each
    replayed call by its params marker (`_CallRouted`). `pre-branch`: the pre-branch answer is
    changed by a declared, claimed edit, the post-branch one served unchanged — both fact worlds
    fail pre-flight, each record naming the pre-branch call, and nothing launches. `post-branch`:
    the SAME edit lands on the post-branch answer, the pre-branch one served unchanged — the
    launch is `accepted` (the paired positive control). `neither`: both unchanged, `accepted`.
    The arms' scripts differ only in which call carries the edit, so the call's side of the
    branch point is the only thing that fails the first arm and passes the third.
    """
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
                      judge=S.FakeJudge(default=_judge_reply()))

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
    """b_fu20 — whatever makes a call unservable (N failed checks, an oracle-side exception on
    every attempt, the budget running out mid-call), the world ledger holds no row for it — no
    `fault` row, no oracle error text — and nothing is stored as its answer.

    M16=A: an unservable call leaves no world-ledger row (its reason is in the world's own
    record, S7); the registry's fault-row writer exempts `OracleUnservable` (RF-1). For each of
    the three causes the world ledger holds no row with `source: fault` for that call and no row
    carrying the oracle's error text; no served answer is stored and no served-answer record is
    written. The oracle-side exception is a model-provider outage on every attempt: the
    `ModelHTTPError` 503 the model client raises once its own retries give up (GPR-01). The
    budget runs out on a tiny per-world budget (`1e-9`): every double is named after a priced
    model (`S.double_model_name`, R-08), so the oracle's requests accrue positive spend in
    whatever unit the implementer picks — no unit, and no unpriced-model fallback, is relied on
    (D1).
    """
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
    reg = _registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier(), **knobs)
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


def test_1224_unservable_call_after_its_live_base_answer_was_recorded(tmp_path):
    """b_fu21 — an uncaptured call whose live base read succeeded and whose oracle then exhausts
    its attempts accounts for no world-ledger row: no base row, no decision row, no fault row;
    its live answer sits only in the world's own base store.

    M16=A: a world's live base answers live in that world's own per-world base store, not as
    world-ledger rows; an unservable call leaves no world-ledger row. The world ledger holds no
    `source: fault` row for the call and no row carrying the oracle's error (O4). The call
    accounts for no decision row, because no served answer was stored (key flow step 7 stores
    and records only after success).
    """
    est = S.estate(tmp_path)
    ep = _episode(tmp_path, captured=[])
    est.answer("idp", "query", ALICE, BASE_ALICE)
    oracle = S.oracle(then=S.submit(UNDECLARED, S.EMPTY_CLAIM))
    reg = _registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier(), retry_cap=2)

    with pytest.raises(S.unservable_cls()):
        S.call(reg, "idp", "query", est.ctx(tmp_path / "run"), **ALICE)
    assert len(est.calls("idp", "query")) == 1, "the live base read happened"
    assert _mentions(S.oracle_rows(ep, "b", "base"), "e-100"), (
        "positive control: the live answer was recorded — in the world's own base store")
    assert S.ledger_rows(ep, "b") == []
    assert _stored(ep, "b", "idp", "query", ALICE) == []


def test_1224_ledger_records_oracle_and_real_error_at_the_world_tier_only(tmp_path):
    """pco05_ledger_record_words — `Ledger.record` records `oracle` and `real-error` at the
    world tier and refuses them at the family tier; `staged` and `patched` are refused;
    `captured` stays primer-only; a live-miss base answer is not written as a world-ledger row.

    Ledger.record records `oracle` and `real-error` at the world tier and refuses them at the
    family tier; `staged` and `patched` are refused; `captured` stays primer-only; a live-miss
    base answer is not written as a world-ledger row (it lives in the world's own base store,
    M16=A). PCO-05.
    """
    ep = S.episode_v2(tmp_path / "unit")
    ledger = S.world_ledger(ep, "b")
    served_call = S.sym(S.LEDGER, "ServedCall")
    ledger_error = S.sym(S.LEDGER, "LedgerError")

    def row(source: str, q: str, world_id: str | None) -> Any:
        return served_call(system="idp", verb="query", params=S.query_params(q),
                           payload_text=_text(BASE_ALICE), source=source, world_id=world_id)

    for word in (S.ORACLE_DECISION, S.REAL_ERROR):
        ledger.record(row(word, f"user:{word}", TOKEN_B))
        with pytest.raises(ledger_error):
            ledger.record(row(word, f"user:{word}-family", None))
    for word in S.RETIRED_DECISIONS:
        with pytest.raises(ledger_error):
            ledger.record(row(word, f"user:{word}", TOKEN_B))
    for world_id in (None, TOKEN_B):
        with pytest.raises(ledger_error):
            ledger.record(row("captured", "user:captured", world_id))
    assert _decisions(ep, "b") == [S.ORACLE_DECISION, S.REAL_ERROR]

    est = S.estate(tmp_path)
    serving = _episode(tmp_path / "serving", captured=[])
    est.answer("idp", "query", ALICE, BASE_ALICE)
    reg = _registry(serving, "b", est, oracle=S.oracle(*_forged_moves()),
                    verifier=S.passing_verifier())
    S.call(reg, "idp", "query", est.ctx(tmp_path / "run"), **ALICE)
    assert _decisions(serving, "b") == [S.ORACLE_DECISION], "no live-miss base row"
    assert _mentions(S.oracle_rows(serving, "b", "base"), "e-100")
