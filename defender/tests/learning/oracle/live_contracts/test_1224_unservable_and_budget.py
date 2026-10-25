from __future__ import annotations

import contextlib
import json
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from defender.configuration._env import FatalConfigError
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.learning.oracle.live_contracts import _spec1224 as S


RUN_ID = "run-1224"
ALICE = S.query_params("user:alice")
#: Identical to what `S.source_run` makes the estate answer for this call, so a sibling
#: scenario's live base and its source capture agree.
ALICE_ROWS = S.default_calls()[0].payload
BOB = S.query_params("user:bob")
BOB_ROWS = {"rows": [{"user": "bob", "event_id": "e-200", "action": "logon", "host": "web-2",
                      "ts": "2026-07-28T15:05:00Z"}]}
CAROL = S.query_params("user:carol")
CAROL_ROWS = {"rows": [{"user": "carol", "event_id": "e-300", "action": "logon",
                        "host": "web-3", "ts": "2026-07-28T15:07:00Z"}]}
HOST_DB1 = S.query_params("host:db-1")
HOST_DB2 = S.query_params("host:db-2")
EDR_ROWS = S.default_calls()[1].payload
LOOKUP_ALICE = {"entity": "alice", "risk": "low", "record_id": "r-0001"}
#: A row the claim never declares: O3's "an oracle double that adds an undeclared row".
UNDECLARED = {"user": "alice", "event_id": "e-999", "action": "logon", "host": "db-1",
              "ts": "2026-07-28T15:22:00Z"}
#: World b's fact f1 ("alice obtained a TGT and logged on to db-1 at 15:22Z"), as one forged
#: row with the base answer's own columns and value types and an id no real answer holds.
FORGED_ROW = {"user": "alice", "event_id": "e-9001", "action": "logon", "host": "db-1",
              "ts": "2026-07-28T15:22:00Z"}
TINY_BUDGET = 1e-9
SUBMIT = S.COINED["tool.submit"]


def _with_undeclared(answer: dict) -> dict:
    return {"rows": [*answer["rows"], dict(UNDECLARED)]}


def _q(q: str, system: str = "idp") -> Any:
    """One gather `query` call on a stub system's `query` verb."""
    return S.query_turn(system, "query", {"q": q})


def _explore(q: str = "host:db-1") -> S.Move:
    """One oracle-side (or verifier-side) exploration query on edr."""
    return S.run_query("edr", "query", {"q": q})


def _unservable(exc: BaseException) -> bool:
    """`exc` is the coined `OracleUnservable` (or an exception group holding one)."""
    cls = S.unservable_cls()
    if isinstance(exc, cls):
        return True
    return isinstance(exc, BaseExceptionGroup) and exc.subgroup(cls) is not None


def _the_unservable(exc: BaseException) -> BaseException:
    cls = S.unservable_cls()
    while isinstance(exc, BaseExceptionGroup):
        exc = exc.subgroup(cls).exceptions[0]
    return exc


def _no_preflight(*_a: Any, **_k: Any) -> int:
    """The role-preflight seam, neutralised whatever it is called with (M25 scopes the
    production one by a branching flag)."""
    return 0


def _no_visualize(*_a: Any, **_k: Any) -> None:
    return None


def _main_fn(system: str = "idp") -> Any:
    H = S.replay_harness()
    return H.ReplayFn([
        H.Turn(tool_calls=[("gather", {
            "lead_id": S.LEAD, "system": system, "goal": f"measure the {system} lead",
            "what_to_summarize": ["what the system says"]})]),
        H.Turn(text="Investigation complete."),
    ])


@dataclass
class _Run:
    """One driven investigation and its records, read raw off the run dir."""

    run_dir: Path
    main: Any
    gather: Any
    raised: BaseException | None = None
    #: What `drive()` returned (None for a run that ended by raising), and the run states the
    #: investigator's calls carried into the registry (`S.tap_run_states`).
    summary: dict | None = None
    carried: list[Any] = field(default_factory=list)

    @property
    def state(self) -> Any:
        """The run's one `RunState` (#1235 round 2): the driver's `summary["run_state"]`, or —
        for a run that ended by raising — the one state its calls carried."""
        if self.summary is not None:
            return self.summary["run_state"]
        return S.the_run_state(self.carried)

    @property
    def rows(self) -> list[dict]:
        """`executed_queries.jsonl` rows of THIS scenario's lead (lead zero's are not ours)."""
        return [r for r in S.read_jsonl(self.run_dir / "executed_queries.jsonl")
                if r.get("lead_id") == S.LEAD]

    def rows_for(self, system: str, q: str) -> list[dict]:
        return [r for r in self.rows
                if r.get("system") == system and (r.get("params") or {}).get("q") == q]

    @property
    def breaker(self) -> dict:
        """The run's circuit-breaker state, read off the run's `RunState` (#1235: never a file in
        the run dir)."""
        return self.state.breaker_snapshot()

    def failures(self, system: str) -> int:
        return int(self.breaker.get("systems", {}).get(system, {}).get("failures", 0))

    @property
    def budget(self) -> dict:
        """The run's budget counters, read off the run's `RunState` (#1235)."""
        return self.state.budget_snapshot()

    @property
    def trace_result(self) -> dict:
        rows = [r for r in S.read_jsonl(self.run_dir / "tool_trace.jsonl")
                if r.get("type") == "result"]
        return rows[-1] if rows else {}

    @property
    def wire(self) -> list[dict]:
        return S.read_jsonl(self.run_dir / "wire_logs" / "llm_requests.jsonl")

    def oracle_side_wire_rows(self) -> list[dict]:
        """Wire-log rows a model double of the oracle or verifier produced, or that name either
        role (`fake-oracle` / `fake-verifier` are the doubles' model names)."""
        out = []
        for row in self.wire:
            names = " ".join(str(row.get(k) or "") for k in ("agent_id", "writer_id", "model"))
            if "oracle" in names.lower() or "verifier" in names.lower():
                out.append(row)
        return out

    @property
    def transcript(self) -> str:
        """Everything the investigator's two models were shown."""
        return "\n".join([*self.gather.seen, *self.main.seen])

    @property
    def evidence_text(self) -> str:
        """The lead's evidence rows and every payload sidecar, as text."""
        parts = [json.dumps(r, sort_keys=True) for r in self.rows]
        raw = self.run_dir / "gather_raw"
        if raw.is_dir():
            parts += [p.read_text(encoding="utf-8", errors="replace")
                      for p in sorted(raw.rglob("*")) if p.is_file()]
        return "\n".join(parts)


def _drive(root: Path, est: S.Estate, verbs: Any, turns: list[Any], *,
           limits: dict | None = None, system: str = "idp") -> _Run:
    """One whole investigation: MAIN dispatches one gather lead whose scripted turns are
    `turns`, with `verbs` injected as the run's verb registry. `OracleUnservable` escaping the
    run is kept on `.raised`; any other exception propagates."""
    H = S.replay_harness()
    run_dir = H.materialize(root / RUN_ID, H.GOLDEN_AB3, run_id=RUN_ID)
    run = _Run(run_dir, _main_fn(system), H.ReplayFn(list(turns)))
    run.carried = S.tap_run_states(verbs)
    try:
        run.summary = H.drive(run_dir, run_id=RUN_ID, main=run.main, gather=run.gather,
                              verbs=verbs, limits=limits, tenant=est.place())
    except Exception as exc:  # noqa: BLE001 — only the coined class is kept, the rest re-raise
        if not _unservable(exc):
            raise
        run.raised = _the_unservable(exc)
    return run


@dataclass
class _Sibling:
    ep: Path
    rc: Any = None
    raised: BaseException | None = None
    run: _Run | None = None

    @property
    def aborted(self) -> bool:
        return self.raised is not None or (self.rc is not None and self.rc != 0)

    def record(self, label: str = "b") -> dict | None:
        return S.read_world_record(self.ep, label)


def _sibling_episode(tmp_path: Path, monkeypatch: Any, est: S.Estate) -> Path:
    """A v2 episode whose source is a finished run on the fixture tenant (a sibling resumes
    from it). Called BEFORE a scenario scripts its own answers: the source run answers the
    default captured calls."""
    from defender.episodes._episode_handle import Episode

    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    _base, src = S.source_run(tmp_path, est)
    ep = S.episode_v2(tmp_path, doc=S.family_v2(source_run_dir=str(src)),
                      root=S.tenant_episodes(S.FIXTURE_TENANT))
    with Episode.open(ep) as held:
        T.episode_view(held, tenant=est.place(tenant_id=S.FIXTURE_TENANT)).close()
    return ep


def _resume(ep: Path, est: S.Estate, *, oracle: S.ScriptedModel, verifier: S.ScriptedModel,
            turns: list[Any], label: str = "b", **knobs: Any) -> _Sibling:
    """World `label`'s sibling: the REAL `run.main --episode`, handed the oracle and verifier
    through its coined seams; its lifecycle seam drives the real investigation (replay
    harness) over the world registry, so whatever escapes the investigation reaches the
    sibling's own abort path as it would in production."""
    H = S.replay_harness()
    sib = _Sibling(ep)

    def lifecycle(**kw: Any) -> Any:
        run_dir = Path(kw["run"].run_dir)
        sib.run = _Run(run_dir, _main_fn(), H.ReplayFn(list(turns)))
        reg = S.world_registry(ep, label, est, oracle=oracle, verifier=verifier,
                               world=kw.get("world"), **knobs)
        sib.run.carried = S.tap_run_states(reg)
        sib.run.summary = H.drive(run_dir, run_id=run_dir.name, main=sib.run.main,
                                  gather=sib.run.gather, verbs=reg, tenant=est.place())
        return sib.run.summary

    # #1105 PR 2 (declared change 6): `--tenant T --episode <episode id> --world L`.
    argv = ["--tenant", S.FIXTURE_TENANT, "--episode", ep.name, "--world", label]
    try:
        from defender.tests.support.tenancy._launch_publish_p4 import in_process_publish

        # #1108 P4 (OD14, O11): plus the in-process launch-time publish.
        sib.rc = S.mod(S.RUN).main(argv, lifecycle=lifecycle, visualize=_no_visualize,
                                   preflight=_no_preflight, oracle=oracle.model,
                                   verifier=verifier.model, roster=est.roster(),
                                   publish=in_process_publish())
    except SystemExit as stop:
        sib.rc = 0 if stop.code is None else stop.code
    except Exception as exc:  # noqa: BLE001 — only the coined class is kept, the rest re-raise
        if not _unservable(exc):
            raise
        sib.raised = _the_unservable(exc)
    return sib


def _names_call(call: Any, system: str, verb: str, q: str) -> bool:
    text = json.dumps(call, sort_keys=True, default=str)
    return system in text and verb in text and q in text


def _appended(model: S.ScriptedModel, i: int) -> str:
    """The host text appended to the conversation since the double's last reply, as request
    `i` carried it (request `j+1` follows the double's `j`-th scripted move)."""
    return S.host_tail(model.messages[i])


def _tool_result(model: S.ScriptedModel, i: int, tool: str) -> str:
    """What the host handed back in request `i` AS THE RESULT of the double's `tool` call: the
    content of the trailing request's tool-return or retry-prompt parts naming `tool` — the
    in-turn answer to that tool call, as distinct from any verdict or prompt the host appended
    after a failed attempt. Empty when the host answered the call some other way."""
    from pydantic_ai.messages import ModelResponse, RetryPromptPart, ToolReturnPart

    tail: list[Any] = []
    for msg in reversed(model.messages[i]):
        if isinstance(msg, ModelResponse):
            break
        tail.insert(0, msg)
    out: list[str] = []
    for msg in tail:
        for part in getattr(msg, "parts", []):
            if isinstance(part, ToolReturnPart | RetryPromptPart) and part.tool_name == tool:
                content = part.content
                out.append(content if isinstance(content, str)
                           else json.dumps(content, sort_keys=True, default=str))
    return "\n".join(out)


def _carries_submission(model: S.ScriptedModel, i: int, served: Any) -> bool:
    """Request `i`'s history still holds the double's earlier `submit` of `served` — the same
    conversation, appended to, not a fresh one."""
    from pydantic_ai.messages import ModelResponse, ToolCallPart

    for msg in model.messages[i]:
        if not isinstance(msg, ModelResponse):
            continue
        for part in msg.parts:
            if (isinstance(part, ToolCallPart) and part.tool_name == SUBMIT
                    and part.args_as_dict().get("served") == served):
                return True
    return False


def _timing_box(out: bytes, *, cut_off: int = 0) -> tuple[Any, list[dict]]:
    """A SANDBOXED box factory (a `_DockerTransport`, GD-16, as `S.sandboxed_box`) that also
    records the time bound each run is handed; it answers with `out` as the program's stdout
    (the scripted program's own output: content, not a fault).

    The first `cut_off` runs outlive their time bound: the transport raises what the docker
    transport's `subprocess.run(..., timeout=)` raises then, `subprocess.TimeoutExpired` with
    the docker exec argv and the bound it was handed. `BoxExecutor.run_parsed` passes it
    through unwrapped, with no `BoxResult` and no exit code (GPR-02, executed on a real
    container and on the host executor)."""
    spec_mod = S.mod("box._spec")
    codec = S.mod("execution.box_codec")
    seen: list[dict] = []

    @dataclass(frozen=True)
    class _Recording(spec_mod._DockerTransport):
        def __call__(self, frame: bytes, *, cwd: Path, timeout: float) -> Any:
            seen.append({"frame": frame, "timeout": timeout})
            if len(seen) <= cut_off:
                raise subprocess.TimeoutExpired(  # GPR-02
                    ["docker", "exec", "-i", "-w", str(cwd), self.name,
                     "python3", "-m", "defender.execution.bash_exec"], timeout)
            return codec.RawExec(rc=0, stdout=codec.encode_response(
                codec.BoxResult(rc=0, out=out, err=b"")), stderr=b"")

    def factory() -> Any:
        transport = _Recording(name="oracle-box-1224", spec=spec_mod.BoxSpec())
        return spec_mod.BoxExecutor(spec=spec_mod.BoxSpec(), transport=transport,
                                    name=transport.name)

    return factory, seen


def _served_rows(ep: Path, label: str, q: str) -> list[dict]:
    """World-ledger rows for the investigator call `idp.query q=<q>`."""
    return [r for r in S.ledger_rows(ep, label) if (r.get("params") or {}).get("q") == q]


def _cached(ep: Path, label: str, q: str) -> list[dict]:
    """Served-answer cache entries for the call `q=<q>`."""
    return [r for r in S.oracle_rows(ep, label, "answers")
            if (r.get("params") or {}).get("q") == q]


def _blocked(path: Path) -> Path:
    """Put a DIRECTORY where a store file must be written: every write to it then fails with
    the operating system's own error (a real input through the real primitive)."""
    if path.is_file():
        path.unlink()
    path.mkdir(parents=True, exist_ok=True)
    return path


def test_1224_failed_check_is_appended_to_the_oracle_conversation_and_retried(tmp_path):
    """a submission failing a host check is answered, in the same oracle conversation, by a request naming the failed check, and the call retried."""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    ep = S.episode_v2(tmp_path)
    bad = _with_undeclared(ALICE_ROWS)
    o = S.oracle(S.submit(bad, S.EMPTY_CLAIM), S.submit(ALICE_ROWS, S.EMPTY_CLAIM))
    reg = S.world_registry(ep, "b", est, oracle=o, verifier=S.passing_verifier(), retry_cap=3)

    served = S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice")

    assert served == ALICE_ROWS, "the call was not retried to the second, valid submission"
    assert o.submissions() == 2
    assert not o.overrun
    retry = _appended(o, 1)
    assert S.verdict_names(retry, "check 1"), (
        f"the request after the failed submission does not name check 1: {retry[:400]!r}")
    assert _carries_submission(o, 1, bad), (
        "the retry did not continue the same conversation: the failed submission is not in "
        "the history the oracle was handed")
    rows = _served_rows(ep, "b", "user:alice")
    assert len(rows) == 1, rows
    assert rows[0]["source"] in (S.PASSTHROUGH, S.ORACLE_DECISION), rows


def test_1224_query_tool_reraises_oracle_unservable_with_no_row_and_no_breaker_charge(tmp_path):
    """an unservable call leaves no queries row and no breaker charge; the lead's served call before it is recorded (control)."""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    est.answer("idp", "query", BOB, BOB_ROWS)
    ep = S.episode_v2(tmp_path)
    o = S.oracle(S.submit(ALICE_ROWS), *[S.text_only("ORCL-MARK-d05b: I will not.")] * 3)
    reg = S.world_registry(ep, "b", est, oracle=o, verifier=S.passing_verifier(), retry_cap=1)

    run = _drive(tmp_path, est, reg, [_q("user:alice"), _q("user:bob"), S.done_turn()])

    served = run.rows_for("idp", "user:alice")
    assert len(served) == 1, run.rows
    assert served[0]["exit_code"] == 0, run.rows
    assert run.rows_for("idp", "user:bob") == [], "the unservable call was written as a row"
    assert run.failures("idp") == 0, run.breaker
    assert run.breaker.get("total_failures", 0) == 0, run.breaker
    assert run.gather.calls == 2, "the lead's model was asked again after the unservable call"


def test_1224_sibling_aborts_with_an_unservable_reason(tmp_path, monkeypatch):
    """a sibling whose call goes unservable ends its run and leaves its own world record naming "oracle unservable" and the failing call."""
    est = S.estate(tmp_path)
    ep = _sibling_episode(tmp_path, monkeypatch, est)
    est.answer("idp", "query", BOB, BOB_ROWS)
    o = S.oracle(*[S.text_only("ORCL-MARK-d05d: no.")] * 4)

    sib = _resume(ep, est, oracle=o, verifier=S.passing_verifier(),
                  turns=[_q("user:bob"), S.done_turn()], retry_cap=1)

    assert sib.aborted, f"the sibling finished normally (rc {sib.rc!r}) after an unservable call"
    rec = sib.record("b")
    assert rec is not None, "the sibling exited without writing its own world record"
    assert rec["world"] == "b"
    assert rec["reason"] == S.REASON_UNSERVABLE, rec
    assert _names_call(rec.get("call"), "idp", "query", "user:bob"), rec
    assert sib.record("a") is None
    assert sib.record("c") is None


def test_1224_no_oracle_error_reaches_the_sibling_transcript_or_evidence(tmp_path):
    """check failures, verifier failures, prose turns and exhausted retries leave no oracle error text in the investigator's records."""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    est.answer("idp", "query", BOB, BOB_ROWS)
    ep = S.episode_v2(tmp_path)
    vrfy, orcl = "VRFY-MARK-7f3 the logon telemetry is absent", "ORCL-MARK-9c2 I cannot do it"
    o = S.oracle(S.submit(ALICE_ROWS), S.submit(_with_undeclared(BOB_ROWS)),
                 S.submit(BOB_ROWS), *[S.text_only(orcl)] * 3)
    v = S.verifier(S.verdict(True), S.verdict(False, vrfy))
    reg = S.world_registry(ep, "b", est, oracle=o, verifier=v, retry_cap=3)

    run = _drive(tmp_path, est, reg, [_q("user:alice"), _q("user:bob"), S.done_turn()])

    assert o.submissions() >= 3, "the failures were not exercised"
    assert v.requests >= 2, "the failures were not exercised"
    for text, where in ((run.transcript, "transcript"), (run.evidence_text, "evidence")):
        for needle in ("VRFY-MARK-7f3", "ORCL-MARK-9c2", "e-999", "OracleUnservable"):
            assert needle not in text, f"{needle!r} reached the sibling's {where}"
    ledger = json.dumps(S.ledger_rows(ep, "b"))
    assert "VRFY-MARK-7f3" not in ledger
    assert "ORCL-MARK-9c2" not in ledger
    # Control: the served call is shown and recorded as real data.
    assert "e-100" in run.transcript
    assert "e-100" in run.evidence_text


def test_1224_oracle_retries_charge_no_investigator_budget(tmp_path):
    """however many oracle and verifier attempts a call takes, the sibling's budget state and the lead's request count match an unbranched run of the same …"""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    est.answer("edr", "query", HOST_DB1, EDR_ROWS)
    est.answer("idp", "lookup", {"entity": "alice"}, LOOKUP_ALICE)
    ep = S.episode_v2(tmp_path)
    o = S.oracle(_explore(), _explore(), S.check(ALICE_ROWS),
                 S.submit(_with_undeclared(ALICE_ROWS)), _explore(), S.submit(ALICE_ROWS))
    v = S.verifier(S.run_query("idp", "lookup", {"entity": "alice"}), S.verdict(True))
    reg = S.world_registry(ep, "b", est, oracle=o, verifier=v, retry_cap=3)
    turns = [_q("user:alice"), S.done_turn()]

    branched = _drive(tmp_path / "w", est, reg, turns)
    plain = _drive(tmp_path / "p", est, S.plain_registry(est), turns)

    assert o.requests >= 6, "the oracle took no extra turns"
    assert v.requests >= 2, "the verifier took no extra turns"
    assert not o.overrun
    assert branched.rows_for("idp", "user:alice")[0]["exit_code"] == 0
    for key in ("tool_calls", "subagent_spawns"):
        assert branched.budget[key] == plain.budget[key], (key, branched.budget, plain.budget)
    assert branched.gather.calls == plain.gather.calls
    assert branched.main.calls == plain.main.calls
    assert branched.oracle_side_wire_rows() == [], "oracle or verifier traffic in the wire log"
    agents = {row.get("agent_id") for row in branched.wire}
    assert {"main", f"gather:{S.LEAD}"} <= agents, agents
    assert len(branched.wire) == len(plain.wire), "the wire log gained rows"
    assert branched.trace_result["num_turns"] == plain.trace_result["num_turns"]


def test_1224_oracle_verifier_and_exploration_cost_is_charged_to_the_oracle_budget(tmp_path):
    """oracle turns, verifier turns and exploration are all stopped by the world's oracle budget, which ends the call unservable with reason budget."""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    est.answer("edr", "query", HOST_DB1, EDR_ROWS)
    U = S.unservable_cls()

    # The oracle's own turns and exploration.
    o = S.oracle(*[_explore()] * 25)
    reg = S.world_registry(S.episode_v2(tmp_path / "o"), "b", est, oracle=o,
                           verifier=S.passing_verifier(), budget=TINY_BUDGET, retry_cap=3)
    with pytest.raises(U) as stopped:
        S.call(reg, "idp", "query", est.ctx(tmp_path / "inv-o"), q="user:alice")
    assert stopped.value.reason == S.REASON_BUDGET
    assert o.requests < 25, "the oracle's spend was not bounded"
    assert not o.overrun, "the oracle's spend was not bounded"

    # The verifier's turns and exploration.
    v2 = S.verifier(*[_explore()] * 25)
    reg2 = S.world_registry(S.episode_v2(tmp_path / "v"), "b", est,
                            oracle=S.oracle(S.submit(ALICE_ROWS)), verifier=v2,
                            budget=TINY_BUDGET, retry_cap=3)
    with pytest.raises(U) as stopped2:
        S.call(reg2, "idp", "query", est.ctx(tmp_path / "inv-v"), q="user:alice")
    assert stopped2.value.reason == S.REASON_BUDGET
    assert v2.requests < 25, "the verifier's spend was not bounded"
    assert not v2.overrun, "the verifier's spend was not bounded"

    # Control: the same exploration under the default budget runs and serves.
    calls_before = len(est.calls("edr", "query"))
    o3 = S.oracle(_explore(), _explore(), _explore(), S.submit(ALICE_ROWS))
    reg3 = S.world_registry(S.episode_v2(tmp_path / "c"), "b", est, oracle=o3,
                            verifier=S.passing_verifier(), retry_cap=3)
    assert S.call(reg3, "idp", "query", est.ctx(tmp_path / "inv-c"),
                  q="user:alice") == ALICE_ROWS
    assert len(est.calls("edr", "query")) - calls_before == 3
    assert not o3.overrun


def test_1224_exhausted_oracle_budget_makes_the_sibling_unservable(tmp_path):
    """an exhausted oracle budget raises OracleUnservable with reason budget, which escapes the investigation, and the investigator is shown nothing of it."""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    U = S.unservable_cls()

    reg = S.world_registry(S.episode_v2(tmp_path / "r"), "b", est,
                           oracle=S.oracle(S.submit(ALICE_ROWS)),
                           verifier=S.passing_verifier(), budget=TINY_BUDGET)
    with pytest.raises(U) as stopped:
        S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice")
    assert stopped.value.reason == S.REASON_BUDGET

    reg2 = S.world_registry(S.episode_v2(tmp_path / "d"), "b", est,
                            oracle=S.oracle(S.submit(ALICE_ROWS)),
                            verifier=S.passing_verifier(), budget=TINY_BUDGET)
    run = _drive(tmp_path / "w", est, reg2, [_q("user:alice"), S.done_turn()])
    assert isinstance(run.raised, U), (
        f"OracleUnservable did not escape the investigation (raised: {run.raised!r})")
    assert run.raised.reason == S.REASON_BUDGET, run.raised.reason
    assert _names_call(run.raised.call, "idp", "query", "user:alice"), run.raised.call
    assert run.rows_for("idp", "user:alice") == []
    assert run.failures("idp") == 0
    assert run.breaker.get("total_failures", 0) == 0, run.breaker
    assert run.gather.calls == 1, "the lead's model was shown the budget failure"
    assert run.main.calls == 1, "the investigation went on after the budget failure"
    assert "OracleUnservable" not in run.transcript

    ctl = S.world_registry(S.episode_v2(tmp_path / "c"), "b", est,
                           oracle=S.oracle(S.submit(ALICE_ROWS)),
                           verifier=S.passing_verifier())
    ok = _drive(tmp_path / "k", est, ctl, [_q("user:alice"), S.done_turn()])
    assert ok.rows_for("idp", "user:alice")[0]["exit_code"] == 0


def test_1224_side_query_rerun_sees_data_that_moved_since_the_oracle_ran(tmp_path):
    """when tenant data moves between the oracle's removal side query and check 5's re-run, the count mismatch fails the attempt and the claimed answer is …"""
    r1 = {"user": "alice", "event_id": "e-100", "action": "logon", "host": "web-1",
          "ts": "2026-07-28T15:00:00Z"}
    r2 = {"user": "alice", "event_id": "e-101", "action": "logon", "host": "10.0.0.9",
          "ts": "2026-07-28T15:01:00Z"}
    r3 = {"user": "alice", "event_id": "e-102", "action": "logon", "host": "10.0.0.9",
          "ts": "2026-07-28T15:02:00Z"}
    side = {"entity": "10.0.0.9"}
    served = {"rows": [r1]}
    the_claim = S.claim(removed=[S.removed(r2, system="idp", verb="lookup", params=side,
                                           count=1)])

    def scenario(root: Path, *, moves: bool) -> tuple[Any, Path, S.Estate]:
        est = S.estate(root)
        est.answer("idp", "query", ALICE, {"rows": [r1, r2]})
        est.answer("idp", "lookup", side, {"rows": [r2]})
        ep = S.episode_v2(root)
        o = S.oracle(S.run_query("idp", "lookup", side), S.submit(served, the_claim),
                     fault=S.Fault(delay=0.4))
        reg = S.world_registry(ep, "b", est, oracle=o, verifier=S.passing_verifier(),
                               retry_cap=1)
        if moves:
            def watch() -> None:
                deadline = time.monotonic() + 10
                while not est.calls("idp", "lookup") and time.monotonic() < deadline:
                    time.sleep(0.02)
                est.answer("idp", "lookup", side, {"rows": [r2, r3]})
            threading.Thread(target=watch, daemon=True).start()
        return reg, ep, est

    reg, _ep, est = scenario(tmp_path / "ctl", moves=False)
    assert S.call(reg, "idp", "query", est.ctx(tmp_path / "inv-c"), q="user:alice") == served

    reg, ep, est = scenario(tmp_path / "mv", moves=True)
    with pytest.raises(S.unservable_cls()):
        S.call(reg, "idp", "query", est.ctx(tmp_path / "inv-m"), q="user:alice")
    assert len(est.calls("idp", "lookup")) >= 2, "check 5 never re-ran the side query"
    assert _served_rows(ep, "b", "user:alice") == []
    assert _cached(ep, "b", "user:alice") == []


def test_oracle_turn_ends_without_submitting(tmp_path):
    """a turn that ends without one valid submission serves nothing, the oracle is told what was missing, and such turns count toward N."""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    o = S.oracle(S.text_only("I think the answer is the base answer."),
                 S.Move(SUBMIT, {"served": ALICE_ROWS}),
                 S.Move(SUBMIT, {"served": ALICE_ROWS,
                                 "claim": {**S.EMPTY_CLAIM, "confidence": "high"}}),
                 S.submit(ALICE_ROWS))
    reg = S.world_registry(S.episode_v2(tmp_path / "a"), "b", est, oracle=o,
                           verifier=S.passing_verifier(), retry_cap=4)

    assert S.call(reg, "idp", "query", est.ctx(tmp_path / "inv-a"),
                  q="user:alice") == ALICE_ROWS
    assert o.submissions() == 3, "an invalid submission was served: the valid fourth move was never reached"
    assert not o.overrun, "an invalid submission was served: the valid fourth move was never reached"
    told = _appended(o, 1)
    assert SUBMIT in told.lower(), (
        f"the oracle was not told its turn ended without a submission: {told!r}")
    for i in (2, 3):
        assert _appended(o, i).strip(), f"the oracle was told nothing after move {i - 1}"

    ep = S.episode_v2(tmp_path / "b")
    o2 = S.oracle(*[S.text_only("Still thinking about it.")] * 6)
    reg2 = S.world_registry(ep, "b", est, oracle=o2, verifier=S.passing_verifier(),
                            retry_cap=2)
    with pytest.raises(S.unservable_cls()):
        S.call(reg2, "idp", "query", est.ctx(tmp_path / "inv-b"), q="user:alice")
    assert o2.requests >= 2, "a prose-only turn made the call unservable without a retry"
    assert _served_rows(ep, "b", "user:alice") == []


def test_input_oracle_model_returns_nothing_usable(tmp_path):
    """an empty reply, a refusal, or a reply cut off mid-answer is an ordinary failed attempt: nothing is served from it, the retry is told, the …"""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    refusal = "I won't fabricate attack telemetry; that could be used to cause harm."
    cut_off = '{"served": {"rows": [{"user": "alice", "event_id": "e-1'
    o = S.oracle(S.text_only(""), S.text_only(refusal), S.text_only(cut_off),
                 S.submit(ALICE_ROWS))
    reg = S.world_registry(S.episode_v2(tmp_path / "a"), "b", est, oracle=o,
                           verifier=S.passing_verifier(), retry_cap=4)

    assert S.call(reg, "idp", "query", est.ctx(tmp_path / "inv-a"),
                  q="user:alice") == ALICE_ROWS
    assert o.submissions() == 1
    assert not o.overrun
    for i in (1, 2, 3):
        assert _appended(o, i).strip(), f"the retry after move {i - 1} was told nothing"

    ep = S.episode_v2(tmp_path / "b")
    o2 = S.oracle(*[S.text_only(refusal)] * 6)
    reg2 = S.world_registry(ep, "b", est, oracle=o2, verifier=S.passing_verifier(),
                            retry_cap=2)
    with pytest.raises(S.unservable_cls()):
        S.call(reg2, "idp", "query", est.ctx(tmp_path / "inv-b"), q="user:alice")
    assert o2.requests >= 2, "a refusal made the world unservable at once, without a retry"
    assert _served_rows(ep, "b", "user:alice") == []


def test_verifier_provider_fails_after_the_host_checks_passed(tmp_path):
    """a verifier provider failure after the host checks passed re-asks the verifier once inside the attempt; nothing is served until a verifier pass is …"""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    ep = S.episode_v2(tmp_path / "a")
    o = S.oracle(S.submit(ALICE_ROWS))
    # GPR-01: the verifier's first request fails as its provider client fails after retries.
    v = S.verifier(S.raising(S.OUTAGE), S.verdict(True))
    reg = S.world_registry(ep, "b", est, oracle=o, verifier=v, retry_cap=2)

    run = _drive(tmp_path / "w", est, reg, [_q("user:alice"), S.done_turn()])

    assert run.raised is None
    assert run.rows_for("idp", "user:alice")[0]["exit_code"] == 0
    assert v.requests == 2, "the verifier was not re-asked after its provider failed"
    assert not v.overrun
    # M03=A: the re-ask is inside the attempt; it spends no oracle attempt of its own.
    assert o.submissions() == 1
    assert not o.overrun
    for leak in ("ModelHTTPError", "provider answered 503"):
        assert leak not in run.transcript, leak
        assert leak not in run.evidence_text, leak

    ep2 = S.episode_v2(tmp_path / "b")
    o2 = S.oracle(then=S.submit(ALICE_ROWS))
    v2 = S.verifier(then=S.raising(S.OUTAGE))  # GPR-01, on every request
    reg2 = S.world_registry(ep2, "b", est, oracle=o2, verifier=v2, retry_cap=2)
    with pytest.raises(S.unservable_cls()):
        S.call(reg2, "idp", "query", est.ctx(tmp_path / "inv-b"), q="user:alice")
    assert o2.submissions() == 2, (
        f"{o2.submissions()} oracle submissions under retry_cap=2: each attempt's verifier "
        "failure (after its one re-ask) must fail exactly that attempt")
    assert v2.requests == 4, (
        f"{v2.requests} verifier requests: expected 2 attempts x (1 request + 1 re-ask)")
    assert _served_rows(ep2, "b", "user:alice") == []
    assert _cached(ep2, "b", "user:alice") == []


def test_verifier_replies_with_neither_a_pass_nor_a_failure(tmp_path):
    """a verifier reply with no clean verdict is not a pass: nothing is served, and the oracle is told the verifier produced no usable verdict."""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    ep = S.episode_v2(tmp_path / "a")
    o = S.oracle(S.submit(ALICE_ROWS), S.submit(ALICE_ROWS))
    v = S.verifier(*[S.text_only("VERDICT: PASS - the logon telemetry is present.")] * 8)
    reg = S.world_registry(ep, "b", est, oracle=o, verifier=v, retry_cap=2)

    with pytest.raises(S.unservable_cls()):
        S.call(reg, "idp", "query", est.ctx(tmp_path / "inv-a"), q="user:alice")
    assert o.submissions() == 2, "the oracle was not retried after the unusable verdict"
    assert S.verdict_names(_appended(o, 1), "verifier"), _appended(o, 1)[:400]
    assert _served_rows(ep, "b", "user:alice") == []
    assert _cached(ep, "b", "user:alice") == []

    ctl = S.world_registry(S.episode_v2(tmp_path / "c"), "b", est,
                           oracle=S.oracle(S.submit(ALICE_ROWS)),
                           verifier=S.verifier(S.verdict(True)), retry_cap=2)
    assert S.call(ctl, "idp", "query", est.ctx(tmp_path / "inv-c"),
                  q="user:alice") == ALICE_ROWS


def test_exploration_query_errors_on_the_real_system(tmp_path):
    """a real-system error on the oracle's own exploration is feedback inside the turn, seen only by the oracle; it is not the world's telemetry and the …"""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    est.fail("edr", "query", HOST_DB1, fault="TransportFault",
             detail="EXPLORE-ERR-55: the edr cluster lacks this feature")
    ep = S.episode_v2(tmp_path)
    o = S.oracle(_explore(), S.submit(ALICE_ROWS))
    reg = S.world_registry(ep, "b", est, oracle=o, verifier=S.passing_verifier(), retry_cap=1)

    run = _drive(tmp_path, est, reg, [_q("user:alice"), S.done_turn()])

    assert run.raised is None
    assert run.rows_for("idp", "user:alice")[0]["exit_code"] == 0
    assert "EXPLORE-ERR-55" in _appended(o, 1), "the oracle was not shown its tool's error"
    assert "EXPLORE-ERR-55" not in run.transcript
    assert "EXPLORE-ERR-55" not in run.evidence_text
    assert [r for r in run.rows if r.get("system") == "edr"] == []
    assert run.failures("edr") == 0
    assert [r for r in S.ledger_rows(ep, "b") if r.get("system") == "edr"] == []
    side = [r for r in S.oracle_rows(ep, "b", "ledger")
            if r.get("system") == "edr" and r.get("actor") == "oracle"]
    assert side, "the oracle's exploration was not recorded oracle-side"


def test_python_runs_past_its_time_limit(tmp_path):
    """the oracle's Python is bounded in time and output; a run cut off by its time bound is in-turn feedback the oracle is told about, not a failed …"""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    ep = S.episode_v2(tmp_path)
    box, runs = _timing_box(b"A" * (12 * 1024 * 1024), cut_off=1)
    served = {"rows": [*ALICE_ROWS["rows"], FORGED_ROW]}
    o = S.oracle(S.python("import time\nwhile True:\n    time.sleep(1)\n"),
                 S.python("while True:\n    print('A' * 4096)\n"),
                 S.forge("fx-1", "f1", "idp", FORGED_ROW),
                 S.submit(served, S.claim(added=[S.added("fx-1", "f1")])))
    reg = S.world_registry(ep, "b", est, oracle=o, verifier=S.passing_verifier(), box=box,
                           retry_cap=1)

    assert S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice") == served, (
        "the cut-off run was charged as a failed attempt (M03=A: it is in-turn feedback)")
    assert o.submissions() == 1
    assert not o.overrun
    stored = [r for r in S.ledger_rows(ep, "b") if r.get("source") == S.ORACLE_DECISION]
    assert len(stored) == 1, S.ledger_rows(ep, "b")
    assert stored[0].get("attempts") == 1, (
        f"the cut-off counted as an attempt: {stored[0].get('attempts')!r}")
    assert len(runs) >= 2, "the python tool did not run both programs in the box"
    assert all(0 < r["timeout"] < float("inf") for r in runs), runs
    python_tool = S.COINED["tool.python"]
    told = _tool_result(o, 1, python_tool).lower().replace("-", " ")
    assert told.strip(), (
        "the oracle was not told, as the python tool's own result in the turn, about its "
        f"cut-off run (host text appended instead: {_appended(o, 1)[:400]!r})")
    assert any(w in told for w in ("timed out", "timeout", "time limit", "time bound",
                                   "deadline", "cut off")), (
        f"the python result does not say the run outlived its time bound: {told[:400]!r}")
    output = _tool_result(o, 2, python_tool)
    assert output.strip(), "the 12 MB program's result never reached the oracle"
    assert len(output) < 2 * 1024 * 1024, "the program's output reached the oracle whole"


def test_resumed_sibling_leaves_the_oracle_side_trace_of_the_first_attempt(tmp_path):
    """the first attempt's oracle-side ledger rows survive a resume oracle-side only: not lost, not duplicated, and never in the evidence, world ledger or …"""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    est.answer("idp", "query", BOB, BOB_ROWS)
    est.answer("edr", "query", HOST_DB1, EDR_ROWS)
    est.answer("edr", "query", HOST_DB2, {"events": []})
    est.answer("siem-x", "lookup", {"entity": "alice"}, LOOKUP_ALICE)
    ep = S.episode_v2(tmp_path)
    base_before = (ep / "served" / "base.jsonl").read_bytes()

    first = S.world_registry(
        ep, "b", est, oracle=S.oracle(_explore("host:db-1"), S.submit(ALICE_ROWS)),
        verifier=S.verifier(S.run_query("siem-x", "lookup", {"entity": "alice"}),
                            S.verdict(True)))
    run1 = _drive(tmp_path / "w", est, first, [_q("user:alice"), S.done_turn()])
    resumed = S.world_registry(
        ep, "b", est, oracle=S.oracle(_explore("host:db-2"), S.submit(BOB_ROWS)),
        verifier=S.passing_verifier())
    run2 = _drive(tmp_path / "r", est, resumed, [_q("user:bob"), S.done_turn()])

    side = S.oracle_rows(ep, "b", "ledger")

    def n(system: str, actor: str, needle: str) -> int:
        return sum(1 for r in side if r.get("system") == system and r.get("actor") == actor
                   and needle in json.dumps(r.get("params"), sort_keys=True))

    assert n("edr", "oracle", "host:db-1") == 1, side
    assert n("siem-x", "verifier", "alice") == 1, side
    assert n("edr", "oracle", "host:db-2") == 1, side
    world = S.ledger_rows(ep, "b")
    assert sorted((r.get("params") or {}).get("q") for r in world) == ["user:alice", "user:bob"]
    for run in (run1, run2):
        assert {r["system"] for r in run.rows} == {"idp"}
    assert (ep / "served" / "base.jsonl").read_bytes() == base_before


def test_conc_15_calls_issued_after_the_sibling_is_unservable(tmp_path):
    """calls issued after the sibling went unservable get no oracle turn: the failed call is not re-run, a new call is not served, and neither leaves a row."""
    est = S.estate(tmp_path)
    for params, rows in ((ALICE, ALICE_ROWS), (BOB, BOB_ROWS), (CAROL, CAROL_ROWS)):
        est.answer("idp", "query", params, rows)
    ep = S.episode_v2(tmp_path)
    o = S.oracle(S.submit(ALICE_ROWS), *[S.text_only("ORCL-MARK-159: no.")] * 3,
                 S.submit(CAROL_ROWS), S.submit(BOB_ROWS))
    reg = S.world_registry(ep, "b", est, oracle=o, verifier=S.passing_verifier(), retry_cap=1)
    ctx = est.ctx(tmp_path / "inv")
    U = S.unservable_cls()

    assert S.call(reg, "idp", "query", ctx, q="user:alice") == ALICE_ROWS
    with pytest.raises(U):
        S.call(reg, "idp", "query", ctx, q="user:bob")
    asked = o.requests

    with pytest.raises(U):
        S.call(reg, "idp", "query", ctx, q="user:carol")
    with pytest.raises(U):
        S.call(reg, "idp", "query", ctx, q="user:bob")
    with contextlib.suppress(U):  # whether the cached call is still answered is not pinned
        S.call(reg, "idp", "query", ctx, q="user:alice")
    assert o.requests == asked, "a call issued after the sibling was unservable got a turn"
    assert _served_rows(ep, "b", "user:carol") == []
    assert _served_rows(ep, "b", "user:bob") == []
    assert _cached(ep, "b", "user:bob") == []
    assert _cached(ep, "b", "user:carol") == []


def test_resume_after_the_sibling_was_already_unservable(tmp_path, monkeypatch):
    """an operator's resume of a sibling that exited unservable does not retry the failing call, and the world's validity and its single record are …"""
    est = S.estate(tmp_path)
    ep = _sibling_episode(tmp_path, monkeypatch, est)
    est.answer("idp", "query", BOB, BOB_ROWS)
    turns = [_q("user:bob"), S.done_turn()]

    first = _resume(ep, est, oracle=S.oracle(*[S.text_only("no")] * 4),
                    verifier=S.passing_verifier(), turns=turns, retry_cap=1)
    assert first.aborted
    rec = first.record("b")
    assert rec is not None
    assert rec["reason"] == S.REASON_UNSERVABLE
    assert _names_call(rec.get("call"), "idp", "query", "user:bob"), rec
    after_abort = sorted(p.name for p in (ep / S.WORLD_RECORDS).iterdir())
    assert after_abort == [f"{T.world_id(ep, 'b')}.yaml"], f"the abort left {after_abort}, not one record for b"
    assert first.run is not None
    from defender.tests.support.storage._alert_plant import unseal_fixture_input
    unseal_fixture_input(first.run.run_dir)
    shutil.rmtree(first.run.run_dir)

    o2 = S.oracle(S.submit(BOB_ROWS))
    again = _resume(ep, est, oracle=o2, verifier=S.passing_verifier(), turns=turns,
                    retry_cap=1)

    assert "user:bob" not in o2.all_seen(), "the resume retried the failing call"
    assert _served_rows(ep, "b", "user:bob") == []
    assert again.record("b") == rec, "the resume rewrote the world's validity record"
    records = sorted(p.name for p in (ep / S.WORLD_RECORDS).iterdir())
    assert records == [f"{T.world_id(ep, 'b')}.yaml"], records


def test_disk_full_while_freezing_forged_rows(tmp_path):
    """a verified answer whose forged rows cannot be frozen is a failed attempt: it is not served, nothing half-written is frozen, and no store error …"""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    served = {"rows": [*ALICE_ROWS["rows"], FORGED_ROW]}
    the_claim = S.claim(added=[S.added("fx-1", "f1")])

    def moves() -> list[S.Move]:
        return [S.forge("fx-1", "f1", "idp", FORGED_ROW), S.submit(served, the_claim)]

    ctl_ep = S.episode_v2(tmp_path / "c")
    ctl = S.world_registry(ctl_ep, "b", est, oracle=S.oracle(*moves()),
                           verifier=S.passing_verifier(), retry_cap=1)
    assert S.call(ctl, "idp", "query", est.ctx(tmp_path / "inv-c"), q="user:alice") == served
    assert [r["forged_id"] for r in S.oracle_rows(ctl_ep, "b", "forged")] == ["fx-1"]

    ep = S.episode_v2(tmp_path / "f")
    reg = S.world_registry(ep, "b", est, oracle=S.oracle(*moves()),
                           verifier=S.passing_verifier(), retry_cap=1)
    store = _blocked(S.oracle_dir(ep, "b") / "forged.jsonl")
    run = _drive(tmp_path / "w", est, reg, [_q("user:alice"), S.done_turn()])

    assert run.rows_for("idp", "user:alice") == [], "an answer that could not be frozen was served"
    assert list(store.iterdir()) == [], "a partial forged row was left behind"
    assert run.failures("idp") == 0
    assert run.breaker.get("total_failures", 0) == 0
    assert run.gather.calls == 1
    for needle in ("Is a directory", "IsADirectoryError", "Errno", "e-9001"):
        assert needle not in run.transcript, needle
        assert needle not in run.evidence_text, needle
    assert _served_rows(ep, "b", "user:alice") == []
    assert _cached(ep, "b", "user:alice") == []


def test_oracle_ledger_append_fails_after_a_good_answer(tmp_path):
    """when the oracle-side ledger cannot record the call's exploration, the verified answer is not served, and the failure never lands in the sibling's …"""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    est.answer("edr", "query", HOST_DB1, EDR_ROWS)

    ctl_ep = S.episode_v2(tmp_path / "c")
    ctl = S.world_registry(ctl_ep, "b", est, oracle=S.oracle(_explore(), S.submit(ALICE_ROWS)),
                           verifier=S.passing_verifier(), retry_cap=1)
    assert S.call(ctl, "idp", "query", est.ctx(tmp_path / "inv-c"),
                  q="user:alice") == ALICE_ROWS
    assert [r for r in S.oracle_rows(ctl_ep, "b", "ledger") if r.get("system") == "edr"]

    ep = S.episode_v2(tmp_path / "f")
    reg = S.world_registry(ep, "b", est, oracle=S.oracle(_explore(), S.submit(ALICE_ROWS)),
                           verifier=S.passing_verifier(), retry_cap=1)
    _blocked(S.oracle_dir(ep, "b") / "ledger.jsonl")
    run = _drive(tmp_path / "w", est, reg, [_q("user:alice"), S.done_turn()])

    assert run.rows_for("idp", "user:alice") == []
    assert S.ledger_rows(ep, "b") == [], "the oracle-side failure landed in the world ledger"
    assert run.failures("idp") == 0
    assert run.breaker.get("total_failures", 0) == 0
    for needle in ("Is a directory", "IsADirectoryError", "Errno", "ledger.jsonl"):
        assert needle not in run.transcript, needle
        assert needle not in run.evidence_text, needle


def test_oracle_budget_is_spent_by_pre_flight_before_the_sibling_starts(tmp_path, monkeypatch):
    """one oracle budget per world spans pre-flight and the sibling: a world whose pre-flight exhausted it leaves its sibling nothing to spend, unservable …"""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    monkeypatch.setenv(S.KNOB_BUDGET, str(TINY_BUDGET))
    monkeypatch.setenv(S.KNOB_RETRY_CAP, "3")
    est = S.estate(tmp_path)
    launched = S.launch(tmp_path, est, oracle=S.oracle(then=S.text_only("(pre-flight)")),
                        verifier=S.passing_verifier(), preflight=_no_preflight)
    outcome = S.read_outcome(launched.ep)
    assert outcome is not None, f"pre-flight wrote no outcome record ({launched.message!r})"
    b_entries = [w for w in outcome.get("unservable_worlds") or [] if w.get("world") == "b"]
    assert b_entries, outcome
    assert S.REASON_BUDGET in str(b_entries[0].get("reason")), outcome

    est.answer("idp", "query", BOB, BOB_ROWS)
    U = S.unservable_cls()
    o2, v2 = S.oracle(S.submit(BOB_ROWS)), S.passing_verifier()
    reg = S.world_registry(launched.ep, "b", est, oracle=o2, verifier=v2, budget=TINY_BUDGET)
    with pytest.raises(U) as stopped:
        S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:bob")
    assert stopped.value.reason == S.REASON_BUDGET
    assert o2.requests == 0, "the sibling was handed a fresh budget beside pre-flight's"
    assert v2.requests == 0, "the sibling was handed a fresh budget beside pre-flight's"

    # The isolating control: the same tiny budget on a world pre-flight never spent from lets
    # the oracle make its first request, then stops the call for budget.
    o4 = S.oracle(S.submit(BOB_ROWS))
    fresh = S.world_registry(S.episode_v2(tmp_path / "fresh-tiny"), "b", est, oracle=o4,
                             verifier=S.passing_verifier(), budget=TINY_BUDGET)
    with pytest.raises(U) as fresh_stopped:
        S.call(fresh, "idp", "query", est.ctx(tmp_path / "inv-t"), q="user:bob")
    assert fresh_stopped.value.reason == S.REASON_BUDGET
    assert o4.requests >= 1, (
        "a world with nothing spent made no oracle request under the tiny budget: the "
        "pre-flighted world's zero requests do not show carried pre-flight spend")

    monkeypatch.delenv(S.KNOB_BUDGET)
    o3 = S.oracle(S.submit(BOB_ROWS))
    ctl = S.world_registry(S.episode_v2(tmp_path / "fresh"), "b", est, oracle=o3,
                           verifier=S.passing_verifier())
    assert S.call(ctl, "idp", "query", est.ctx(tmp_path / "inv-c"), q="user:bob") == BOB_ROWS
    assert o3.requests >= 1


def test_1224_retry_cap_zero_is_refused_and_one_allows_exactly_one_failed_attempt(tmp_path):
    """a retry cap of zero is refused at configuration; a cap of one allows exactly one failed attempt of each kind, and limiter wait is never one."""
    settings = S.sym(S.ORACLE, S.COINED["fn.settings"])
    for bad in ("0", "-1", "two", "1.5"):
        with pytest.raises(FatalConfigError) as refused:
            settings({S.KNOB_RETRY_CAP: bad})
        assert S.KNOB_RETRY_CAP in str(refused.value), (bad, str(refused.value))
    assert settings({S.KNOB_RETRY_CAP: "1"}).retry_cap == 1

    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    est.answer("edr", "query", HOST_DB1, EDR_ROWS)
    U = S.unservable_cls()
    ctx = est.ctx(tmp_path / "inv")

    check = S.oracle(S.submit(_with_undeclared(ALICE_ROWS)), S.submit(ALICE_ROWS))
    reg = S.world_registry(S.episode_v2(tmp_path / "h"), "b", est, oracle=check,
                           verifier=S.passing_verifier(), retry_cap=1)
    with pytest.raises(U):
        S.call(reg, "idp", "query", ctx, q="user:alice")
    assert check.submissions() == 1, "a failed host check was retried under a cap of one"

    vo = S.oracle(S.submit(ALICE_ROWS), S.submit(ALICE_ROWS))
    vv = S.verifier(S.verdict(False, "f1's logon is missing"), S.verdict(True))
    reg = S.world_registry(S.episode_v2(tmp_path / "v"), "b", est, oracle=vo, verifier=vv,
                           retry_cap=1)
    with pytest.raises(U):
        S.call(reg, "idp", "query", ctx, q="user:alice")
    assert vo.submissions() == 1, "a verifier failure was retried under a cap of one"

    slow = S.oracle(S.submit(ALICE_ROWS), S.submit(ALICE_ROWS), fault=S.Fault(delay=2.0))
    reg = S.world_registry(S.episode_v2(tmp_path / "d"), "b", est, oracle=slow,
                           verifier=S.passing_verifier(), retry_cap=1, turn_deadline=0.3)
    began = time.monotonic()
    with pytest.raises(U):
        S.call(reg, "idp", "query", ctx, q="user:alice")
    assert time.monotonic() - began < 1.8, "the hung oracle request outlived the turn deadline"
    assert slow.requests == 1, "an expired turn deadline was retried under a cap of one"

    mute = S.oracle(*[S.text_only("Thinking.")] * 6)
    reg = S.world_registry(S.episode_v2(tmp_path / "t"), "b", est, oracle=mute,
                           verifier=S.passing_verifier(), retry_cap=1)
    with pytest.raises(U):
        S.call(reg, "idp", "query", ctx, q="user:alice")

    before = len(est.calls("edr", "query"))
    paced = S.oracle(_explore(), _explore(), _explore(), S.submit(ALICE_ROWS))
    reg = S.world_registry(S.episode_v2(tmp_path / "r"), "b", est, oracle=paced,
                           verifier=S.passing_verifier(), retry_cap=1, rate=1.0,
                           turn_deadline=1.5)
    assert S.call(reg, "idp", "query", ctx, q="user:alice") == ALICE_ROWS, (
        "limiter wait was counted toward the turn deadline")
    explored = est.calls("edr", "query")[before:]
    assert len(explored) == 3
    assert explored[-1]["t"] - explored[0]["t"] >= 1.8, "the limiter never made a query wait"
