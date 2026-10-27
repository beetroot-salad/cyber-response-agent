from __future__ import annotations

from defender.tests.support.learning.branch import _triplet_947 as T

import json
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from defender import _yaml
from defender.tests.support.presentation import _episode_1025 as E
from defender.tests.support.runtime.state import _1255_world as W
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.learning.core import _state1135
from defender.tests.learning.oracle.live_contracts import _spec1224 as S

#: The configured episodes root (no default exists; `cli.episodes_root` refuses an unset one).
EPISODES_ENV = "DEFENDER_EPISODES_BASE"


def _names(root: Path) -> set[str]:
    """The entries of `root` (none when it does not exist yet: the tenant's `episodes/` is made
    by the first launch)."""
    return {p.name for p in Path(root).iterdir()} if Path(root).is_dir() else set()



@pytest.fixture(autouse=True)
def episodes_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Every launch here needs a configured episodes root outside the data root and the
    checkout, and a learning-state root of its own (an accepted launch ends in the judge,
    which would otherwise write into the checkout)."""
    monkeypatch.setenv(EPISODES_ENV, str(tmp_path / "episodes-root"))
    S.T.isolate_learning_state(tmp_path, monkeypatch)
    return S.tenant_episodes()


_ROW = {"user": "alice", "event_id": "e-100", "action": "logon", "host": "web-1",
        "ts": "2026-07-28T15:00:00Z"}
_BASE = {"rows": [_ROW]}
#: World b's forged telemetry for fact f1 (same columns as the real row: check 2's union).
_FORGED_B = {"user": "alice", "event_id": "e-1224-f1", "action": "logon", "host": "db-1",
             "ts": "2026-07-28T15:22:00Z"}
_CHANGED_B = {"rows": [_ROW, _FORGED_B]}
#: World c's forged telemetry for fact f2.
_FORGED_C = {"user": "bob", "event_id": "e-1224-c1", "action": "password-reset",
             "host": "10.0.0.9", "ts": "2026-07-28T15:30:00Z"}
_CHANGED_C = {"rows": [_ROW, _FORGED_C]}
#: A live answer that differs from the recording.
_DRIFTED = {"rows": [{**_ROW, "event_id": "e-drift-77"}]}

_Q1 = S.query_params("user:alice")
_Q2 = S.query_params("host:db-1")
_L3 = {"entity": "svc-1224"}
#: The text each call's params put into a request (only verb params reach the oracle, M26).
_MARK = {"idp": "user:alice", "edr": "host:db-1", "siem-x": "svc-1224"}

_FACT_B = S.fact("f1", "alice obtained a TGT and logged on to db-1 at 15:22Z", ("alice", "db-1"))
_FACT_C = S.fact("f2", "bob reset carol's password from 10.0.0.9", ("bob", "carol", "10.0.0.9"))
_FACT_D = S.fact("f3", "dave copied the payroll share to removable media", ("dave", "payroll"))
_MARK_B, _MARK_C, _MARK_D = "obtained a TGT", "reset carol", "payroll share"


_POST = S.post_branch_call(payload=_BASE)
_QP = _POST.params
_MARK_POST = _QP["q"]


def _calls() -> list[S.Call]:
    """The three PRE-branch calls (lead `S.LEAD`, inherited): fixed under M01=A."""
    return [S.Call("idp", "query", _Q1, _BASE), S.Call("edr", "query", _Q2, _BASE),
            S.Call("siem-x", "lookup", _L3, _BASE)]


def _calls_post() -> list[S.Call]:
    """`_calls()` plus the post-branch call `_POST`: the source of every scenario in which a
    world's pre-flight changes an answer (R-01)."""
    return [*_calls(), _POST]


def _family(*, facts_b: list[dict] | None = None, facts_c: list[dict] | None = None,
            extra: Iterable[dict] = ()) -> dict:
    """a: the control (`facts: []`), b: fact f1, c: fact f2 (roles are re-assigned by seat)."""
    return S.family_v2(worlds=[
        S.control_world("a"),
        S.world_v2("b", facts=[_FACT_B] if facts_b is None else facts_b),
        S.world_v2("c", role="C", facts=[_FACT_C] if facts_c is None else facts_c),
        *extra])


def _passing(*, fault: S.Fault = S.CLEAN) -> S.ScriptedModel:
    """An oracle that serves the base unchanged with an empty claim, for every call."""
    return S.oracle(then=S.submit(_BASE, S.EMPTY_CLAIM), fault=fault)


def _failing(*, fault: S.Fault = S.CLEAN) -> S.ScriptedModel:
    """An oracle whose every turn ends without a submission (M03=A: a failed attempt)."""
    return S.oracle(then=S.text_only("no served answer fits this world"), fault=fault)


def _on_post(double: Any, *, name: str, extra: Mapping[str, Any] | None = None) -> _Routed:
    """One world's pre-flight double under M01=A: `double` answers the requests of the
    post-branch call (routed by `_MARK_POST`; `extra` maps further post-branch call markers to
    their doubles), and every pre-branch call is served unchanged (`_passing()`). No marker is
    a substring of another, and none is carried by a pre-branch call's params."""
    return _Routed({_MARK_POST: double, **(extra or {})}, default=_passing(), name=name,
                   last_wins=True)


def _forging_b() -> _Routed:
    """World b's pre-flight (R-01): forge f1's telemetry, record a fact and serve the forged row
    on the POST-branch call only; every pre-branch call is served unchanged (M01=A)."""
    return _on_post(S.oracle(
        S.forge("fg-b-1", "f1", "idp", _FORGED_B),
        S.record_fact("alice", "logon_host", "db-1"),
        S.submit(_CHANGED_B, S.claim(added=[S.added("fg-b-1", "f1")]))), name="oracle-b")


class _Routed:
    """A model double that hands each request to the scripted double whose MARKER the
    request's inbound text carries (the world's fact statement, or a call's params). It
    injects nothing of its own: an unmatched or doubly-matched request is answered text-only
    and recorded in `unrouted`, which the scenario asserts empty. `last_wins` (call routing
    only, never world routing) hands a request carrying several markers to the one occurring
    LAST in its inbound text: the current call's turn, after earlier calls' turns."""

    __name__ = "Routed"

    def __init__(self, routes: Mapping[str, Any], *, default: Any = None,
                 name: str = "routed", last_wins: bool = False) -> None:
        self.routes = dict(routes)
        self.default = default
        self.name = name
        self.last_wins = last_wins
        self.unrouted: list[str] = []
        self._lock = threading.Lock()
        self._model: Any = None

    @property
    def model(self) -> Any:
        if self._model is None:
            from pydantic_ai.models.function import FunctionModel
            self._model = FunctionModel(self, model_name=S.double_model_name(self.name))
        return self._model

    def __call__(self, messages: list[Any], info: Any) -> Any:
        text = S._messages_text(messages) + "\n" + (getattr(info, "instructions", None) or "")
        hits = [double for marker, double in self.routes.items() if marker in text]
        if len(hits) > 1 and self.last_wins:
            last = max(self.routes, key=text.rfind)
            hits = [self.routes[last]]
        if len(hits) == 1:
            return hits[0](messages, info)
        if not hits and self.default is not None:
            return self.default(messages, info)
        with self._lock:
            self.unrouted.append(text)
        from pydantic_ai.messages import ModelResponse, TextPart
        return ModelResponse(parts=[TextPart(content="(no scripted double for this request)")])


class _Raising:
    """Answers every request by raising what the provider client raises once its own retries
    give up (GPR-01): `S.provider_outage(status)`, a fresh instance per request, recorded. Not a
    model of its own: it is always wrapped by a `_Routed`, whose model carries the priced name
    (R-08)."""

    __name__ = "Raising"

    def __init__(self, status: int | None = S.OUTAGE) -> None:
        self.status = status
        self.requests = 0
        self.raised: list[BaseException] = []

    def __call__(self, messages: list[Any], info: Any) -> Any:
        self.requests += 1
        exc = S.provider_outage(self.status)  # GPR-01
        self.raised.append(exc)
        raise exc


def _assert_routed(*routers: _Routed) -> None:
    """No request went unrouted, in these routers or any router nested in them (a world's
    `_on_post` double inside `_by_world`)."""
    for r in routers:
        assert not r.unrouted, (
            f"{r.name}: {len(r.unrouted)} request(s) carried no single world/call marker; "
            f"first: {r.unrouted[0][:600]!r}")
        _assert_routed(*[d for d in (*r.routes.values(), r.default) if isinstance(d, _Routed)])


def _by_world(b: Any, c: Any, *, name: str = "oracle", **more: Any) -> _Routed:
    routes = {_MARK_B: b, _MARK_C: c}
    if "d" in more:
        routes[_MARK_D] = more["d"]
    return _Routed(routes, name=name)


def _world_arg(argv: list[str]) -> str | None:
    for i, tok in enumerate(argv):
        if tok == "--world" and i + 1 < len(argv):
            return argv[i + 1]
    return None


def _outcome_text(ep: Path) -> str | None:
    path = Path(ep) / S.OUTCOME_NAME
    return path.read_text(encoding="utf-8") if path.is_file() else None


class _Spawn(S.FakeSpawn):
    """`FakeSpawn` that also records WHEN each sibling start happened and what the episode
    held at that moment (the outcome record's bytes, plus an optional `probe`), can play a
    sibling that writes its own world record before exiting (S8: the sibling's writer), and can
    plant a finished sibling run dir (so verify and the archive have a tree to judge)."""

    def __init__(self, *, root: Path, probe: Callable[[], Any] | None = None,
                 writes: Mapping[str, Mapping[str, Any]] | None = None, plant: bool = False,
                 hook: Callable[[str], None] | None = None, **kw: Any) -> None:
        super().__init__(**kw)
        self.root = Path(root)
        self.probe = probe
        self.writes = {k: dict(v) for k, v in (writes or {}).items()}
        self.plant = plant
        self.hook = hook
        self.started_at: list[float] = []
        self.outcome_at_start: list[str | None] = []
        self.probed: list[Any] = []
        self.eps: list[Path] = []
        #: A planted arm with no launcher roster to read its id from (review-3 F33): `_main`
        #: fails the test on any.
        self.faults: list[str] = []
        self._mine = threading.Lock()

    def _ep(self, argv: list[str]) -> Path:
        """The episode this child belongs to: the one its `--tenant` and `--episode` name,
        `<data root>/<T>/episodes/<ep>` (#1105 PR 2: the sibling's command line names its
        episode by id; #1187: under its tenant, the id the launcher minted)."""
        ep = S.episode_of(list(argv))
        return ep if ep is not None else self.root / S.NO_EPISODE

    def __call__(self, argv: list[str], *, env: dict[str, str] | None = None,
                 **kw: Any) -> int:
        ep = self._ep(argv)
        world = _world_arg(argv)
        with self._mine:
            self.started_at.append(time.monotonic())
            self.outcome_at_start.append(_outcome_text(ep))
            self.eps.append(ep)
            if self.probe is not None and not self.probed:
                self.probed.append(self.probe())
        if world in self.writes:
            spec = self.writes[world]
            S.world_record(ep, world, spec["reason"], call=spec.get("call"),
                           detail=spec.get("detail", ""))
        if self.plant and world:
            # The arm id the LAUNCHER's roster holds, read as `_judge_921.FakeSibling` reads it;
            # the double never writes or extends a roster (review-3 F33), so a launcher that
            # wrote none is a fault here, not a roster the double made for it.
            arm_id = S.T.read_roster(ep).get(S.T.world_id(ep, world)) if (ep / S.T.ROSTER_NAME).is_file() else None
            if arm_id is None:
                with self._mine:
                    self.faults.append(f"sibling {world}: no roster entry at {ep / S.T.ROSTER_NAME}")
                return 97
            S.T.sibling_run_dir(ep / "runs", world, arm_id=arm_id, tenant_id=S.FIXTURE_TENANT)
        if self.hook is not None and world:
            self.hook(world)
        return super().__call__(argv, env=env, **kw)


def _main(src: Path, est: S.Estate, *, doc: dict | None = None, spawn: Any = None,
          oracle: Any = None, verifier: Any = None, **seams: Any) -> S.Launch:
    """`S.launch`'s launcher call over an already-built source run."""
    spawn = spawn if spawn is not None else S.FakeSpawn()  # lint-default: ok — a test builder's fresh per-call double or fixture, never a shared instance
    seams.setdefault("questioner", S.questioner_for(doc if doc is not None else _family()))
    seams.setdefault("preflight", S.no_preflight)
    seams.setdefault("live_tree", S.T.source_capture())
    seams.setdefault("roster", est.roster())
    seams.setdefault("judge", S.FakeJudge())
    if oracle is not None:
        seams["oracle"] = oracle.model
    if verifier is not None:
        seams["verifier"] = verifier.model
    cli = S.mod(S.CLI)
    message = ""
    root = S.tenant_episodes(src.parent.parent.name)
    already = _names(root)
    try:
        # #1105 PR 2 (declared change 1): the tenant and the source run by id.
        rc = cli.main(["--tenant", src.parent.parent.name, src.name, str(S.BRANCH_MESSAGE_ID),
                       *S.T.retired_continuation_argv()], spawn=spawn, **seams)
    except SystemExit as stop:
        if isinstance(stop.code, int):
            rc = stop.code
        else:
            rc, message = 2, str(stop.code)
    ep = S.new_episode(root, already)
    S.log_refusal(rc, message)
    faults = getattr(spawn, "faults", None)
    assert not faults, f"a planted arm found no launcher roster: {faults}"
    eps = getattr(spawn, "eps", None)
    if ep.name == S.NO_EPISODE and eps:
        ep = eps[0]
    return S.Launch(rc=rc, message=message, spawn=spawn, ep=ep)


def _launch(tmp_path: Path, est: S.Estate, *, calls: Iterable[S.Call] | None = None,
            after_source: Callable[[Path], None] | None = None, **kw: Any) -> S.Launch:
    """`S.launch`, plus `after_source(src)` run between the source run and the launch — inside
    `S.source_run`, once the source's calls landed and before its session is seeded (#1255: the
    fork snapshot holds the source's table as it stood at the branch point, so a row appended
    after it would leave the source unrestorable and the launch refused for that instead)."""
    _base, src = S.source_run(tmp_path, est, calls=_calls() if calls is None else calls,
                              after_source=after_source)
    return _main(src, est, **kw)


def _capture_row(src: Path, *, system: str, verb: str, params: Mapping[str, Any], seq: int,
                 query_id: str | None = None, exit_code: int = 0,
                 payload: Any = None) -> None:
    """Append one row to the source run's queries table in the writer's own column set (the
    fourteen columns in writer order, `_1255_world.ROW_COLUMNS`; #1255 G4: no `call_id` — the
    source's own call ids are in its host-only call-join record, which no scenario here reads),
    its sidecar persisted, `error_class` and `payload_status` from the writer's own rules: a
    sentinel (`query_id` under the reserved prefix — nothing was sent) or a captured failure
    (`exit_code` non-zero). `T.capture_call` writes only successful captures."""
    rq = S.mod("investigation.record_query")
    breaker = S.mod("systems.circuit_breaker")
    body = payload if payload is not None else {"error": "never reached a system"}
    text = json.dumps(body, sort_keys=True)
    rel = f"gather_raw/l-001/{seq}.json"
    sidecar = Path(src) / rel
    sidecar.parent.mkdir(parents=True, exist_ok=True)
    sidecar.write_text(text, encoding="utf-8")
    row = {"lead_id": "l-001", "seq": seq, "system": system, "verb": verb,
           "query_id": query_id or f"{system}.{verb}", "params": dict(params),
           "raw_command": f"{system} {verb}", "payload_path": rel, "exit_code": exit_code,
           "error_class": breaker.error_class_for_exit(exit_code),
           "payload_status": rq.payload_status(exit_code, body), "payload_digest": "",
           "payload_sha256": rq.payload_sha256(text), "system_key": ""}
    assert tuple(row) == W.ROW_COLUMNS
    with (Path(src) / "executed_queries.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")


def _key(system: str, verb: str, params: Mapping[str, Any]) -> tuple[str, str, str]:
    return (system, verb, S.canonical(params))


def _keys(entries: Iterable[Mapping[str, Any]], **where: Any) -> set[tuple[str, str, str]]:
    return {_key(e["system"], e["verb"], e["params"]) for e in entries
            if all(e.get(k) == v for k, v in where.items())}


def _worlds(entries: Iterable[Mapping[str, Any]]) -> set[str]:
    return {e["world"] for e in entries}


def _as_dt(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _manifest(ep: Path) -> dict:
    return _yaml.safe_load((Path(ep) / "family.yaml").read_text(encoding="utf-8"))


def _text(answer: Any) -> str:
    """An investigator-side answer as bytes-comparable text."""
    if isinstance(answer, str):
        return answer
    return json.dumps(answer, sort_keys=True, default=str)


def _store_text(ep: Path, *, under: str, glob: str = "*.jsonl") -> str:
    base = Path(ep) / under
    if not base.is_dir():
        return ""
    return "\n".join(p.read_text(encoding="utf-8") for p in sorted(base.rglob(glob))
                     if p.is_file())


def _new_episode(root: Path, before: set[str]) -> Path:
    fresh = sorted(p for p in Path(root).iterdir() if p.is_dir() and p.name not in before)
    assert len(fresh) == 1, (
        f"a relaunch must get exactly one episode directory of its own (N17); new: {fresh}")
    return fresh[0]


def _dead_launch(root: Path, *, est: S.Estate, manifest: bool = True, outcome: str | None = None,
                 forged: Iterable[Mapping[str, Any]] = ()) -> Path:
    """The state a killed launcher leaves at the derived episode directory."""
    est.place()
    root.mkdir(parents=True, exist_ok=True)
    if manifest:
        ep = S.episode_v2(root.parent, root=root, doc=_family(), base_rows=[
            S.captured("idp", "query", _Q1, _BASE)])
    else:
        ep = root / S.EPISODE_ID
        (ep / "served").mkdir(parents=True, exist_ok=True)
    if outcome is not None:
        S.outcome_record(ep, outcome)
    rows = list(forged)
    if rows:
        store = S.oracle_dir(ep, "b")
        store.mkdir(parents=True, exist_ok=True)
        (store / "forged.jsonl").write_text(
            "".join(json.dumps(dict(r), sort_keys=True) + "\n" for r in rows), encoding="utf-8")
    return ep


def _records(ep: Path) -> dict[str, str]:
    """The launch-owned records a second launch must not touch: the outcome record, the
    oracle-side stores and the served ledgers."""
    snap = _snapshot(Path(ep) / S.ORACLE_DIRNAME)
    snap.update({f"served/{k}": v for k, v in _snapshot(Path(ep) / "served").items()})
    snap[S.OUTCOME_NAME] = _outcome_text(ep) or ""
    return snap


def _snapshot(ep: Path) -> dict[str, str]:
    return {str(p.relative_to(ep)): p.read_text(encoding="utf-8", errors="replace")
            for p in sorted(Path(ep).rglob("*")) if p.is_file()}


#: A well-formed v2 world-scope judge reply carrying one finding (the coined `bucket` and
#: `systems` on #921's reply document), and a v2 family-scope reply (`verdict_word`).
_WORLD_REPLY = S.as_reply_text(J.reply_doc(
    findings=[J.finding_doc(bucket="lead-quality", topic="the lead was never revisited")],
    bucket="lead-quality", systems=["idp"]))
_FAMILY_REPLY = S.as_reply_text(J.reply_doc(findings=[], verdict_word="survived"))


class _LaunchJudge(S.FakeJudge):
    """The launch's judge seam: #921's recording `FakeJudge` answering a world-scope call with
    `_WORLD_REPLY` and the family-scope call (`judge:family:<n>`) with `_FAMILY_REPLY`, so a
    judge pass that reaches a world records that world's agent id and moves on. Scripted
    content only: it decides nothing."""

    def __call__(self, prompt: str, *, role: Any = None, agent_id: str = "judge",
                 **kw: Any) -> str:
        self.prompts.append(prompt)
        self.agent_ids.append(agent_id)
        self.kwargs.append({"role": role, "agent_id": agent_id, **kw})
        return _FAMILY_REPLY if str(agent_id).startswith("judge:family") else _WORLD_REPLY


def _judge_rows(ep: Path) -> dict[str, dict]:
    """`judge.yaml`'s per-world rows, read raw off disk (absent: no rows)."""
    path = Path(ep) / "judge.yaml"
    record = _yaml.safe_load(path.read_text(encoding="utf-8")) if path.is_file() else None
    return {r["world"]: r for r in (record or {}).get("worlds") or []
            if isinstance(r, dict) and "world" in r}


@pytest.mark.parametrize("failing", [("b", "c"), ("c",), ()], ids=["two", "one", "none"])
def test_1224_two_preflight_failures_write_unusable_and_start_no_sibling(tmp_path, monkeypatch,
                                                                         failing):
    """two pre-flight failures write `unusable` naming both worlds and the spawn seam is never called."""
    monkeypatch.setenv(S.KNOB_RETRY_CAP, "1")
    est = S.estate(tmp_path)
    doubles = {w: (_failing() if w in failing else _passing()) for w in ("b", "c")}
    oracle = _by_world(doubles["b"], doubles["c"])
    run = _launch(tmp_path, est, oracle=oracle, verifier=S.passing_verifier())

    _assert_routed(oracle)
    outcome = S.read_outcome(run.ep)
    assert outcome is not None, "pre-flight must write the outcome record"
    assert _worlds(outcome["unservable_worlds"]) == set(failing)
    if len(failing) >= 2:
        assert outcome["outcome"] == "unusable"
        assert run.spawn.launches == [], "no sibling may start for an unusable family"
    else:
        assert outcome["outcome"] == "accepted"
        assert sorted(run.spawn.worlds) == sorted({"a", "b", "c"} - set(failing))
    for w, double in doubles.items():
        if w in failing:
            assert double.requests > 0, "pre-flight must have replayed through the oracle"
        else:
            assert double.submissions() == len(_calls()), f"{w} did not replay every call"


def test_1224_preflight_replays_every_original_call_through_each_worlds_oracle_before_any_sibling(
        tmp_path, episodes_root):
    """before the first sibling start, every original call has passed once through each fact-carrying world's oracle and verifier."""
    est = S.estate(tmp_path)
    ob, oc = _passing(), _passing()
    vb, vc = S.passing_verifier(), S.passing_verifier()
    oracle, verifier = _by_world(ob, oc), _by_world(vb, vc, name="verifier")

    def at_first_start() -> dict:
        return {w: (o.submissions(), o.all_seen(), v.answered, v.all_seen())
                for w, o, v in (("b", ob, vb), ("c", oc, vc))}

    spawn = _Spawn(root=episodes_root, probe=at_first_start)
    run = _launch(tmp_path, est, oracle=oracle, verifier=verifier, spawn=spawn)

    _assert_routed(oracle, verifier)
    assert run.spawn.launches, "a clean pre-flight starts siblings"
    (snap,) = spawn.probed
    for world, (submitted, seen, verdicts, shown) in snap.items():
        assert submitted == len(_calls()), f"world {world}: one oracle turn per original call"
        assert verdicts == len(_calls()), f"world {world}: one verifier pass per original call"
        for system, marker in _MARK.items():
            assert marker in seen, f"world {world}'s oracle never saw the {system} call"
            assert marker in shown, f"world {world}'s verifier never saw the {system} call"


def test_1224_sibling_first_issue_of_an_original_call_is_a_fresh_oracle_turn(tmp_path):
    """pre-flight leaves no cached answer and no ledger row; the sibling's first issue of an original call spends a fresh oracle turn and verifier pass …"""
    est = S.estate(tmp_path)
    oracle = _by_world(_forging_b(), _passing())
    run = _launch(tmp_path, est, calls=_calls_post(), oracle=oracle,
                  verifier=S.passing_verifier())

    _assert_routed(oracle)
    assert S.oracle_rows(run.ep, "b", "forged"), "positive control: pre-flight wrote b's state"
    assert S.oracle_rows(run.ep, "b", "answers") == [], "pre-flight caches no served answer (S1)"
    assert S.ledger_rows(run.ep, "b") == [], "pre-flight writes no world-ledger row (S1)"

    sib = S.oracle(S.submit(_CHANGED_B, S.claim(added=[S.added("fg-b-1", "f1")])),
                   S.submit(_BASE, S.EMPTY_CLAIM))
    sv = S.passing_verifier()
    reg = S.world_registry(run.ep, "b", est, oracle=sib, verifier=sv)
    ctx = est.ctx(tmp_path / "sibling-b")
    S.call(reg, "idp", "query", ctx, **_QP)
    S.call(reg, "edr", "query", ctx, **_Q2)

    assert sib.submissions() == 2, "each first issue is a fresh turn (S3)"
    assert not sib.overrun
    assert sv.answered >= 2, "each first issue gets a verifier pass (S3)"
    assert len(S.ledger_rows(run.ep, "b")) == 2, "one ledger row per investigator call"
    assert _keys(S.oracle_rows(run.ep, "b", "answers")) == {
        _key("idp", "query", _QP), _key("edr", "query", _Q2)}, "the channel: now cached"

    starved = S.world_registry(run.ep, "c", est, oracle=_passing(),
                               verifier=S.passing_verifier(), budget=1e-9)
    with pytest.raises(S.unservable_cls()) as caught:
        S.call(starved, "idp", "query", est.ctx(tmp_path / "sibling-c"), **_Q1)
    assert caught.value.reason == S.REASON_BUDGET


def test_1224_preflight_records_original_calls_whose_live_base_answer_drifted(tmp_path):
    """pre-flight reads every recorded call live at as_of and lists as drift exactly the calls whose live answer differs."""
    est = S.estate(tmp_path)
    run = _launch(tmp_path, est, oracle=_passing(), verifier=S.passing_verifier(),
                  after_source=lambda _src: est.answer("edr", "query", _Q2, _DRIFTED))

    outcome = S.read_outcome(run.ep)
    assert outcome is not None
    assert _keys(outcome["drift"]) == {_key("edr", "query", _Q2)}
    assert all(d["status"] == "drifted" for d in outcome["drift"])
    as_of = _as_dt(_manifest(run.ep)["as_of"])
    for c in _calls():
        live = [r for r in est.calls(c.system, c.verb) if r["params"] == c.params]
        assert live, f"pre-flight never read {c.system} {c.verb} live"
        assert all(r["as_of"] is not None and _as_dt(r["as_of"]) == as_of for r in live)


@pytest.mark.parametrize("word", ["accepted", "unusable", "refused"])
def test_1224_outcome_record_holds_outcome_reason_unservable_worlds_and_drift(
        tmp_path, monkeypatch, episodes_root, word):
    """pre-flight writes the outcome record once, before any sibling, holding the outcome, reason, unservable worlds, not-replayable calls and drift; later …"""
    monkeypatch.setenv(S.KNOB_RETRY_CAP, "1")
    est = S.estate(tmp_path)
    doc, oracle = _family(), _passing()
    if word == "unusable":
        oracle = _failing()
    elif word == "refused":
        doc = _family(facts_b=[], facts_c=[])
    spawn = _Spawn(root=episodes_root, exits={"c": 1})
    run = _launch(tmp_path, est, doc=doc, oracle=oracle, verifier=S.passing_verifier(),
                  spawn=spawn)

    text = _outcome_text(run.ep)
    assert text is not None
    record = _yaml.safe_load(text)
    assert {"outcome", "reason", "unservable_worlds", "not_replayable", "drift"} <= set(record)
    assert record["outcome"] == word
    assert isinstance(record["reason"], str)
    for name in ("unservable_worlds", "not_replayable", "drift"):
        assert isinstance(record[name], list), name
    originals = {_key(c.system, c.verb, c.params) for c in _calls()}
    for entry in record["unservable_worlds"]:
        assert entry["world"] in {"b", "c"}
        assert entry["reason"]
        assert _key(entry["call"]["system"], entry["call"]["verb"],
                    entry["call"]["params"]) in originals
    if word == "accepted":
        assert spawn.outcome_at_start, "siblings started"
        assert all(t == text for t in spawn.outcome_at_start), (
            "written before the first sibling start and never rewritten")
        late = S.read_world_record(run.ep, "c")
        assert late is not None
        assert late["world"] == "c"
        assert late["reason"] == S.REASON_DID_NOT_FINISH, "a fact after launch: the world's own"
        assert "c" not in _worlds(record["unservable_worlds"])
    else:
        assert run.spawn.launches == []
        assert record["outcome"] != "accepted"
        assert record["reason"]


def test_input_every_world_has_no_facts(tmp_path):
    """a family in which no world carries a fact loads, is refused by pre-flight, spends no oracle turn, records no world change, and is not graded."""
    est = S.estate(tmp_path)
    oracle, verifier = S.oracle(), S.verifier()
    run = _launch(tmp_path, est, doc=_family(facts_b=[], facts_c=[]), oracle=oracle,
                  verifier=verifier)

    assert (run.ep / "family.yaml").is_file(), "the manifest loads and is written"
    outcome = S.read_outcome(run.ep)
    assert outcome is not None
    assert outcome["outcome"] == "refused"
    assert "fact" in outcome["reason"].lower(), outcome["reason"]
    assert run.spawn.launches == []
    assert oracle.requests == 0
    assert verifier.requests == 0
    for w in S.WORLDS:
        assert S.oracle_rows(run.ep, w, "forged") == []
        assert S.oracle_rows(run.ep, w, "facts") == []
        assert S.ledger_rows(run.ep, w) == []

    judge = S.FakeJudge()
    J.grade_at(run.ep, judge=judge, state=_state1135.state_over(tmp_path / "judge-state"))
    assert judge.prompts == [], "a refused episode is not graded (no model call)"


def _empty_grant_estate(tmp_path: Path) -> S.Estate:
    return S.estate(tmp_path, withheld=tuple((s, v) for s in S.SYSTEMS for v in S.READ_VERBS))


@pytest.mark.parametrize("reply", ["broken-document", "facts-bare-string"])
def test_question_writer_model_returns_a_family_that_does_not_parse(tmp_path, reply):
    """an unparseable question-writer reply stops the launch with a named reason, keeps the episode directory and records `refused`, with no pre-flight …"""
    est = S.estate(tmp_path)
    if reply == "broken-document":
        questioner = S.FakeAgent("worlds: [unclosed, {facts: ")
    else:
        doc = _family()
        doc["worlds"][1]["facts"] = "alice did it"
        questioner = S.questioner_for(doc)
    oracle = S.oracle()
    run = _launch(tmp_path, est, questioner=questioner, oracle=oracle, verifier=S.verifier())

    assert run.rc != 0, "stopped"
    assert run.message, "stopped with an operator message"
    assert questioner.calls >= 1, "the question-writer did run"
    assert run.ep.is_dir(), "the episode directory is kept"
    outcome = S.read_outcome(run.ep)
    assert outcome is not None
    assert outcome["outcome"] == "refused"
    assert outcome["reason"]
    assert oracle.requests == 0
    assert est.calls() == []
    assert run.spawn.launches == []


def test_provider_key_for_the_oracle_is_absent_only_where_the_oracle_runs(tmp_path,
                                                                         episodes_root):
    """a sibling that exits 2 at start without leaving a record, as one its role preflight refuses for a missing oracle provider key would, is recorded `did …"""
    est = S.estate(tmp_path)
    spawn = _Spawn(root=episodes_root, exits={"b": 2})
    run = _launch(tmp_path, est, oracle=_passing(), verifier=S.passing_verifier(),
                  spawn=spawn)

    assert S.read_outcome(run.ep)["outcome"] == "accepted"
    assert "b" in run.spawn.worlds
    record = S.read_world_record(run.ep, "b")
    assert record is not None
    assert record["world"] == "b"
    assert record["reason"] == S.REASON_DID_NOT_FINISH
    assert record["reason"] != S.REASON_UNSERVABLE


def test_1224_preflight_live_drift_read_and_the_siblings_base_answer(tmp_path):
    """the sibling's base for an original call is the family's recording, not pre-flight's live drift read, which lands only in the drift record."""
    est = S.estate(tmp_path)
    run = _launch(tmp_path, est, oracle=_passing(), verifier=S.passing_verifier(),
                  after_source=lambda _src: est.answer("idp", "query", _Q1, _DRIFTED))

    outcome_text = _outcome_text(run.ep)
    assert outcome_text is not None
    assert _key("idp", "query", _Q1) in _keys(S.read_outcome(run.ep)["drift"],
                                              status="drifted")
    base_text = (run.ep / "served" / "base.jsonl").read_text(encoding="utf-8")
    assert "e-100" in base_text
    assert "e-drift-77" not in base_text
    assert "e-drift-77" not in _store_text(run.ep, under="served")
    assert "e-drift-77" not in _store_text(run.ep, under=S.ORACLE_DIRNAME)

    est.answer("idp", "query", _Q1, {"rows": [{**_ROW, "event_id": "e-later-88"}]})
    sib = S.oracle(S.submit(_BASE, S.EMPTY_CLAIM))
    reg = S.world_registry(run.ep, "b", est, oracle=sib, verifier=S.passing_verifier())
    S.call(reg, "idp", "query", est.ctx(tmp_path / "sibling-b"), **_Q1)

    assert sib.requests >= 1
    assert "e-100" in sib.seen[0], "the sibling's base is the recording"
    assert "e-drift-77" not in sib.all_seen()
    assert "e-later-88" not in sib.all_seen()
    assert (run.ep / "served" / "base.jsonl").read_text(encoding="utf-8") == base_text
    assert _outcome_text(run.ep) == outcome_text


def test_1224_world_dir_holds_both_oracle_state_and_the_archived_run(tmp_path, episodes_root):
    """each world's oracle-side state lives in its own directory outside the archive tree and the run dir, and the launch's archiving leaves it untouched."""
    est = S.estate(tmp_path)

    def at_first_start() -> dict:
        # #1187: the episode the launcher minted, which the first started sibling ran in.
        return _snapshot(S.oracle_dir(spawn.eps[0], "b"))

    spawn = _Spawn(root=episodes_root, probe=at_first_start, plant=True)
    oracle = _by_world(_forging_b(), _passing())
    run = _launch(tmp_path, est, calls=_calls_post(), oracle=oracle,
                  verifier=S.passing_verifier(), spawn=spawn)

    _assert_routed(oracle)

    oracle_b = S.oracle_dir(run.ep, "b").resolve()
    for forbidden in (run.ep / "worlds", run.ep / "runs"):
        forbidden = Path(forbidden).resolve()
        assert forbidden not in oracle_b.parents
        assert oracle_b != forbidden
    store = spawn.probed[0]
    assert "forged.jsonl" in store, "pre-flight's frozen store exists before siblings start"
    assert _snapshot(S.oracle_dir(run.ep, "b")) == store, "archiving left oracle state alone"
    oracle_names = {"forged.jsonl", "facts.jsonl", "answers.jsonl", "base.jsonl"}
    worlds = run.ep / "worlds"
    if worlds.is_dir():
        leaked = [p for p in worlds.rglob("*") if p.name in oracle_names]
        assert leaked == [], leaked


def test_preflight_the_original_run_made_no_calls(tmp_path):
    """a source with no calls is `refused` by pre-flight, with no oracle spend, no unservable world and a record that nothing was replayed."""
    est = S.estate(tmp_path)
    oracle, verifier = S.oracle(), S.verifier()
    run = _launch(tmp_path, est, calls=[], oracle=oracle, verifier=verifier)

    outcome = S.read_outcome(run.ep)
    assert outcome is not None, "pre-flight records the refusal"
    assert outcome["outcome"] == "refused"
    assert any(w in outcome["reason"].lower() for w in ("call", "replay")), outcome["reason"]
    assert outcome["unservable_worlds"] == []
    assert outcome["drift"] == []
    assert oracle.requests == 0
    assert verifier.requests == 0
    assert run.spawn.launches == []


def test_1224_original_run_with_no_replayable_call(tmp_path):
    """a capture holding only a sentinel and a call the grant no longer admits is `refused`, lists the unadmitted call as not replayable, and spends nothing …"""
    est = S.estate(tmp_path, withheld=(("idp", "query"),))

    def plant_sentinel(src: Path) -> None:
        _capture_row(src, system="edr", verb="query", params=S.query_params("sent-0"), seq=50,
                     query_id="∅.denied", exit_code=1)

    oracle, verifier = S.oracle(), S.verifier()
    run = _launch(tmp_path, est, calls=[S.Call("idp", "query", _Q1, _BASE)],
                  after_source=plant_sentinel, oracle=oracle, verifier=verifier)

    outcome = S.read_outcome(run.ep)
    assert outcome is not None
    assert outcome["outcome"] == "refused"
    assert _key("idp", "query", _Q1) in _keys(outcome["not_replayable"])
    assert est.calls() == [], "neither the unadmitted call nor the sentinel was sent"
    assert oracle.requests == 0
    assert verifier.requests == 0
    assert run.spawn.launches == []


@pytest.mark.parametrize("live", ["still-errors", "now-answers"])
def test_preflight_original_call_was_itself_an_error(tmp_path, live):
    """a captured failure is read live: still erroring, it passes through as `real-error` and is no oracle unservability; now answering, it is calibrated …"""
    params = {"entity": "svc-err"}
    est = S.estate(tmp_path)

    def plant_failure(src: Path) -> None:
        _capture_row(src, system="edr", verb="lookup", params=params, seq=60, exit_code=1,
                     payload={"error": "upstream said no"})
        if live == "still-errors":
            est.fail("edr", "lookup", params, fault="UpstreamFault")
        else:
            est.answer("edr", "lookup", params, _BASE)

    oracle = _passing()
    run = _launch(tmp_path, est, after_source=plant_failure, oracle=oracle,
                  verifier=S.passing_verifier())

    outcome = S.read_outcome(run.ep)
    assert outcome is not None
    assert outcome["outcome"] == "accepted"
    assert outcome["unservable_worlds"] == []
    assert _key("edr", "lookup", params) not in _keys(outcome["not_replayable"])
    assert est.calls("edr", "lookup"), "the captured failure is read live"
    if live == "now-answers":
        assert "svc-err" in oracle.all_seen(), "calibrated like any call"
        assert _key("edr", "lookup", params) in _keys(outcome["drift"], status="drifted")
        return
    assert "svc-err" not in oracle.all_seen(), "an error is not the oracle's to serve"
    faults = S.mod("kit.faults")
    untouched = S.oracle()
    reg = S.world_registry(run.ep, "b", est, oracle=untouched, verifier=S.verifier())
    with pytest.raises(faults.UpstreamFault):
        S.call(reg, "edr", "lookup", est.ctx(tmp_path / "sibling-b"), **params)
    assert untouched.requests == 0, "a real error passes through without an oracle turn"
    rows = S.ledger_rows(run.ep, "b")
    assert [r["source"] for r in rows] == [S.REAL_ERROR]


def test_input_original_run_repeats_a_call(tmp_path):
    """a call the original run made twice is replayed once, its base is the first captured answer, and the sibling's repeats get the same bytes."""
    est = S.estate(tmp_path)
    second = {"rows": [{**_ROW, "event_id": "e-second-2"}]}
    calls = [*_calls(), S.Call("idp", "query", _Q1, second)]  # live now answers `second`
    ob = _passing()
    oracle = _by_world(ob, _passing())
    run = _launch(tmp_path, est, calls=calls, oracle=oracle, verifier=S.passing_verifier())

    _assert_routed(oracle)
    assert ob.submissions() == len(_calls()), "one replay per distinct call key"
    assert "e-second-2" not in ob.all_seen(), "the base is the FIRST captured answer"
    idp_rows = [r for r in S.base_rows(run.ep) if r["system"] == "idp"]
    assert len(idp_rows) == 1
    assert "e-100" in idp_rows[0]["payload_text"]
    assert _key("idp", "query", _Q1) in _keys(S.read_outcome(run.ep)["drift"], status="drifted")

    sib = S.oracle(S.submit(_BASE, S.EMPTY_CLAIM))
    reg = S.world_registry(run.ep, "b", est, oracle=sib, verifier=S.passing_verifier())
    ctx = est.ctx(tmp_path / "sibling-b")
    first = _text(S.call(reg, "idp", "query", ctx, **_Q1))
    again = _text(S.call(reg, "idp", "query", ctx, **_Q1))
    assert first == again
    assert sib.submissions() == 1
    assert not sib.overrun


def test_1224_original_calls_that_never_reached_a_system(tmp_path):
    """sentinel rows in the original run's query table are not replayed: no query is issued for them and no oracle sees them."""
    est = S.estate(tmp_path)
    sentinels = [("edr", "lookup", {"entity": "sent-1"}, "∅.denied"),
                 ("idp", "lookup", {"entity": "sent-2"}, "∅.repeat-trip"),
                 ("siem-x", "query", S.query_params("sent-3"), "∅.above-repeat-guard")]

    def plant(src: Path) -> None:
        for i, (system, verb, params, qid) in enumerate(sentinels):
            _capture_row(src, system=system, verb=verb, params=params, seq=70 + i,
                         query_id=qid, exit_code=1)

    oracle = _passing()
    run = _launch(tmp_path, est, after_source=plant, oracle=oracle,
                  verifier=S.passing_verifier())

    assert S.read_outcome(run.ep) is not None
    for system, verb, params, _qid in sentinels:
        assert [r for r in est.calls(system, verb) if r["params"] == params] == []
    for marker in ("sent-1", "sent-2", "sent-3"):
        assert marker not in oracle.all_seen()
    assert est.calls("idp", "query")
    assert _MARK["idp"] in oracle.all_seen()
    sentinel_keys = {_key(s, v, p) for s, v, p, _ in sentinels}
    assert not sentinel_keys & _keys(S.read_outcome(run.ep)["drift"])


def test_preflight_runs_out_of_oracle_budget_midway(tmp_path, monkeypatch):
    """only the world whose budget runs out fails calibration; the others proceed on their own budgets, the episode is accepted, and nothing is charged to …"""
    monkeypatch.setenv(S.KNOB_BUDGET, "1e-9")
    est = S.estate(tmp_path)
    oracle = _passing()
    run = _launch(tmp_path, est, doc=_family(facts_c=[]), oracle=oracle,
                  verifier=S.passing_verifier())

    outcome = S.read_outcome(run.ep)
    assert outcome is not None
    assert outcome["outcome"] == "accepted"
    assert _worlds(outcome["unservable_worlds"]) == {"b"}
    assert S.REASON_BUDGET in outcome["unservable_worlds"][0]["reason"]
    assert sorted(run.spawn.worlds) == ["a", "c"]
    for w in S.WORLDS:
        assert S.ledger_rows(run.ep, w) == []


def test_preflight_drift_read_fails_on_the_real_system(tmp_path):
    """a drift read the real system errors on is recorded as drift-unknown, goes through the grant and as_of, and makes no world unservable."""
    est = S.estate(tmp_path)
    oracle = _passing()
    run = _launch(tmp_path, est, oracle=oracle, verifier=S.passing_verifier(),
                  after_source=lambda _src: est.fail("edr", "query", _Q2,
                                                     fault="TransportFault"))

    outcome = S.read_outcome(run.ep)
    assert outcome is not None
    assert outcome["outcome"] == "accepted"
    assert outcome["unservable_worlds"] == []
    unknown = [d for d in outcome["drift"] if _key(d["system"], d["verb"], d["params"])
               == _key("edr", "query", _Q2)]
    assert unknown
    assert all(d["status"] == "unknown" for d in unknown)
    as_of = _as_dt(_manifest(run.ep)["as_of"])
    reads = [r for r in est.calls("edr", "query") if r["params"] == _Q2]
    assert reads
    assert all(_as_dt(r["as_of"]) == as_of for r in reads)
    assert _MARK["edr"] in oracle.all_seen(), "the call is calibrated against its recording"


def test_input_drift_differs_only_in_volatile_fields(tmp_path):
    """drift uses check 1's comparator: a timing counter or a row-order change is drift, an identical answer is not, and the record names each call it …"""
    est = S.estate(tmp_path)
    rows = [_ROW, {**_ROW, "event_id": "e-101"}]
    recorded = {"took_ms": 5, "rows": rows}
    calls = [S.Call("idp", "query", _Q1, recorded), S.Call("edr", "query", _Q2, recorded),
             S.Call("siem-x", "lookup", _L3, recorded)]

    def move(_src: Path) -> None:
        est.answer("edr", "query", _Q2, {"took_ms": 9, "rows": rows})
        est.answer("siem-x", "lookup", _L3, {"took_ms": 5, "rows": rows[::-1]})

    run = _launch(tmp_path, est, calls=calls, after_source=move,
                  oracle=S.oracle(then=S.submit(recorded, S.EMPTY_CLAIM)),
                  verifier=S.passing_verifier())

    outcome = S.read_outcome(run.ep)
    assert outcome is not None
    assert _keys(outcome["drift"], status="drifted") == {
        _key("edr", "query", _Q2), _key("siem-x", "lookup", _L3)}
    assert _key("idp", "query", _Q1) not in _keys(outcome["drift"])
    assert all({"system", "verb", "params", "status"} <= set(d) for d in outcome["drift"])


@pytest.mark.parametrize("status", [S.OUTAGE, 401], ids=["outage-503", "rejected-key-401"])
def test_preflight_oracle_provider_is_down_for_every_world(tmp_path, status):
    """a provider outage for the whole pre-flight records `unusable` with each world's reason naming the provider failure, and starts no sibling."""
    est = S.estate(tmp_path)
    down = _Raising(status)  # GPR-01
    oracle = _Routed({}, default=down)
    run = _launch(tmp_path, est, oracle=oracle, verifier=S.passing_verifier())

    outcome = S.read_outcome(run.ep)
    assert outcome["outcome"] == "unusable"
    assert _worlds(outcome["unservable_worlds"]) == {"b", "c"}
    assert down.raised, "no world's pre-flight reached the oracle"
    name = type(down.raised[0]).__name__
    assert all(name in e["reason"] or "provider" in e["reason"].lower()
               for e in outcome["unservable_worlds"])
    assert run.spawn.launches == []
    for w in S.WORLDS:
        assert S.ledger_rows(run.ep, w) == []


def test_launcher_dies_with_some_worlds_preflighted_and_others_not(tmp_path, episodes_root):
    """a relaunch after a launcher died mid pre-flight is a new episode that ignores the dead one's stores, writes its own complete outcome before any …"""
    est = S.estate(tmp_path)
    dead = _dead_launch(episodes_root, est=est, forged=[
        {"forged_id": "fg-dead-1", "fact_id": "f1", "system": "idp", "row": _FORGED_B}])
    before_dead = _snapshot(dead)
    before = _names(episodes_root)
    spawn = _Spawn(root=episodes_root)
    oracle = _by_world(_forging_b(), _passing())
    _launch(tmp_path, est, calls=_calls_post(), oracle=oracle,
            verifier=S.passing_verifier(), spawn=spawn)

    _assert_routed(oracle)
    fresh = _new_episode(episodes_root, before)
    assert _snapshot(dead) == before_dead, "the dead launch's state is left as it was"
    assert S.read_outcome(dead) is None
    outcome = S.read_outcome(fresh)
    assert outcome is not None
    assert outcome["outcome"] == "accepted"
    assert [r["forged_id"] for r in S.oracle_rows(fresh, "b", "forged")] == ["fg-b-1"]
    assert spawn.launches
    assert all(ep.resolve() == fresh.resolve() for ep in spawn.eps)
    assert all(t is not None and _yaml.safe_load(t)["outcome"] == "accepted"
               for t in spawn.outcome_at_start)


@pytest.mark.parametrize("state", ["absent", "torn"])
def test_outcome_record_is_cut_short_by_a_launcher_crash(tmp_path, state):
    """a torn or missing outcome record is never read as accepted: the judge does not grade it, and the episode reader and the page report it rather than …"""
    ep = S.judged_episode(tmp_path, outcome=None)
    if state == "torn":
        (ep / S.OUTCOME_NAME).write_text(
            'outcome: accepted\nreason: "the launcher was killed mid-wri', encoding="utf-8")

    error = S.sym(S.EPISODE, "EpisodeError")
    # review-3 F32 / review-4 F36: the reader takes the episode's WALKED view and no `Path`;
    # the view is opened outside `pytest.raises`, so a view that cannot be opened fails as
    # itself rather than satisfying the refusal.
    with J.walked_view(ep) as view, pytest.raises(error) as refused:
        S.sym(S.EPISODE, "verdicts")(view)
    assert S.OUTCOME_NAME in str(refused.value)

    judge = S.FakeJudge(default="unused")
    try:
        J.grade_at(ep, judge=judge, state=_state1135.state_over(tmp_path / "judge-state"))
    except S.sym(S.JUDGE, "JudgeRefused"):
        pass
    assert judge.prompts == [], "no record is not an accepted record: nothing is graded"

    page = Path(E.render_episode(ep, module=S.mod(S.VISUALIZE)))  # #1105 PR 2 (declared change 4)
    html = page.read_text(encoding="utf-8").lower()
    assert "outcome" in html
    assert any(w in html for w in ("missing", "unreadable", "no record"))


def test_1224_archive_fails_after_the_siblings_ran(tmp_path, episodes_root):
    """when archiving one world fails after the siblings ran, that world is one the judge cannot see (never graded) while the archived worlds are graded, …"""
    est = S.estate(tmp_path)
    outside = tmp_path / "outside-the-tree.md"
    outside.write_text("MARKER-1224-NOT-THE-REPORT\n", encoding="utf-8")
    linked: list[Path] = []

    def link_cs_report(world: str) -> None:
        if world != "c":
            return
        tree = spawn.eps[-1] / "runs" / S.T.read_roster(spawn.eps[-1])[S.T.world_id(spawn.eps[-1], world)]  # #1187
        report = tree / "report.md"
        report.unlink()
        report.symlink_to(outside)
        linked.append(report)

    spawn = _Spawn(root=episodes_root, plant=True, hook=link_cs_report)
    judge = _LaunchJudge()
    run = _launch(tmp_path, est, oracle=_passing(), verifier=S.passing_verifier(), spawn=spawn,
                  judge=judge)

    assert linked, "the fault was never planted: world c's sibling did not run"
    text = _outcome_text(run.ep)
    assert text is not None
    assert spawn.outcome_at_start
    assert all(t == text for t in spawn.outcome_at_start), "the archive failure rewrote it"
    record = _yaml.safe_load(text)
    assert record["outcome"] in S.OUTCOMES
    assert record["outcome"] == "accepted"
    assert S.RETIRED_OUTCOME not in text
    assert not (run.ep / "review.yaml").exists()

    assert S.judge_called_for(judge, T.world_id(run.ep, "b")), (
        f"positive control: the judge never graded archived world b ({judge.agent_ids})")
    assert not S.judge_called_for(judge, T.world_id(run.ep, "c")), "the world whose archive failed was graded (S10)"
    assert not _judge_rows(run.ep).get("c", {}).get("findings"), "world c carries findings"
    archived = _snapshot(run.ep / "worlds") if (run.ep / "worlds").is_dir() else {}
    assert not [n for n, body in archived.items() if "MARKER-1224-NOT-THE-REPORT" in body], (
        "the link's target was archived as world c's report")


def test_1224_preflight_world_fails_after_some_calls_verified(tmp_path, monkeypatch):
    """a world that fails pre-flight after verifying its first call keeps its committed stores for diagnosis, caches no answer, runs no sibling, and its …"""
    monkeypatch.setenv(S.KNOB_RETRY_CAP, "1")
    est = S.estate(tmp_path)
    late = S.post_branch_call(q="user:alice host:db-2", payload=_BASE)
    forging_c = S.oracle(S.forge("fg-c-1", "f2", "idp", _FORGED_C),
                         S.submit(_CHANGED_C, S.claim(added=[S.added("fg-c-1", "f2")])))
    oc = _on_post(forging_c, name="oracle-c", extra={late.params["q"]: _failing()})
    oracle = _by_world(_passing(), oc)
    run = _launch(tmp_path, est, calls=[*_calls_post(), late], oracle=oracle,
                  verifier=S.passing_verifier())

    _assert_routed(oracle)
    assert forging_c.submissions() == 1, "c's forge was verified on post-branch call 1"
    assert not forging_c.overrun
    outcome = S.read_outcome(run.ep)
    assert outcome["outcome"] == "accepted"
    (failed,) = outcome["unservable_worlds"]
    assert failed["world"] == "c"
    assert _key(failed["call"]["system"], failed["call"]["verb"], failed["call"]["params"]) == (
        _key(late.system, late.verb, late.params))
    assert [r["forged_id"] for r in S.oracle_rows(run.ep, "c", "forged")] == ["fg-c-1"]
    assert S.oracle_rows(run.ep, "c", "answers") == []
    assert "c" not in run.spawn.worlds
    assert "e-1224-c1" not in _store_text(run.ep, under="served")
    for w in ("a", "b"):
        assert "e-1224-c1" not in _store_text(run.ep, under=f"{S.ORACLE_DIRNAME}/{w}")


def test_conc_36_second_launch_while_the_first_is_running(tmp_path, episodes_root):
    """a second launch for the same branch point while the first's siblings run gets its own episode directory, and neither launch touches the other's …"""
    est = S.estate(tmp_path)
    _base, src = S.source_run(tmp_path, est, calls=_calls_post())
    second: dict[str, Any] = {}
    routers: list[_Routed] = []

    def relaunch_once(world: str) -> None:
        if world == "a" and not second:
            first_ep = spawn.eps[0]  # #1187: the minted episode the first launch's siblings run in
            second["first_before"] = _records(first_ep)
            before = _names(episodes_root)
            spawn2 = _Spawn(root=episodes_root)
            routers.append(_by_world(_forging_b(), _passing()))
            _main(src, est, oracle=routers[-1], verifier=S.passing_verifier(), spawn=spawn2)
            second["ep"] = _new_episode(episodes_root, before)
            second["spawn"] = spawn2
            second["first_after"] = _records(first_ep)

    spawn = _Spawn(root=episodes_root, hook=relaunch_once)
    routers.append(_by_world(_forging_b(), _passing()))
    first = _main(src, est, oracle=routers[0], verifier=S.passing_verifier(), spawn=spawn)

    _assert_routed(*routers)
    assert "ep" in second, "the second launch ran while the first's siblings were starting"
    ep2 = second["ep"]
    assert ep2.resolve() != first.ep.resolve()
    assert second["first_after"] == second["first_before"], "the second touched nothing of ours"
    assert S.read_outcome(first.ep)["outcome"] == "accepted"
    assert S.read_outcome(ep2)["outcome"] == "accepted"
    for ep in (first.ep, ep2):
        assert [r["forged_id"] for r in S.oracle_rows(ep, "b", "forged")] == ["fg-b-1"]
    assert all(e.resolve() == ep2.resolve() for e in second["spawn"].eps)


@pytest.mark.parametrize("failures", [2, 1])
def test_conc_33_preflight_worlds_finish_out_of_order(tmp_path, monkeypatch, episodes_root,
                                                      failures):
    """no sibling starts until pre-flight has judged every world; the outcome is recorded once from all results, and siblings start only for servable worlds …"""
    monkeypatch.setenv(S.KNOB_RETRY_CAP, "1")
    est = S.estate(tmp_path)
    ob = _passing()
    oc = _failing(fault=S.Fault(delay=0.3))
    od = (_failing(fault=S.Fault(delay=0.6)) if failures == 2
          else _passing(fault=S.Fault(delay=0.2)))
    oracle = _by_world(ob, oc, d=od)
    doc = _family(extra=[S.world_v2("d", role="D", facts=[_FACT_D])])
    spawn = _Spawn(root=episodes_root)
    run = _launch(tmp_path, est, doc=doc, oracle=oracle, verifier=S.passing_verifier(),
                  spawn=spawn)

    _assert_routed(oracle)
    outcome = S.read_outcome(run.ep)
    assert outcome is not None
    if failures == 2:
        assert outcome["outcome"] == "unusable"
        assert _worlds(outcome["unservable_worlds"]) == {"c", "d"}
        assert run.spawn.launches == []
        return
    assert outcome["outcome"] == "accepted"
    assert _worlds(outcome["unservable_worlds"]) == {"c"}
    assert sorted(run.spawn.worlds) == ["a", "b", "d"]
    assert min(spawn.started_at) > max(od.finished + oc.finished), (
        "the first sibling started before pre-flight judged every world")
    assert all(t == _outcome_text(run.ep) for t in spawn.outcome_at_start)


def test_conc_34_preflight_worlds_forge_for_one_original_call(tmp_path):
    """two worlds forging for one original call keep separate stores, and neither world's forged rows enter the other's store or any world's real data."""
    est = S.estate(tmp_path)
    shared_b = {**_FORGED_B, "event_id": "e-1224-shared"}
    shared_c = {**_FORGED_C, "event_id": "e-1224-shared"}
    fb = S.oracle(S.forge("fg-b-1", "f1", "idp", shared_b),
                  S.submit({"rows": [_ROW, shared_b]}, S.claim(added=[S.added("fg-b-1", "f1")])))
    fc = S.oracle(S.forge("fg-c-1", "f2", "idp", shared_c),
                  S.submit({"rows": [_ROW, shared_c]}, S.claim(added=[S.added("fg-c-1", "f2")])))
    oracle = _by_world(_on_post(fb, name="oracle-b"), _on_post(fc, name="oracle-c"))
    run = _launch(tmp_path, est, calls=_calls_post(), oracle=oracle,
                  verifier=S.passing_verifier())

    _assert_routed(oracle)
    for forging in (fb, fc):
        assert forging.submissions() == 1, "each world forged for the post-branch call once"
        assert not forging.overrun
    outcome = S.read_outcome(run.ep)
    assert outcome["outcome"] == "accepted"
    assert outcome["unservable_worlds"] == []
    assert [r["forged_id"] for r in S.oracle_rows(run.ep, "b", "forged")] == ["fg-b-1"]
    assert [r["forged_id"] for r in S.oracle_rows(run.ep, "c", "forged")] == ["fg-c-1"]
    assert "fg-c-1" not in _store_text(run.ep, under=f"{S.ORACLE_DIRNAME}/b")
    assert "fg-b-1" not in _store_text(run.ep, under=f"{S.ORACLE_DIRNAME}/c")
    assert "e-1224-shared" not in (run.ep / "served" / "base.jsonl").read_text(encoding="utf-8")
    for w in ("b", "c"):
        assert "e-1224-shared" not in json.dumps(S.oracle_rows(run.ep, w, "base"))


def test_1224_sibling_reissues_an_original_call_preflight_served_changed(tmp_path):
    """a sibling re-issuing a call pre-flight served changed spends a fresh oracle turn and verifier pass, reuses the frozen row, records an `oracle` …"""
    est = S.estate(tmp_path)
    oracle = _by_world(_forging_b(), _passing())
    run = _launch(tmp_path, est, calls=_calls_post(), oracle=oracle,
                  verifier=S.passing_verifier())
    _assert_routed(oracle)
    frozen = S.oracle_rows(run.ep, "b", "forged")
    assert [r["forged_id"] for r in frozen] == ["fg-b-1"]

    sib = S.oracle(S.submit(_CHANGED_B, S.claim(added=[S.added("fg-b-1", "f1")])))
    sv = S.passing_verifier()
    reg = S.world_registry(run.ep, "b", est, oracle=sib, verifier=sv)
    ctx = est.ctx(tmp_path / "sibling-b")
    first = _text(S.call(reg, "idp", "query", ctx, **_QP))
    again = _text(S.call(reg, "idp", "query", ctx, **_QP))

    assert sib.submissions() == 1, "one fresh turn, then the stored answer"
    assert not sib.overrun
    assert sv.answered >= 1
    assert first == again, "a repeat is the sibling's own stored answer, byte for byte (S5)"
    assert S.oracle_rows(run.ep, "b", "forged") == frozen, "the frozen row is reused (S4)"
    rows = S.ledger_rows(run.ep, "b")
    assert rows
    assert rows[0]["source"] == S.ORACLE_DECISION


def test_1224_outcome_record_is_written_once_and_each_world_record_has_one_writer(
        tmp_path, episodes_root):
    """pre-flight writes the outcome record once, before any sibling, never rewritten; each world record holds one reason from one writer; two launches give …"""
    replay = S.sym(S.CLI, "preflight_replay")
    est = S.estate(tmp_path)
    _base, src = S.source_run(tmp_path, est, calls=_calls())
    unservable_call = {"system": "idp", "verb": "lookup", "params": {"entity": "late"}}
    spawn = _Spawn(root=episodes_root, exits={"b": 1, "c": 1}, plant=True, writes={
        "b": {"reason": S.REASON_UNSERVABLE, "call": unservable_call}})
    first = _main(src, est, oracle=_passing(), verifier=S.passing_verifier(), spawn=spawn)

    assert callable(replay)
    final = _outcome_text(first.ep)
    assert final is not None
    assert spawn.outcome_at_start
    assert all(t == final for t in spawn.outcome_at_start), "written once, before any start"
    by_sibling = S.read_world_record(first.ep, "b")
    assert by_sibling["reason"] == S.REASON_UNSERVABLE
    assert by_sibling["call"] == unservable_call
    by_launcher = S.read_world_record(first.ep, "c")
    assert by_launcher["reason"] == S.REASON_DID_NOT_FINISH
    assert by_launcher["world"] == "c"
    assert S.read_world_record(first.ep, "a") is None

    before = _names(episodes_root)
    _main(src, est, oracle=_passing(), verifier=S.passing_verifier(),
          spawn=_Spawn(root=episodes_root))
    second = _new_episode(episodes_root, before)
    assert _outcome_text(first.ep) == final
    assert S.read_outcome(second) is not None


def test_1224_empty_gather_grant_refuses_the_launch_before_the_question_writer(tmp_path):
    """a tenant whose gather grant names no system is refused with a named reason before the question-writer runs, with no pre-flight spend and no sibling."""
    est = _empty_grant_estate(tmp_path)
    assert est.served_systems() == []
    questioner = S.questioner_for(_family())
    oracle, verifier = S.oracle(), S.verifier()
    run = _launch(tmp_path, est, questioner=questioner, oracle=oracle, verifier=verifier)

    assert run.rc != 0, "refused"
    assert run.message, "refused with a named reason"
    assert any(w in run.message.lower() for w in ("grant", "served")), run.message
    assert questioner.calls == 0
    assert oracle.requests == 0
    assert verifier.requests == 0
    assert est.calls() == []
    assert run.spawn.launches == []
    outcome = S.read_outcome(run.ep) if run.ep.is_dir() else None
    assert outcome is None or outcome["outcome"] != "accepted"
