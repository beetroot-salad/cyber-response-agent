"""#920 PR 1 — the estate seam: what a branched sibling queries THROUGH, and what it records.

A sibling world does not replay a snapshot. It queries the live estate through
`WorldRegistry`, a `ModuleVerbRegistry` subclass whose verbs run FOR REAL against the adapter
and then answer to the world: `prepare` retargets the call at the world's staged corpus before
it runs, `apply` patches the response after it does.

**The safety property inverts from the issue's original framing.** Under staging a query
reaching a real adapter IS the design, so "no adapter was called" is not the thing to gate.
The hazard is a response reaching the defender WITHOUT passing the applier — silent scenario
deletion, a run that looks fine and measures nothing. So the ledger is the gate: every served
payload lands there with the DECISION that produced it, `passthrough` is a recorded decision
rather than an absence, and `Ledger.record` refuses a `ServedCall` whose source is outside
`SOURCES` — before the payload is handed back.

WHAT THIS FILE OWNS
-------------------
1. **Structural coverage** — `decide()` is GRANTED for every entry of the shipped gather grant
   (28 entries, 7 systems), and every callable `verbs()` hands back is a WRAPPED one carrying
   the real body's decoration and keyword-only signature. Structural, not enumerated: there is
   no route to a bare adapter body, so no system can be silently left out of the estate.
2. **Nominal typing** — `build_agent_core` refuses a registry-shaped stand-in; `WorldRegistry`
   passes, because it went through the real constructor with a real `VerbGrant`.
3. **Every served response is recorded with a decision** — including the refusal arm, where
   the caller must get NO payload.
4. **The family tier** — `world_id=None` rows are the family's base recording, replayed by
   every sibling, so the same key costs exactly ONE adapter call. That is what buys A/B
   invariance from an estate that is live and moving under both siblings.
5. **`touches` gates cost and semantics** — a system no world declares is never staged.

WHAT IT DOES NOT OWN. The elastic rewrite rules (`redirect` / `rewrite_from` / `view_name`,
and the 12 committed templates they have to survive) are `test_920_elastic_staging.py`; the
branch/fork half of PR 1 is `test_920_branch_seam.py` and `e2e/test_920_branch_resume.py`.
Staging appears here only where the SEAM is the subject — that the retarget reaches the
adapter body, and that `touches` decides whether it happens at all.

Hermetic. The real-adapters half constructs a registry over the REAL
`defender/scripts/adapters` and the REAL grant — a cold read plus (for `decide`) an import, no
network, no verb body run. The serving half runs verb bodies for real against a fake adapters
DIRECTORY written to `tmp_path`: a real file the cold `VERBS = {...}` reader parses and the
loader imports, rather than a patched module, because the grant/adapter agreement check runs
off that text before anything is served. Fakes enter through the constructor's own DI seams
(`world=`, `ledger=`, `applier=`, `verbs=`); nothing here uses `monkeypatch.setattr`.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import ModelResponse, TextPart  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402

from defender._io import read_jsonl_rows  # noqa: E402
from defender._paths import PATHS  # noqa: E402
from defender.learning.branch.estate.applier import WorldApplier  # noqa: E402
from defender.learning.branch.estate.registry import (  # noqa: E402
    EstateError,
    WorldRegistry,
)
from defender.learning.branch.ledger import (  # noqa: E402
    BASE,
    PASSTHROUGH,
    PATCHED,
    SOURCES,
    STAGED,
    Ledger,
    LedgerError,
    ServedCall,
    request_key,
)
from defender.runtime import driver, observe  # noqa: E402
from defender.runtime.tools import GatherDeps  # noqa: E402
from defender.runtime.verb_grant import VerbGrant  # noqa: E402
from defender.runtime.verbs import (  # noqa: E402
    GRANTED,
    ModuleVerbRegistry,
    VerbContext,
    body_param_of,
    declared_params,
    engine_of,
    model_facing_params,
    validate_params,
    verb_class_of,
    wrapper_only_params,
)
from defender.tests._engine_helpers import fake_model  # noqa: E402

#: The estate a real branched run queries: the shipped adapters and the shipped gather grant.
#: Read through `PATHS`, the same seam `build_agent_core` defaults to, so a tree that moves its
#: adapters moves this with it.
REAL_ADAPTERS = PATHS.adapters_dir
GATHER_GRANT = driver.GATHER_DEF.verb_grant

#: What the shipped grant covers today. Asserted rather than derived, so a grant that SHRINKS
#: — a system quietly dropped out of the estate — fails here instead of making the structural
#: sweep below cover less and still pass.
GRANTED_ENTRIES = 28
GRANTED_SYSTEMS = 7


# --------------------------------------------------------------------------
# the fake estate: a real adapters directory, with verb bodies that count
# --------------------------------------------------------------------------

#: A recording adapter. Written to disk rather than patched in, because `ModuleVerbRegistry`
#: COLD-READS this text (`declared_verb_names` parses the `VERBS = {...}` literal without
#: importing) and checks the grant against it at construction — a module-object stand-in would
#: never reach that check, so the fixture would not be the shape the seam actually admits.
#:
#: `defender/tests/_repo.py`'s `seed_adapter_stubs` is the neighbouring tool and is NOT it: its
#: `ADAPTER_BODY` is `VERBS = {}`, which declares a system that serves nothing. Serving is the
#: whole subject here.
_RECORDING_ADAPTER = '''\
"""A verb body that records the params it was CALLED with, under a run dir the test reads."""
from __future__ import annotations

import json
from pathlib import Path

from defender.runtime.verbs import VerbContext, verb

CALLS = "adapter-calls.jsonl"


def _record(ctx: VerbContext, name: str, params: dict) -> int:
    """Log this call and hand back the run's call ORDINAL.

    The ordinal rides in the PAYLOAD, so "the family's recording was replayed" and "the
    adapter ran a second time" are distinguishable from the payload alone — a second live
    call cannot coincidentally produce the first one's bytes."""
    log = Path(ctx.run_dir) / CALLS
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"verb": name, "params": params}) + "\\n")
    return len(log.read_text(encoding="utf-8").splitlines())


@verb(engine="esql", body_param="query")
def esql(ctx: VerbContext, *, query: str, limit: int = 5) -> dict:
    return {"query": query, "call": _record(ctx, "esql", {"query": query, "limit": limit})}


@verb()
def get_host(ctx: VerbContext, *, host: str) -> dict:
    """`owner` is the estate's own answer, and the field a world patch overwrites."""
    return {"host": host, "owner": "estate", "call": _record(ctx, "get-host", {"host": host})}


@verb()
def health_check(ctx: VerbContext) -> dict:
    return {"ok": True, "call": _record(ctx, "health-check", {})}


VERBS = {"esql": esql, "get-host": get_host, "health-check": health_check}
'''

#: The fake estate's grant. `elastic` is the one system with a stager, `cmdb` one of the six
#: without — the pair the `touches` and family-tier arms need.
FAKE_GRANT = VerbGrant(role="gather", entries=(
    ("elastic", "esql", "r"), ("elastic", "health-check", "r"),
    ("cmdb", "get-host", "r"), ("cmdb", "health-check", "r"),
))

CALLS_LOG = "adapter-calls.jsonl"


@dataclass(frozen=True)
class World:
    """The world object the seam reads: an id, and the systems it declares it touches."""

    world_id: str
    touches: tuple[str, ...] = ()


@dataclass(frozen=True)
class DecisionApplier:
    """An applier that names one decision and changes nothing else.

    The fault-injection seam for the ledger's vocabulary check: it can name a decision outside
    `SOURCES`, which no shipped applier can. It classifies nothing and records nothing — the
    assertions read the ledger the production code wrote."""

    decision: str

    def prepare(
        self, system: str, verb: str, params: dict, world: Any, ctx: Any = None,
    ) -> dict:
        return params

    def apply(
        self, system: str, verb: str, params: dict, payload: Any, world: Any,
    ) -> tuple[str, Any]:
        return self.decision, payload


def fake_estate(tmp_path: Path) -> Path:
    """A real adapters directory declaring `elastic` and `cmdb`, both recording."""
    adapters = tmp_path / "adapters"
    adapters.mkdir(parents=True, exist_ok=True)
    for name in ("elastic_adapter.py", "cmdb_adapter.py"):
        (adapters / name).write_text(_RECORDING_ADAPTER, encoding="utf-8")
    return adapters


def run_ctx(tmp_path: Path) -> VerbContext:
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    return VerbContext(defender_dir=tmp_path, run_dir=run_dir, env={})


def adapter_calls(ctx: VerbContext, verb: str | None = None) -> list[dict]:
    """Every call the fake adapter bodies actually ran, optionally for one verb."""
    rows = read_jsonl_rows(Path(ctx.run_dir) / CALLS_LOG)
    return [r for r in rows if verb is None or r.get("verb") == verb]


def served_rows(ledger_path: Path) -> list[dict]:
    return read_jsonl_rows(ledger_path)


@pytest.fixture
def logger(tmp_path):
    lg = observe.RequestLogger(tmp_path / "llm_requests.jsonl")
    try:
        yield lg
    finally:
        lg.close()


#: The default world for tests whose subject is not the world: it touches nothing, so it stages
#: nothing and patches nothing, and every decision it produces is `passthrough`.
UNTOUCHED_WORLD = World("w1")


def world_registry(
    adapters: Path, grant: VerbGrant, ledger_path: Path, *,
    world: Any = UNTOUCHED_WORLD, applier: Any = None,
) -> WorldRegistry:
    """A `WorldRegistry` built through its own constructor, over a fresh ledger at `path`."""
    return WorldRegistry(
        adapters, grant, world=world, ledger=Ledger(ledger_path), applier=applier,
    )


# ==========================================================================
# 1. structural coverage: every granted verb, and no route to a bare body
# ==========================================================================


def test_the_shipped_grant_still_spans_seven_systems():
    """    The estate's coverage claim is only as wide as the grant it is measured over, so the
    grant's own shape is pinned first — 28 entries across 7 systems. Without this arm a grant
    that lost a system would make every sweep below cover one system less and stay green."""
    assert len(GATHER_GRANT.entries) == GRANTED_ENTRIES
    assert len(GATHER_GRANT.systems) == GRANTED_SYSTEMS


def test_every_granted_verb_decides_granted_through_the_world_registry(tmp_path):
    """    `decide()` answers GRANTED for all 28 shipped grant entries.

    This is the coverage claim, and it runs through the REAL adapters: `decide` resolves the
    callable through `verbs()`, so a wrapper that broke `verb_class_of` would fail the grant's
    class agreement (a `GrantError`, not a soft denial) and a wrapper that lost a verb name
    would answer UNDECLARED. Whole-grant rather than per-system spot checks, because the
    property is "no system is left out of the estate"."""
    reg = world_registry(REAL_ADAPTERS, GATHER_GRANT, tmp_path / "served.jsonl")

    refused = [
        (system, verb, reg.decide(system, verb).outcome)
        for system, verb, _ in GATHER_GRANT.entries
        if reg.decide(system, verb).outcome != GRANTED
    ]

    assert refused == []


def test_no_route_to_a_verb_hands_back_a_bare_adapter_body(tmp_path):
    """    Both routes to a callable — `decide().fn` and the query tool's own second lookup,
    `registry.verbs(system)[verb]` — hand back a WRAPPER over the real body, never the body.

    A bare body is a query that reaches the defender without passing the applier, which is the
    silent-scenario-deletion hazard the ledger exists to make visible: it would be a response
    with no row. Pinned as `__wrapped__ is real`, so the wrapper is proven to be over THIS
    body rather than merely to be some other callable."""
    reg = world_registry(REAL_ADAPTERS, GATHER_GRANT, tmp_path / "served.jsonl")
    plain = ModuleVerbRegistry(REAL_ADAPTERS, GATHER_GRANT)

    bare = []
    for system, verb, _ in GATHER_GRANT.entries:
        real = plain.verbs(system)[verb]
        for route, fn in (("verbs", reg.verbs(system)[verb]), ("decide", reg.decide(system, verb).fn)):
            if fn is real or getattr(fn, "__wrapped__", None) is not real:
                bare.append((system, verb, route))

    assert bare == []


def test_the_wrapper_carries_the_decoration_the_seam_reads(tmp_path):
    """    `verb_class_of`, `engine_of` and `body_param_of` read the same values off the wrapper as
    off the body, for all 28 entries.

    Not cosmetic. `verb_class_of` is what `VerbRegistry.decide` compares against the grant, and
    the engine/body-param pair is how the query tool decides a payload's shape — the elastic
    `esql`/`query`/`alerts` verbs are the ones carrying non-default values, so they are the
    ones a `functools.wraps` regression would silently blank."""
    reg = world_registry(REAL_ADAPTERS, GATHER_GRANT, tmp_path / "served.jsonl")
    plain = ModuleVerbRegistry(REAL_ADAPTERS, GATHER_GRANT)

    drifted = []
    for system, verb, verb_class in GATHER_GRANT.entries:
        real, served = plain.verbs(system)[verb], reg.verbs(system)[verb]
        read = (verb_class_of(served), engine_of(served), body_param_of(served))
        want = (verb_class_of(real), engine_of(real), body_param_of(real))
        if read != want or verb_class_of(served) != verb_class:
            drifted.append((system, verb, read, want))

    assert drifted == []
    # One engine-bearing verb spelled out, because a sweep that compared two blanks against
    # each other would also pass. `esql` is the only `engine="esql"` verb in the estate; the
    # other two (`query`, `alerts`) run the lucene engine.
    assert (engine_of(reg.verbs("elastic")["esql"]), body_param_of(reg.verbs("elastic")["esql"])) \
        == ("esql", "query")


def test_the_wrapper_keeps_the_keyword_only_signature_the_boundary_introspects(tmp_path):
    """    `declared_params`, `model_facing_params` and `wrapper_only_params` — the three
    signature reads `validate_params` enforces with and `list_verbs` publishes from — answer
    identically through the wrapper.

    They are one number: what a model is SHOWN and what the boundary ACCEPTS both come from
    `model_facing_params`, so a wrapper whose signature read differently would publish a
    surface the seam then refuses."""
    reg = world_registry(REAL_ADAPTERS, GATHER_GRANT, tmp_path / "served.jsonl")
    plain = ModuleVerbRegistry(REAL_ADAPTERS, GATHER_GRANT)

    drifted = []
    for system, verb, _ in GATHER_GRANT.entries:
        real, served = plain.verbs(system)[verb], reg.verbs(system)[verb]
        for read in (declared_params, model_facing_params, wrapper_only_params):
            if read(served) != read(real):
                drifted.append((system, verb, read.__name__))

    assert drifted == []


def test_a_wrapper_only_param_is_still_reserved_through_the_wrapper(tmp_path):
    """    `ticket.list-tickets` reserves `require_closed` to the benign judge's first-party tool,
    and the wrapper must not hand that reservation back to gather.

    The live case for the signature claim above: the param is DECLARED (so it is in
    `declared_params`) and model-facing NOTHING, so a wrapper that flattened the two reads into
    one would open a param whose only effect is to silently narrow a lead's read to closed
    tickets."""
    reg = world_registry(REAL_ADAPTERS, GATHER_GRANT, tmp_path / "served.jsonl")
    served = reg.verbs("ticket")["list-tickets"]

    assert "require_closed" in declared_params(served)
    assert "require_closed" not in model_facing_params(served)
    refusal = validate_params(served, {"require_closed": True})
    assert refusal is not None
    assert "require_closed" in refusal
    assert validate_params(served, {"status": "open"}) is None


# ==========================================================================
# 2. nominal typing: the build site's isinstance check
# ==========================================================================

def _built(logger, verbs):
    with override_allow_model_requests(False):
        return driver.build_agent_core(
            driver.GATHER_DEF, deps_type=GatherDeps, instructions="x", logger=logger,
            agent_id="gather", verbs=verbs,
            make_model=fake_model(lambda messages, info: ModelResponse(
                parts=[TextPart(content="ok")])),
        )


def test_build_agent_core_refuses_a_registry_shaped_stand_in(logger):
    """    A duck-typed registry that answers `verbs()`/`decide()` is refused by the build site.

    This is the reason `WorldRegistry` SUBCLASSES `ModuleVerbRegistry` rather than
    reimplementing its surface: a structural check cannot tell a real grant from a stand-in
    that answers GRANTED to everything, so the check is nominal and the estate has to satisfy
    it for real."""
    class RegistryShaped:
        def systems(self):
            return ("elastic",)

        def verbs(self, system):
            return {}

        def decide(self, system, verb):
            return None

    with pytest.raises(TypeError, match="real VerbRegistry"):
        _built(logger, RegistryShaped())


def test_build_agent_core_accepts_a_world_registry(logger, tmp_path):
    """    A `WorldRegistry` passes that same check and builds gather's verb-bearing tools.

    The positive arm of the pair: without it, a check that refused EVERYTHING would satisfy
    the negative one, and the sibling run would have no way to query at all."""
    reg = world_registry(
        REAL_ADAPTERS, GATHER_GRANT, tmp_path / "served.jsonl",
        world=World("w1", touches=("elastic",)),
    )

    agent = _built(logger, reg)

    assert {"query", "list_verbs"} <= set(agent._function_toolset.tools)


# ==========================================================================
# 3. every served response is recorded with a decision
# ==========================================================================

def test_serving_through_the_wrapper_writes_a_row_carrying_the_decision(tmp_path):
    """    One served call, one world row: the system, the verb, the params AS PREPARED, the
    payload bytes, the decision and the world id.

    `passthrough` is a DECISION here, not an absence — this world touches nothing, so the
    applier honestly reports that it changed nothing. A response with no row is the failure
    the table exists to make visible, so the row's presence is the assertion."""
    ledger_path = tmp_path / "served.jsonl"
    ctx = run_ctx(tmp_path)
    reg = world_registry(
        fake_estate(tmp_path), FAKE_GRANT, ledger_path, world=World("w1"),
    )

    payload = reg.verbs("cmdb")["get-host"](ctx, host="canary-1")

    world_rows = [r for r in served_rows(ledger_path) if r["world_id"] == "w1"]
    assert len(world_rows) == 1
    row = world_rows[0]
    assert (row["system"], row["verb"], row["params"]) == ("cmdb", "get-host", {"host": "canary-1"})
    assert row["source"] == PASSTHROUGH
    assert json.loads(row["payload_text"]) == payload


@pytest.mark.parametrize("decision", sorted(SOURCES))
def test_every_decision_in_the_vocabulary_serves_and_is_recorded(tmp_path, decision):
    """    Each of the four decisions `SOURCES` names is servable and lands in the row.

    The vocabulary is closed at the ledger, so this is the whole of what an applier may say;
    running all four keeps the refusal below meaning "outside the vocabulary" rather than
    "anything the shipped applier does not happen to emit"."""
    ledger_path = tmp_path / "served.jsonl"
    ctx = run_ctx(tmp_path)
    reg = world_registry(
        fake_estate(tmp_path), FAKE_GRANT, ledger_path,
        world=World("w1"), applier=DecisionApplier(decision),
    )

    payload = reg.verbs("cmdb")["get-host"](ctx, host="canary-1")

    assert payload["host"] == "canary-1"
    assert [r["source"] for r in served_rows(ledger_path) if r["world_id"] == "w1"] == [decision]


def test_an_invented_decision_refuses_before_the_payload_is_returned(tmp_path):
    """    An applier naming a decision outside `SOURCES` raises `LedgerError`, and the CALLER GETS
    NO PAYLOAD.

    The ordering is the property. A ledger that recorded the refusal and served anyway would
    let a response reach the defender with no honest decision behind it — exactly the silent
    deletion the table exists to catch — so the refusal has to sit between the applier and the
    return. The adapter's own call still happened (the base row is there): the refusal is at
    the RECORD, which is where the vocabulary lives, and pinning that keeps the failure
    attributable rather than looking like a query that never ran."""
    ledger_path = tmp_path / "served.jsonl"
    ctx = run_ctx(tmp_path)
    reg = world_registry(
        fake_estate(tmp_path), FAKE_GRANT, ledger_path,
        world=World("w1"), applier=DecisionApplier("mutated"),
    )
    served = reg.verbs("cmdb")["get-host"]

    with pytest.raises(LedgerError, match="mutated"):
        served(ctx, host="canary-1")

    rows = served_rows(ledger_path)
    assert [r["source"] for r in rows] == [BASE], "the invented decision was written anyway"
    assert [r["world_id"] for r in rows] == [None]
    assert len(adapter_calls(ctx, "get-host")) == 1


def test_the_ledger_refuses_an_invented_decision_at_its_own_door(tmp_path):
    """    `Ledger.record` is where the vocabulary is OWNED, so it refuses directly too.

    The registry deliberately does not re-check the decision it just received — the same rule
    in two places is a rule with a copy that can drift, and the copy that drifts is the one
    that stops refusing. This arm is what makes that delegation safe to rely on."""
    ledger = Ledger(tmp_path / "served.jsonl")
    call = ServedCall(
        system="cmdb", verb="get-host", params={"host": "canary-1"},
        payload_text="{}", source="invented", world_id="w1",
    )

    with pytest.raises(LedgerError, match="invented"):
        ledger.record(call)

    assert served_rows(tmp_path / "served.jsonl") == []


# ==========================================================================
# 4. the family tier: one base recording, no second adapter call
# ==========================================================================

def test_the_same_key_twice_is_one_adapter_call_and_one_payload(tmp_path):
    """    Serving one key twice returns identical payloads and issues EXACTLY ONE adapter call.

    The estate is live: two calls minutes apart see different data, so a sibling that re-asked
    would measure the estate's drift and call it the world's difference. The recording is what
    buys determinism back without snapshot-restore, and the adapter's own call log is what
    proves it — the payload's call ordinal would differ on a second live call."""
    ledger_path = tmp_path / "served.jsonl"
    ctx = run_ctx(tmp_path)
    reg = world_registry(
        fake_estate(tmp_path), FAKE_GRANT, ledger_path, world=World("w1"),
    )
    served = reg.verbs("cmdb")["get-host"]

    first = served(ctx, host="canary-1")
    second = served(ctx, host="canary-1")

    assert first == second
    assert len(adapter_calls(ctx, "get-host")) == 1
    assert [r["source"] for r in served_rows(ledger_path)] == [BASE, PASSTHROUGH, PASSTHROUGH]


def test_two_siblings_read_one_base_recording(tmp_path):
    """    Two worlds sharing a ledger and asking the same question get the same bytes off ONE
    adapter call.

    This is the A/B invariance the branch is for: everything the two worlds did not stage is
    literally identical, so a difference between siblings is readable as the staging rather
    than as the estate having moved between two queries. The base row (`world_id=None`) is
    written once; each world still records its own served row, because what the applier decided
    is per world."""
    ledger_path = tmp_path / "served.jsonl"
    adapters, ctx = fake_estate(tmp_path), run_ctx(tmp_path)
    ledger = Ledger(ledger_path)
    a = WorldRegistry(adapters, FAKE_GRANT, world=World("a"), ledger=ledger)
    b = WorldRegistry(adapters, FAKE_GRANT, world=World("b"), ledger=ledger)

    from_a = a.verbs("cmdb")["get-host"](ctx, host="canary-1")
    from_b = b.verbs("cmdb")["get-host"](ctx, host="canary-1")

    assert from_a == from_b
    assert len(adapter_calls(ctx, "get-host")) == 1
    rows = served_rows(ledger_path)
    assert [r["world_id"] for r in rows] == [None, "a", "b"]


def test_a_ledger_reopened_from_disk_replays_the_family_recording(tmp_path):
    """    A ledger rebuilt from the file — the shape a later sibling process opens — replays the
    base row rather than re-asking the estate.

    The memo is loaded in `__post_init__`, so a sibling started minutes later (or after a
    crash) inherits the family's answer. Without this arm the tier would only hold within one
    process, which is not where siblings live."""
    ledger_path = tmp_path / "served.jsonl"
    adapters, ctx = fake_estate(tmp_path), run_ctx(tmp_path)
    first = WorldRegistry(adapters, FAKE_GRANT, world=World("a"), ledger=Ledger(ledger_path))
    from_a = first.verbs("cmdb")["get-host"](ctx, host="canary-1")

    reopened = WorldRegistry(
        adapters, FAKE_GRANT, world=World("b"), ledger=Ledger(ledger_path))
    from_b = reopened.verbs("cmdb")["get-host"](ctx, host="canary-1")

    assert from_a == from_b
    assert len(adapter_calls(ctx, "get-host")) == 1


def test_two_spellings_of_one_question_are_one_key(tmp_path):
    """    Params built in a different order are the SAME key, so they cost one adapter call.

    `request_key` sorts, the way `record_query._request_key` does and for the same reason: two
    spellings of one question would otherwise split one memo into two, and the pair would see
    the estate twice at two different moments."""
    ledger_path = tmp_path / "served.jsonl"
    ctx = run_ctx(tmp_path)
    reg = world_registry(
        fake_estate(tmp_path), FAKE_GRANT, ledger_path, world=World("w1"),
    )
    served = reg.verbs("elastic")["esql"]
    body = "FROM logs-* | LIMIT 5"

    first = served(ctx, query=body, limit=5)
    second = served(ctx, limit=5, query=body)

    assert request_key("elastic", "esql", {"query": body, "limit": 5}) \
        == request_key("elastic", "esql", {"limit": 5, "query": body})
    assert first == second
    assert len(adapter_calls(ctx, "esql")) == 1


def test_a_staged_call_records_its_base_under_the_view_it_asked_for(tmp_path):
    """    Two worlds staging the same query do NOT share a base row — each asks a different
    corpus, so each costs its own adapter call.

    The counterpart to the invariance above, and it is design rather than leakage: the key is
    taken from the params AS PREPARED, and staging is exactly the act of changing them. A key
    taken before `prepare` would collapse the two worlds onto one recording and hand world B
    world A's documents — the contamination `view_name`'s per-world alias exists to prevent."""
    ledger_path = tmp_path / "served.jsonl"
    adapters, ctx = fake_estate(tmp_path), run_ctx(tmp_path)
    ledger = Ledger(ledger_path)
    body = "FROM logs-system.auth-*\n| STATS COUNT(*)"
    a = WorldRegistry(adapters, FAKE_GRANT, world=World("a", ("elastic",)), ledger=ledger)
    b = WorldRegistry(adapters, FAKE_GRANT, world=World("b", ("elastic",)), ledger=ledger)

    from_a = a.verbs("elastic")["esql"](ctx, query=body)
    from_b = b.verbs("elastic")["esql"](ctx, query=body)

    assert from_a["query"] == "FROM logs-system.auth-w-a\n| STATS COUNT(*)"
    assert from_b["query"] == "FROM logs-system.auth-w-b\n| STATS COUNT(*)"
    assert len(adapter_calls(ctx, "esql")) == 2
    assert {r["world_id"] for r in served_rows(ledger_path)} == {None, "a", "b"}


# ==========================================================================
# 5-6. staging reaches the adapter, and `touches` decides whether it happens
# ==========================================================================

def test_a_staged_call_reaches_the_adapter_already_retargeted(tmp_path):
    """    The verb body itself is called with the RETARGETED query, and the row says `staged`.

    `prepare` is the strong path: the corpus is staged and Elasticsearch does its own
    filtering, aggregation and sorting over it, so the result is correct by construction. That
    only holds if the retarget survives all the way into the call — asserted against what the
    adapter body RECORDED, not against what the seam returned."""
    ledger_path = tmp_path / "served.jsonl"
    ctx = run_ctx(tmp_path)
    reg = world_registry(
        fake_estate(tmp_path), FAKE_GRANT, ledger_path,
        world=World("w1", touches=("elastic",)),
    )

    reg.verbs("elastic")["esql"](ctx, query="FROM logs-nginx.access-*\n| LIMIT 5")

    assert [c["params"]["query"] for c in adapter_calls(ctx, "esql")] == [
        "FROM logs-nginx.access-w-w1\n| LIMIT 5"]
    assert [r["source"] for r in served_rows(ledger_path) if r["world_id"] == "w1"] == [STAGED]


def test_a_system_the_world_does_not_touch_is_never_staged(tmp_path):
    """    An untouched system's query reaches the adapter byte-identical, and reports
    `passthrough`.

    `touches` gates COST as much as semantics: a system no world declares is never staged,
    never patched, and a difference observed there is corrupt by construction rather than
    something to explain. The negative arm of the staging test above — same system, same
    query, only `touches` differs."""
    ledger_path = tmp_path / "served.jsonl"
    ctx = run_ctx(tmp_path)
    body = "FROM logs-nginx.access-*\n| LIMIT 5"
    reg = world_registry(
        fake_estate(tmp_path), FAKE_GRANT, ledger_path, world=World("w1", touches=()),
    )

    reg.verbs("elastic")["esql"](ctx, query=body)

    assert [c["params"]["query"] for c in adapter_calls(ctx, "esql")] == [body]
    assert [r["source"] for r in served_rows(ledger_path) if r["world_id"] == "w1"] \
        == [PASSTHROUGH]


@pytest.mark.parametrize(("system", "touches"), [
    ("elastic", ()),          # has a stager, but this world does not touch it
    ("cmdb", ("cmdb",)),      # touched, but has no stager at all
    ("cmdb", ()),             # neither
])
def test_prepare_is_the_identity_wherever_staging_does_not_apply(system, touches):
    """    `prepare` hands the params straight back unless the system has a stager AND the world
    touches it. Both halves of that conjunction are gated here.

    The `cmdb` rows are the interesting ones: a world may touch a system that no stager knows
    how to stage, and that must cost nothing rather than fall through to a guess. Applied to a
    dict of the caller's, so a `prepare` that mutated in place — editing a base payload every
    sibling replays — would show up as the input changing."""
    applier = WorldApplier()
    params = {"query": "FROM logs-* | LIMIT 5", "limit": 5}

    prepared = applier.prepare(system, "esql", dict(params), World("w1", touches))

    assert prepared == params
    assert applier.apply(system, "esql", prepared, {"rows": []}, World("w1", touches)) \
        == (PASSTHROUGH, {"rows": []})


def test_a_touched_staged_system_reports_staged_without_touching_the_payload():
    """    `apply` on a staged system reports `STAGED` and hands the payload back untouched.

    Nothing is left to do after the fact: the difference is already IN the documents the engine
    read. Reporting it rather than staying silent is what keeps "the world changed this"
    distinguishable from "the applier never ran" — which, in a table where a missing row is the
    alarm, is the whole distinction."""
    applier = WorldApplier()
    payload = {"rows": [{"host": "canary-1"}]}

    decision, out = applier.apply(
        "elastic", "esql", {"query": "FROM v"}, payload, World("w1", ("elastic",)))

    assert decision == STAGED
    assert out is payload


def test_a_world_may_not_answer_to_the_family_tiers_key(tmp_path):
    """    A world whose `world_id` is `None` is refused at construction.

    `None` is how the family tier spells "this is what the estate answered", and every sibling
    replays that slot instead of re-asking a live system. A world answering to it would write
    its own applied payload there, and the next sibling would serve another world's difference
    AS the estate — while recording an honest-looking `passthrough` row of its own, because
    from its side nothing was applied. Silent scenario INJECTION, the inverse of the deletion
    the ledger was built to catch, and invisible in exactly the record meant to show it.

    Refused at CONSTRUCTION rather than at the write: by the time a payload is being recorded
    the world has already served, and a check there would have to be repeated at every writer."""
    ledger_path = tmp_path / "served.jsonl"

    class BaseWorld:
        world_id = None
        touches = ("cmdb",)

    with pytest.raises(EstateError):
        WorldRegistry(
            fake_estate(tmp_path), FAKE_GRANT, world=BaseWorld(),
            ledger=Ledger(ledger_path),
            applier=WorldApplier({"cmdb": {"canary-1": {"owner": "world"}}}))

    assert not ledger_path.exists(), "a refused world must not have written a row"


def test_a_sibling_never_replays_another_worlds_patch_as_the_estate(tmp_path):
    """    One world's patch never becomes the family's base recording.

    The family tier is what buys A/B invariance: `world_id=None` means "this is what the estate
    answered", and every sibling replays it rather than re-asking a live system. A patching
    world serves first here; the sibling that follows must still read the ESTATE's `owner`, not
    the first world's, even though the two share one ledger."""
    ledger_path = tmp_path / "served.jsonl"
    adapters, ctx = fake_estate(tmp_path), run_ctx(tmp_path)
    ledger = Ledger(ledger_path)

    patcher = WorldRegistry(
        adapters, FAKE_GRANT, world=World("base", ("cmdb",)), ledger=ledger,
        applier=WorldApplier({"cmdb": {"canary-1": {"owner": "world"}}}))
    sibling = WorldRegistry(adapters, FAKE_GRANT, world=World("b"), ledger=ledger)

    assert patcher.verbs("cmdb")["get-host"](ctx, host="canary-1")["owner"] == "world"
    assert sibling.verbs("cmdb")["get-host"](ctx, host="canary-1")["owner"] == "estate"

    rows = served_rows(ledger_path)
    assert [r["world_id"] for r in rows] == [None, "base", "b"], (
        "the estate's recording, the patcher's own row and the sibling's own row are three "
        f"distinct slots; got {[r['world_id'] for r in rows]}")
    assert json.loads(rows[0]["payload_text"])["owner"] == "estate", (
        "the family tier must hold what the ADAPTER said, never what a world made of it")


def test_a_base_world_stages_nothing(tmp_path):
    """    The base world stages nothing, so it queries the estate exactly as it is.

    Its payloads ARE the estate's, which is what makes a base-versus-sibling difference read as
    exactly the sibling's staging with no third thing to subtract. Driven through the seam
    rather than the stager, because the id that reaches `redirect` comes from the world object
    by way of `_staging_world`.

    THE TWO ROWS ARE KEYED APART, and that is the point: the family recording is `world_id=None`
    and the base world's own served row carries its own id, even though the payloads are equal.
    A base world that answered to `None` would share the family's slot — harmless only while it
    changes nothing, and silent scenario INJECTION the moment it does, because every sibling
    replays that slot as the estate while its own row honestly reports `passthrough`. Keying
    them apart makes that unreachable instead of merely unlikely."""
    ledger_path = tmp_path / "served.jsonl"
    ctx = run_ctx(tmp_path)
    body = "FROM logs-system.auth-*\n| LIMIT 5"

    class BaseWorld:
        # Base-ness is `touches`, not the id: a base world has no declared difference, so there
        # is no system its difference could reach and nothing to stage. Expressing it as a
        # reserved id instead would conflate "the base world" with "the family's recording",
        # which is the slot every sibling replays.
        world_id = "base"
        touches = ()

    reg = world_registry(
        fake_estate(tmp_path), FAKE_GRANT, ledger_path, world=BaseWorld(),
    )
    reg.verbs("elastic")["esql"](ctx, query=body)

    assert [c["params"]["query"] for c in adapter_calls(ctx, "esql")] == [body]
    assert [r["world_id"] for r in served_rows(ledger_path)] == [None, "base"], (
        "the family recording and the base world's own row must not share a slot")


def test_two_siblings_rows_pair_on_the_question_asked_not_the_one_run(tmp_path):
    """    A staged call records BOTH identities, so a cross-world comparison can find its pairs.

    `ΔO` is computed over the keys two worlds have in common. On a staged system the prepared
    forms differ BY CONSTRUCTION — that is what staging is — so a comparison keyed on them
    alone intersects to nothing: A recorded `FROM …-w-A`, B recorded `FROM …-w-B`, no row of
    A's ever meets a row of B's, and "the worlds differ" and "the worlds are identical" produce
    the same empty answer. Silent, and silent on the event stream, where most of a run's
    evidence lives.

    The memo key must NOT be the asked form, and this pins both halves: pair on what was asked,
    memoize on what ran. Keyed the other way, B replays A's answer — read off A's staged
    corpus — which is contamination rather than merely a re-read."""
    ledger_path = tmp_path / "served.jsonl"
    adapters, ctx = fake_estate(tmp_path), run_ctx(tmp_path)
    ledger = Ledger(ledger_path)
    body = "FROM logs-system.auth-*\n| LIMIT 5"

    for wid in ("A", "B"):
        reg = WorldRegistry(
            adapters, FAKE_GRANT, world=World(wid, ("elastic",)), ledger=ledger)
        reg.verbs("elastic")["esql"](ctx, query=body)

    rows = [r for r in served_rows(ledger_path) if r["world_id"] in ("A", "B")]
    assert len(rows) == 2

    ran = {r["world_id"]: r["params"]["query"] for r in rows}
    assert ran["A"] != ran["B"], "each world must read its OWN corpus"

    asked = {r["world_id"]: r["asked_params"]["query"] for r in rows}
    assert asked["A"] == asked["B"] == body, (
        "both worlds were asked the same question; without that recorded, their rows cannot "
        f"be paired and ΔO over this system is empty rather than measured. Got {asked}")


def test_an_unstaged_call_records_one_identity_not_two(tmp_path):
    """    Nothing was rewritten, so there is no second identity to record.

    The column is written only when it says something. Echoing `params` onto every row would
    make the two identities look like one thing, which is the confusion the pair exists to
    prevent."""
    ledger_path = tmp_path / "served.jsonl"
    adapters, ctx = fake_estate(tmp_path), run_ctx(tmp_path)
    reg = WorldRegistry(
        adapters, FAKE_GRANT, world=World("A", ("cmdb",)), ledger=Ledger(ledger_path))

    reg.verbs("cmdb")["get-host"](ctx, host="canary-1")

    own = [r for r in served_rows(ledger_path) if r["world_id"] == "A"]
    assert len(own) == 1
    assert "asked_params" not in own[0], (
        "an unstaged call's asked and run forms are the same call; a second column would be a "
        f"copy that can only drift. Got {own[0]}")

    # And the two identities coincide on the object, which is what "one identity" MEANS —
    # the absent column is the storage consequence, not the property itself.
    call = ServedCall(
        system="cmdb", verb="get-host", params={"host": "canary-1"},
        payload_text="{}", source=PATCHED, world_id="A")
    assert call.key == call.correlation_key
