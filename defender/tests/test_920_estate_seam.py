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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import ModelResponse, TextPart  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402

from defender._io import read_jsonl_rows  # noqa: E402
from defender._paths import PATHS  # noqa: E402
from defender.learning.branch.estate.applier import WorldApplier  # noqa: E402
from defender.learning.branch.estate.lookups import apply_patches  # noqa: E402
from defender.learning.branch.estate.registry import (  # noqa: E402
    EstateError,
    WorldRegistry,
)
from defender.learning.branch.ledger import (  # noqa: E402
    APPLIER_DECISIONS,
    BASE,
    BASE_FILENAME,
    CAPTURED,
    FAMILY_SOURCES,
    FAULT,
    PASSTHROUGH,
    PATCHED,
    REFUSED,
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
        # `world_id` rides along because it is the DECLARATION half of a retarget: the real
        # elastic adapter confines the staged index by it, so a seam that rewrote the query
        # and left the ctx unbranched would refuse every staged read at the boundary.
        fh.write(json.dumps(
            {"verb": name, "params": params, "world_id": ctx.world_id}) + "\\n")
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

#: The branch point's own moment (#947). Every world here is served under ONE clock, so nothing
#: below turns on its value — but a registry cannot be built without one, because a defaulted
#: clock is a wall-clock stamp in a branched run and the whole point is that there are none.
AS_OF = datetime(2026, 5, 25, 15, 30, 45, tzinfo=UTC)


def fresh_ledger(path: Path) -> Ledger:
    """A `Ledger` over `path`, beside the primed capture #947 made REQUIRED.

    EMPTY, deliberately. Nothing in this file is about the capture; what `base_path` has to be
    here is a FILE, which is `Ledger.__post_init__`'s ordering guarantee that the episode was
    primed before any sibling opened a ledger over it. Empty, every key MISSES it and falls
    through to the live `base` recording — which is exactly the tier the family arms below were
    written against, so their subject is unchanged."""
    base = path.parent / BASE_FILENAME
    base.parent.mkdir(parents=True, exist_ok=True)
    base.touch()
    return Ledger(path, base_path=base)


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

    def restore(
        self, system: str, verb: str, payload: Any, asked: dict | None, prepared: dict,
        ctx: Any = None,
    ) -> Any:
        return payload

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
        adapters, grant, world=world, ledger=fresh_ledger(ledger_path), applier=applier,
        as_of=AS_OF,
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


def test_the_vocabulary_splits_into_the_tier_the_seam_and_the_applier():
    """    `SOURCES` is three kinds of label, and only one kind is an applier's to name.

    Without this split the sweep below reads as "any applier may claim any member", which
    includes the FAMILY tier's own labels — the slot every sibling replays from. That tier is
    two labels since #947: `captured` is the source run's own capture, primed before any sibling
    forked, and `base` is the live read of a key the capture never held. Both are `world_id=None`
    and neither is an applier's to claim; the split between them is `test_947_ledger_tiers.py`."""
    assert APPLIER_DECISIONS | FAMILY_SOURCES | {REFUSED, FAULT} == SOURCES
    assert BASE in FAMILY_SOURCES
    assert CAPTURED in FAMILY_SOURCES
    assert not (APPLIER_DECISIONS & FAMILY_SOURCES)


@pytest.mark.parametrize("decision", sorted(APPLIER_DECISIONS))
def test_every_decision_in_the_vocabulary_serves_and_is_recorded(tmp_path, decision):
    """    Each decision an APPLIER may name is servable and lands in the row.

    The vocabulary is closed at the ledger, so this is the whole of what an applier may say;
    running all of them keeps the refusal below meaning "outside the vocabulary" rather than
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
    ledger = fresh_ledger(tmp_path / "served.jsonl")
    call = ServedCall(
        system="cmdb", verb="get-host", params={"host": "canary-1"},
        payload_text="{}", source="invented", world_id="w1",
    )

    with pytest.raises(LedgerError, match="invented"):
        ledger.record(call)

    assert served_rows(tmp_path / "served.jsonl") == []


@pytest.mark.parametrize(("source", "world_id"), [(BASE, "w1"), (PASSTHROUGH, None)])
def test_the_two_tiers_have_to_agree(tmp_path, source, world_id):
    """    `base` and `world_id=None` say the same thing, so a row where they disagree is refused.

    Both arms are an injection, read from opposite ends. A `base` row owned by a world puts
    that world's answer in the slot every sibling replays from — one world's difference served
    AS the estate, while each sibling's own row still reads `passthrough`. A world-tier row
    with no owner is the mirror: a difference nobody can attribute, which a comparison then
    counts against whichever sibling it happens to read next."""
    ledger = fresh_ledger(tmp_path / "served.jsonl")

    with pytest.raises(LedgerError, match="FAMILY tier"):
        ledger.record(ServedCall(
            system="cmdb", verb="get-host", params={"host": "canary-1"},
            payload_text="{}", source=source, world_id=world_id))

    assert served_rows(tmp_path / "served.jsonl") == []


def test_an_estate_fault_still_leaves_a_row(tmp_path):
    """    The adapter body raising is a RESPONSE the defender sees, so it lands in the table.

    `QueryCapture` catches whatever the body raises and hands the model a fault row, so a seam
    that wrote nothing here would leave exactly the state this table exists to make visible —
    "a served response with no row" — and a reader counting evidence would see the sibling
    simply never asking. The fault is its own class rather than `refused`, because a world that
    cannot be staged and an estate that is down are different facts.

    The exception still reaches the caller untouched: the row is a record, not a rescue."""
    adapters = fake_estate(tmp_path)
    down = (adapters / "cmdb_adapter.py").read_text(encoding="utf-8").replace(
        'def get_host(ctx: VerbContext, *, host: str) -> dict:',
        'def get_host(ctx: VerbContext, *, host: str) -> dict:\n'
        '    raise RuntimeError("cmdb is down")')
    (adapters / "cmdb_adapter.py").write_text(down, encoding="utf-8")
    ledger_path = tmp_path / "served.jsonl"
    reg = world_registry(adapters, FAKE_GRANT, ledger_path, world=World("w1"))

    with pytest.raises(RuntimeError, match="cmdb is down"):
        reg.verbs("cmdb")["get-host"](run_ctx(tmp_path), host="canary-1")

    rows = served_rows(ledger_path)
    assert [r["source"] for r in rows] == [FAULT], (
        f"an estate fault left {[r['source'] for r in rows]} behind; a served response with no "
        "row is the one state this table exists to make visible")
    assert rows[0]["world_id"] == "w1"
    assert "cmdb is down" in rows[0]["payload_text"]


@pytest.mark.parametrize("touches", [None, 7, object()])
def test_a_world_whose_touches_cannot_be_read_is_refused_at_construction(tmp_path, touches):
    """    A `touches` that is neither a name nor a sequence of them is refused where the world
    arrives, not where it is asked.

    `_touches` answers `False` for everything it cannot read, and a world that touches nothing
    routes every response to `passthrough` — so the run measures nothing while every row still
    reads honestly. Asked per call instead, the `TypeError` surfaces deep inside `served`, where
    it is not an `AdapterFault` and the query tool files it as exit 2: an INFRA code, which the
    circuit breaker counts as the estate being down for this sibling and up for its base."""
    with pytest.raises(EstateError, match="touches"):
        world_registry(fake_estate(tmp_path), FAKE_GRANT, tmp_path / "served.jsonl",
                       world=World("w1", touches))

    assert not (tmp_path / "served.jsonl").exists(), "a refused world must not have written a row"


def test_a_patch_for_a_system_the_world_does_not_touch_is_refused(tmp_path):
    """    A patch table naming a system the world does not declare is refused at construction.

    `apply` asks `touches` FIRST, so an undeclared system is never patched — the overlay is
    dropped and the row reports `passthrough`, truthfully, which is exactly what makes it
    invisible. Half a world's difference silently absent, with the ledger reading clean, is the
    silent-scenario-deletion hazard this whole table exists to catch; the two halves are
    authored together, so the mismatch is caught where both are in hand."""
    with pytest.raises(EstateError, match="cmdb"):
        world_registry(
            fake_estate(tmp_path), FAKE_GRANT, tmp_path / "served.jsonl",
            world=World("w1", touches=("elastic",)),
            applier=WorldApplier(patches={"cmdb": {"canary-1": {"owner": "worldA"}}}))


def test_a_patch_for_a_staged_system_is_refused_too(tmp_path):
    """    A patch table naming a STAGED system is refused at construction, declared or not.

    The same drop, one door over, and a worse row behind it. `apply` reports `STAGED` for any
    system with a stager and hands the payload back untouched — correctly, because on the event
    stream a world's difference lives in the documents the engine read. So an entity patch
    authored for `elastic` is never applied AND the row reads `staged`, i.e. the strongest
    possible confirmation that the world was applied to a response it never touched. The
    `touches` check alone let it through: the world declares `elastic`, so the mismatch it looks
    for is not there."""
    with pytest.raises(EstateError, match="elastic"):
        world_registry(
            fake_estate(tmp_path), FAKE_GRANT, tmp_path / "served.jsonl",
            world=World("w1", touches=("elastic",)),
            applier=WorldApplier(patches={"elastic": {"canary-1": {"owner": "worldA"}}}))


@pytest.mark.parametrize("world_id", ["world A", "W1", "w*1"])
def test_a_world_a_stager_cannot_name_is_refused_at_construction(tmp_path, world_id):
    """    A world id no staged system could build a corpus name from is refused where the world
    arrives, not once per served call.

    The id reaches the view name unfiltered, so one a stager cannot carry does not cost one
    query — it costs the whole event stream: every `esql`/`query`/`alerts` call lands as a
    `refused` row while the base world keeps all of it, and the sibling reads as one that simply
    asked nothing. The answer is a property of the id rather than of a call, so it is asked
    once. Only for a system the world DECLARES, which the last case pins."""
    with pytest.raises(EstateError, match="elastic"):
        world_registry(
            fake_estate(tmp_path), FAKE_GRANT, tmp_path / "served.jsonl",
            world=World(world_id, touches=("elastic",)))

    # A world that stages nothing never names a corpus, so the same id is servable.
    world_registry(
        fake_estate(tmp_path), FAKE_GRANT, tmp_path / "served2.jsonl",
        world=World(world_id, touches=("cmdb",)))


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
    ledger = fresh_ledger(ledger_path)
    a = WorldRegistry(adapters, FAKE_GRANT, world=World("a"), ledger=ledger, as_of=AS_OF)
    b = WorldRegistry(adapters, FAKE_GRANT, world=World("b"), ledger=ledger, as_of=AS_OF)

    from_a = a.verbs("cmdb")["get-host"](ctx, host="canary-1")
    from_b = b.verbs("cmdb")["get-host"](ctx, host="canary-1")

    assert from_a == from_b
    assert len(adapter_calls(ctx, "get-host")) == 1
    rows = served_rows(ledger_path)
    assert [r["world_id"] for r in rows] == [None, "a", "b"]


def test_a_duplicate_base_row_resolves_the_same_way_in_memory_and_on_disk(tmp_path):
    """    Two base rows for one key resolve to the FIRST, whether the answer comes from this
    process's memo or from a rebuild off the file.

    `base_payload`'s own docstring concedes the window: the check-then-act spans the adapter
    call, so two siblings — two worker threads, or two processes — can both miss and both
    record. The file then holds two rows for one key, and the tie-break is the only thing left
    to make them agree. Resolved one way in `record` and the other in `_refresh`, this process
    served the second payload while any process rebuilding from the file served the first: two
    answers to one question with both rows reading honestly, which is exactly the invariance
    the family tier exists to buy."""
    ledger_path = tmp_path / "served.jsonl"
    ledger = fresh_ledger(ledger_path)
    call = dict(system="cmdb", verb="get-host", params={"host": "canary-1"},
                source=BASE, world_id=None)

    ledger.record(ServedCall(payload_text='{"owner": "first"}', **call))
    ledger.record(ServedCall(payload_text='{"owner": "second"}', **call))

    assert ledger.base_payload("cmdb", "get-host", {"host": "canary-1"}) \
        == fresh_ledger(ledger_path).base_payload("cmdb", "get-host", {"host": "canary-1"}) \
        == '{"owner": "first"}'


def test_a_ledger_reopened_from_disk_replays_the_family_recording(tmp_path):
    """    A ledger rebuilt from the file — the shape a later sibling process opens — replays the
    base row rather than re-asking the estate.

    The memo is loaded in `__post_init__`, so a sibling started minutes later (or after a
    crash) inherits the family's answer. Without this arm the tier would only hold within one
    process, which is not where siblings live."""
    ledger_path = tmp_path / "served.jsonl"
    adapters, ctx = fake_estate(tmp_path), run_ctx(tmp_path)
    first = WorldRegistry(adapters, FAKE_GRANT, world=World("a"), ledger=fresh_ledger(ledger_path), as_of=AS_OF)
    from_a = first.verbs("cmdb")["get-host"](ctx, host="canary-1")

    reopened = WorldRegistry(
        adapters, FAKE_GRANT, world=World("b"), ledger=fresh_ledger(ledger_path), as_of=AS_OF)
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
    ledger = fresh_ledger(ledger_path)
    body = "FROM logs-system.auth-*\n| STATS COUNT(*)"
    a = WorldRegistry(adapters, FAKE_GRANT, world=World("a", ("elastic",)), ledger=ledger, as_of=AS_OF)
    b = WorldRegistry(adapters, FAKE_GRANT, world=World("b", ("elastic",)), ledger=ledger, as_of=AS_OF)

    from_a = a.verbs("elastic")["esql"](ctx, query=body)
    from_b = b.verbs("elastic")["esql"](ctx, query=body)

    # TWO adapter calls, each against its own world's corpus — the subject of this test.
    assert [c["params"]["query"] for c in adapter_calls(ctx, "esql")] == [
        "FROM wv-a-logs-system.auth-\n| STATS COUNT(*)",
        "FROM wv-b-logs-system.auth-\n| STATS COUNT(*)"]
    assert {r["world_id"] for r in served_rows(ledger_path)} == {None, "a", "b"}
    # And neither world's identity reaches what the model reads: the echoed query comes back
    # as the one it wrote, so a lead narrowing the template it was just served does not
    # re-bind a staged name and stage it twice.
    assert from_a["query"] == from_b["query"] == body


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
        "FROM wv-w1-logs-nginx.access-\n| LIMIT 5"]
    assert [r["source"] for r in served_rows(ledger_path) if r["world_id"] == "w1"] == [STAGED]


def test_a_retargeted_call_declares_its_world_to_the_adapter(tmp_path):
    """    The body that receives the retargeted query also receives the world it was retargeted
    for — and a call that was NOT retargeted still reads as an unbranched run.

    The two halves of a world view are one act. The name is built OUTSIDE every configured
    corpus pattern on purpose, so that the base run and every sibling that does not stage the
    event stream cannot reach it through the pattern it came from; `confine_index` therefore
    cannot admit it by reach and admits it by declaration instead. A seam that rewrote the
    query and left the ctx unbranched would have every staged read refused at the boundary —
    the sibling green against nothing while the base kept its evidence.

    The negative arm is what keeps the declaration scoped: `cmdb` has no stager, so nothing
    moved, and a ctx naming the world there would widen a boundary for a call that never
    needed it."""
    ctx = run_ctx(tmp_path)
    reg = world_registry(
        fake_estate(tmp_path), FAKE_GRANT, tmp_path / "served.jsonl",
        world=World("w1", touches=("elastic", "cmdb")),
    )

    reg.verbs("elastic")["esql"](ctx, query="FROM logs-nginx.access-*\n| LIMIT 5")
    reg.verbs("cmdb")["get-host"](ctx, host="canary-1")

    assert [(c["verb"], c["world_id"]) for c in adapter_calls(ctx)] == [
        ("esql", "w1"), ("get-host", None)]


def test_the_familys_base_recording_carries_no_worlds_identity(tmp_path):
    """    The base row a sibling replays holds the payload as ASKED, whichever world ran it first.

    The family tier records once per key and every sibling reads that row back. It is written
    by whoever called first — and on a staged system that world's corpus identity is echoed in
    the payload, so an unrestored recording hands every OTHER sibling the first one's view
    name as though it were the estate's answer. Restored before the row is written, the shared
    recording names the corpus the model asked for and nothing about who ran it.

    The world row beside it is checked too: both tiers carry the asked identity, so a
    comparison across them is reading the evidence rather than the harness."""
    ledger_path = tmp_path / "served.jsonl"
    adapters, ctx = fake_estate(tmp_path), run_ctx(tmp_path)
    body = "FROM logs-system.auth-*\n| STATS COUNT(*)"
    reg = world_registry(adapters, FAKE_GRANT, ledger_path,
                         world=World("a", touches=("elastic",)))

    reg.verbs("elastic")["esql"](ctx, query=body)

    rows = {r["world_id"]: json.loads(r["payload_text"]) for r in served_rows(ledger_path)}
    assert set(rows) == {None, "a"}, f"expected a base row and a world row, got {set(rows)}"
    assert rows[None]["query"] == body, (
        f"the family's shared recording carries world a's view ({rows[None]['query']!r}) — "
        "every other sibling would replay it as the estate's own answer")
    assert rows["a"]["query"] == body
    # The row still says which call RAN: the staged identity is one column over, so nothing
    # about what actually reached the corpus is lost by taking it out of the payload.
    assert [r["params"]["query"] for r in served_rows(ledger_path) if r["world_id"] == "a"] == [
        "FROM wv-a-logs-system.auth-\n| STATS COUNT(*)"]


def test_a_ledger_write_failure_does_not_displace_the_refusal_it_records(tmp_path):
    """    When recording WHY a call failed itself fails, the call's own failure is what propagates.

    Both recording arms run inside a handler that records and then re-raises. A bare
    `ledger.record(...)` there is a second exception source in front of the `raise`: an
    unwritable ledger replaces the refusal, and the two are not interchangeable. A
    `StagingError` carries `USAGE_EXIT_CODE`, deliberately outside `circuit_breaker`'s
    `INFRA_EXIT_CODES`; the `OSError` that replaced it is unrecognised, so `query_tool` files
    it as `DEFAULT_FAULT_EXIT` — an infra code. Two of those trip the breaker for the system
    and five abort the run, in the SIBLING and not in its base, which is the "up for one, down
    for the other" contamination the usage class exists to prevent."""
    ledger_path = tmp_path / "served.jsonl"
    ctx = run_ctx(tmp_path)
    reg = world_registry(fake_estate(tmp_path), FAKE_GRANT, ledger_path,
                         world=World("a", touches=("elastic",)))

    def _unwritable(_call):
        raise OSError(28, "No space left on device")

    reg.ledger.record = _unwritable

    # A comma list is a `StagingError` out of `prepare` — the refusal arm.
    from defender.learning.branch.estate.stagers.elastic import StagingError

    with pytest.raises(StagingError):
        reg.verbs("elastic")["esql"](ctx, query="FROM logs-a-*, logs-b-*\n| LIMIT 1")


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


def test_a_patch_reaches_every_object_that_names_the_entity_at_any_depth():
    """    One entity's patch lands in every object naming it, nested and listed alike.

    That is #845's constraint read literally — the overlay is authored ONCE and applied by
    code, or a host has an owner when asked about directly and none when listed. The count
    comes back beside the payload because it is what separates "this world changed nothing
    here" from "this world does not touch this system"."""
    payload = {"hosts": [{"name": "canary-1"}, {"name": "other-9"}],
               "detail": {"ci_name": "canary-1", "nested": {"hostname": "canary-1"}}}

    out, applied = apply_patches(payload, {"canary-1": {"owner": "worldA"}})

    assert applied == 3
    assert out["hosts"][0]["owner"] == "worldA"
    assert "owner" not in out["hosts"][1]
    assert out["detail"]["owner"] == "worldA"
    assert out["detail"]["nested"]["owner"] == "worldA"


def test_a_payload_naming_nothing_comes_back_as_itself():
    """    A payload no patch matches is handed back as the SAME object, subtrees included.

    The commonest case by far — most calls name none of the patched entities — and the caller
    discards the result whole, so rebuilding it is pure waste. `is` rather than `==`, because
    equality cannot tell a shared subtree from a fresh copy of one."""
    payload = {"rows": [{"host": "nothing-here"}], "meta": {"total": 1}}

    out, applied = apply_patches(payload, {"canary-1": {"owner": "worldA"}})

    assert applied == 0
    assert out is payload
    assert out["meta"] is payload["meta"]


def test_the_family_recording_is_neither_mutated_nor_lent_out():
    """    Patching neither writes into the base tree nor hands the caller the world's own objects.

    Two halves of one rule. The base payload is the FAMILY's recording — mutating it edits one
    sibling's world into the row every other sibling replays. And the overlay is authored once
    and lives for the whole run, so a patch VALUE referenced into a served payload is a mutable
    handle on the world itself: one `append` downstream and every later call, in every sibling
    sharing the applier, serves the edited overlay."""
    patches = {"canary-1": {"owner": "worldA", "tags": ["x"]}}
    payload = {"hosts": [{"name": "canary-1"}, {"name": "canary-1"}]}

    out, _ = apply_patches(payload, patches)

    assert payload == {"hosts": [{"name": "canary-1"}, {"name": "canary-1"}]}, (
        "the base recording was edited in place")
    out["hosts"][0]["tags"].append("MUTATED")
    assert patches == {"canary-1": {"owner": "worldA", "tags": ["x"]}}, (
        "the served payload held a live reference into the world's own overlay")
    assert out["hosts"][1]["tags"] == ["x"], "two patched nodes share one list object"


def test_two_entities_naming_one_object_resolve_in_the_tables_order():
    """    A node both patched entities name takes the LATER table entry on a shared key.

    Deterministic, and deterministic the same way every run: resolving out of a set of matched
    names would order by hash, so the same world and the same payload would disagree between
    processes about what the sibling was served."""
    patches = {"e-1": {"owner": "first", "a": 1}, "e-2": {"owner": "second", "b": 2}}

    out, applied = apply_patches({"host": "e-1", "alias": "e-2"}, patches)

    assert applied == 2
    assert out["owner"] == "second"
    assert (out["a"], out["b"]) == (1, 2)


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
            ledger=fresh_ledger(ledger_path), as_of=AS_OF,
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
    ledger = fresh_ledger(ledger_path)

    patcher = WorldRegistry(
        adapters, FAKE_GRANT, world=World("base", ("cmdb",)), ledger=ledger, as_of=AS_OF,
        applier=WorldApplier({"cmdb": {"canary-1": {"owner": "world"}}}))
    sibling = WorldRegistry(adapters, FAKE_GRANT, world=World("b"), ledger=ledger, as_of=AS_OF)

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
    alone intersects to nothing: a recorded `FROM wv-a-…`, b recorded `FROM wv-b-…`, no row of
    a's ever meets a row of b's, and "the worlds differ" and "the worlds are identical" produce
    the same empty answer. Silent, and silent on the event stream, where most of a run's
    evidence lives.

    The ids are LOWER CASE because an index or alias name is: `world_view` refuses an id the
    cluster could not hold, since a view named above the case rule is answered with an empty
    result rather than refused (`_search` passes `ignore_unavailable=true`).

    The memo key must NOT be the asked form, and this pins both halves: pair on what was asked,
    memoize on what ran. Keyed the other way, B replays A's answer — read off A's staged
    corpus — which is contamination rather than merely a re-read."""
    ledger_path = tmp_path / "served.jsonl"
    adapters, ctx = fake_estate(tmp_path), run_ctx(tmp_path)
    ledger = fresh_ledger(ledger_path)
    body = "FROM logs-system.auth-*\n| LIMIT 5"

    for wid in ("a", "b"):
        reg = WorldRegistry(
            adapters, FAKE_GRANT, world=World(wid, ("elastic",)), ledger=ledger, as_of=AS_OF)
        reg.verbs("elastic")["esql"](ctx, query=body)

    rows = [r for r in served_rows(ledger_path) if r["world_id"] in ("a", "b")]
    assert len(rows) == 2

    ran = {r["world_id"]: r["params"]["query"] for r in rows}
    assert ran["a"] != ran["b"], "each world must read its OWN corpus"

    asked = {r["world_id"]: r["asked_params"]["query"] for r in rows}
    assert asked["a"] == asked["b"] == body, (
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
        adapters, FAKE_GRANT, world=World("A", ("cmdb",)), ledger=fresh_ledger(ledger_path), as_of=AS_OF)

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
