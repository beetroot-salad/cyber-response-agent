"""#920 PR 1 — the estate seam: what a branched sibling queries THROUGH, and what it records.

A sibling world does not replay a snapshot. It queries the live estate through
`WorldRegistry`, a `ModuleVerbRegistry` subclass whose verbs run FOR REAL against the adapter
and then answer to the world. (#1224 replaced #920's staging applier with each world's live
oracle: a world with no facts is served its base answer, `passthrough`; a world with facts is
served by an oracle turn, whose contract is `tests/live_oracle_1224/`.)

**The ledger is the gate.** The hazard is a response reaching the defender with no record of
the decision behind it — silent scenario deletion, a run that looks fine and measures nothing.
So every served payload lands in the ledger with the DECISION that produced it, `passthrough`
is a recorded decision rather than an absence, and `Ledger.record` refuses a `ServedCall` whose
source is outside `SOURCES` — before the payload is handed back.

WHAT THIS FILE OWNS
-------------------
1. **Structural coverage** — `decide()` is GRANTED for every entry of the shipped gather grant,
   and every callable `verbs()` hands back is a WRAPPED one carrying the real body's decoration
   and keyword-only signature. Structural, not enumerated: there is no route to a bare adapter
   body, so no system can be silently left out of the estate.
2. **Nominal typing** — `build_agent_core` refuses a registry-shaped stand-in; `WorldRegistry`
   passes, because it went through the real constructor with a real `VerbGrant`.
3. **Every served response is recorded with a decision** — including the refusal arm, where
   the caller must get NO payload.
4. **The family tier and the world's own base** — `world_id=None` rows are the family's
   recording, replayed by every sibling with no adapter call; a key the recording lacks is read
   live ONCE per world and kept in that world's oracle store (never a ledger row, M16).

Hermetic. The real-adapters half constructs a registry over the REAL
`defender/scripts/adapters` and the REAL grant — a cold read plus (for `decide`) an import, no
network, no verb body run. The serving half runs verb bodies for real against a fake adapters
DIRECTORY written to `tmp_path`: a real file the cold `VERBS = {...}` reader parses and the
loader imports, rather than a patched module, because the grant/adapter agreement check runs
off that text before anything is served. Fakes enter through the constructor's own DI seams
(`world=`, `ledger=`); nothing here uses `monkeypatch.setattr`.
"""
from __future__ import annotations

import contextlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
import functools
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import ModelResponse, TextPart  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402

from defender._episode_handle import Episode  # noqa: E402
from defender._io import read_jsonl_rows  # noqa: E402
from defender._paths import PATHS  # noqa: E402
from defender.runtime.verbs import read_roster  # noqa: E402
from defender.learning.branch.estate.registry import (  # noqa: E402
    EstateError,
    WorldRegistry,
)
from defender._episode_paths import LAYOUT, EpisodePaths  # noqa: E402
from defender.learning.branch.ledger import (  # noqa: E402
    BASE,
    CAPTURED,
    FAMILY_SOURCES,
    FAULT,
    ORACLE,
    PASSTHROUGH,
    REAL_ERROR,
    REFUSED,
    SOURCES,
    STAGED,
    Ledger,
    LedgerError,
    ServedCall,
    payload_text,
    request_key,
)
from defender.runtime import driver, observe  # noqa: E402
from defender.runtime.tools import GatherDeps  # noqa: E402
from defender.runtime.verb_grant import VerbGrant  # noqa: E402
from defender.runtime.verbs import (  # noqa: E402
    DENIED,
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
from defender.tests import _tenants1106 as T1106  # noqa: E402
from defender.tests.live_oracle_1224._spec1224 import build_registry  # noqa: E402

#: The estate a real branched run queries: the shipped adapters and the shipped gather grant.
#: Read through `PATHS`, the same seam `build_agent_core` defaults to, so a tree that moves its
#: adapters moves this with it.
REAL_ADAPTERS = PATHS.adapters_dir


@functools.cache
def _gather_grant():
    """The shipped gather grant — the committed playground tenant's (#1106 M4: no grant is
    fixed per process, so it is projected from a tenant's table, lazily)."""
    return T1106.fixture_grants().gather


#: What the shipped grant covers today. Asserted rather than derived, so a grant that SHRINKS
#: — a system quietly dropped out of the estate — fails here instead of making the structural
#: sweep below cover less and still pass.
GRANTED_ENTRIES = 30
GRANTED_SYSTEMS = 8


# the fake estate: a real adapters directory, with verb bodies that count

#: A recording adapter. Written to disk rather than patched in, because `ModuleVerbRegistry`
#: COLD-READS this text (`read_roster` parses the `VERBS = {...}` literal without
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
    """`owner` is the estate's own answer."""
    return {"host": host, "owner": "estate", "call": _record(ctx, "get-host", {"host": host})}


@verb()
def health_check(ctx: VerbContext) -> dict:
    return {"ok": True, "call": _record(ctx, "health-check", {})}


VERBS = {"esql": esql, "get-host": get_host, "health-check": health_check}
'''

#: The fake estate's grant: two systems, `elastic.get-host` declared by the fake estate and
#: withheld here (the denial arm).
FAKE_GRANT = VerbGrant(role="gather", entries=(
    ("elastic", "esql", "r"), ("elastic", "health-check", "r"),
    ("cmdb", "get-host", "r"), ("cmdb", "health-check", "r"),
))

CALLS_LOG = "adapter-calls.jsonl"

#: The branch point's own moment (#947). Every world here is served under ONE clock, so nothing
#: below turns on its value — but a registry cannot be built without one, because a defaulted
#: clock is a wall-clock stamp in a branched run and the whole point is that there are none.
AS_OF = datetime(2026, 5, 25, 15, 30, 45, tzinfo=UTC)


#: A world ledger's place in an episode, `<episode>/served/<world id>.jsonl`, relative to a
#: test's tmp dir: a `Ledger` is built only by `Ledger.for_world(episode, world_id)` (#1133 rev
#: 2), so the file every test here reads back is where that puts it.
SERVED_FILE = Path("ep", "served", "w.jsonl")


def fresh_ledger(path: Path) -> Ledger:
    """A `Ledger` over `path` (`<episode>/served/<world id>.jsonl`), beside the primed capture
    #947 made REQUIRED.

    EMPTY, deliberately. Nothing in this file is about the capture; what `base_path` has to be
    here is a FILE, which is `Ledger.__post_init__`'s ordering guarantee that the episode was
    primed before any sibling opened a ledger over it. Empty, every key MISSES it and falls
    through to a live read kept in the world's own store. The episode stays held for as long as
    the ledger that writes through it."""
    episode = Episode.create(path.parent.parent)
    with contextlib.suppress(FileExistsError):
        episode.served_base.create("")
    ledger = Ledger.for_world(episode, path.stem)
    assert ledger.path == path, (ledger.path, path)
    return ledger


@dataclass(frozen=True)
class World:
    """The world object the seam reads: an id, and the facts it asserts (none: a control,
    served its base answer as `passthrough`)."""

    world_id: str
    facts: tuple[dict, ...] = ()


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
    return VerbContext(defender_dir=tmp_path, run_dir=run_dir, env={},
                       tenant=T1106.fixture_run_tenant())


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


#: The default world for tests whose subject is not the world: it asserts no facts, so every
#: decision it produces is `passthrough` and no oracle turn is ever taken.
UNTOUCHED_WORLD = World("w1")


def world_registry(
    adapters: Path, grant: VerbGrant, ledger_path: Path, *,
    world: Any = UNTOUCHED_WORLD,
) -> WorldRegistry:
    """A `WorldRegistry` built through its own constructor, over a fresh ledger at `path`."""
    return build_registry(
        read_roster(adapters), grant, world=world, ledger=fresh_ledger(ledger_path),
        as_of=AS_OF, tenant=T1106.fixture_run_tenant(),
    )


# 1. structural coverage: every granted verb, and no route to a bare body


def test_the_shipped_grant_still_spans_every_system():
    """    The estate's coverage claim is only as wide as the grant it is measured over, so the
    grant's own shape is pinned first — 30 entries across 8 systems (#983 added
    `tacit-knowledge`, and its `health-check` with it). Without this arm a grant
    that lost a system would make every sweep below cover one system less and stay green."""
    assert len(_gather_grant().entries) == GRANTED_ENTRIES
    assert len(_gather_grant().systems) == GRANTED_SYSTEMS


def test_every_granted_verb_decides_granted_through_the_world_registry(tmp_path):
    """    `decide()` answers GRANTED for all 28 shipped grant entries.

    This is the coverage claim, and it runs through the REAL adapters: `decide` resolves the
    callable through `verbs()`, so a wrapper that broke `verb_class_of` would fail the grant's
    class agreement (a `GrantError`, not a soft denial) and a wrapper that lost a verb name
    would answer UNDECLARED. Whole-grant rather than per-system spot checks, because the
    property is "no system is left out of the estate"."""
    reg = world_registry(REAL_ADAPTERS, _gather_grant(), tmp_path / SERVED_FILE)

    refused = [
        (system, verb, reg.decide(system, verb).outcome)
        for system, verb, _ in _gather_grant().entries
        if reg.decide(system, verb).outcome != GRANTED
    ]

    assert refused == []


def test_no_route_to_a_verb_hands_back_a_bare_adapter_body(tmp_path):
    """    Both routes to a callable — `decide().fn` and the query tool's own second lookup,
    `registry.verbs(system)[verb]` — hand back a WRAPPER over the real body, never the body.

    A bare body is a query that reaches the defender without passing the seam, which is the
    silent-scenario-deletion hazard the ledger exists to make visible: it would be a response
    with no row. Pinned as `__wrapped__ is real`, so the wrapper is proven to be over THIS
    body rather than merely to be some other callable."""
    reg = world_registry(REAL_ADAPTERS, _gather_grant(), tmp_path / SERVED_FILE)
    plain = ModuleVerbRegistry(read_roster(REAL_ADAPTERS), _gather_grant())

    bare = []
    for system, verb, _ in _gather_grant().entries:
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
    reg = world_registry(REAL_ADAPTERS, _gather_grant(), tmp_path / SERVED_FILE)
    plain = ModuleVerbRegistry(read_roster(REAL_ADAPTERS), _gather_grant())

    drifted = []
    for system, verb, verb_class in _gather_grant().entries:
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
    reg = world_registry(REAL_ADAPTERS, _gather_grant(), tmp_path / SERVED_FILE)
    plain = ModuleVerbRegistry(read_roster(REAL_ADAPTERS), _gather_grant())

    drifted = []
    for system, verb, _ in _gather_grant().entries:
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
    reg = world_registry(REAL_ADAPTERS, _gather_grant(), tmp_path / SERVED_FILE)
    served = reg.verbs("ticket")["list-tickets"]

    assert "require_closed" in declared_params(served)
    assert "require_closed" not in model_facing_params(served)
    refusal = validate_params(served, {"require_closed": True})
    assert refusal is not None
    assert "require_closed" in refusal
    assert validate_params(served, {"status": "open"}) is None


# 2. nominal typing: the build site's isinstance check

def _built(logger, verbs):
    with override_allow_model_requests(False):
        return driver.build_agent_core(
            T1106.fixture_gather_def(), deps_type=GatherDeps, instructions="x", logger=logger,
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
        REAL_ADAPTERS, _gather_grant(), tmp_path / SERVED_FILE,
        world=World("w1"),
    )

    agent = _built(logger, reg)

    assert {"query", "list_verbs"} <= set(agent._function_toolset.tools)


# 3. every served response is recorded with a decision

def test_serving_through_the_wrapper_writes_a_row_carrying_the_decision(tmp_path):
    """    One served call, one world row: the system, the verb, the params as asked, the
    payload bytes, the decision and the world id.

    `passthrough` is a DECISION here, not an absence — this world asserts no facts, so the seam
    honestly reports that it served the base answer. A response with no row is the failure
    the table exists to make visible, so the row's presence is the assertion."""
    ledger_path = tmp_path / SERVED_FILE
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


def test_the_vocabulary_splits_into_the_tier_the_seam_and_the_world():
    """    `SOURCES` is three kinds of label, and only one kind is a world's serving to name.

    Without this split "the vocabulary is closed" reads as "any world may claim any member",
    which includes the FAMILY tier's own labels — the slot every sibling replays from. That tier
    is two labels since #947: `captured` is the source run's own capture, primed before any
    sibling forked, and `base` is a family-tier read of a key the capture never held. Both are
    `world_id=None` and neither is a world's to claim; the split between them is
    `test_947_ledger_tiers.py`. #1224's world decisions are `passthrough`, `oracle` and
    `real-error`; the retired staging decisions are not a new row's to name."""
    world_decisions = {PASSTHROUGH, ORACLE, REAL_ERROR}
    assert world_decisions | FAMILY_SOURCES | {REFUSED, FAULT} == SOURCES
    assert BASE in FAMILY_SOURCES
    assert CAPTURED in FAMILY_SOURCES
    assert not (world_decisions & FAMILY_SOURCES)
    assert not ({STAGED, "patched"} & SOURCES)


def test_the_ledger_refuses_an_invented_decision_at_its_own_door(tmp_path):
    """    `Ledger.record` is where the vocabulary is OWNED, so it refuses directly too.

    The registry deliberately does not re-check the decision it just received — the same rule
    in two places is a rule with a copy that can drift, and the copy that drifts is the one
    that stops refusing. This arm is what makes that delegation safe to rely on."""
    ledger = fresh_ledger(tmp_path / SERVED_FILE)
    call = ServedCall(
        system="cmdb", verb="get-host", params={"host": "canary-1"},
        payload_text="{}", source="invented", world_id="w1",
    )

    with pytest.raises(LedgerError, match="invented"):
        ledger.record(call)

    assert served_rows(tmp_path / SERVED_FILE) == []


@pytest.mark.parametrize(("source", "world_id"), [(BASE, "w1"), (PASSTHROUGH, None)])
def test_the_two_tiers_have_to_agree(tmp_path, source, world_id):
    """    `base` and `world_id=None` say the same thing, so a row where they disagree is refused.

    Both arms are an injection, read from opposite ends. A `base` row owned by a world puts
    that world's answer in the slot every sibling replays from — one world's difference served
    AS the estate, while each sibling's own row still reads `passthrough`. A world-tier row
    with no owner is the mirror: a difference nobody can attribute, which a comparison then
    counts against whichever sibling it happens to read next."""
    ledger = fresh_ledger(tmp_path / SERVED_FILE)

    with pytest.raises(LedgerError, match="FAMILY tier"):
        ledger.record(ServedCall(
            system="cmdb", verb="get-host", params={"host": "canary-1"},
            payload_text="{}", source=source, world_id=world_id))

    assert served_rows(tmp_path / SERVED_FILE) == []


def test_an_estate_fault_still_leaves_a_row(tmp_path):
    """    The adapter body raising is a RESPONSE the defender sees, so it lands in the table.

    `QueryCapture` catches whatever the body raises and hands the model a fault row, so a seam
    that wrote nothing here would leave exactly the state this table exists to make visible —
    "a served response with no row" — and a reader counting evidence would see the sibling
    simply never asking. The real system's error is its own class (`real-error`, #1224 O4): it
    passes through as itself, never cached, and is told apart from a refusal.

    The exception still reaches the caller untouched: the row is a record, not a rescue."""
    adapters = fake_estate(tmp_path)
    down = (adapters / "cmdb_adapter.py").read_text(encoding="utf-8").replace(
        'def get_host(ctx: VerbContext, *, host: str) -> dict:',
        'def get_host(ctx: VerbContext, *, host: str) -> dict:\n'
        '    raise RuntimeError("cmdb is down")')
    (adapters / "cmdb_adapter.py").write_text(down, encoding="utf-8")
    ledger_path = tmp_path / SERVED_FILE
    reg = world_registry(adapters, FAKE_GRANT, ledger_path, world=World("w1"))

    with pytest.raises(RuntimeError, match="cmdb is down"):
        reg.verbs("cmdb")["get-host"](run_ctx(tmp_path), host="canary-1")

    rows = served_rows(ledger_path)
    assert [r["source"] for r in rows] == [REAL_ERROR], (
        f"an estate fault left {[r['source'] for r in rows]} behind; a served response with no "
        "row is the one state this table exists to make visible")
    assert rows[0]["world_id"] == "w1"
    assert "cmdb is down" in rows[0]["payload_text"]


def test_a_denied_call_is_a_refused_row_and_a_listing_of_the_same_verb_is_not(tmp_path):
    """    #860 — a verb the grant WITHHOLDS is turned away at the grant decision, one frame
    before the seam; of every call the defender makes it was the one that left no row here, so
    every reader of this ledger (the judge's "no row on H" above all) saw a sibling that never
    asked. `decide_call` — the dispatch path's decision — files it as `refused`, against the
    params as ASKED, under the world's own id; and the adapter body is never reached.

    The NEGATIVE arms are what make the split earn its name. `decide` — the same question,
    asked by the discovery tool about every verb a system declares — records nothing: a
    withheld verb the model merely READ ABOUT was refused nothing. And a granted call's
    decision records nothing either: its row is the served one, written when the call runs.

    Observed failing by: no row, a row with the wrong source/params/world, a row for the
    listing, or a row for the granted decision."""
    ledger_path = tmp_path / SERVED_FILE
    ctx = run_ctx(tmp_path)
    reg = world_registry(fake_estate(tmp_path), FAKE_GRANT, ledger_path, world=World("w1"))
    asked = {"host": "web-01"}

    # `elastic.get-host` is DECLARED by the fake estate and absent from FAKE_GRANT: a denial.
    listing = reg.decide("elastic", "get-host")
    assert listing.outcome == DENIED
    assert served_rows(ledger_path) == [], "a LISTING of a withheld verb left a row"

    granted = reg.decide_call("elastic", "esql", {"query": "FROM logs\n| LIMIT 1"})
    assert granted.outcome == GRANTED
    assert served_rows(ledger_path) == [], "a granted DECISION left a row (its row is the served one)"

    decision = reg.decide_call("elastic", "get-host", asked)
    assert decision.outcome == DENIED
    rows = served_rows(ledger_path)
    assert [r["source"] for r in rows] == [REFUSED], (
        f"a denied call left {[r['source'] for r in rows]} behind; a refusal that writes no "
        "row is a served response with no row")
    assert (rows[0]["system"], rows[0]["verb"], rows[0]["params"]) == ("elastic", "get-host", asked)
    assert rows[0]["world_id"] == "w1"
    assert rows[0]["payload_text"] == decision.refusal, "the row's text is the refusal the model sees"
    assert adapter_calls(ctx) == [], "the estate was called for a call the grant withheld"


def test_an_adapter_that_cannot_load_at_the_decision_is_a_fault_row_and_still_raises(tmp_path):
    """    The other refusal the grant decision makes before the seam: an adapter whose module
    cannot be imported raises out of `decide`. Filed `fault`: it is the environment's outage,
    not a refusal of the call, and a `refused` row would charge it to the world. Re-raised
    untouched: what the query tool makes of
    that exception (§7 R2, the load-error row it writes) is the query tool's own.

    Observed failing by: no row, a `refused` row, or the exception swallowed."""
    adapters = fake_estate(tmp_path)
    (adapters / "elastic_adapter.py").write_text(
        _RECORDING_ADAPTER + "\nraise ImportError('the elastic client is not installed')\n",
        encoding="utf-8")
    ledger_path = tmp_path / SERVED_FILE
    reg = world_registry(adapters, FAKE_GRANT, ledger_path, world=World("w1"))

    with pytest.raises(ImportError, match="not installed"):
        reg.decide_call("elastic", "esql", {"query": "FROM logs"})

    rows = served_rows(ledger_path)
    assert [r["source"] for r in rows] == [FAULT], f"an adapter that could not load left {rows}"
    assert "not installed" in rows[0]["payload_text"]
    assert rows[0]["world_id"] == "w1"


def test_the_verb_table_handed_back_is_the_callers_to_edit(tmp_path):
    """    `verbs()` returns a COPY, so one caller's edit cannot reach the next lookup.

    The wrappers are memoized per system (they are built once and both routes to a callable go
    through them), and `ModuleVerbRegistry.verbs` ends `return dict(verbs)` — callers may treat
    that freedom as theirs. Handing out the live memo means an edit anywhere reaches every later
    lookup INCLUDING `decide`'s, which is the route the grant is checked through: a verb swapped
    in a returned table would then be admitted under the real one's class."""
    reg = world_registry(fake_estate(tmp_path), FAKE_GRANT, tmp_path / SERVED_FILE)
    served = reg.verbs("cmdb")["get-host"]

    reg.verbs("cmdb")["get-host"] = "not a verb at all"

    assert reg.verbs("cmdb")["get-host"] is served
    assert reg.decide("cmdb", "get-host").fn is served


def test_the_reserved_base_world_id_cannot_name_the_family_capture(tmp_path):
    """The natural id ``base`` is refused when it would make both ledger tiers one file.

    It is a safe corpus name and a safe filename component, so generic validation admits it.
    Under the episode factory, though, it resolves to ``served/base.jsonl`` — exactly the file
    siblings replay as their immutable capture. Construction must fail before any world row can
    be appended there.
    """
    episode_root = tmp_path / "episode"
    capture = EpisodePaths(episode_root).served_base
    capture.parent.mkdir(parents=True, exist_ok=True)
    capture.touch()

    with Episode.open(episode_root) as episode, \
            pytest.raises(LedgerError, match="family's own capture"):
        Ledger.for_world(episode, "base")

    assert capture.read_text(encoding="utf-8") == ""


# 4. the family tier and the world's kept base: no second adapter call

def test_the_same_key_twice_is_one_adapter_call_and_one_payload(tmp_path):
    """    Serving one key twice returns identical payloads and issues EXACTLY ONE adapter call.

    The estate is live: two calls minutes apart see different data, so a sibling that re-asked
    would measure the estate's drift and call it the world's difference. The world's kept base
    read is what buys determinism back, and the adapter's own call log is what proves it — the
    payload's call ordinal would differ on a second live call. The live read is kept in the
    world's oracle store and is never a ledger row (M16): the ledger holds the two served
    calls and nothing else."""
    ledger_path = tmp_path / SERVED_FILE
    ctx = run_ctx(tmp_path)
    reg = world_registry(
        fake_estate(tmp_path), FAKE_GRANT, ledger_path, world=World("w1"),
    )
    served = reg.verbs("cmdb")["get-host"]

    first = served(ctx, host="canary-1")
    second = served(ctx, host="canary-1")

    assert first == second
    assert len(adapter_calls(ctx, "get-host")) == 1
    assert [r["source"] for r in served_rows(ledger_path)] == [PASSTHROUGH, PASSTHROUGH]


def test_two_siblings_read_one_base_recording(tmp_path):
    """    Two worlds asking a question the family recorded get the same bytes off NO adapter call.

    This is the A/B invariance the branch is for: everything the capture holds is literally
    identical across siblings, so a difference between them is readable as the world rather
    than as the estate having moved between two queries. Each world still records its own
    served row, because what was served is per world."""
    ledger_path = tmp_path / SERVED_FILE
    adapters, ctx = fake_estate(tmp_path), run_ctx(tmp_path)
    base = EpisodePaths(tmp_path / "ep").served_base
    base.parent.mkdir(parents=True, exist_ok=True)
    base.write_text(json.dumps({
        "system": "cmdb", "verb": "get-host", "params": {"host": "canary-1"},
        "payload_text": payload_text({"host": "canary-1", "owner": "captured"}),
        "source": CAPTURED, "world_id": None}) + "\n", encoding="utf-8")
    ledger = fresh_ledger(ledger_path)
    a = build_registry(read_roster(adapters), FAKE_GRANT, world=World("a"), ledger=ledger, as_of=AS_OF)
    b = build_registry(read_roster(adapters), FAKE_GRANT, world=World("b"), ledger=ledger, as_of=AS_OF)

    from_a = a.verbs("cmdb")["get-host"](ctx, host="canary-1")
    from_b = b.verbs("cmdb")["get-host"](ctx, host="canary-1")

    assert from_a == from_b == {"host": "canary-1", "owner": "captured"}
    assert adapter_calls(ctx, "get-host") == []
    rows = served_rows(ledger_path)
    assert [(r["world_id"], r["source"]) for r in rows] == [("a", PASSTHROUGH), ("b", PASSTHROUGH)]


def test_a_duplicate_base_row_resolves_the_same_way_in_memory_and_on_disk(tmp_path):
    """    Two base rows for one key resolve to the FIRST, whether the answer comes from this
    process's memo or from a rebuild off the file.

    The check-then-act spans the adapter call and `base_payload` reads the memo unlocked, so
    two of ONE world's gather threads can both miss and both record — the tier split closed the
    cross-process half of this, not the cross-thread half. The file then holds two rows for one
    key, and the tie-break is the only thing left to make them agree. Resolved one way in
    `record` and the other in `_absorb`, this process served the second payload while any
    process rebuilding from the file served the first: two answers to one question with both
    rows reading honestly, which is exactly the invariance the family tier exists to buy."""
    ledger_path = tmp_path / SERVED_FILE
    ledger = fresh_ledger(ledger_path)
    call = dict(system="cmdb", verb="get-host", params={"host": "canary-1"},
                source=BASE, world_id=None)

    ledger.record(ServedCall(payload_text='{"owner": "first"}', **call))
    ledger.record(ServedCall(payload_text='{"owner": "second"}', **call))

    assert ledger.base_payload("cmdb", "get-host", {"host": "canary-1"}) \
        == fresh_ledger(ledger_path).base_payload("cmdb", "get-host", {"host": "canary-1"}) \
        == '{"owner": "first"}'


def test_a_world_reopened_from_disk_replays_its_own_kept_base_read(tmp_path):
    """    A world rebuilt from disk — the shape a resumed sibling process opens — replays its own
    kept base read rather than re-asking the estate, and another world does not.

    The kept read lives in the world's oracle store on disk, so a sibling restarted after a
    crash inherits its own answer. It is the world's own and never the family's (M16): a
    different world asking the same uncaptured key reads live for itself."""
    ledger_path = tmp_path / SERVED_FILE
    adapters, ctx = fake_estate(tmp_path), run_ctx(tmp_path)
    first = build_registry(read_roster(adapters), FAKE_GRANT, world=World("a"), ledger=fresh_ledger(ledger_path), as_of=AS_OF)
    from_a = first.verbs("cmdb")["get-host"](ctx, host="canary-1")

    reopened = build_registry(
        read_roster(adapters), FAKE_GRANT, world=World("a"), ledger=fresh_ledger(ledger_path), as_of=AS_OF)
    again = reopened.verbs("cmdb")["get-host"](ctx, host="canary-1")

    assert from_a == again
    assert len(adapter_calls(ctx, "get-host")) == 1

    other = build_registry(
        read_roster(adapters), FAKE_GRANT, world=World("b"), ledger=fresh_ledger(ledger_path), as_of=AS_OF)
    other.verbs("cmdb")["get-host"](ctx, host="canary-1")

    assert len(adapter_calls(ctx, "get-host")) == 2, "one world's live read served another"
    assert (ledger_path.parent / LAYOUT.oracle_dir("a")).is_dir()


def test_two_spellings_of_one_question_are_one_key(tmp_path):
    """    Params built in a different order are the SAME key, so they cost one adapter call.

    `request_key` sorts, the way `_query_rules._request_key` does and for the same reason: two
    spellings of one question would otherwise split one memo into two, and the pair would see
    the estate twice at two different moments."""
    ledger_path = tmp_path / SERVED_FILE
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


# 5. a failure keeps its row, and a world with no facts is served its base

def test_a_ledger_write_failure_does_not_displace_the_failure_it_records(tmp_path):
    """    When recording WHY a call failed itself fails, the call's own failure is what propagates.

    The recording arms run inside a handler that records and then re-raises. A bare
    `ledger.record(...)` there is a second exception source in front of the `raise`: an
    unwritable ledger replaces the real system's error, and the two are not interchangeable —
    the `OSError` is unrecognised, so `query_tool` files it as `DEFAULT_FAULT_EXIT`, an infra
    code, counted against the sibling's breaker for a failure that is not the one it had."""
    adapters = fake_estate(tmp_path)
    down = (adapters / "cmdb_adapter.py").read_text(encoding="utf-8").replace(
        'def get_host(ctx: VerbContext, *, host: str) -> dict:',
        'def get_host(ctx: VerbContext, *, host: str) -> dict:\n'
        '    raise RuntimeError("cmdb is down")')
    (adapters / "cmdb_adapter.py").write_text(down, encoding="utf-8")
    reg = world_registry(adapters, FAKE_GRANT, tmp_path / SERVED_FILE, world=World("a"))

    def _unwritable(_call):
        raise OSError(28, "No space left on device")

    reg.ledger.record = _unwritable

    with pytest.raises(RuntimeError, match="cmdb is down"):
        reg.verbs("cmdb")["get-host"](run_ctx(tmp_path), host="canary-1")


def test_a_world_with_no_facts_reaches_the_adapter_unchanged(tmp_path):
    """    A world asserting no facts sends its query to the adapter byte-identical, and reports
    `passthrough` — no oracle turn, no rewrite. A difference observed there is corrupt by
    construction rather than something to explain."""
    ledger_path = tmp_path / SERVED_FILE
    ctx = run_ctx(tmp_path)
    body = "FROM logs-nginx.access-*\n| LIMIT 5"
    reg = world_registry(
        fake_estate(tmp_path), FAKE_GRANT, ledger_path, world=World("w1", facts=()),
    )

    reg.verbs("elastic")["esql"](ctx, query=body)

    assert [c["params"]["query"] for c in adapter_calls(ctx, "esql")] == [body]
    assert [r["source"] for r in served_rows(ledger_path) if r["world_id"] == "w1"] \
        == [PASSTHROUGH]


def test_a_world_may_not_answer_to_the_family_tiers_key(tmp_path):
    """    A world whose `world_id` is `None` is refused at construction.

    `None` is how the family tier spells "this is what the estate answered", and every sibling
    replays that slot instead of re-asking a live system. A world answering to it would write
    its own served payload there, and the next sibling would serve another world's difference
    AS the estate — while recording an honest-looking `passthrough` row of its own. Silent
    scenario INJECTION, the inverse of the deletion the ledger was built to catch, and invisible
    in exactly the record meant to show it.

    Refused at CONSTRUCTION rather than at the write: by the time a payload is being recorded
    the world has already served, and a check there would have to be repeated at every writer."""
    ledger_path = tmp_path / SERVED_FILE

    class BaseWorld:
        world_id = None
        facts = ({"fact_id": "f1", "statement": "web-1's owner is the platform team",
                  "entities": ["web-1"]},)

    with pytest.raises(EstateError):
        build_registry(
            read_roster(fake_estate(tmp_path)), FAKE_GRANT, world=BaseWorld(),
            ledger=fresh_ledger(ledger_path), as_of=AS_OF)

    assert not ledger_path.exists(), "a refused world must not have written a row"


def test_the_control_worlds_rows_are_its_own_never_the_familys(tmp_path):
    """    The control world queries the estate exactly as it is, and its rows carry its own id.

    Its payloads ARE the estate's, which is what makes a control-versus-sibling difference read
    as exactly the sibling's world. THE ROWS ARE KEYED TO IT, and that is the point: a control
    that answered to `None` would share the family's slot — harmless only while it changes
    nothing, and silent scenario INJECTION the moment it does, because every sibling replays that
    slot as the estate while its own row honestly reports `passthrough`. And its live read never
    enters the family's recording (M16): the primed base stays exactly as primed."""
    ledger_path = tmp_path / SERVED_FILE
    ctx = run_ctx(tmp_path)
    body = "FROM logs-system.auth-*\n| LIMIT 5"

    class ControlWorld:
        # Control-ness is `facts`, not the id: a control asserts nothing, so there is nothing
        # for an oracle to serve. Expressing it as a reserved id instead would conflate "the
        # control world" with "the family's recording", which is the slot every sibling replays.
        world_id = "base"
        facts = ()

    reg = world_registry(
        fake_estate(tmp_path), FAKE_GRANT, ledger_path, world=ControlWorld(),
    )
    reg.verbs("elastic")["esql"](ctx, query=body)

    assert [c["params"]["query"] for c in adapter_calls(ctx, "esql")] == [body]
    assert [(r["world_id"], r["source"]) for r in served_rows(ledger_path)] \
        == [("base", PASSTHROUGH)], "the control world's row must not share the family's slot"
    assert EpisodePaths(tmp_path / "ep").served_base.read_text(encoding="utf-8") == ""


def test_an_unstaged_call_records_one_identity_not_two(tmp_path):
    """    Nothing was rewritten, so there is no second identity to record (#1224: under the
    oracle a call always runs as asked; only archived staging-era rows carry `asked_params`).

    The column is written only when it says something. Echoing `params` onto every row would
    make the two identities look like one thing, which is the confusion the pair exists to
    prevent."""
    ledger_path = tmp_path / SERVED_FILE
    adapters, ctx = fake_estate(tmp_path), run_ctx(tmp_path)
    reg = build_registry(
        read_roster(adapters), FAKE_GRANT, world=World("A"), ledger=fresh_ledger(ledger_path), as_of=AS_OF)

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
        payload_text="{}", source=PASSTHROUGH, world_id="A")
    assert call.key == call.correlation_key
