"""#920 PR 1 — the estate seam: what a branched sibling queries THROUGH, and what it records."""
from __future__ import annotations

from collections.abc import Mapping
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

from defender.episodes._episode_handle import Episode  # noqa: E402
from defender._io import read_jsonl_rows  # noqa: E402
from defender._paths import PATHS  # noqa: E402
from defender.runtime.verbs import read_roster  # noqa: E402
from defender.learning.branch.estate.registry import (  # noqa: E402
    EstateError,
    WorldRegistry,
)
from defender.episodes._episode_paths import LAYOUT, EpisodePaths  # noqa: E402
from defender.learning.branch.ledger import (  # noqa: E402
    BASE,
    CAPTURED,
    FAULT,
    PASSTHROUGH,
    REAL_ERROR,
    REFUSED,
    Ledger,
    LedgerError,
    ServedCall,
    payload_text,
    request_key,
)
from defender.runtime import driver, observe, run_end  # noqa: E402
from defender.runtime.tools import GatherDeps  # noqa: E402
from defender.runtime.verb_grant import VerbGrant  # noqa: E402
from defender.runtime.verbs import (  # noqa: E402
    DENIED,
    GRANTED,
    ModuleVerbRegistry,
    VerbContext,
    declared_params,
    model_facing_params,
    validate_params,
)
from defender.tests.support.runtime.engine._engine_helpers import fake_model  # noqa: E402
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender.tests.learning.oracle.live_contracts import _spec1224 as S24  # noqa: E402
from defender.tests.learning.oracle.live_contracts._spec1224 import build_registry  # noqa: E402

REAL_ADAPTERS = PATHS.adapters_dir

#: #1255 D5's ledger decision for a control world whose oracle turn served something other than
#: its base. Spelled as the word itself: which constant the ledger names it by is the ledger's.
RECONSTRUCTED = "reconstructed"


@functools.cache
def _gather_grant():
    """The shipped gather grant — the committed playground tenant's (#1106 M4: no grant is
    fixed per process, so it is projected from a tenant's table, lazily)."""
    return T1106.fixture_grants().gather


GRANTED_ENTRIES = 30
GRANTED_SYSTEMS = 8


# the fake estate: a real adapters directory, with verb bodies that count

_RECORDING_ADAPTER = '''\
"""A verb body that records the params it was CALLED with, under a run dir the test reads."""
from __future__ import annotations

import json
from pathlib import Path

from defender.runtime.verbs import VerbContext, verb

CALLS = "adapter-calls.jsonl"


def check_settings(*_a, **_k):
    """A fake system needs no settings (#1256 O-5: every adapter declares its check)."""
    return None


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

AS_OF = datetime(2026, 5, 25, 15, 30, 45, tzinfo=UTC)


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

    @property
    def family(self):
        from defender.runtime.branch._family import parse_family
        from defender.tests.support.learning.branch import _triplet_947 as T

        return parse_family(T.family_doc())


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


UNTOUCHED_WORLD = World("w1")


def world_registry(
    adapters: Path, grant: VerbGrant, ledger_path: Path, *,
    world: Any = UNTOUCHED_WORLD, **oracle_side: Any,
) -> WorldRegistry:
    """A `WorldRegistry` built through its own constructor, over a fresh ledger at `path`.
    `oracle_side` is `control_oracle(...)` for a test that serves a live read."""
    return build_registry(
        read_roster(adapters), grant, world=world, ledger=fresh_ledger(ledger_path),
        as_of=AS_OF, tenant=T1106.fixture_run_tenant(), **oracle_side,
    )


def control_oracle(base: Mapping[str, Any]) -> dict[str, Any]:
    """The oracle side of a world with no facts that serves a live read. #1255 D3: every world,
    the control included, answers a question the source never asked through its oracle, and
    every estate here leaves the family's recording empty, so a live read takes an oracle turn.
    This double serves `base` — the fake adapter's answer to that read, call ordinal included —
    back unchanged with an empty claim, so the row stays `passthrough`; its box is a recording
    sandboxed one, so no turn reaches the production box. Whether the turn is TAKEN is #1255's
    to pin (`test_1255_world_serving.py`, `test_1224_serving.py`), not this file's."""
    return {"oracle": S24.oracle(then=S24.submit(dict(base), S24.EMPTY_CLAIM)).model,
            "verifier": S24.passing_verifier().model, "box": S24.sandboxed_box()[0]}


def estate_host(host: Any, call: int = 1) -> dict:
    """The fake estate's `get-host` answer when it is the run's `call`-th adapter call."""
    return {"host": host, "owner": "estate", "call": call}


def estate_esql(query: str, call: int = 1) -> dict:
    """The fake estate's `esql` answer when it is the run's `call`-th adapter call."""
    return {"query": query, "call": call}


# 1. structural coverage: every granted verb, and no route to a bare body


def test_every_granted_verb_decides_granted_through_the_world_registry(tmp_path):
    reg = world_registry(REAL_ADAPTERS, _gather_grant(), tmp_path / SERVED_FILE)

    refused = [
        (system, verb, reg.decide(system, verb).outcome)
        for system, verb, _ in _gather_grant().entries
        if reg.decide(system, verb).outcome != GRANTED
    ]

    assert refused == []


def test_no_route_to_a_verb_hands_back_a_bare_adapter_body(tmp_path):
    reg = world_registry(REAL_ADAPTERS, _gather_grant(), tmp_path / SERVED_FILE)
    plain = ModuleVerbRegistry(read_roster(REAL_ADAPTERS), _gather_grant())

    bare = []
    for system, verb, _ in _gather_grant().entries:
        real = plain.verbs(system)[verb]
        for route, fn in (("verbs", reg.verbs(system)[verb]), ("decide", reg.decide(system, verb).fn)):
            if fn is real or getattr(fn, "__wrapped__", None) is not real:
                bare.append((system, verb, route))

    assert bare == []


def test_a_wrapper_only_param_is_still_reserved_through_the_wrapper(tmp_path):
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
    class RegistryShaped:
        def systems(self):
            return ("elastic",)

        def verbs(self, system):
            return {}

        def decide(self, system, verb):
            return None

    with pytest.raises(TypeError, match="real VerbRegistry"):
        _built(logger, RegistryShaped())


# 3. every served response is recorded with a decision

def test_serving_through_the_wrapper_writes_a_row_carrying_the_decision(tmp_path):
    ledger_path = tmp_path / SERVED_FILE
    ctx = run_ctx(tmp_path)
    reg = world_registry(
        fake_estate(tmp_path), FAKE_GRANT, ledger_path, world=World("w1"),
        **control_oracle(estate_host("canary-1")),
    )

    payload = reg.verbs("cmdb")["get-host"](ctx, host="canary-1")

    world_rows = [r for r in served_rows(ledger_path) if r["world_id"] == "w1"]
    assert len(world_rows) == 1
    row = world_rows[0]
    assert (row["system"], row["verb"], row["params"]) == ("cmdb", "get-host", {"host": "canary-1"})
    assert row["source"] == PASSTHROUGH
    assert json.loads(row["payload_text"]) == payload


def test_the_ledger_refuses_an_invented_decision_at_its_own_door(tmp_path):
    ledger = fresh_ledger(tmp_path / SERVED_FILE)
    call = ServedCall(
        system="cmdb", verb="get-host", params={"host": "canary-1"},
        payload_text="{}", source="invented", world_id="w1",
    )

    with pytest.raises(LedgerError, match="invented"):
        ledger.record(call)

    assert served_rows(tmp_path / SERVED_FILE) == []


def test_an_estate_fault_still_leaves_a_row(tmp_path):
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
    ledger_path = tmp_path / SERVED_FILE
    ctx = run_ctx(tmp_path)
    reg = world_registry(fake_estate(tmp_path), FAKE_GRANT, ledger_path, world=World("w1"))
    asked = {"host": "web-01"}

    # `elastic.get-host` is DECLARED by the fake estate and absent from FAKE_GRANT: a denial.
    listing = reg.decide("elastic", "get-host")
    assert listing.outcome == DENIED
    assert served_rows(ledger_path) == [], "a LISTING of a withheld verb left a row"

    granted = reg.authorize_call("elastic", "esql", {"query": "FROM logs\n| LIMIT 1"})
    assert granted.outcome == GRANTED
    assert served_rows(ledger_path) == [], "a granted DECISION left a row (its row is the served one)"

    decision = reg.authorize_call("elastic", "get-host", asked)
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
    adapters = fake_estate(tmp_path)
    (adapters / "elastic_adapter.py").write_text(
        _RECORDING_ADAPTER + "\nraise ImportError('the elastic client is not installed')\n",
        encoding="utf-8")
    ledger_path = tmp_path / SERVED_FILE
    reg = world_registry(adapters, FAKE_GRANT, ledger_path, world=World("w1"))

    params = {"query": "FROM logs"}
    authorization = reg.authorize_call("elastic", "esql", params)
    assert authorization.outcome == GRANTED
    assert authorization.fn is None
    assert served_rows(ledger_path) == []
    with pytest.raises(ImportError, match="not installed"):
        reg.resolve_call("elastic", "esql", params)

    rows = served_rows(ledger_path)
    assert [r["source"] for r in rows] == [FAULT], f"an adapter that could not load left {rows}"
    assert "not installed" in rows[0]["payload_text"]
    assert rows[0]["world_id"] == "w1"


def test_the_verb_table_handed_back_is_the_callers_to_edit(tmp_path):
    reg = world_registry(fake_estate(tmp_path), FAKE_GRANT, tmp_path / SERVED_FILE)
    served = reg.verbs("cmdb")["get-host"]

    reg.verbs("cmdb")["get-host"] = "not a verb at all"

    assert reg.verbs("cmdb")["get-host"] is served
    assert reg.decide("cmdb", "get-host").fn is served


def test_the_reserved_base_world_id_cannot_name_the_family_capture(tmp_path):
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
    ledger_path = tmp_path / SERVED_FILE
    ctx = run_ctx(tmp_path)
    reg = world_registry(
        fake_estate(tmp_path), FAKE_GRANT, ledger_path, world=World("w1"),
        **control_oracle(estate_host("canary-1")),
    )
    served = reg.verbs("cmdb")["get-host"]

    first = served(ctx, host="canary-1")
    second = served(ctx, host="canary-1")

    assert first == second
    assert len(adapter_calls(ctx, "get-host")) == 1
    assert [r["source"] for r in served_rows(ledger_path)] == [PASSTHROUGH, PASSTHROUGH]


def test_two_siblings_read_one_base_recording(tmp_path):
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
    ledger_path = tmp_path / SERVED_FILE
    adapters, ctx = fake_estate(tmp_path), run_ctx(tmp_path)
    first = build_registry(read_roster(adapters), FAKE_GRANT, world=World("a"), ledger=fresh_ledger(ledger_path), as_of=AS_OF,
                           **control_oracle(estate_host("canary-1")))
    from_a = first.verbs("cmdb")["get-host"](ctx, host="canary-1")

    reopened = build_registry(
        read_roster(adapters), FAKE_GRANT, world=World("a"), ledger=fresh_ledger(ledger_path), as_of=AS_OF,
        **control_oracle(estate_host("canary-1")))
    again = reopened.verbs("cmdb")["get-host"](ctx, host="canary-1")

    assert from_a == again
    assert len(adapter_calls(ctx, "get-host")) == 1

    other = build_registry(
        read_roster(adapters), FAKE_GRANT, world=World("b"), ledger=fresh_ledger(ledger_path), as_of=AS_OF,
        **control_oracle(estate_host("canary-1", call=2)))
    other.verbs("cmdb")["get-host"](ctx, host="canary-1")

    assert len(adapter_calls(ctx, "get-host")) == 2, "one world's live read served another"
    assert (ledger_path.parent / LAYOUT.oracle_dir("a")).is_dir()


def test_two_spellings_of_one_question_are_one_key(tmp_path):
    ledger_path = tmp_path / SERVED_FILE
    ctx = run_ctx(tmp_path)
    body = "FROM logs-* | LIMIT 5"
    reg = world_registry(
        fake_estate(tmp_path), FAKE_GRANT, ledger_path, world=World("w1"),
        **control_oracle(estate_esql(body)),
    )
    served = reg.verbs("elastic")["esql"]

    first = served(ctx, query=body, limit=5)
    second = served(ctx, limit=5, query=body)

    assert request_key("elastic", "esql", {"query": body, "limit": 5}) \
        == request_key("elastic", "esql", {"limit": 5, "query": body})
    assert first == second
    assert len(adapter_calls(ctx, "esql")) == 1


# 5. a failure keeps its row, and a world with no facts is served its base

def test_a_ledger_write_failure_ends_the_run_and_keeps_the_failure_it_records(tmp_path):
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

    with pytest.raises(run_end.CallRecordWriteFailed) as caught:
        reg.verbs("cmdb")["get-host"](run_ctx(tmp_path), host="canary-1")

    assert caught.value.record == run_end.TRUNCATED_BY_SERVED_LEDGER, caught.value
    assert "cmdb.get-host" in str(caught.value), "the refusal does not name the call"
    write_failure = caught.value.__cause__
    assert isinstance(write_failure, OSError), write_failure
    system_error = write_failure.__context__
    assert isinstance(system_error, RuntimeError), (
        "the system's own failure was displaced from the chain by the ledger's")
    assert "cmdb is down" in str(system_error), system_error


def test_a_world_may_not_answer_to_the_family_tiers_key(tmp_path):
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
    ledger_path = tmp_path / SERVED_FILE
    ctx = run_ctx(tmp_path)
    body = "FROM logs-system.auth-*\n| LIMIT 5"

    class ControlWorld:
        world_id = "base"
        facts = ()

    reg = world_registry(
        fake_estate(tmp_path), FAKE_GRANT, ledger_path, world=ControlWorld(),
        **control_oracle(estate_esql(body)),
    )
    reg.verbs("elastic")["esql"](ctx, query=body)

    assert [c["params"]["query"] for c in adapter_calls(ctx, "esql")] == [body]
    assert [(r["world_id"], r["source"]) for r in served_rows(ledger_path)] \
        == [("base", PASSTHROUGH)], "the control world's row must not share the family's slot"
    assert EpisodePaths(tmp_path / "ep").served_base.read_text(encoding="utf-8") == ""


def test_an_unstaged_call_records_one_identity_not_two(tmp_path):
    ledger_path = tmp_path / SERVED_FILE
    adapters, ctx = fake_estate(tmp_path), run_ctx(tmp_path)
    reg = build_registry(
        read_roster(adapters), FAKE_GRANT, world=World("A"), ledger=fresh_ledger(ledger_path), as_of=AS_OF,
        **control_oracle(estate_host("canary-1")))

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
