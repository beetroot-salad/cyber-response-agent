"""#947 Part A — the bound clock"""
from __future__ import annotations

from defender.tests._spec1077 import fixture_run as _run_handle_1165

import contextlib
import dataclasses
import datetime as dt
import json
import sys
import time
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender import _clock  # noqa: E402
from defender._io import read_jsonl_rows  # noqa: E402
from defender._paths import PATHS  # noqa: E402
from defender.learning.branch.estate.registry import EstateError  # noqa: E402
from defender.tests.live_oracle_1224._spec1224 import build_registry  # noqa: E402
from defender.runtime.verbs import read_roster  # noqa: E402
from defender._episode_handle import Episode  # noqa: E402
from defender._episode_paths import BASE_FILENAME, SERVED_DIRNAME  # noqa: E402
from defender.learning.branch.ledger import (  # noqa: E402
    PASSTHROUGH,
    Ledger,
)
from defender.runtime.verb_grant import VerbGrant  # noqa: E402
from defender.runtime.verbs import VerbContext  # noqa: E402
from defender.tests import _tenants1106  # noqa: E402
from defender.tests.tenant_1107_settings import _spec1107 as S  # noqa: E402
from defender.scripts.adapters import elastic_adapter, host_state_adapter  # noqa: E402
from defender.tests._branch_947 import (  # noqa: E402
    GOLDEN_INVESTIGATION,
    branch_mod,
    legal_source,
    spec_at,
)
from defender.tests._session_store_705 import (  # noqa: E402
    make_store,
    runs_base,
    store_mod,
)

#: The branch point's own moment. Far enough from `now` that a stamp taken from the wall clock
#: cannot coincidentally equal it — which is what makes "the payload carries T0" an assertion
#: rather than a hope.
T0 = dt.datetime(2026, 5, 25, 15, 30, 45, tzinfo=dt.UTC)
T0_Z = "2026-05-25T15:30:45Z"

REAL_ADAPTERS = PATHS.adapters_dir


def _gather_grant() -> VerbGrant:
    """The committed playground tenant's gather grant (#1106: grants are per run, projected from
    the run's tenant's table — there is no process-level `GATHER_DEF.verb_grant` any more)."""
    return _tenants1106.fixture_grants().gather

#: What the fake `docker` records, under the run dir the test reads.
DOCKER_LOG = "docker-calls.jsonl"

#: The elastic config a driven search resolves through. `logs-*` is its own configured pattern,
#: so `confine_index` admits it by reach and the arms below are about the WINDOW alone.
EVENTS_INDEX = "logs-*"
ALERTS_INDEX = ".alerts-security.alerts-*"


# the injected estate: a `docker` on the run's own PATH, and a fake adapters dir

#: A `docker` that answers the two transport shapes this file drives and records every argv it
#: was handed. The shebang is the RUNNING interpreter's absolute path, deliberately: the child's
#: PATH holds this directory alone, so a `/usr/bin/env python3` line would resolve nothing.
_DOCKER_SHIM = r'''
import json
import os
import sys

argv = sys.argv[1:]
with open(os.environ["DOCKER_CALL_LOG"], "a", encoding="utf-8") as fh:
    fh.write(json.dumps(argv) + "\n")

if "inspect" in argv:
    sys.stdout.write('"/canary-1"\t"nginx:1.25"\n')
elif "sh" in argv:
    # The curl lane: `docker exec -i <c> sh -c 'exec curl … "$@"' -- …`. `curl -w` writes the
    # status on its own trailing line and `split_status` recovers it with `rfind`, so the
    # status must be LAST with no newline after it.
    sys.stdout.write(json.dumps({"hits": {"total": {"value": 0}, "hits": []}}))
    sys.stdout.write("\n200")
elif "getent" in argv:
    sys.stdout.write("root:x:0:0:root:/root:/bin/bash\n")
elif "sha256sum" in argv:
    sys.stdout.write("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  /etc/hosts\n")
elif "dpkg-query" in argv:
    sys.stdout.write("openssh-server 1:8.9p1-3\n")
elif "cat" in argv:
    sys.stdout.write("root:x:0:0:root:/root:/bin/bash\n")
else:
    sys.stdout.write("  PID  PPID USER STAT ELAPSED COMMAND\n    1     0 root Ss 01:00 /sbin/init\n")
'''

#: The fake estate's verb bodies, recording the CLOCK and the WORLD their ctx carried. Written
#: to disk rather than patched in, because `ModuleVerbRegistry` parses this text before it
#: imports it — see the module docstring.
_CLOCK_ADAPTER = '''\
"""Verb bodies that record what the seam put on their ctx."""
from __future__ import annotations

import json
from pathlib import Path

from defender.runtime.verbs import VerbContext, verb

CALLS = "adapter-calls.jsonl"


def _record(ctx: VerbContext, name: str, params: dict) -> None:
    log = Path(ctx.run_dir) / CALLS
    log.parent.mkdir(parents=True, exist_ok=True)
    at = getattr(ctx, "as_of", None)
    with log.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "verb": name, "params": params,
            "as_of": None if at is None else at.isoformat(),
        }) + "\\n")


@verb(engine="esql", body_param="query")
def esql(ctx: VerbContext, *, query: str, limit: int = 5) -> dict:
    _record(ctx, "esql", {"query": query, "limit": limit})
    return {"query": query}


@verb()
def get_host(ctx: VerbContext, *, host: str) -> dict:
    _record(ctx, "get-host", {"host": host})
    return {"host": host, "owner": "estate"}


@verb()
def health_check(ctx: VerbContext) -> dict:
    _record(ctx, "health-check", {})
    return {"ok": True}


VERBS = {"esql": esql, "get-host": get_host, "health-check": health_check}
'''

#: The fake estate's grant: two systems, so the every-system arm has a pair to compare.
FAKE_GRANT = VerbGrant(role="gather", entries=(
    ("elastic", "esql", "r"), ("elastic", "health-check", "r"),
    ("cmdb", "get-host", "r"), ("cmdb", "health-check", "r"),
))


class World:
    """The world object the seam reads: an id, and the systems it declares it touches."""

    def __init__(self, world_id: str, touches: tuple[str, ...] = ()):
        self.world_id = world_id
        self.touches = touches


def fake_estate(tmp_path: Path) -> Path:
    adapters = tmp_path / "adapters"
    adapters.mkdir(parents=True, exist_ok=True)
    for name in ("elastic_adapter.py", "cmdb_adapter.py"):
        (adapters / name).write_text(_CLOCK_ADAPTER, encoding="utf-8")
    return adapters


#: The open `Episode` handles of the running test, closed when it ends (`_held_episodes`).
_HELD: list[contextlib.ExitStack] = []


@pytest.fixture(autouse=True)
def _held_episodes():
    """Scope every handle `primed_ledger` opens to the test that asked for it."""
    with contextlib.ExitStack() as stack:
        _HELD.append(stack)
        try:
            yield
        finally:
            _HELD.pop()


def primed_ledger(tmp_path: Path, name: str = "served.jsonl") -> Ledger:
    """A ledger over `name`, with the primed capture beside it that #947 makes REQUIRED."""
    served = tmp_path / SERVED_DIRNAME
    served.mkdir(parents=True, exist_ok=True)
    base = served / BASE_FILENAME
    base.touch()
    episode = _HELD[-1].enter_context(Episode.open(tmp_path))
    return Ledger.for_world(episode, name.removesuffix(".jsonl"))


def fake_docker(tmp_path: Path) -> Path:
    """A `docker` on a PATH of this test's own, and the run dir it logs under."""
    bindir = tmp_path / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    shim = bindir / "docker"
    shim.write_text(f"#!{sys.executable}\n{_DOCKER_SHIM}", encoding="utf-8")
    shim.chmod(0o755)
    return bindir


def docker_ctx(tmp_path: Path, *, as_of: dt.datetime | None = None,
               defender_dir: Path | None = None,
               tenant: Any = None) -> VerbContext:
    """A `VerbContext` whose env is the whole world the transports fork into."""
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    if tenant is None:
        tenant = _fixture_tenant(tmp_path)
    return VerbContext(
        defender_dir=defender_dir if defender_dir is not None else tmp_path / "defender",
        run_dir=run_dir,
        # #1107: the run's tenant record — a fixture tenant whose every system names the
        # docker context `spec-947`, unless a caller hands its own.
        tenant=tenant,
        env={
            "PATH": str(fake_docker(tmp_path)),
            "DOCKER_CALL_LOG": str(tmp_path / DOCKER_LOG),
        },
        as_of=as_of,
    )


def _fixture_tenant(tmp_path: Path) -> Any:
    """The record resolved from a tenant folder planted under `tmp_path`, whose host-state and
    elastic (this file's indices) config name the docker context `spec-947`."""
    root = tmp_path / "tenants"
    texts = S.config_texts("spec947", events_index=EVENTS_INDEX, alerts_index=ALERTS_INDEX)
    folder = S.plant(root, marker="spec947", configs=texts)
    S.set_key(folder, "host-state", "HOST_STATE_DOCKER_CONTEXT", "spec-947")
    S.set_key(folder, "elastic", "ELASTIC_DOCKER_CONTEXT", "spec-947")
    return S.resolve(root)


def elastic_ctx(tmp_path: Path, *, as_of: dt.datetime | None = None) -> VerbContext:
    """`docker_ctx`, over a tenant that carries the elastic config `load_config` refuses to run
    without."""
    return docker_ctx(tmp_path, as_of=as_of, defender_dir=tmp_path / "defender")


def docker_calls(tmp_path: Path) -> list[list[str]]:
    log = tmp_path / DOCKER_LOG
    if not log.is_file():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line]


def search_body(tmp_path: Path) -> dict:
    """The search body the LAST driven query actually put on the wire."""
    argv = docker_calls(tmp_path)[-1]
    return json.loads(argv[argv.index("-d") + 1])


def range_filter(body: dict) -> dict | None:
    """The `@timestamp` bounds this body carries, or `None` when it carries no range at all."""
    for entry in body["query"]["bool"]["filter"]:
        if "range" in entry:
            return entry["range"]["@timestamp"]
    return None


def adapter_calls(ctx: VerbContext) -> list[dict]:
    return read_jsonl_rows(Path(ctx.run_dir) / "adapter-calls.jsonl")


def served_rows(ledger: Ledger) -> list[dict]:
    return read_jsonl_rows(ledger.path)


# 1. the format

def test_the_z_spelling_drops_the_precision_it_cannot_carry():
    """`z_seconds` answers whole seconds with a trailing `Z`, and `Z_SECONDS` is that format."""
    assert _clock.z_seconds(dt.datetime(2026, 5, 25, 15, 30, 45, 987654, tzinfo=dt.UTC)) == T0_Z
    assert _clock.z_seconds(T0) == T0_Z
    assert dt.datetime.strptime(T0_Z, _clock.Z_SECONDS).replace(tzinfo=dt.UTC) == T0


def test_a_naive_moment_is_read_as_utc_and_not_as_local_time(tz_east_of_utc):
    """A naive input is UTC, the rule `parse_iso_utc` documents — never the host's zone."""
    naive = dt.datetime(2026, 5, 25, 15, 30, 45)

    assert _clock.z_seconds(naive) == T0_Z
    assert _clock.z_seconds(naive) != _clock.z_seconds(naive.astimezone()), (
        "the naive moment was read as local time — the stamp moves with the host's zone")


def test_an_offset_bearing_moment_is_converted_rather_than_relabelled():
    """An aware moment in another zone is CONVERTED to UTC before the `Z` is written."""
    berlin = dt.datetime(2026, 5, 25, 17, 30, 45, tzinfo=dt.timezone(dt.timedelta(hours=2)))

    assert _clock.z_seconds(berlin) == T0_Z


@pytest.fixture
def tz_east_of_utc(monkeypatch):
    """This process, five hours east of UTC."""
    monkeypatch.setenv("TZ", "XXX-5")
    time.tzset()
    try:
        assert dt.datetime(2026, 5, 25, 15, 30).astimezone().utcoffset() == dt.timedelta(hours=5), (
            "the host did not take the TZ override, so local and UTC are the same clock here")
        yield
    finally:
        monkeypatch.undo()
        time.tzset()


# 2. the seam: `VerbContext.as_of`, threaded unconditionally


def test_an_unstaged_host_state_call_reaches_the_adapter_carrying_the_runs_clock(tmp_path):
    """THE arm of this batch"""
    ctx = docker_ctx(tmp_path)
    reg = build_registry(read_roster(REAL_ADAPTERS), _gather_grant(), world=World("w1"),
                        ledger=primed_ledger(tmp_path), as_of=T0)

    payload = reg.verbs("host-state")["proc-tree"](ctx, host="web-1")

    assert payload["captured_at"] == T0_Z, (
        f"the served payload is stamped {payload['captured_at']!r}, not the branch point's own "
        "moment — two siblings of one branch would disagree here for neither world's reason")
    assert payload["captured_at"] != _clock.z_seconds(dt.datetime.now(dt.UTC)), (
        "the stamp is this afternoon's, so the fixture is not discriminating")
    assert json.loads(served_rows(reg.ledger)[-1]["payload_text"])["captured_at"] == T0_Z, (
        "the ledger recorded a different moment from the one the caller was served")


def test_the_clock_rides_every_served_call_on_every_system(tmp_path):
    """Every served call reaches its adapter body with `ctx.as_of` set, whichever system it addresses."""
    ctx = docker_ctx(tmp_path)
    reg = build_registry(read_roster(fake_estate(tmp_path)), FAKE_GRANT,
                        world=World("w1", ("elastic",)), ledger=primed_ledger(tmp_path),
                        as_of=T0)

    reg.verbs("elastic")["esql"](ctx, query="FROM logs-nginx.access-*\n| LIMIT 5")
    reg.verbs("cmdb")["get-host"](ctx, host="canary-1")

    assert [(c["verb"], c["as_of"]) for c in adapter_calls(ctx)] == [
        ("esql", T0.isoformat()),
        ("get-host", T0.isoformat()),
    ]


def test_a_context_that_cannot_carry_the_clock_is_served_anyway(tmp_path):
    """A ctx with no `as_of` FIELD is handed to the body untouched, not repaired and not raised on."""
    @dataclasses.dataclass(frozen=True)
    class ClocklessContext:
        """A ctx from before the clock existed: no `as_of` to replace."""

        defender_dir: Path
        run_dir: Path
        env: dict
        capture: object = None
        world_id: str | None = None

    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    reg = build_registry(read_roster(fake_estate(tmp_path)), FAKE_GRANT, world=World("w1"),
                        ledger=primed_ledger(tmp_path), as_of=T0)

    payload = reg.verbs("cmdb")["get-host"](
        ClocklessContext(defender_dir=tmp_path, run_dir=run_dir, env={}), host="canary-1")

    assert payload["host"] == "canary-1"
    # #1224: the live base read is kept in the world's oracle store, never as a ledger row (M16),
    # so the one row is the call served to the investigator.
    assert [r["source"] for r in served_rows(reg.ledger)] == [PASSTHROUGH]


@pytest.mark.parametrize("as_of", [
    None,
    "2026-05-25T15:30:45Z",
    1748187045,
    dt.datetime(2026, 5, 25, 15, 30, 45),
    dt.datetime(2026, 5, 25, 17, 30, 45, tzinfo=dt.timezone(dt.timedelta(hours=2))),
])
def test_a_registry_refuses_a_clock_that_cannot_honestly_spell_z(tmp_path, as_of):
    """A world registry is refused at construction unless its clock is an AWARE, ZERO-OFFSET datetime."""
    with pytest.raises(EstateError):
        build_registry(read_roster(fake_estate(tmp_path)), FAKE_GRANT, world=World("w1"),
                      ledger=primed_ledger(tmp_path), as_of=as_of)


def test_a_registry_will_not_serve_without_being_told_which_moment_it_serves(tmp_path):
    """`as_of` is REQUIRED and keyword-only"""
    with pytest.raises(TypeError):
        build_registry(read_roster(fake_estate(tmp_path)), FAKE_GRANT, world=World("w1"),
                      ledger=primed_ledger(tmp_path))


# 3. the stamps: host-state's `captured_at`, elastic's open window

#: The six verbs whose payload carries `captured_at`, with the arguments each needs. Named as
#: the VERB TABLE spells them, not as python functions, because the table is what the estate
#: serves and a verb renamed there is a verb the seam no longer reaches.
STAMPING_VERBS = [
    ("container-inspect", {"container_id": "abc123def456"}),
    ("proc-tree", {"host": "web-1"}),
    ("passwd", {"host": "web-1"}),
    ("authorized-keys", {"host": "web-1"}),
    ("fim-checksum", {"host": "web-1", "path": "/etc/hosts"}),
    ("package-list", {"host": "web-1"}),
]


@pytest.mark.parametrize(("verb", "params"), STAMPING_VERBS)
def test_every_host_state_capture_reads_the_runs_clock(tmp_path, verb, params):
    """All six stamping verbs take `captured_at` from `ctx.as_of` when the run names one."""
    ctx = docker_ctx(tmp_path, as_of=T0)

    payload = host_state_adapter.VERBS[verb](ctx, **params)

    assert payload["captured_at"] == T0_Z


@pytest.mark.parametrize("verb", ["query", "alerts"])
def test_an_unbounded_search_is_closed_at_the_runs_clock(tmp_path, verb):
    """A search naming NEITHER bound is bounded at T0 on the wire — and only at T0."""
    ctx = elastic_ctx(tmp_path, as_of=T0)

    getattr(elastic_adapter, verb)(ctx, native_query="event.action:ssh_login")

    assert range_filter(search_body(tmp_path)) == {"lte": T0_Z}, (
        "the unbounded search did not close at the branch point's own moment")


@pytest.mark.parametrize("verb", ["query", "alerts"])
def test_an_empty_string_end_is_closed_at_the_runs_clock(tmp_path, verb):
    """``end=""`` is the same open bound the body builder already treats as absent."""
    ctx = elastic_ctx(tmp_path, as_of=T0)

    getattr(elastic_adapter, verb)(ctx, native_query="event.action:ssh_login", end="")

    assert range_filter(search_body(tmp_path)) == {"lte": T0_Z}


@pytest.mark.parametrize(("start", "end", "expected"), [
    (None, "2026-06-01T00:00:00Z", {"lte": "2026-06-01T00:00:00Z"}),
    ("2026-05-01T00:00:00Z", None, {"gte": "2026-05-01T00:00:00Z", "lte": T0_Z}),
    ("2026-05-01T00:00:00Z", "2026-06-01T00:00:00Z",
     {"gte": "2026-05-01T00:00:00Z", "lte": "2026-06-01T00:00:00Z"}),
])
def test_a_search_that_names_its_own_end_is_never_rewritten(tmp_path, start, end, expected):
    """A PRESENT `end` survives untouched — including one that runs past T0 — and an absent one is filled beside whatever `start` the caller gave."""
    ctx = elastic_ctx(tmp_path, as_of=T0)

    elastic_adapter.query(ctx, native_query="event.action:ssh_login", start=start, end=end)

    assert range_filter(search_body(tmp_path)) == expected


@pytest.mark.parametrize("verb", ["query", "alerts"])
def test_a_branched_search_bounds_its_hits_at_the_cluster_and_keeps_its_window(tmp_path, verb):
    """A branched search carries the clock as a `post_filter`, beside a `query` window left as the caller spelled it (R-10=A) — so the cluster drops..."""
    ctx = elastic_ctx(tmp_path, as_of=T0)

    getattr(elastic_adapter, verb)(ctx, native_query="event.action:ssh_login",
                                   start="2026-05-01T00:00:00Z", end="2026-06-01T00:00:00Z")

    body = search_body(tmp_path)
    assert range_filter(body) == {"gte": "2026-05-01T00:00:00Z", "lte": "2026-06-01T00:00:00Z"}
    bounds = [c["range"]["@timestamp"] for c in body["post_filter"]["bool"]["should"]
              if "range" in c]
    assert bounds == [{"lte": T0_Z}]


def test_filling_the_window_does_not_edit_the_callers_own_arguments(tmp_path):
    """Two searches in a row through one context give the same window, so the fill went into a FRESH local rather than into anything the caller (or the..."""
    ctx = elastic_ctx(tmp_path, as_of=T0)

    elastic_adapter.query(ctx, native_query="a")
    first = range_filter(search_body(tmp_path))
    elastic_adapter.query(ctx, native_query="b", start="2026-05-01T00:00:00Z")
    second = range_filter(search_body(tmp_path))

    assert first == {"lte": T0_Z}
    assert second == {"gte": "2026-05-01T00:00:00Z", "lte": T0_Z}


# the ES|QL half of the window: a stage appended, never a predicate edited

#: The clause a bounded ES|QL query carries. `<=`, matching `_build_search_body`'s `lte` on the
#: parameter path — the two halves close the same window, so a document written at exactly the
#: branch point is inside both or the same instant is evidence on one lane and not the other.
BOUND = f'| WHERE @timestamp <= "{T0_Z}"'


def test_the_bound_lands_after_the_source_command_not_after_the_first_line(tmp_path):
    """A whole pipeline written on ONE line still takes the bound immediately after its source command."""
    out = elastic_adapter.bounded_esql(docker_ctx(tmp_path, as_of=T0),
                                       "FROM logs-zeek.ssh-* | LIMIT 1")

    assert out == f"FROM logs-zeek.ssh-*\n{BOUND}\n| LIMIT 1"


def test_the_source_commands_own_suffix_stays_attached_to_it(tmp_path):
    """A `METADATA` clause belongs to the source command, so the bound goes after it."""
    out = elastic_adapter.bounded_esql(docker_ctx(tmp_path, as_of=T0),
                                       "FROM logs-x-* METADATA _id | LIMIT 5")

    assert out == f"FROM logs-x-* METADATA _id\n{BOUND}\n| LIMIT 5"


def test_a_pipe_inside_a_quoted_name_is_not_a_stage_boundary(tmp_path):
    """A `|` inside a quoted index name is part of the NAME, not the end of the source command."""
    out = elastic_adapter.bounded_esql(docker_ctx(tmp_path, as_of=T0), 'FROM "logs|weird"')

    # By LINES, so the assertion names the stage boundary and nothing else: a query with no
    # downstream stage has no bytes after the clause to be exact about, and trailing whitespace
    # there is not what this arm is asking about.
    assert out.splitlines() == ['FROM "logs|weird"', BOUND]


def test_the_models_own_time_predicate_is_left_exactly_as_written(tmp_path):
    """A query that already bounds `@timestamp` keeps that clause BYTE-IDENTICAL, with the run's bound alongside it."""
    asked = ('FROM logs-system.auth-*\n'
             '| WHERE @timestamp >= "2026-05-01T00:00:00Z" AND @timestamp < "2026-06-01T00:00:00Z"\n'
             '| STATS events = COUNT(*) BY user = user.name')

    out = elastic_adapter.bounded_esql(docker_ctx(tmp_path, as_of=T0), asked)

    assert out == ('FROM logs-system.auth-*\n'
                   f'{BOUND}\n'
                   '| WHERE @timestamp >= "2026-05-01T00:00:00Z" AND @timestamp < "2026-06-01T00:00:00Z"\n'
                   '| STATS events = COUNT(*) BY user = user.name')
    assert asked.partition("\n")[2] in out, (
        "the model's own predicate was edited — the clock reads no predicate and writes none")


def test_the_bound_reaches_the_wire_and_stays_out_of_the_evidence(tmp_path):
    """The BOUNDED query is what Elasticsearch runs"""
    ctx = elastic_ctx(tmp_path, as_of=T0)
    asked = "FROM logs-zeek.ssh-*\n| LIMIT 5"

    payload = elastic_adapter.esql(ctx, query=asked)

    assert payload["query"] == asked, (
        f"the payload records {payload['query']!r} — a clause the model never wrote is now in "
        "the run's own record of the question it asked")
    assert search_body(tmp_path)["query"] == f"FROM logs-zeek.ssh-*\n{BOUND}\n| LIMIT 5", (
        "the query that reached the cluster carries no bound, so the episode reads the live "
        "tail and cannot be replayed")


def test_both_halves_of_the_window_include_the_branch_point_itself(tmp_path):
    """The ES|QL clause and the search body close the window INCLUSIVELY, both of them."""
    ctx = elastic_ctx(tmp_path, as_of=T0)

    clause = elastic_adapter.bounded_esql(ctx, "FROM logs-zeek.ssh-*")
    elastic_adapter.query(ctx, native_query="event.action:ssh_login")

    assert clause.splitlines()[-1] == f'| WHERE @timestamp <= "{T0_Z}"'
    assert range_filter(search_body(tmp_path)) == {"lte": T0_Z}


# 4. T0 itself: derived from the prefix, and pinned into the spec

def _stamped_turn(store, session_id, moment, *, text="a turn"):
    """One complete pair whose messages AND parts carry `moment`."""
    from pydantic_ai.messages import (
        ModelRequest, ModelResponse, ToolCallPart, ToolReturnPart,
    )
    store.append(session_id, [ModelResponse(
        parts=[ToolCallPart(tool_name="read_file", args={"path": "/tmp/alert.json"},
                            tool_call_id=text)],
        timestamp=moment)], agent_id="main")
    store.append(session_id, [ModelRequest(
        parts=[ToolReturnPart(tool_name="read_file", content="{}", tool_call_id=text,
                              timestamp=moment)],
        timestamp=moment)], agent_id="main")


def _timed_source(tmp_path, moments):
    """A run whose turns land at `moments`, in that order. Returns `(store, run_dir, path_ids)`."""
    ss = store_mod()
    store = make_store(tmp_path, case_id="case-clock")
    run_dir = runs_base(tmp_path) / "run-clock-001"
    run_dir.mkdir(parents=True, exist_ok=True)
    ss.write_case_pointer(_run_handle_1165(run_dir), case_id="case-clock", store_path=store.path)
    session_id = store.new_session(agent_id="main")
    for i, moment in enumerate(moments):
        _stamped_turn(store, session_id, moment, text=f"t{i}")
    return store, run_dir, ss.path_row_ids(store, session_id)


def test_t0_is_the_latest_moment_the_prefix_carries(tmp_path):
    """`branch_point_time` answers the MAXIMUM message timestamp in the prefix, truncated to whole seconds — and it is aware UTC."""
    branch = branch_mod()
    latest = dt.datetime(2026, 5, 25, 15, 31, 0, 654321, tzinfo=dt.UTC)
    store, run_dir, path_ids = _timed_source(tmp_path, [
        dt.datetime(2026, 5, 25, 15, 30, 0, tzinfo=dt.UTC),
        latest,
        dt.datetime(2026, 5, 25, 15, 30, 30, tzinfo=dt.UTC),
    ])

    derived = branch.branch_point_time(store, run_dir, path_ids[-1], source_run=_run_handle_1165(run_dir))

    assert derived == latest.replace(microsecond=0), (
        f"T0 is {derived}, not the prefix's own latest moment truncated to seconds")
    assert derived.utcoffset() == dt.timedelta(0), f"T0 is not aware UTC: {derived!r}"
    assert _clock.z_seconds(derived) == "2026-05-25T15:31:00Z"


def test_t0_ignores_everything_the_run_did_after_the_branch(tmp_path):
    """A branch point in the middle of a finished run derives the moment IT stood at, not the moment the run ended at."""
    branch = branch_mod()
    store, run_dir, path_ids = _timed_source(tmp_path, [
        dt.datetime(2026, 5, 25, 15, 30, 0, tzinfo=dt.UTC),
        dt.datetime(2026, 5, 25, 16, 40, 0, tzinfo=dt.UTC),
    ])

    early = branch.branch_point_time(store, run_dir, path_ids[1], source_run=_run_handle_1165(run_dir))
    late = branch.branch_point_time(store, run_dir, path_ids[-1], source_run=_run_handle_1165(run_dir))

    assert early == dt.datetime(2026, 5, 25, 15, 30, 0, tzinfo=dt.UTC)
    assert late == dt.datetime(2026, 5, 25, 16, 40, 0, tzinfo=dt.UTC)


def test_the_branch_spec_carries_the_moment_it_forks_at(tmp_path):
    """`as_of` is a REQUIRED coordinate of a `BranchSpec`, not an optional one."""
    branch = branch_mod()
    names = [f.name for f in dataclasses.fields(branch.BranchSpec)]
    as_of = next(f for f in dataclasses.fields(branch.BranchSpec) if f.name == "as_of")

    assert names[:3] == ["source_run_dir", "branch_message_id", "continuation_prompt"], (
        f"the three original coordinates moved: {names}")
    assert as_of.default is dataclasses.MISSING, "a resume can be spelled without a moment"
    assert as_of.default_factory is dataclasses.MISSING, (
        "the moment defaults to something the caller never chose — most likely `now`, which "
        "is the wall clock this batch exists to take out of a branched run")


def test_a_spec_whose_clock_disagrees_with_its_branch_point_is_refused(tmp_path):
    """`validate` refuses a spec whose `as_of` is not the moment the branch point derives."""
    branch = branch_mod()
    store, run_dir, _session_id, path_ids = legal_source(
        tmp_path, investigation=GOLDEN_INVESTIGATION.read_text(encoding="utf-8"))
    legal = spec_at(store, run_dir, path_ids[-1])

    assert branch.validate(store, legal, source_run=_run_handle_1165((legal).source_run_dir)) is None, (
        "the derived spec was refused, so the refusal below pins nothing")

    for wrong in (dt.timedelta(seconds=1), dt.timedelta(hours=3)):
        with pytest.raises(branch.BranchError):
            branch.validate(store, dataclasses.replace(legal, as_of=legal.as_of + wrong), source_run=_run_handle_1165((dataclasses.replace(legal, as_of=legal.as_of + wrong)).source_run_dir))


@pytest.mark.parametrize("as_of", [
    None,
    "2026-05-25T15:30:45Z",
    dt.datetime(2026, 5, 25, 15, 30, 45),
    dt.datetime(2026, 5, 25, 17, 30, 45, tzinfo=dt.timezone(dt.timedelta(hours=2))),
])
def test_a_spec_whose_clock_is_not_aware_utc_is_refused(tmp_path, as_of):
    """A spec's moment must be an aware, zero-offset datetime, refused as a `BranchError`."""
    branch = branch_mod()
    store, run_dir, _session_id, path_ids = legal_source(
        tmp_path, investigation=GOLDEN_INVESTIGATION.read_text(encoding="utf-8"))

    with pytest.raises(branch.BranchError):
        branch.validate(store, spec_at(store, run_dir, path_ids[-1], as_of=as_of), source_run=_run_handle_1165((spec_at(store, run_dir, path_ids[-1], as_of=as_of)).source_run_dir))
