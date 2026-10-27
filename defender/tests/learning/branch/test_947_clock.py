from __future__ import annotations

from defender.tests.support.learning.branch import _triplet_947 as T

import re

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
from defender.tests.learning.oracle.live_contracts._spec1224 import build_registry  # noqa: E402
from defender.systems.verbs import read_roster  # noqa: E402
from defender.records._episode_handle import Episode  # noqa: E402
from defender.records._episode_paths import BASE_FILENAME, SERVED_DIRNAME  # noqa: E402
from defender.learning.branch.ledger import (  # noqa: E402
    PASSTHROUGH,
    Ledger,
)
from defender.systems.verb_grant import VerbGrant  # noqa: E402
from defender.systems.verbs import VerbContext  # noqa: E402
from defender.tests.support.runtime.state import _1255_clock as C
from defender.tests.support.tenancy import _tenants1106
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S  # noqa: E402
from defender.integrations import elastic_adapter, host_state_adapter  # noqa: E402
from defender.tests.support.learning.branch._branch_947 import (  # noqa: E402
    branch_mod,
    spec_at,
)

T0 = dt.datetime(2026, 5, 25, 15, 30, 45, tzinfo=dt.UTC)
T0_Z = "2026-05-25T15:30:45Z"

REAL_ADAPTERS = PATHS.adapters_dir

#: #1255 C4: the branch point `recorded_branch` forks at arrives at this reading of its
#: source's run clock (`_1255_clock.record_source`'s script: 10 s, then 600 s of MAIN work).
R = C.BRANCH_READING


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

_CLOCK_ADAPTER = '''\
"""Verb bodies that record what the seam put on their ctx."""
from __future__ import annotations

from defender.tests.support.learning.branch import _triplet_947 as T

import json
from pathlib import Path

from defender.kit.verbs import VerbContext, verb

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
        self.label = world_id
        self.world_id = T.fixture_world_id(world_id)
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


CLOCK_WORLD_ID = T.fixture_world_id("w1")


def primed_ledger(tmp_path: Path, *, world_id: str = CLOCK_WORLD_ID) -> Ledger:
    """A ledger over an explicit world UUID, with the primed capture beside it that #947 makes REQUIRED."""
    served = tmp_path / SERVED_DIRNAME
    served.mkdir(parents=True, exist_ok=True)
    base = served / BASE_FILENAME
    base.touch()
    episode = _HELD[-1].enter_context(Episode.open(tmp_path))
    return Ledger.for_world(episode, world_id)


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


def pass_through() -> dict[str, Any]:
    """`build_registry`'s oracle-side seam (`oracle=`, `verifier=`: models) for a world with no
    facts. Under #1255 D3 (rev 4) such a world — a control world, like every `World` stub here —
    answers each call through one oracle turn, so a registry built over production's lazy oracle
    model would reach a provider. This double serves the base answer UNCHANGED (the oracle's own
    `BASE_HANDLE` spelling, with an empty claim) and the verifier passes it; by D5 (rev 5) a
    control-world turn that leaves the base unchanged is still recorded `passthrough`. It
    decides nothing a test here asserts: what is served stays the real base."""
    from defender.tests.learning.oracle.live_contracts import _spec1224 as S

    base = S.sym("learning.branch.estate.oracle", "BASE_HANDLE")
    return {"oracle": S.oracle(then=S.submit(base, S.EMPTY_CLAIM)).model,
            "verifier": S.passing_verifier().model}


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


def test_a_registry_served_host_state_capture_is_never_stamped_with_the_cut_off(tmp_path):
    ctx = docker_ctx(tmp_path)
    reg = build_registry(read_roster(REAL_ADAPTERS), _gather_grant(), world=World("w1"),
                        ledger=primed_ledger(tmp_path), as_of=T0, **pass_through())
    before = _clock.z_seconds(dt.datetime.now(dt.UTC))

    payload = reg.verbs("host-state")["proc-tree"](ctx, host="web-1")

    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", str(payload.get("captured_at"))), (
        f"the served capture carries no `Z` stamp at all, so nothing below is observed: {payload}")
    assert payload["captured_at"] != T0_Z, (
        "the served capture is stamped with the world's cut-off T0 — a visible time frozen at "
        "the fork while every other time the model sees advances (#1255)")
    assert before <= payload["captured_at"] <= _clock.z_seconds(dt.datetime.now(dt.UTC)), (
        "a capture served outside any run is not stamped with the wall clock (C4)")
    assert json.loads(served_rows(reg.ledger)[-1]["payload_text"])["captured_at"] == (
        payload["captured_at"]), "the ledger recorded a different moment from the one served"


def test_the_clock_rides_every_served_call_on_every_system(tmp_path):
    """Every served call reaches its adapter body with `ctx.as_of` set, whichever system it addresses."""
    ctx = docker_ctx(tmp_path)
    reg = build_registry(read_roster(fake_estate(tmp_path)), FAKE_GRANT,
                        world=World("w1", ("elastic",)), ledger=primed_ledger(tmp_path),
                        as_of=T0, **pass_through())

    reg.verbs("elastic")["esql"](ctx, query="FROM logs-nginx.access-*\n| LIMIT 5")
    reg.verbs("cmdb")["get-host"](ctx, host="canary-1")

    assert [(c["verb"], c["as_of"]) for c in adapter_calls(ctx)] == [
        ("esql", T0.isoformat()),
        ("get-host", T0.isoformat()),
    ]


def test_the_clock_never_perturbs_the_params_a_call_records(tmp_path):
    ctx = docker_ctx(tmp_path)
    reg = build_registry(read_roster(fake_estate(tmp_path)), FAKE_GRANT, world=World("A", ("cmdb",)),
                        ledger=primed_ledger(tmp_path, world_id=T.fixture_world_id("A")), as_of=T0, **pass_through())

    reg.verbs("cmdb")["get-host"](ctx, host="canary-1")

    own = [r for r in served_rows(reg.ledger) if r["world_id"] == T.fixture_world_id("A")]
    assert len(own) == 1, f"one served call, one world row; got {own}"
    assert "asked_params" not in own[0], (
        f"an unstaged call recorded a second identity: {own[0]}")
    assert own[0]["params"] == {"host": "canary-1"}
    assert own[0]["source"] == PASSTHROUGH


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
                        ledger=primed_ledger(tmp_path), as_of=T0, **pass_through())

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

STAMPING_VERBS = [
    ("container-inspect", {"container_id": "abc123def456"}),
    ("proc-tree", {"host": "web-1"}),
    ("passwd", {"host": "web-1"}),
    ("authorized-keys", {"host": "web-1"}),
    ("fim-checksum", {"host": "web-1", "path": "/etc/hosts"}),
    ("package-list", {"host": "web-1"}),
]


@pytest.mark.parametrize(("verb", "params"), STAMPING_VERBS)
def test_no_host_state_capture_is_stamped_with_the_cut_off(tmp_path, verb, params):
    ctx = docker_ctx(tmp_path, as_of=T0)
    before = _clock.z_seconds(dt.datetime.now(dt.UTC))

    payload = host_state_adapter.VERBS[verb](ctx, **params)

    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", str(payload.get("captured_at"))), (
        f"{verb} carries no `Z` capture stamp: {payload}")
    assert payload["captured_at"] != T0_Z, (
        f"{verb}'s capture is stamped with the world's cut-off T0 (#1255: the run clock stamps)")
    assert before <= payload["captured_at"] <= _clock.z_seconds(dt.datetime.now(dt.UTC)), (
        f"{verb}'s capture outside any run is not stamped with the wall clock (C4)")


@pytest.mark.parametrize(("verb", "params"), STAMPING_VERBS)
def test_an_ordinary_run_still_stamps_the_wall_clock(tmp_path, verb, params):
    ctx = docker_ctx(tmp_path, as_of=None)
    before = _clock.z_seconds(dt.datetime.now(dt.UTC))

    payload = host_state_adapter.VERBS[verb](ctx, **params)

    assert before <= payload["captured_at"] <= _clock.z_seconds(dt.datetime.now(dt.UTC))


def test_the_health_check_stamps_nothing_and_stays_that_way(tmp_path):
    stamped = host_state_adapter.VERBS["health-check"](docker_ctx(tmp_path, as_of=T0))
    plain = host_state_adapter.VERBS["health-check"](docker_ctx(tmp_path, as_of=None))

    assert "captured_at" not in stamped
    assert "captured_at" not in plain


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


def test_t0_is_the_snapshots_run_clock_reading_at_each_branch_response(recorded_branch):
    from defender.learning.branch import cli

    _store, run_dir, l2_response, source = recorded_branch
    l1_response = C.branch_response(run_dir, tool="read_file", arg_suffix=f"/{C.LESSONS[0]}.md")

    early = cli.branch_point_clock(source, l1_response)
    late = cli.branch_point_clock(source, l2_response)

    assert (early, late) == (C.FIRST_READ_READING, C.BRANCH_READING), (
        f"T0 is not the snapshot's run-clock reading at each branch response: early={early} "
        f"(expected {C.FIRST_READ_READING}), late={late} (expected {C.BRANCH_READING})")
    assert late.utcoffset() == dt.timedelta(0), f"T0 is not aware UTC: {late!r}"
    framework = C.source_message_times(run_dir)
    assert framework, "the source's messages carry no timestamps; the check below is empty"
    assert not {early, late} & set(framework), (
        "T0 is a framework message timestamp (the wall clock), not the run clock's reading")


def test_the_branch_spec_carries_the_moment_it_forks_at(tmp_path):
    """`as_of` is a REQUIRED coordinate of a `BranchSpec`, not an optional one."""
    branch = branch_mod()
    names = [f.name for f in dataclasses.fields(branch.BranchSpec)]
    as_of = next(f for f in dataclasses.fields(branch.BranchSpec) if f.name == "as_of")

    # #1255 (D1): the continuation prompt is no coordinate of a branch — its removal is
    # slice A's demand (`test_920_branch_seam`); this arm keeps the two that remain in place.
    assert names[:2] == ["source_run_dir", "branch_message_id"], (
        f"the two coordinates moved: {names}")
    assert as_of.default is dataclasses.MISSING, "a resume can be spelled without a moment"
    assert as_of.default_factory is dataclasses.MISSING, (
        "the moment defaults to something the caller never chose — most likely `now`, which "
        "is the wall clock this batch exists to take out of a branched run")


@pytest.fixture
def recorded_branch(tmp_path, monkeypatch):
    """A branch point #1255 admits: a source RECORDED through `run.main` (so it carries what a
    fork needs, N4) and its tool-calling MAIN response (D1), with the source's store held open
    for the test. `_branch_947.legal_source` writes its turns straight into a store and branches
    at a tool RETURN — after #1255 it is a pre-change source that every launch refuses, so a
    positive arm over it would go red for N4's reason instead of this file's.

    Yields `(store, source run folder, branch message id, opened source run)`."""
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    _tenant_id, run_dir = C.record_source(tmp_path)
    source = C.opened_source(run_dir)
    branch_id = C.branch_response(run_dir, tool="read_file", arg_suffix=f"/{C.LESSONS[1]}.md")
    store = branch_mod().source_store_if_any(run_dir, source_run=source)
    assert store is not None, "the recorded source left no session store"
    try:
        yield store, run_dir, branch_id, source
    finally:
        store.close()


def test_a_spec_whose_clock_disagrees_with_its_branch_point_is_refused(recorded_branch):
    branch = branch_mod()
    store, run_dir, branch_id, source = recorded_branch
    legal = spec_at(store, run_dir, branch_id, as_of=R)

    assert branch.validate(store, legal, source_run=source) is None, (
        "the spec at the snapshot's run-clock reading was refused, so the refusal below pins "
        "nothing")

    for wrong in (dt.timedelta(seconds=1), dt.timedelta(seconds=-1), dt.timedelta(hours=3)):
        with pytest.raises(branch.BranchError):
            branch.validate(store, dataclasses.replace(legal, as_of=legal.as_of + wrong),
                            source_run=source)
    framework = C.source_message_times(run_dir)
    assert framework, "the source's messages carry no timestamps; the check below is empty"
    for wall in framework:
        with pytest.raises(branch.BranchError):
            branch.validate(store, dataclasses.replace(legal, as_of=wall), source_run=source)


@pytest.mark.parametrize("as_of", [
    None,
    _clock.z_seconds(R),
    R.replace(tzinfo=None),
    R.astimezone(dt.timezone(dt.timedelta(hours=2))),
], ids=["none", "a-string", "naive", "plus-two-hours"])
def test_a_spec_whose_clock_is_not_aware_utc_is_refused(recorded_branch, as_of):
    branch = branch_mod()
    store, run_dir, branch_id, source = recorded_branch

    assert branch.validate(store, spec_at(store, run_dir, branch_id, as_of=R),
                           source_run=source) is None, (
        "the spec at the snapshot's run-clock reading was refused, so the refusal below pins "
        "nothing")
    with pytest.raises(branch.BranchError):
        branch.validate(store, spec_at(store, run_dir, branch_id, as_of=as_of), source_run=source)
