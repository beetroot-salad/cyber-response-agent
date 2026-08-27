"""#947 Part A — the bound clock: what a served payload says about WHEN it was taken.

A branched episode has two consumers of a timestamp and neither may read the wall clock. Two
siblings forked from ONE branch point must not produce payloads that differ merely because
they executed at different moments — a `captured_at` that moved between them is a difference
belonging to neither world, and every reader downstream (`ΔO`, the judge, the visualizer)
counts it as one. And an episode has to be REPLAYABLE: re-running it next week must ask the
estate the same questions, which for an open-ended window means the same window.

So T0 — the branch point's own moment — is threaded as a value: onto `VerbContext.as_of`, from
there into the one adapter that mints a timestamp (`host-state`) and the one that mints a
window (`elastic`), and into `BranchSpec` so an episode records the moment it was forked at
rather than re-deriving it from a run that has since been read again.

WHAT THIS FILE OWNS
-------------------
1. **The format** (`_clock.z_seconds`) — the trailing-`Z`, whole-second spelling, and the two
   ways of getting a naive input wrong.
2. **The seam** — `VerbContext.as_of`, and that the estate registry threads it onto EVERY
   served call, staged or not. That is the arm the batch turns on: the world-id declaration
   fires only when staging moved the call, and a clock copied from it would reach the elastic
   verbs and no others, leaving the six host-state stamps live.
3. **The stamps** — the six `host-state` verbs that carry `captured_at`, the one that does not,
   and the elastic window whose ABSENT end is what an unbounded query resolves against.
4. **T0 itself** — `branch_point_time` over the prefix, and `validate`'s refusal of a spec that
   disagrees with it.

Hermetic, and with NO `monkeypatch.setattr`. The adapters are driven for real over a `docker`
planted on the RUN's own `PATH`: both transports fork with `env=dict(ctx.env)`
(`_stub_transport._child_env`) and `subprocess` resolves the program off THAT env
(`os.get_exec_path(env)`), so the run's context is already the injection seam and no module
attribute is swapped. The estate half runs verb bodies against a fake adapters DIRECTORY
written to `tmp_path`, for `test_920_estate_seam`'s reason: `ModuleVerbRegistry` cold-reads the
`VERBS = {...}` literal through the AST before importing, so a module-object stand-in never
reaches the check the grant is validated by.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import json
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender import _clock  # noqa: E402
from defender._io import read_jsonl_rows  # noqa: E402
from defender._paths import PATHS  # noqa: E402
from defender.learning.branch.estate.registry import EstateError, WorldRegistry  # noqa: E402
from defender.learning.branch.ledger import (  # noqa: E402
    BASE_FILENAME,
    PASSTHROUGH,
    SERVED_DIRNAME,
    STAGED,
    Ledger,
)
from defender.runtime import driver  # noqa: E402
from defender.runtime.verb_grant import VerbGrant  # noqa: E402
from defender.runtime.verbs import VerbContext  # noqa: E402
from defender.scripts.adapters import elastic_adapter, host_state_adapter  # noqa: E402
from defender.tests._branch_947 import (  # noqa: E402
    GOLDEN_INVESTIGATION,
    branch_mod,
    legal_source,
    spec_at,
)
from defender.tests.test_920_elastic_staging import (  # noqa: E402
    COMMITTED,
    ESQL_TEMPLATES,
    leading_source,
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
GATHER_GRANT = driver.GATHER_DEF.verb_grant

#: What the fake `docker` records, under the run dir the test reads.
DOCKER_LOG = "docker-calls.jsonl"

#: The elastic config a driven search resolves through. `logs-*` is its own configured pattern,
#: so `confine_index` admits it by reach and the arms below are about the WINDOW alone.
EVENTS_INDEX = "logs-*"
ALERTS_INDEX = ".alerts-security.alerts-*"


# --------------------------------------------------------------------------
# the injected estate: a `docker` on the run's own PATH, and a fake adapters dir
# --------------------------------------------------------------------------

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
            "verb": name, "params": params, "world_id": ctx.world_id,
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

#: The fake estate's grant: `elastic` is the one system with a stager, `cmdb` one of the six
#: without — the pair the staged/unstaged arm needs.
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


def primed_ledger(tmp_path: Path, name: str = "served.jsonl") -> Ledger:
    """A ledger over `name`, with the primed capture beside it that #947 makes REQUIRED.

    Empty, because these arms are not about the capture: what the base file has to be here is
    a FILE, which is the ordering guarantee `Ledger.__post_init__` enforces — the episode was
    primed before any sibling opened a ledger over it.
    """
    served = tmp_path / SERVED_DIRNAME
    served.mkdir(parents=True, exist_ok=True)
    base = served / BASE_FILENAME
    base.touch()
    return Ledger(served / name, base_path=base)


def fake_docker(tmp_path: Path) -> Path:
    """A `docker` on a PATH of this test's own, and the run dir it logs under."""
    bindir = tmp_path / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    shim = bindir / "docker"
    shim.write_text(f"#!{sys.executable}\n{_DOCKER_SHIM}", encoding="utf-8")
    shim.chmod(0o755)
    return bindir


def docker_ctx(tmp_path: Path, *, as_of: dt.datetime | None = None,
               defender_dir: Path | None = None) -> VerbContext:
    """A `VerbContext` whose env is the whole world the transports fork into.

    `as_of` DEFAULTS TO NONE, and that default is the production shape: `query_tool.py` builds
    `VerbContext(defender_dir=…, run_dir=…, env=…)` and names no moment, so the registry's own
    `_at` is the only thing in the tree that ever puts one there.

    WHICH MEANS AN ARM ABOUT THE INJECTION MUST NOT PASS ONE. Handed `as_of=T0` here, the
    adapter reads T0 off the context the TEST built and the registry's injection is pure
    redundancy — delete it outright and every such arm still passes. Only the arms driving an
    adapter DIRECTLY, with no registry between them, may name a moment here: for those, this
    parameter IS the seam under test."""
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    return VerbContext(
        defender_dir=defender_dir if defender_dir is not None else tmp_path / "defender",
        run_dir=run_dir,
        env={
            "PATH": str(fake_docker(tmp_path)),
            "DOCKER_CALL_LOG": str(tmp_path / DOCKER_LOG),
            "SOC_PLAYGROUND_DOCKER_CONTEXT": "spec-947",
        },
        as_of=as_of,
    )


def elastic_ctx(tmp_path: Path, *, as_of: dt.datetime | None = None) -> VerbContext:
    """`docker_ctx`, plus the config file `load_config` refuses to run without."""
    defender_dir = tmp_path / "defender"
    config = defender_dir / "knowledge" / "environment" / "systems" / "elastic" / "config.env"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(
        f"ELASTICSEARCH_URL=http://elasticsearch:9200\nKIBANA_URL=http://kibana:5601\n"
        f"ELASTIC_EVENTS_INDEX={EVENTS_INDEX}\nELASTIC_ALERTS_INDEX={ALERTS_INDEX}\n",
        encoding="utf-8")
    return docker_ctx(tmp_path, as_of=as_of, defender_dir=defender_dir)


def docker_calls(tmp_path: Path) -> list[list[str]]:
    log = tmp_path / DOCKER_LOG
    if not log.is_file():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line]


def search_body(tmp_path: Path) -> dict:
    """The search body the LAST driven query actually put on the wire.

    Read off the argv the transport forked with rather than off `_build_search_body`'s return,
    because the window is filled one frame above it: a fix applied to the wrong local would
    still satisfy a unit call and reach Elasticsearch unbounded.
    """
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


# ==========================================================================
# 1. the format
# ==========================================================================

def test_the_z_spelling_drops_the_precision_it_cannot_carry():
    """    `z_seconds` answers whole seconds with a trailing `Z`, and `Z_SECONDS` is that format.

    Truncation is not cosmetic: the string is compared against a stored T0 and against event
    timestamps, and a microsecond-bearing moment formats to something that no longer round-trips
    to itself — two spellings of one instant comparing unequal over a difference no reader can
    see."""
    assert _clock.z_seconds(dt.datetime(2026, 5, 25, 15, 30, 45, 987654, tzinfo=dt.UTC)) == T0_Z
    assert _clock.z_seconds(T0) == T0_Z
    assert dt.datetime.strptime(T0_Z, _clock.Z_SECONDS).replace(tzinfo=dt.UTC) == T0


def test_a_naive_moment_is_read_as_utc_and_not_as_local_time(tz_east_of_utc):
    """    A naive input is UTC, the rule `parse_iso_utc` documents — never the host's zone.

    THE failure a timestamp helper must not have. `astimezone()` on a naive datetime reads it as
    LOCAL and shifts the moment by the host's offset, silently, and differently on a developer's
    machine than in CI. The fixture puts this process five hours east of UTC precisely so the
    two implementations answer different strings; under `TZ=UTC` they agree and the arm would
    pin nothing, which is what the fixture's own assertion guards."""
    naive = dt.datetime(2026, 5, 25, 15, 30, 45)

    assert _clock.z_seconds(naive) == T0_Z
    assert _clock.z_seconds(naive) != _clock.z_seconds(naive.astimezone()), (
        "the naive moment was read as local time — the stamp moves with the host's zone")


def test_an_offset_bearing_moment_is_converted_rather_than_relabelled():
    """    An aware moment in another zone is CONVERTED to UTC before the `Z` is written.

    The complement of the arm above, and the reason the registry's own check is on
    `utcoffset()` rather than on `tzinfo is not None`: a `Z` written over a +02:00 wall clock
    is a string that lies about the instant it names, by exactly the offset."""
    berlin = dt.datetime(2026, 5, 25, 17, 30, 45, tzinfo=dt.timezone(dt.timedelta(hours=2)))

    assert _clock.z_seconds(berlin) == T0_Z


def test_the_z_spelling_and_now_iso_stay_two_different_strings():
    """    `z_seconds` did not become `now_iso`, and `now_iso` did not become `z_seconds`.

    They are pinned apart because both are load-bearing: `tests/test_env.py` pins `now_iso`'s
    `+00:00` tail, and the host-state payload contract is the `Z` one
    (`skills/host-state/SKILL.md` tells readers to cross-reference `captured_at` against event
    timestamps). One home for the format, two spellings, and nothing silently unifying them."""
    assert _clock.now_iso().endswith("+00:00")
    assert _clock.z_seconds(dt.datetime.now(dt.UTC)).endswith("Z")
    assert "+00:00" not in _clock.z_seconds(T0)


@pytest.fixture
def tz_east_of_utc(monkeypatch):
    """This process, five hours east of UTC.

    A POSIX `TZ` string rather than a zone name, so the fixture does not depend on a tz database
    being installed — under a missing one a zone name silently resolves to UTC and the arm it
    supports would pass against the very implementation it exists to catch.

    THE RESTORE IS IN A `finally`, and the guard assertion is INSIDE it. `monkeypatch`'s own
    finalizer puts `TZ` back but only `time.tzset()` clears libc's cached zone — so an assert
    raised in fixture SETUP, before the `yield`, meant pytest never resumed this generator and
    the whole worker ran five hours east of UTC for every later test, failing them somewhere
    else entirely. That is exactly the host this assertion exists to detect."""
    monkeypatch.setenv("TZ", "XXX-5")
    time.tzset()
    try:
        assert dt.datetime(2026, 5, 25, 15, 30).astimezone().utcoffset() == dt.timedelta(hours=5), (
            "the host did not take the TZ override, so local and UTC are the same clock here")
        yield
    finally:
        monkeypatch.undo()
        time.tzset()


# ==========================================================================
# 2. the seam: `VerbContext.as_of`, threaded unconditionally
# ==========================================================================

def test_the_clock_is_appended_after_the_world_id_it_rides_beside():
    """    `as_of` is the LAST field of `VerbContext`, and defaults to `None`.

    The position is the demand. Twenty-odd sites build a `VerbContext`, several of them
    positionally, and a field inserted before `world_id` rebinds every one of them silently —
    a run whose ctx claims a world it is not being served for, which `confine_index` then
    admits views for. Defaulted, because `None` is the ordinary run and the base world alike:
    both read the estate as it is now."""
    names = [f.name for f in dataclasses.fields(VerbContext)]

    assert names[-2:] == ["world_id", "as_of"], f"the clock did not land last: {names}"
    assert VerbContext(defender_dir=Path("/d"), run_dir=Path("/r"), env={}).as_of is None
    # Positionally, exactly as the pre-947 sites build one: the fifth argument is still the
    # world, not the clock.
    assert VerbContext(Path("/d"), Path("/r"), {}, None, "w1").world_id == "w1"


def test_an_unstaged_host_state_call_reaches_the_adapter_carrying_the_runs_clock(tmp_path):
    """    THE arm of this batch: a `host-state` read — a system NO world stages — comes back
    stamped with T0, through the real registry, the real grant and the real adapter body.

    The world-id declaration one column over fires only when staging MOVED the call (the second
    `registry._carrying` call site, and `test_920_estate_seam` pins that it stays scoped). A clock
    copied from that shape would reach the three elastic verbs and nothing else — leaving all
    six host-state stamps on the wall clock, which is where they are today and which is exactly
    what makes two siblings' `captured_at` differ for no world's reason.

    THE CONTEXT NAMES NO MOMENT. `docker_ctx` builds the production shape — `query_tool.py`
    hands the seam a `VerbContext` with no `as_of` — so the T0 in the payload can only have come
    from the registry putting it there. Handed a pre-seeded ctx, this arm passes with the
    injection deleted outright, which is the whole property gone with nothing red.

    The stamp is asserted against T0 AND against `now`: equal to the first and different from
    the second is what separates "the clock was threaded" from "the adapter stamped something
    that happened to be a timestamp"."""
    ctx = docker_ctx(tmp_path)
    reg = WorldRegistry(REAL_ADAPTERS, GATHER_GRANT, world=World("w1"),
                        ledger=primed_ledger(tmp_path), as_of=T0)

    payload = reg.verbs("host-state")["proc-tree"](ctx, host="web-1")

    assert payload["captured_at"] == T0_Z, (
        f"the served payload is stamped {payload['captured_at']!r}, not the branch point's own "
        "moment — two siblings of one branch would disagree here for neither world's reason")
    assert payload["captured_at"] != _clock.z_seconds(dt.datetime.now(dt.UTC)), (
        "the stamp is this afternoon's, so the fixture is not discriminating")
    assert json.loads(served_rows(reg.ledger)[-1]["payload_text"])["captured_at"] == T0_Z, (
        "the ledger recorded a different moment from the one the caller was served")


def test_the_clock_rides_every_served_call_staged_or_not(tmp_path):
    """    Both a staged call and an unstaged one reach their adapter body with `ctx.as_of` set —
    while only the staged one carries the world-id declaration.

    Two facts in one table because they are the pair that is easy to confuse: the DECLARATION
    is conditional by design (an untouched call addresses the corpus itself and has nothing to
    declare), and the CLOCK is not, because every payload a sibling records has to be
    reproducible whatever path it took to get there. An implementation that threaded the clock
    where the world is threaded would show up here as an unstaged call with `as_of: None`.

    The context arrives NAMING NO MOMENT, as `query_tool.py` builds it — so both `as_of` values
    below are the registry's own work and not the fixture's."""
    ctx = docker_ctx(tmp_path)
    reg = WorldRegistry(fake_estate(tmp_path), FAKE_GRANT,
                        world=World("w1", ("elastic",)), ledger=primed_ledger(tmp_path),
                        as_of=T0)

    reg.verbs("elastic")["esql"](ctx, query="FROM logs-nginx.access-*\n| LIMIT 5")
    reg.verbs("cmdb")["get-host"](ctx, host="canary-1")

    assert [(c["verb"], c["world_id"], c["as_of"]) for c in adapter_calls(ctx)] == [
        ("esql", "w1", T0.isoformat()),
        ("get-host", None, T0.isoformat()),
    ]


def test_the_clock_never_perturbs_the_params_a_call_records(tmp_path):
    """    Threading the clock does not make an unstaged call look staged: no `asked_params`
    column, and the row's `params` are the ones the model asked with.

    `registry.py` computes `asked = dict(params) if prepared != params else None`, and
    `asked is not None` is what fires the world-id declaration, the applier's `restore` and the
    `asked_params` column. A clock delivered through `params` — or a `prepare` that copied the
    dict on the way past — would make every call on every system report as rewritten: every row
    carrying a second identity identical to its first, the pairing column that exists to survive
    staging reduced to noise, and `restore` running over payloads nothing staged."""
    ctx = docker_ctx(tmp_path)
    reg = WorldRegistry(fake_estate(tmp_path), FAKE_GRANT, world=World("A", ("cmdb",)),
                        ledger=primed_ledger(tmp_path), as_of=T0)

    reg.verbs("cmdb")["get-host"](ctx, host="canary-1")

    own = [r for r in served_rows(reg.ledger) if r["world_id"] == "A"]
    assert len(own) == 1, f"one served call, one world row; got {own}"
    assert "asked_params" not in own[0], (
        f"an unstaged call recorded a second identity: {own[0]}")
    assert own[0]["params"] == {"host": "canary-1"}
    assert own[0]["source"] == PASSTHROUGH
    assert [c["world_id"] for c in adapter_calls(ctx)] == [None], (
        "the ctx declared a world for a call staging never moved")


def test_a_staged_call_still_records_the_two_identities_it_always_did(tmp_path):
    """    The positive control for the arm above: when staging DOES move a call, the row still
    carries both identities and reports `staged`.

    Without it, an implementation that simply stopped computing `asked` at all would satisfy
    "an unstaged call records one identity" and lose the cross-world pairing entirely."""
    ctx = docker_ctx(tmp_path)
    body = "FROM logs-system.auth-*\n| LIMIT 5"
    reg = WorldRegistry(fake_estate(tmp_path), FAKE_GRANT, world=World("a", ("elastic",)),
                        ledger=primed_ledger(tmp_path), as_of=T0)

    reg.verbs("elastic")["esql"](ctx, query=body)

    own = [r for r in served_rows(reg.ledger) if r["world_id"] == "a"]
    assert [r["source"] for r in own] == [STAGED]
    assert own[0]["asked_params"]["query"] == body
    assert own[0]["params"]["query"] != body


def test_a_context_that_cannot_carry_the_clock_is_served_anyway(tmp_path):
    """    A ctx with no `as_of` FIELD is handed to the body untouched, not repaired and not raised
    on.

    `dataclasses.replace` raises `TypeError` on a dataclass that simply does not declare the
    field, and a `TypeError` here is not an `AdapterFault` — the query tool files it as exit 2,
    an INFRA code the circuit breaker reads as the estate being DOWN for this sibling and up for
    its base. One outage on one side of the pair is the exact contamination the whole seam is
    built to exclude, and it would be caused by a test stub rather than by anything in the run.

    So the guard errs toward serving: a ctx that cannot carry the declaration keeps whatever it
    already had. Every real seam builds a `VerbContext`, which does carry it — the arm above is
    the live case."""
    from defender.learning.branch.ledger import BASE

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
    reg = WorldRegistry(fake_estate(tmp_path), FAKE_GRANT, world=World("w1"),
                        ledger=primed_ledger(tmp_path), as_of=T0)

    payload = reg.verbs("cmdb")["get-host"](
        ClocklessContext(defender_dir=tmp_path, run_dir=run_dir, env={}), host="canary-1")

    assert payload["host"] == "canary-1"
    assert [r["source"] for r in served_rows(reg.ledger)] == [BASE, PASSTHROUGH]


@pytest.mark.parametrize("as_of", [
    None,
    "2026-05-25T15:30:45Z",
    1748187045,
    dt.datetime(2026, 5, 25, 15, 30, 45),
    dt.datetime(2026, 5, 25, 17, 30, 45, tzinfo=dt.timezone(dt.timedelta(hours=2))),
])
def test_a_registry_refuses_a_clock_that_cannot_honestly_spell_z(tmp_path, as_of):
    """    A world registry is refused at construction unless its clock is an AWARE, ZERO-OFFSET
    datetime.

    Not `tzinfo is not None`: a +02:00 moment is aware and formats a `Z` string that lies about
    the instant by its offset — every `captured_at` in the episode two hours out, consistently,
    which is the shape no reader can spot. A string or an epoch int is the other door: both
    reach `strftime` as an `AttributeError` deep inside a verb body, where the query tool files
    it as exit 2 — an INFRA code the circuit breaker reads as the estate being down for this
    sibling and up for its base.

    Refused where the world arrives rather than per call, for `touches`'s reason: the answer is
    a property of the clock, not of a call, and per-call it reads as a sibling that asked
    nothing."""
    with pytest.raises(EstateError):
        WorldRegistry(fake_estate(tmp_path), FAKE_GRANT, world=World("w1"),
                      ledger=primed_ledger(tmp_path), as_of=as_of)


def test_a_zero_offset_zone_that_is_not_utc_itself_is_accepted(tmp_path):
    """    A tzinfo that is not `datetime.UTC` but answers a zero offset is a good clock.

    This is the live case, not a hypothetical: T0 is derived from message timestamps the store
    round-trips through pydantic, which hands them back carrying `TzInfo(0)` — equal to UTC as
    an instant, and not `datetime.UTC` as an object. A registry that checked identity would
    refuse every T0 the derivation actually produces."""
    class ZeroOffset(dt.tzinfo):
        def utcoffset(self, moment):
            return dt.timedelta(0)

        def dst(self, moment):
            return dt.timedelta(0)

        def tzname(self, moment):
            return "UTC"

    reg = WorldRegistry(fake_estate(tmp_path), FAKE_GRANT, world=World("w1"),
                        ledger=primed_ledger(tmp_path),
                        as_of=dt.datetime(2026, 5, 25, 15, 30, 45, tzinfo=ZeroOffset()))

    # `reg.as_of` DIRECTLY, no `hasattr` fallback: the fallback made this line a tautology —
    # `_clock.z_seconds(T0) == T0_Z` holds by construction, so a registry that stopped carrying
    # `as_of` at all still passed the one assertion about it carrying `as_of`. An
    # `AttributeError` is the correct failure for that.
    assert _clock.z_seconds(reg.as_of) == T0_Z


def test_a_registry_will_not_serve_without_being_told_which_moment_it_serves(tmp_path):
    """    `as_of` is REQUIRED and keyword-only: a registry built without one does not construct.

    Defaulting it to `datetime.now()` is the failure mode this rules out — every call site that
    forgot the clock would keep working and keep minting wall-clock stamps, which is precisely
    the state the batch is removing, with nothing red to show for it."""
    with pytest.raises(TypeError):
        WorldRegistry(fake_estate(tmp_path), FAKE_GRANT, world=World("w1"),
                      ledger=primed_ledger(tmp_path))


# ==========================================================================
# 3. the stamps: host-state's `captured_at`, elastic's open window
# ==========================================================================

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
    """    All six stamping verbs take `captured_at` from `ctx.as_of` when the run names one.

    Enumerated rather than spot-checked because they are six independent call sites of one
    helper, and one left on `datetime.now()` is one payload class whose bytes differ between
    siblings — invisible against the five that agree, and reported by ΔO as the world's doing.
    """
    ctx = docker_ctx(tmp_path, as_of=T0)

    payload = host_state_adapter.VERBS[verb](ctx, **params)

    assert payload["captured_at"] == T0_Z


@pytest.mark.parametrize(("verb", "params"), STAMPING_VERBS)
def test_an_ordinary_run_still_stamps_the_wall_clock(tmp_path, verb, params):
    """    With no clock on the ctx, the same six verbs stamp NOW — the unbranched run, unchanged.

    The positive control for the arm above, and the one that keeps `as_of=None` meaning "the
    ordinary run" rather than "no stamp at all": a host-state read genuinely IS a point-in-time
    capture, and its readers are told to cross-reference the value against event timestamps."""
    ctx = docker_ctx(tmp_path, as_of=None)
    before = _clock.z_seconds(dt.datetime.now(dt.UTC))

    payload = host_state_adapter.VERBS[verb](ctx, **params)

    assert before <= payload["captured_at"] <= _clock.z_seconds(dt.datetime.now(dt.UTC))


def test_the_health_check_stamps_nothing_and_stays_that_way(tmp_path):
    """    `health-check` carries no `captured_at`, clock or no clock.

    It reaches no corpus and observes no state, so a timestamp on it would be a payload-contract
    change for nothing — and it is the one verb of the seven where a stamp could not be checked
    against anything. Pinned so "six verbs stamp" cannot quietly become seven."""
    stamped = host_state_adapter.VERBS["health-check"](docker_ctx(tmp_path, as_of=T0))
    plain = host_state_adapter.VERBS["health-check"](docker_ctx(tmp_path, as_of=None))

    assert "captured_at" not in stamped
    assert "captured_at" not in plain


@pytest.mark.parametrize("verb", ["query", "alerts"])
def test_an_unbounded_search_is_closed_at_the_runs_clock(tmp_path, verb):
    """    A search naming NEITHER bound is bounded at T0 on the wire — and only at T0.

    Today a query with no window omits the range filter entirely, so it reads the LIVE TAIL of
    the index: run the same episode a week later and the same question returns a different
    corpus, which is replayability lost in the one place a branch cannot detect it. The end is
    filled and the start is left alone, because the past does not change: an invented `gte`
    would silently narrow a lead's read to a window the model never asked for.

    Asserted against the body the transport actually forked with, not against
    `_build_search_body`'s return: the fill belongs one frame above it, and a fix applied to
    the wrong local would satisfy a unit call and still reach Elasticsearch unbounded."""
    ctx = elastic_ctx(tmp_path, as_of=T0)

    getattr(elastic_adapter, verb)(ctx, native_query="event.action:ssh_login")

    assert range_filter(search_body(tmp_path)) == {"lte": T0_Z}, (
        "the unbounded search did not close at the branch point's own moment")


def test_an_ordinary_run_leaves_an_unbounded_search_unbounded(tmp_path):
    """    With no clock on the ctx, a bound-less search carries no range filter at all.

    Today's behaviour, pinned so the fill is scoped to a branched run. An unbranched
    investigation reading the live tail is correct — it IS asking about now — and a filled `lte`
    there would silently exclude documents indexed during the run."""
    ctx = elastic_ctx(tmp_path, as_of=None)

    elastic_adapter.query(ctx, native_query="event.action:ssh_login")

    assert range_filter(search_body(tmp_path)) is None


@pytest.mark.parametrize("verb", ["query", "alerts"])
def test_an_empty_string_end_is_closed_at_the_runs_clock(tmp_path, verb):
    """``end=""`` is the same open bound the body builder already treats as absent.

    It is valid for the declared string parameter. If the branch-clock fill instead tests only
    ``is None``, the empty string survives to the body builder, is omitted there as falsy, and
    the request reaches Elasticsearch with no ``lte`` filter — reading the live tail.
    """
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
    """    A PRESENT `end` survives untouched — including one that runs past T0 — and an absent one
    is filled beside whatever `start` the caller gave.

    The clamp is the tempting mistake and it is the wrong one twice over. A lead deliberately
    reading a window around a later event would have its question silently narrowed, and the
    narrowing is invisible in the payload: the envelope echoes the index, not the window. The
    fill is for the ABSENT end only, which is the one case where no one has said anything."""
    ctx = elastic_ctx(tmp_path, as_of=T0)

    elastic_adapter.query(ctx, native_query="event.action:ssh_login", start=start, end=end)

    assert range_filter(search_body(tmp_path)) == expected


def test_filling_the_window_does_not_edit_the_callers_own_arguments(tmp_path):
    """    Two searches in a row through one context give the same window, so the fill went into a
    FRESH local rather than into anything the caller (or the next call) can see.

    A fill written back into a shared structure is the classic version of this bug: the first
    unbounded query pins the window, and the second — a different lead, minutes later — inherits
    it and reports as though it had asked for it."""
    ctx = elastic_ctx(tmp_path, as_of=T0)

    elastic_adapter.query(ctx, native_query="a")
    first = range_filter(search_body(tmp_path))
    elastic_adapter.query(ctx, native_query="b", start="2026-05-01T00:00:00Z")
    second = range_filter(search_body(tmp_path))

    assert first == {"lte": T0_Z}
    assert second == {"gte": "2026-05-01T00:00:00Z", "lte": T0_Z}


# --------------------------------------------------------------------------
# the ES|QL half of the window: a stage appended, never a predicate edited
# --------------------------------------------------------------------------

#: The clause a bounded ES|QL query carries. `<=`, matching `_build_search_body`'s `lte` on the
#: parameter path — the two halves close the same window, so a document written at exactly the
#: branch point is inside both or the same instant is evidence on one lane and not the other.
BOUND = f'| WHERE @timestamp <= "{T0_Z}"'


def test_the_bound_lands_after_the_source_command_not_after_the_first_line(tmp_path):
    """    A whole pipeline written on ONE line still takes the bound immediately after its source
    command.

    The failure this exists for is not a formatting nit. `FROM logs-zeek.ssh-* | LIMIT 1` split
    on `\n` puts the clause after `LIMIT`, which takes one arbitrary row and only THEN filters
    it by timestamp — not a narrower row set but an empty one, which reads downstream as a lead
    that measured nothing rather than as a broken query. `|` is the separator ES|QL actually
    uses, and `controls.add_esql_window`'s docstring names this exact case; the clock's copy has
    to make the same cut or the two halves of the tree disagree about where a stage goes."""
    out = elastic_adapter.bounded_esql(docker_ctx(tmp_path, as_of=T0),
                                       "FROM logs-zeek.ssh-* | LIMIT 1")

    assert out == f"FROM logs-zeek.ssh-*\n{BOUND}\n| LIMIT 1"


def test_the_source_commands_own_suffix_stays_attached_to_it(tmp_path):
    """    A `METADATA` clause belongs to the source command, so the bound goes after it.

    `FROM x METADATA _id` is one command in two words, and a cut that took the FROM alone would
    strand `METADATA _id` at the head of the next stage — where it is not a valid stage at all,
    so the lead's whole query is refused by Elasticsearch rather than narrowed. Committed
    templates use the clause, which is why it is pinned rather than left to the splitter."""
    out = elastic_adapter.bounded_esql(docker_ctx(tmp_path, as_of=T0),
                                       "FROM logs-x-* METADATA _id | LIMIT 5")

    assert out == f"FROM logs-x-* METADATA _id\n{BOUND}\n| LIMIT 5"


def test_a_pipe_inside_a_quoted_name_is_not_a_stage_boundary(tmp_path):
    """    A `|` inside a quoted index name is part of the NAME, not the end of the source command.

    The naive `partition("|")` cuts here, and what it produces is not a wrong window — it is a
    query sliced through the middle of a string literal, `FROM "logs` followed by a stage
    beginning `|weird"`. Refused by the cluster, so the lead loses its evidence entirely; and
    refused for a reason no reader can attribute to the clock. The splitter has to understand
    quoting, which is why this lane reuses the one `esql_text` already owns."""
    out = elastic_adapter.bounded_esql(docker_ctx(tmp_path, as_of=T0), 'FROM "logs|weird"')

    # By LINES, so the assertion names the stage boundary and nothing else: a query with no
    # downstream stage has no bytes after the clause to be exact about, and trailing whitespace
    # there is not what this arm is asking about.
    assert out.splitlines() == ['FROM "logs|weird"', BOUND]


def test_the_models_own_time_predicate_is_left_exactly_as_written(tmp_path):
    """    A query that already bounds `@timestamp` keeps that clause BYTE-IDENTICAL, with the run's
    bound alongside it.

    This is the arm that catches an implementation trying to be helpful — merging the two
    windows, narrowing the model's `<` to the run's `<=`, or replacing a bound it judges wider.
    Any of those is the query-language surgery the stager refuses everywhere else: the clock
    does not read the predicate the model wrote, it appends an INDEPENDENT stage after the
    source, and appending a stage can only narrow a row set. Two `WHERE`s in a pipeline is
    ordinary ES|QL and needs no reconciling.

    A lead that deliberately reads a window around a later event is exactly who gets hurt by the
    helpful version, and the damage is invisible: the payload echoes the query the lead asked,
    so a narrowed window looks like a window that simply held less."""
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


def test_an_unbranched_run_sends_the_query_exactly_as_written(tmp_path):
    """    With no clock on the ctx, `bounded_esql` is the identity.

    The positive control against a bound that fires everywhere. An ordinary investigation asking
    an unbounded question IS asking about now, and a clause appended there would silently
    exclude documents indexed while the run was thinking — a lead reporting less than the estate
    holds, on the lane where most of a run's evidence lives."""
    asked = "FROM logs-zeek.ssh-*\n| LIMIT 5"

    assert elastic_adapter.bounded_esql(docker_ctx(tmp_path, as_of=None), asked) == asked


def test_the_bound_reaches_the_wire_and_stays_out_of_the_evidence(tmp_path):
    """    The BOUNDED query is what Elasticsearch runs; the ASKED query is what the payload records.

    THE arm of this half, and the two directions fail differently. Send the asked form and the
    window is not closed at all — the episode is unreplayable and nothing says so. Record the
    bounded form and a clause the model never wrote enters the run's own account of what it
    asked: the payload is the lead's evidence, `executed_queries.jsonl` keys off it, a later
    lead re-binds the template it was just served, and the ledger's `restore` cannot help —
    it repairs a staged CORPUS identity in that echo, which is a substitution in the `FROM`, and
    knows nothing about an inserted stage.

    Both sides are read for real: what the transport was handed comes off the fake `docker`'s
    own argv, and the payload comes back from the real verb."""
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
    """    The ES|QL clause and the search body close the window INCLUSIVELY, both of them.

    One instant, two lanes, and they must agree about it: `<=` here and `lte` there. Split, a
    document written at exactly T0 is evidence for a lead that used `query` and invisible to one
    that used `esql` — a difference between two siblings' payloads that belongs to neither
    world, arriving from the boundary condition rather than from anything either lead did."""
    ctx = elastic_ctx(tmp_path, as_of=T0)

    clause = elastic_adapter.bounded_esql(ctx, "FROM logs-zeek.ssh-*")
    elastic_adapter.query(ctx, native_query="event.action:ssh_login")

    assert clause.splitlines()[-1] == f'| WHERE @timestamp <= "{T0_Z}"'
    assert range_filter(search_body(tmp_path)) == {"lte": T0_Z}


@pytest.mark.parametrize(("stem", "body"), COMMITTED, ids=[s for s, _ in COMMITTED])
def test_every_committed_template_takes_the_bound_with_its_pipes_intact(tmp_path, stem, body):
    """    A real template comes back as its source command, the bound, and EVERY OTHER BYTE
    unchanged.

    The strongest form the claim can take, and over the 12 bodies a gather lead actually sends
    rather than over queries invented here: multi-line `STATS ... BY ...` blocks, `WHERE`
    continuation lines, trailing `| SORT`, and the exact whitespace of each. A clock that
    reflowed a pipeline would change what the query MEANS on some template nobody wrote a case
    for, and the sweep covers them without enumerating them.

    The expected value is built by a LINE split, deliberately independent of the `|`-splitter
    under test — every committed template opens with its source command alone on line one, so
    the two agree here and only here. Computing it with the implementation's own helper would
    let the assertion and the code agree by construction."""
    head, _, tail = body.partition("\n")
    assert head == f"FROM {leading_source(body)}", stem

    out = elastic_adapter.bounded_esql(docker_ctx(tmp_path, as_of=T0), body)

    assert out == f"{head}\n{BOUND}\n{tail}", stem


def test_the_swept_catalog_is_the_corpus_this_half_claims():
    """    12 committed ES|QL templates, which is what the sweep above is sized against.

    Asserted rather than derived, for `test_920_elastic_staging`'s reason: a catalog that
    shrank — or a fence reader that stopped matching — would make the parametrization collect
    fewer cases, or none, and stay green while covering nothing."""
    assert len(COMMITTED) == ESQL_TEMPLATES


# ==========================================================================
# 4. T0 itself: derived from the prefix, and pinned into the spec
# ==========================================================================

def _stamped_turn(store, session_id, moment, *, text="a turn"):
    """One complete pair whose messages AND parts carry `moment`.

    Both halves are stamped because the framework defaults a part's timestamp to `now`: a
    fixture that stamped only the message would leave a live `now` inside it, and an
    implementation reading either would answer a different T0 from the one this test computed.
    """
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
    ss.write_case_pointer(run_dir, case_id="case-clock", store_path=store.path)
    session_id = store.new_session(agent_id="main")
    for i, moment in enumerate(moments):
        _stamped_turn(store, session_id, moment, text=f"t{i}")
    return store, run_dir, ss.path_row_ids(store, session_id)


def test_t0_is_the_latest_moment_the_prefix_carries(tmp_path):
    """    `branch_point_time` answers the MAXIMUM message timestamp in the prefix, truncated to
    whole seconds — and it is aware UTC.

    The maximum, not the last row: a session is a tree walked by parent id and nothing forces
    the store's order to be chronological (item 3's synthesized turn is written straight into
    MAIN's session after the fact). An implementation reading the tail row's timestamp answers
    a moment EARLIER than something the prefix already contains, and then stamps payloads that
    predate evidence the sibling can see — so the fixture puts the latest moment in the middle.

    Truncated, because `z_seconds` truncates: a T0 carrying microseconds formats to a string
    that no longer round-trips, and the stored T0 and the stamps derived from it stop
    comparing equal."""
    branch = branch_mod()
    latest = dt.datetime(2026, 5, 25, 15, 31, 0, 654321, tzinfo=dt.UTC)
    store, run_dir, path_ids = _timed_source(tmp_path, [
        dt.datetime(2026, 5, 25, 15, 30, 0, tzinfo=dt.UTC),
        latest,
        dt.datetime(2026, 5, 25, 15, 30, 30, tzinfo=dt.UTC),
    ])

    derived = branch.branch_point_time(store, run_dir, path_ids[-1])

    assert derived == latest.replace(microsecond=0), (
        f"T0 is {derived}, not the prefix's own latest moment truncated to seconds")
    assert derived.utcoffset() == dt.timedelta(0), f"T0 is not aware UTC: {derived!r}"
    assert _clock.z_seconds(derived) == "2026-05-25T15:31:00Z"


def test_t0_ignores_everything_the_run_did_after_the_branch(tmp_path):
    """    A branch point in the middle of a finished run derives the moment IT stood at, not the
    moment the run ended at.

    This is the whole reason T0 is derived from the prefix rather than read off the run: the
    source ran on, and a sibling forked at turn N is living at turn N. Taken from the run's tip,
    every sibling of every branch point in one run would share one clock — and an episode
    branched at 15:31 would close its unbounded windows over evidence that landed at 16:40, i.e.
    over the source's own later answers.

    Both arms run against ONE run, so an implementation that reads the terminal state passes
    neither."""
    branch = branch_mod()
    store, run_dir, path_ids = _timed_source(tmp_path, [
        dt.datetime(2026, 5, 25, 15, 30, 0, tzinfo=dt.UTC),
        dt.datetime(2026, 5, 25, 16, 40, 0, tzinfo=dt.UTC),
    ])

    early = branch.branch_point_time(store, run_dir, path_ids[1])
    late = branch.branch_point_time(store, run_dir, path_ids[-1])

    assert early == dt.datetime(2026, 5, 25, 15, 30, 0, tzinfo=dt.UTC)
    assert late == dt.datetime(2026, 5, 25, 16, 40, 0, tzinfo=dt.UTC)


def test_the_branch_spec_carries_the_moment_it_forks_at(tmp_path):
    """    `as_of` is a REQUIRED coordinate of a `BranchSpec`, not an optional one.

    A resume that could be spelled without a moment is a resume that will be: the episode's
    payloads would then be stamped from whenever the sibling happened to run, and nothing in the
    record would say so. Required, so the spelling that loses replayability does not exist."""
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
    """    `validate` refuses a spec whose `as_of` is not the moment the branch point derives.

    A spec is data — it comes off a CLI flag or a world file — and a T0 that does not belong to
    this branch point is the one input that corrupts an episode SILENTLY: every payload stamps
    consistently, every window closes consistently, and the whole set describes a moment the run
    was never at. Nothing downstream can detect it, because consistency is all any reader can
    check.

    ONE SECOND OFF is the arm that discriminates. A wildly wrong moment would be caught by any
    sanity bound someone might reach for instead — "is this within the run's lifetime" — and a
    T0 a second early is exactly what a caller re-deriving the moment with a different rounding
    rule produces, which is the near miss that would otherwise sail through.

    The positive arm runs first and against the same spec, so the refusal cannot be a `validate`
    that refuses everything."""
    branch = branch_mod()
    store, run_dir, _session_id, path_ids = legal_source(
        tmp_path, investigation=GOLDEN_INVESTIGATION.read_text(encoding="utf-8"))
    legal = spec_at(store, run_dir, path_ids[-1])

    assert branch.validate(store, legal) is None, (
        "the derived spec was refused, so the refusal below pins nothing")

    for wrong in (dt.timedelta(seconds=1), dt.timedelta(hours=3)):
        with pytest.raises(branch.BranchError):
            branch.validate(store, dataclasses.replace(legal, as_of=legal.as_of + wrong))


@pytest.mark.parametrize("as_of", [
    None,
    "2026-05-25T15:30:45Z",
    dt.datetime(2026, 5, 25, 15, 30, 45),
    dt.datetime(2026, 5, 25, 17, 30, 45, tzinfo=dt.timezone(dt.timedelta(hours=2))),
])
def test_a_spec_whose_clock_is_not_aware_utc_is_refused(tmp_path, as_of):
    """    A spec's moment must be an aware, zero-offset datetime, refused as a `BranchError`.

    The shape check is separate from the agreement check above and fails first, because the two
    have different answers for the operator: a naive or offset-bearing moment is a spelling
    fault at the caller, and a mismatch is a spec pointed at the wrong branch point. Refused as
    `BranchError` specifically, because that is the class `run_investigation`'s store-setup
    handler names — a `TypeError` out of here escapes it entirely, leaving the sqlite connection
    open and the wire log still registered in `observe._ACTIVE_PATHS`."""
    branch = branch_mod()
    store, run_dir, _session_id, path_ids = legal_source(
        tmp_path, investigation=GOLDEN_INVESTIGATION.read_text(encoding="utf-8"))

    with pytest.raises(branch.BranchError):
        branch.validate(store, spec_at(store, run_dir, path_ids[-1], as_of=as_of))
