"""#1347 r6.4 O5/P7: `run.py --as-of T` starts the run clock (and the recorded start times) at T, is refused
with `--update-ticket` and the branching flags, and cuts nothing; `--arrived-by` is gone."""
from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import re
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from defender.records import RunPaths, _provenance
from defender.systems.verbs import CALL_RUN_STATE
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.runtime.state import _1255_clock as C

pytestmark = pytest.mark.e2e

L1 = C.LESSONS[0]
AS_OF = dt.datetime(2026, 10, 20, 9, 0, 0, tzinfo=dt.UTC)
AS_OF_Z = "2026-10-20T09:00:00Z"
#: The run's own seconds before its first read; the agent-visible clock moves only by these.
ELAPSED = 20
#: A query whose relative date math Elasticsearch resolves itself: the frozen cluster's clock
#: is pinned to T (D15), so the product sends it as it would to live.
NATIVE_QUERY = "event.action:* AND @timestamp >= now-1h"


@pytest.fixture(autouse=True)
def _roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    T.isolate_learning_state(tmp_path, monkeypatch)
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")


class Seen:
    """What the run handed its adapters: each (context, params), and the run state's budget as
    the platform held it at the first call."""

    def __init__(self) -> None:
        self.calls: list[tuple[Any, dict]] = []
        self.budget: dict[str, Any] | None = None


def wired_registry(seen: Seen, proxied: Any) -> type:
    """The real registry and adapters, each call noted then sent through the real proxy to a recording
    upstream; only tenant, proxy address and token are swapped in the context."""
    from defender.systems.verbs import ModuleVerbRegistry

    class Wired(ModuleVerbRegistry):
        def verbs(self, system: str):
            real = super().verbs(system)

            def wrap(fn):
                def call(ctx, /, **params):
                    seen.calls.append((ctx, dict(params)))
                    state = CALL_RUN_STATE.get()
                    if seen.budget is None and state is not None:
                        seen.budget = dict(state.budget_snapshot())
                    wired = dataclasses.replace(
                        ctx, tenant=proxied.tenant, proxy_url=proxied.proxy_url,
                        request_token=proxied.request_token, token_source=None)
                    return fn(wired, **params)

                call.__wrapped__ = fn
                return call

            return {name: wrap(fn) for name, fn in real.items()}

    return Wired


def launch(tmp_path: Path, flags: list[str], *, registry_cls: type | None = None,
           enqueue: Any = None, learn: bool = False) -> C.Launched:
    """A natural run through `run.main` that makes one gathered elastic query, `flags` added."""
    _base, seed = T.runs_base(tmp_path)
    tenant_id = T.current_tenant().id
    clock = C.FakeClock(C.ARM_START)
    main = C.script(clock, (0, C.append_first_fence()), (ELAPSED, C.gather_turn("l-001", "elastic")),
                    (0, C.read_lesson(L1)), (5, C.DONE))
    gather = C.script(clock, (0, C.query("elastic", "query", {"native_query": NATIVE_QUERY})),
                      (0, C.H.Turn(text="Summary: one query.")))
    argv = C.natural_argv(RunPaths(seed).alert, tenant_id)
    if learn:
        argv.remove("--no-learn")
    return C.run_main([*argv, *flags], clock=clock, main=main, gather=gather,
                      registry_cls=registry_cls, enqueue=enqueue)


def attempt(tmp_path: Path, argv_of: Any) -> tuple[C.Launched, Path, list[str]]:
    """A launch that must be refused: `argv_of(alert, tenant_id)` is its command line. Returns
    the outcome, the runs folder and its listing from before."""
    base, seed = T.runs_base(tmp_path)
    before = sorted(p.name for p in base.iterdir())
    clock = C.FakeClock(C.ARM_START)
    out = C.run_main(argv_of(str(RunPaths(seed).alert), T.current_tenant().id),
                     clock=clock, main=C.script(clock, (0, C.DONE)))
    return out, base, before


def refused(out: C.Launched, capsys: pytest.CaptureFixture, needle: str, base: Path,
            before: list[str]) -> None:
    """The launch exited through a refusal that names `needle` (not argparse's unknown-flag
    message), never reached the driver and minted no run."""
    message = f"{out.refusal} {capsys.readouterr().err}"
    assert out.exit == "SystemExit", f"the launch was not refused: exit={out.exit}"
    assert "unrecognized" not in message, f"the flag is simply unknown: {message!r}"
    assert needle in message, f"the refusal does not name {needle}: {message!r}"
    assert out.run_dir is None, "a refused launch reached the driver"
    assert sorted(p.name for p in base.iterdir()) == before, "a refused launch minted a run dir"


@contextlib.contextmanager
def proxied_runs(tmp_path: Path, data_root: Path) -> Iterator[Callable[..., tuple[C.Launched, Seen]]]:
    """A `run(name, flags)` that launches a natural run whose one elastic query goes through the
    real proxy to a recording upstream (`run.upstream` lists what it was sent)."""
    with H.upstream() as up:
        up.replies[f"/{A.ELASTIC_EVENTS}/_search"] = (
            200, {"Content-Type": "application/json"},
            b'{"hits": {"total": {"value": 0}, "hits": []}}')
        with A.elastic_proxied(tmp_path / "px", data_root, up.url) as (proxied, _tap):
            def run(name: str, flags: list[str]) -> tuple[C.Launched, Seen]:
                seen = Seen()
                out = launch(tmp_path / name, flags, registry_cls=wired_registry(seen, proxied))
                return out, seen

            run.upstream = up  # type: ignore[attr-defined]
            yield run


@pytest.mark.parametrize("spelling", [
    pytest.param(AS_OF_Z, id="z"),
    pytest.param("2026-10-20T11:00:00+02:00", id="colon-offset"),
    pytest.param("2026-10-20T11:00:00+0200", id="compact-offset"),
    pytest.param("2026-10-20T14:30:00+05:30", id="half-hour-east"),
    pytest.param("2026-10-20T05:30:00-03:30", id="half-hour-west"),
])
def test_an_as_of_runs_clock_starts_at_T_whatever_the_offset_it_is_spelled_in(tmp_path, spelling):
    """O5: the first visible time is T (the UTC instant) plus the run's own elapsed seconds,
    whatever the clock source reads at launch."""
    out = launch(tmp_path, ["--as-of", spelling])

    assert out.exit == 0, f"the run did not run: exit={out.exit} refusal={out.refusal}"
    assert C.lesson_reads(out.run_dir, L1) == [C.at(AS_OF, ELAPSED)], C.lesson_rows(out.run_dir)


def test_an_ordinary_runs_clock_starts_at_its_clock_source(tmp_path):
    """O5 control: without the flag the first visible time is the source's reading plus elapsed."""
    out = launch(tmp_path, [])

    assert out.exit == 0, f"refusal={out.refusal}"
    assert C.lesson_reads(out.run_dir, L1) == [C.at(C.ARM_START, ELAPSED)]


def test_an_as_of_run_records_the_run_clocks_start_not_wall_time(tmp_path, data_root):
    """O5/A9: the run state's created_at/started_at and the stamp's started_at are T. Control:
    an ordinary run records its clock source's start in the budget and wall time in the stamp."""
    with proxied_runs(tmp_path, data_root) as run:
        frozen, frozen_seen = run("frozen", ["--as-of", AS_OF_Z])
        ordinary, ordinary_seen = run("ordinary", [])

    assert frozen.exit == 0 and ordinary.exit == 0, (frozen.refusal, ordinary.refusal)
    assert frozen_seen.budget and ordinary_seen.budget, "no call reached the registry with a run state"
    for key in ("created_at", "started_at"):
        assert C.instant(frozen_seen.budget[key]) == AS_OF, f"{key}={frozen_seen.budget[key]}"
        assert C.instant(ordinary_seen.budget[key]) == C.ARM_START, ordinary_seen.budget[key]
    stamped = _provenance.read_provenance(RunPaths(frozen.run_dir).provenance).started_at
    assert C.instant(stamped) == AS_OF, f"the stamp's start is {stamped}, not the run clock's"
    wall = _provenance.read_provenance(RunPaths(ordinary.run_dir).provenance).started_at
    assert abs((C.instant(wall) - dt.datetime.now(dt.UTC)).total_seconds()) < 3600, wall


def test_an_as_of_run_keeps_the_milliseconds_it_was_given(tmp_path, data_root):
    """O5: a fractional second on `--as-of` is kept in the run clock's origin."""
    with proxied_runs(tmp_path, data_root) as run:
        out, seen = run("frozen", ["--as-of", "2026-10-20T09:00:00.250Z"])

    assert out.exit == 0, f"refusal={out.refusal}"
    assert dt.datetime.fromisoformat(seen.budget["started_at"]) == AS_OF + dt.timedelta(milliseconds=250)


@pytest.mark.parametrize(("argv_of", "needle"), [
    pytest.param(lambda alert, tenant: [alert, "--tenant", tenant, "--as-of", AS_OF_Z, "--update-ticket"],
                 "--update-ticket", id="ticket-write"),
    pytest.param(lambda alert, tenant: ["--tenant", tenant, "--episode", T.EPISODE_ID, "--world", "a",
                                        "--as-of", AS_OF_Z], "--as-of", id="episode-and-world"),
    pytest.param(lambda alert, tenant: ["--tenant", tenant, "--episode", T.EPISODE_ID, "--as-of", AS_OF_Z],
                 "--as-of", id="episode-alone"),
    pytest.param(lambda alert, tenant: [alert, "--tenant", tenant, "--world", "a", "--as-of", AS_OF_Z],
                 "--as-of", id="world-alone-with-an-alert"),
])
def test_as_of_is_refused_with_a_ticket_write_or_a_branching_flag(tmp_path, capsys, argv_of, needle):
    """Non-obligation (ticket writes) and O5: a frozen run never writes a ticket and is never a
    branch. Refused naming the flag, before a run exists."""
    out, base, before = attempt(tmp_path, argv_of)

    refused(out, capsys, needle, base, before)


@pytest.mark.parametrize("moment", [
    pytest.param("2026-10-20T09:00:00", id="naive"),
    pytest.param("2026-10-20", id="date-only"),
    pytest.param("", id="empty"),
    pytest.param("yesterday", id="junk"),
    pytest.param("0001-01-01T00:00:00+02:00", id="before-year-1-in-utc"),
    pytest.param("9999-12-31T23:59:59-02:00", id="after-year-9999-in-utc"),
])
def test_an_as_of_that_is_not_an_instant_is_refused_naming_the_flag(tmp_path, capsys, moment):
    """O5: T is ISO-8601 with an offset or `Z`, inside years 1-9999 in UTC (a naive time is never
    read as UTC); anything else is a refusal naming `--as-of`, never an OverflowError."""
    out, base, before = attempt(
        tmp_path, lambda alert, tenant: [alert, "--tenant", tenant, "--as-of", moment])

    refused(out, capsys, "--as-of", base, before)


def test_arrived_by_is_not_accepted(tmp_path, capsys):
    """Withdrawn from product: `--arrived-by` is no flag, with or without `--as-of`. Nothing runs."""
    out, base, before = attempt(tmp_path, lambda alert, tenant: [
        alert, "--tenant", tenant, "--as-of", AS_OF_Z, "--arrived-by", "2026-10-20T09:03:17Z"])

    assert out.exit == "SystemExit", f"--arrived-by was accepted: exit={out.exit}"
    message = f"{out.refusal} {capsys.readouterr().err}"
    assert "--arrived-by" in message, message
    assert out.run_dir is None and sorted(p.name for p in base.iterdir()) == before


@pytest.mark.parametrize(("flags", "enqueued"), [
    pytest.param(["--as-of", AS_OF_Z], 0, id="as-of"),
    pytest.param([], 1, id="ordinary-control"),
])
def test_an_as_of_run_is_never_enqueued_for_curation_even_without_no_learn(tmp_path, flags, enqueued):
    """Held-out isolation: the curation exclusion keys on `--as-of` (replacing `started.cut`),
    so `--no-learn` is not what keeps a frozen run out. Control: an ordinary run is enqueued."""
    asked: list[Any] = []

    def enqueue(*args: Any, **kwargs: Any) -> bool:
        asked.append(args)
        return True

    out = launch(tmp_path, flags, enqueue=enqueue, learn=True)

    assert out.exit == 0, f"refusal={out.refusal}"
    assert len(asked) == enqueued, asked


def test_an_as_of_runs_elastic_request_is_byte_identical_to_an_ordinary_runs(tmp_path, data_root):
    """P7: an `--as-of` run's query reaches Elasticsearch as the same method, path and body bytes as
    an ordinary run's, and the adapter's context has the same fields."""
    with proxied_runs(tmp_path, data_root) as run:
        sent: dict[str, Seen] = {}
        wire: dict[str, list[tuple[str, str, str]]] = {}
        for name, flags in (("ordinary", []), ("frozen", ["--as-of", AS_OF_Z])):
            before = len(run.upstream.seen)
            out, sent[name] = run(name, flags)
            assert out.exit == 0, f"{name}: exit={out.exit} refusal={out.refusal}"
            wire[name] = [(s.method, s.path, s.body) for s in run.upstream.seen[before:]]

    assert wire["ordinary"], "the ordinary run's query never reached the upstream"
    assert wire["frozen"] == wire["ordinary"], (
        f"the --as-of run's request differs: {wire['frozen']} vs {wire['ordinary']}")
    assert [p for _c, p in sent["frozen"].calls] == [p for _c, p in sent["ordinary"].calls]

    def fields(ctx: Any) -> dict:
        return {f.name: getattr(ctx, f.name) for f in dataclasses.fields(ctx)}

    assert set(fields(sent["frozen"].calls[0][0])) == set(fields(sent["ordinary"].calls[0][0])), (
        "the --as-of run's verb context carries a field an ordinary run's does not")


def run_files(run_dir: Path) -> dict[str, str]:
    """Every file under the run dir by relative name, with its text."""
    return {str(p.relative_to(run_dir)): p.read_bytes().decode("utf-8", "replace")
            for p in Path(run_dir).rglob("*") if p.is_file()}


#: What would tell the agent a run is frozen: the flag's name, a freeze, a cut.
FREEZE_WORDS = re.compile(r"as[_-]?of|arrived[_-]?by|frozen|freez|\bcut\b", re.IGNORECASE)
#: Other ways a wall date is written; date part only, so any time of day after it matches.
WALL_DATE_SPELLINGS = ("%d/%m/%Y", "%m/%d/%Y", "%d.%m.%Y", "%d-%m-%Y", "%Y/%m/%d", "%d %b %Y",
                       "%b %d, %Y", "%a %b %d")


def test_an_as_of_run_writes_nothing_about_the_freeze_into_its_run_dir(tmp_path):
    """P4: the run dir has an ordinary run's files, none names the freeze, and no launch wall time
    is in it; T's stamps are (control)."""
    began = dt.datetime.now(dt.UTC)
    ordinary = launch(tmp_path, [])
    plain = run_files(ordinary.run_dir)
    out = launch(tmp_path, ["--as-of", "2026-03-02T09:00:00Z"])

    wall = {n for at in (began, dt.datetime.now(dt.UTC))
            for n in (at.date().isoformat(), at.strftime("%Y%m%d"), str(int(at.timestamp()))[:8],
                      *(at.strftime(f) for f in WALL_DATE_SPELLINGS))}
    wall |= {dt.date.today().isoformat(), C.ARM_START.date().isoformat()}
    assert not wall & {"2026-03-02", "20260302"}, "fixture date collides with the wall clock"
    assert out.exit == 0, f"refusal={out.refusal}"
    text = run_files(out.run_dir)
    assert any("2026-03-02T09:00:20" in t for t in text.values()), (
        "no file carries T's run-clock stamp: the walk is not reading the run")
    assert set(text) == set(plain), (
        f"an --as-of run's dir differs from an ordinary run's: {sorted(set(text) ^ set(plain))}")
    leaks = {name: needle for name, t in text.items() for needle in wall if needle in t or needle in name}
    assert not leaks, f"the launch's wall time is written into the run dir: {leaks}"
    named = {name: m.group() for name, t in text.items()
             if name in plain and (m := FREEZE_WORDS.search(t)) and not FREEZE_WORDS.search(plain[name])}
    assert not named, f"a file of the --as-of run names the freeze: {named}"
