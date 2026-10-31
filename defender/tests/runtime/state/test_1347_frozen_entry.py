"""#1347 O5 / product-side cut: `run.py --as-of T [--arrived-by A]` starts the run clock at T,
cuts every call at (T, A), and refuses the flag combinations a cut run cannot honour."""
from __future__ import annotations

import datetime as dt
import json
import os
import re
from pathlib import Path
from typing import Any

import pytest

from defender.records import RunPaths
from defender.records import _provenance
from defender.systems.verbs import ModuleVerbRegistry, ReadCut
from defender.tests.learning.branch.test_947_clock import DOCKER_LOG, docker_calls, fake_docker
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.runtime.state import _1255_clock as C

pytestmark = pytest.mark.e2e

L1 = C.LESSONS[0]
AS_OF = dt.datetime(2026, 10, 20, 9, 0, 0, tzinfo=dt.UTC)
ARRIVED_BY = dt.datetime(2026, 10, 20, 9, 3, 17, tzinfo=dt.UTC)
AS_OF_Z = "2026-10-20T09:00:00Z"
ARRIVED_BY_Z = "2026-10-20T09:03:17Z"
#: The run's own seconds before its first search; the agent-visible clock moves only by these.
ELAPSED = 20
CUT_FLAGS = ["--as-of", AS_OF_Z, "--arrived-by", ARRIVED_BY_Z]
#: A frozen run sets both cuts; a branched run's run clock is as_of alone. Both start at as_of.
EITHER_CUT = [pytest.param(CUT_FLAGS, id="as-of-and-arrived-by"),
              pytest.param(["--as-of", AS_OF_Z], id="as-of-alone")]


@pytest.fixture(autouse=True)
def _roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate configured roots, enable the real unboxed executor, and put a recording `docker`
    on PATH: the wire every Elastic and host-state call forks into."""
    T.isolate_learning_state(tmp_path, monkeypatch)
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    monkeypatch.setenv("PATH", f"{fake_docker(tmp_path)}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("DOCKER_CALL_LOG", str(tmp_path / DOCKER_LOG))


class Seen:
    """What the run state held when the first verb call reached the registry."""

    def __init__(self) -> None:
        self.budget: dict[str, Any] | None = None
        self.payloads: list[Any] = []
        self.cut: Any = "unset"


def recording_registry(seen: Seen) -> type:
    """The real `ModuleVerbRegistry` (real adapters, real wire), noting the run state's budget and
    each payload; it changes no call."""

    class Recording(ModuleVerbRegistry):
        def verbs(self, system: str):
            seen.cut = self.cut
            real = super().verbs(system)

            def wrap(fn):
                def call(ctx, /, **params):
                    if seen.budget is None and ctx.run_state is not None:
                        seen.budget = dict(ctx.run_state.budget_snapshot())
                    out = fn(ctx, **params)
                    seen.payloads.append(out)
                    return out

                call.__wrapped__ = fn
                return call

            return {name: wrap(fn) for name, fn in real.items()}

    return Recording


def launch(tmp_path: Path, flags: list[str], *, system: str = "elastic", verb: str = "query",
           params: dict | None = None):
    """A natural run through `run.main` that makes one gathered call, with `flags` added."""
    _base, seed = T.runs_base(tmp_path)
    tenant_id = T.current_tenant().id
    clock = C.FakeClock(C.ARM_START)
    main = C.script(clock, (0, C.append_first_fence()), (ELAPSED, C.gather_turn("l-001", system)),
                    (0, C.read_lesson(L1)), (5, C.DONE))
    gather = C.script(clock, (0, C.query(system, verb, params or {"native_query": "event.action:*"})),
                      (0, C.H.Turn(text="Summary: one query.")))
    seen = Seen()
    out = C.run_main([*C.natural_argv(RunPaths(seed).alert, tenant_id), *flags], clock=clock,
                     main=main, gather=gather, registry_cls=recording_registry(seen))
    return out, seen, clock


def wire_filters(tmp_path: Path) -> str:
    """The last search body's cut-bearing parts, as text."""
    argv = docker_calls(tmp_path)[-1]
    body = json.loads(argv[argv.index("-d") + 1])
    return json.dumps({"post_filter": body.get("post_filter"), "filter": body.get("filter")})


@pytest.mark.parametrize("flags", EITHER_CUT)
def test_a_cut_runs_clock_starts_at_as_of_not_at_launch(tmp_path, flags):
    """O5: the first visible time is as_of plus the run's own elapsed seconds, whatever the clock
    source reads at launch and whether or not an arrival cut rides with it."""
    out, _seen, _clock = launch(tmp_path, flags)

    assert out.exit == 0, f"the run did not run: exit={out.exit} refusal={out.refusal}"
    assert C.lesson_reads(out.run_dir, L1) == [C.at(AS_OF, ELAPSED)], (
        f"the run clock did not start at {AS_OF}: {C.lesson_rows(out.run_dir)}")


def test_an_ordinary_run_keeps_the_wall_clock_source_and_cuts_nothing(tmp_path):
    """O5 positive control: no flags, the clock starts at the source's reading and the wire
    carries no cut."""
    out, _seen, _clock = launch(tmp_path, [])

    assert out.exit == 0, f"refusal={out.refusal}"
    assert C.lesson_reads(out.run_dir, L1) == [C.at(C.ARM_START, ELAPSED)]
    assert docker_calls(tmp_path), "the search never reached the wire"
    sent = wire_filters(tmp_path)
    assert AS_OF_Z[:10] not in sent, sent
    assert json.loads(sent) == {"post_filter": None, "filter": None}, (
        f"an ordinary run's search carries a cut: {sent}")


def test_a_cut_run_sends_both_cuts_to_elastic(tmp_path):
    """Product-side cut: every call's context carries as_of and arrived_by; the Elastic request
    bears both, millisecond or second precision, UTC Z."""
    out, _seen, _clock = launch(tmp_path, CUT_FLAGS)

    assert out.exit == 0, f"refusal={out.refusal}"
    sent = wire_filters(tmp_path)
    assert "2026-10-20T09:00:00" in sent, f"as_of is not on the wire: {sent}"
    assert "2026-10-20T09:03:17" in sent, f"arrived_by is not on the wire: {sent}"


def test_as_of_alone_cuts_event_time_and_sends_no_arrival_cut(tmp_path):
    """Product-side cut: `--as-of` without `--arrived-by` bounds event time only (negative
    control for the arrival cut)."""
    out, _seen, _clock = launch(tmp_path, ["--as-of", AS_OF_Z])

    assert out.exit == 0, f"refusal={out.refusal}"
    sent = wire_filters(tmp_path)
    assert "2026-10-20T09:00:00" in sent, f"as_of is not on the wire: {sent}"
    assert "event.ingested" not in sent, f"an arrival cut was sent without --arrived-by: {sent}"


@pytest.mark.parametrize(("as_of", "arrived_by"), [
    pytest.param("2026-10-20T11:00:00+02:00", "2026-10-20T11:03:17+02:00", id="colon-offset"),
    pytest.param("2026-10-20T11:00:00+0200", "2026-10-20T11:03:17+0200", id="compact-offset"),
    pytest.param("2026-10-20T04:00:00-05:00", "2026-10-20T04:03:17-0500", id="west-offsets"),
])
def test_a_cut_spelled_with_an_offset_cuts_at_the_utc_instant(tmp_path, as_of, arrived_by):
    """O2 (UTC instant): the same instant spelled with an offset puts the same bounds on the wire
    and starts the clock at the same moment as its `Z` spelling."""
    out, _seen, _clock = launch(tmp_path, ["--as-of", as_of, "--arrived-by", arrived_by])

    assert out.exit == 0, f"refusal={out.refusal}"
    sent = wire_filters(tmp_path)
    for bound in ("2026-10-20T09:00:00.000Z", "2026-10-20T09:03:17.000Z"):
        assert bound in sent, f"the offset was not converted to the UTC instant: {sent}"
    assert C.lesson_reads(out.run_dir, L1) == [C.at(AS_OF, ELAPSED)]


def test_a_cut_keeps_the_milliseconds_it_was_given(tmp_path):
    """D12 (ms precision): fractional seconds on `--as-of` / `--arrived-by` reach the wire intact."""
    out, _seen, _clock = launch(tmp_path, ["--as-of", "2026-10-20T09:00:00.250Z",
                                           "--arrived-by", "2026-10-20T09:03:17.750Z"])

    assert out.exit == 0, f"refusal={out.refusal}"
    sent = wire_filters(tmp_path)
    for bound in ("2026-10-20T09:00:00.250Z", "2026-10-20T09:03:17.750Z"):
        assert bound in sent, f"the sub-second part of the cut was dropped: {sent}"


@pytest.mark.parametrize(("flags", "cut"), [
    pytest.param(CUT_FLAGS, ReadCut(AS_OF, ARRIVED_BY), id="as-of-and-arrived-by"),
    pytest.param(["--as-of", AS_OF_Z], ReadCut(AS_OF), id="as-of-alone"),
    pytest.param([], None, id="no-cut"),
])
def test_the_run_serves_its_calls_through_a_registry_built_over_its_cut(tmp_path, flags, cut):
    """Product-side cut: the flags become the one read cut the run's verb registry applies to
    every call (None for an ordinary run)."""
    out, seen, _clock = launch(tmp_path, flags)

    assert out.exit == 0, f"refusal={out.refusal}"
    assert seen.cut == cut, f"the registry was built over {seen.cut!r}, not {cut!r}"


@pytest.mark.parametrize("flags", EITHER_CUT)
def test_a_cut_run_records_the_run_clocks_start_not_wall_time(tmp_path, flags):
    """O5 [r6]/P4: the run state's created_at/started_at and provenance's start are as_of, with
    no wall time beside the shifted clock (as_of alone included)."""
    out, seen, _clock = launch(tmp_path, flags)

    assert out.exit == 0, f"refusal={out.refusal}"
    assert seen.budget is not None, "no call reached the registry with a run state"
    for key in ("created_at", "started_at"):
        assert C.instant(seen.budget[key]) == AS_OF, f"{key}={seen.budget[key]}"
    started = _provenance.read_provenance(RunPaths(out.run_dir).provenance).started_at
    assert C.instant(started) == AS_OF, f"provenance start is {started}, not the run clock's"


def test_an_ordinary_run_records_its_clock_source_start(tmp_path):
    """O5 positive control: without flags the run state's start is the clock source's reading,
    and provenance's start is wall time (not any as_of)."""
    out, seen, _clock = launch(tmp_path, [])

    assert out.exit == 0, f"refusal={out.refusal}"
    assert C.instant(seen.budget["created_at"]) == C.ARM_START
    started = _provenance.read_provenance(RunPaths(out.run_dir).provenance).started_at
    assert C.instant(started) is not None
    assert abs((C.instant(started) - dt.datetime.now(dt.UTC)).total_seconds()) < 3600


def test_the_hosts_own_capture_stamp_is_the_run_clock_not_the_arrival_cut(tmp_path):
    """Product-side cut: host-state `captured_at` keeps its capture-stamp meaning (run clock);
    `--arrived-by` never reaches it."""
    out, seen, _clock = launch(tmp_path, CUT_FLAGS, system="host-state", verb="proc-tree",
                               params={"host": "web-1"})

    assert out.exit == 0, f"refusal={out.refusal}"
    stamps = [p["captured_at"] for p in seen.payloads if isinstance(p, dict) and "captured_at" in p]
    assert stamps, f"no host-state payload carried a capture stamp: {seen.payloads}"
    assert C.instant(stamps[0]) == C.at(AS_OF, ELAPSED), (
        f"captured_at {stamps[0]} is not the run clock's reading")
    assert stamps[0] != ARRIVED_BY_Z


def run_files(run_dir: Path) -> dict[str, str]:
    """Every file under the run dir by relative name, with its text."""
    return {str(p.relative_to(run_dir)): p.read_bytes().decode("utf-8", "replace")
            for p in Path(run_dir).rglob("*") if p.is_file()}


#: What would tell the agent a run is cut: the flag names, a freeze, the arrival cut's key.
CUT_WORDS = re.compile(r"as[_-]?of|arrived[_-]?by|frozen|freez|\bcut\b", re.IGNORECASE)


@pytest.mark.parametrize("flags_dates", [
    pytest.param((["--as-of", "2026-03-02T09:00:00Z", "--arrived-by", "2026-03-04T14:41:53Z"],
                  ("2026-03-04", "14:41:53", "20260304")), id="as-of-and-arrived-by"),
    pytest.param((["--as-of", "2026-03-02T09:00:00Z"], ()), id="as-of-alone"),
])
def test_a_cut_run_writes_nothing_about_the_cut_beyond_the_clock_stamps(tmp_path, flags_dates):
    """FR10/P4 (O5 r6): no new file, no cut word, no arrival time and no launch wall time (ISO,
    compact date or epoch) in the run dir; the as_of stamps are there (positive control)."""
    flags, cut_only = flags_dates
    began = dt.datetime.now(dt.UTC)

    ordinary, _seen, _clock = launch(tmp_path, [])
    plain = run_files(ordinary.run_dir)
    out, _seen, _clock = launch(tmp_path, flags)

    wall_needles = {n for at in (began, dt.datetime.now(dt.UTC))
                    for n in (at.date().isoformat(), at.strftime("%Y%m%d"),
                              str(int(at.timestamp()))[:6])}
    wall_needles |= {dt.date.today().isoformat(), C.ARM_START.date().isoformat()}
    assert not wall_needles & {"2026-03-02", "2026-03-04", "20260302", "20260304"}, (
        "fixture dates collide with the wall clock")
    assert out.exit == 0, f"refusal={out.refusal}"
    text = run_files(out.run_dir)
    assert any("2026-03-02T09:00:20" in t for t in text.values()), (
        "no file carries the as_of-derived run-clock stamp: the walk is not reading the run")
    assert set(text) == set(plain), (
        f"a cut run's dir differs from an ordinary run's: {sorted(set(text) ^ set(plain))}")
    leaks = {name: needle for name, t in text.items()
             for needle in (*cut_only, *wall_needles) if needle in t or needle in name}
    assert not leaks, f"the cut or the launch's wall time is written into the run dir: {leaks}"
    named = {name: m.group() for name, t in text.items()
             if name in plain and (m := CUT_WORDS.search(t)) and not CUT_WORDS.search(plain[name])}
    assert not named, f"a file of the cut run names the cut: {named}"


def refused(out, capsys, tmp_path, needle: str, runs_before: list[str], base: Path) -> None:
    """The launch exited through the CLI's refusal path, naming `needle` (not argparse's
    "unrecognized arguments"), and minted no run."""
    assert out.exit == "SystemExit", f"the launch was not refused: exit={out.exit}"
    message = f"{out.refusal} {capsys.readouterr().err.splitlines()[-1:]}"
    assert "unrecognized" not in message, f"the flag is simply unknown: {message!r}"
    assert needle in message, f"the refusal does not name {needle}: {message!r}"
    assert out.run_dir is None, "a refused launch reached the driver"
    assert sorted(p.name for p in base.iterdir()) == runs_before, "a refused launch minted a run dir"


@pytest.mark.parametrize(("flags", "needle"), [
    (["--arrived-by", ARRIVED_BY_Z], "--as-of"),
    (["--as-of", AS_OF_Z, "--update-ticket"], "--update-ticket"),
])
def test_incompatible_cut_flags_are_refused_before_a_run_exists(tmp_path, capsys, flags, needle):
    """Refusal [r5]: `--arrived-by` needs `--as-of`; a cut run never writes a ticket. The refusal
    names the flag and no run dir is minted."""
    base, seed = T.runs_base(tmp_path)
    before = sorted(p.name for p in base.iterdir())
    clock = C.FakeClock(C.ARM_START)

    out = C.run_main([*C.natural_argv(RunPaths(seed).alert, T.current_tenant().id), *flags],
                     clock=clock, main=C.script(clock, (0, C.DONE)))

    refused(out, capsys, tmp_path, needle, before, base)


def test_a_cut_is_refused_with_the_branching_flags(tmp_path, capsys):
    """Refusal [r5]: `--as-of` with `--episode`/`--world` (a sibling's clock is its branch point)."""
    base, _seed = T.runs_base(tmp_path)
    before = sorted(p.name for p in base.iterdir())
    clock = C.FakeClock(C.ARM_START)

    out = C.run_main(["--tenant", T.current_tenant().id, "--episode", T.EPISODE_ID, "--world", "a",
                      "--as-of", AS_OF_Z], clock=clock, main=C.script(clock, (0, C.DONE)))

    refused(out, capsys, tmp_path, "--as-of", before, base)


@pytest.mark.parametrize("branching", [
    pytest.param(["--world", "a"], id="world-alone-with-an-alert"),
    pytest.param(["--episode", T.EPISODE_ID], id="episode-alone"),
])
def test_a_cut_is_refused_with_either_branching_flag_alone(tmp_path, capsys, branching):
    """Refusal [r5]: `--world` or `--episode` on its own beside `--as-of` is refused naming
    `--as-of`, not left to a later check or run."""
    base, seed = T.runs_base(tmp_path)
    before = sorted(p.name for p in base.iterdir())
    clock = C.FakeClock(C.ARM_START)
    alert = [] if "--episode" in branching else [str(RunPaths(seed).alert)]

    out = C.run_main([*alert, "--tenant", T.current_tenant().id, *branching, "--as-of", AS_OF_Z],
                     clock=clock, main=C.script(clock, (0, C.DONE)))

    refused(out, capsys, tmp_path, "--as-of", before, base)


def refused_moment(tmp_path, capsys, flags: list[str], needle: str) -> None:
    base, seed = T.runs_base(tmp_path)
    before = sorted(p.name for p in base.iterdir())
    clock = C.FakeClock(C.ARM_START)

    out = C.run_main([*C.natural_argv(RunPaths(seed).alert, T.current_tenant().id), *flags],
                     clock=clock, main=C.script(clock, (0, C.DONE)))

    refused(out, capsys, tmp_path, needle, before, base)


@pytest.mark.parametrize("flag", ["--as-of", "--arrived-by"])
@pytest.mark.parametrize("moment", [
    pytest.param("2026-10-20T09:00:00", id="naive"),
    pytest.param("2026-10-20", id="date-only"),
    pytest.param("", id="empty"),
    pytest.param("yesterday", id="junk"),
])
def test_a_cut_moment_that_is_not_an_instant_is_refused_naming_the_flag(
    tmp_path, capsys, flag, moment,
):
    """Refusal (agent decision within r6.1: a moment is ISO-8601 with an offset or `Z`; a naive
    time is never read as UTC) names the flag and mints no run."""
    other = ["--as-of", AS_OF_Z] if flag == "--arrived-by" else []

    refused_moment(tmp_path, capsys, [*other, flag, moment], flag)


@pytest.mark.parametrize("flag", ["--as-of", "--arrived-by"])
@pytest.mark.parametrize("moment", [
    pytest.param("0001-01-01T00:00:00+02:00", id="before-year-1-in-utc"),
    pytest.param("9999-12-31T23:59:59-02:00", id="after-year-9999-in-utc"),
])
def test_a_cut_moment_outside_the_representable_years_is_refused_cleanly(
    tmp_path, capsys, flag, moment,
):
    """Refusal: an offset moment whose UTC instant falls outside years 1-9999 is a refusal naming
    the flag, never an `OverflowError` out of the launch."""
    other = ["--as-of", AS_OF_Z] if flag == "--arrived-by" else []

    refused_moment(tmp_path, capsys, [*other, flag, moment], flag)
