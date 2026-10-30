"""#1347 O5 / product-side cut: `run.py --as-of T [--arrived-by A]` starts the run clock at T,
cuts every call at (T, A), and refuses the flag combinations a cut run cannot honour."""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
from typing import Any

import pytest

from defender.records import RunPaths
from defender.records import _provenance
from defender.systems.verbs import ModuleVerbRegistry
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


def recording_registry(seen: Seen) -> type:
    """The real `ModuleVerbRegistry` (real adapters, real wire), noting the run state's budget and
    each payload; it changes no call."""

    class Recording(ModuleVerbRegistry):
        def verbs(self, system: str):
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


def test_a_cut_runs_clock_starts_at_as_of_not_at_launch(tmp_path):
    """O5: the first visible time is as_of plus the run's own elapsed seconds, whatever the clock
    source reads at launch."""
    out, _seen, _clock = launch(tmp_path, CUT_FLAGS)

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


def test_a_cut_run_records_the_run_clocks_start_not_wall_time(tmp_path):
    """O5 [r6]/P4: the run state's created_at/started_at and provenance's start are as_of, with
    no wall time beside the shifted clock."""
    out, seen, _clock = launch(tmp_path, CUT_FLAGS)

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


def test_a_cut_run_writes_nothing_about_the_cut_beyond_the_clock_stamps(tmp_path):
    """FR10/P4: neither arrived_by nor the launch's wall-clock date appears in any file under the
    run dir; the as_of-derived stamps do (positive control: the walk reads real files)."""
    as_of, arrived_by = "2026-03-02T09:00:00Z", "2026-03-04T14:41:53Z"
    wall = {dt.datetime.now(dt.UTC).date().isoformat(), dt.date.today().isoformat(),
            C.ARM_START.date().isoformat()}
    assert not wall & {"2026-03-02", "2026-03-04"}, "fixture dates collide with the wall clock"

    out, _seen, _clock = launch(tmp_path, ["--as-of", as_of, "--arrived-by", arrived_by])

    assert out.exit == 0, f"refusal={out.refusal}"
    files = [p for p in Path(out.run_dir).rglob("*") if p.is_file()]
    text = {p: p.read_bytes().decode("utf-8", "replace") for p in files}
    assert any("2026-03-02T09:00:20" in t for t in text.values()), (
        "no file carries the as_of-derived run-clock stamp: the walk is not reading the run")
    leaks = {str(p.relative_to(out.run_dir)): needle for p, t in text.items()
             for needle in ("2026-03-04", "14:41:53", "20260304", *wall) if needle in t or needle in str(p)}
    assert not leaks, f"the cut or the launch's wall time is written into the run dir: {leaks}"


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
