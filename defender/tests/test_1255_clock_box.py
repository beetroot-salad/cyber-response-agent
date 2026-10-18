"""#1255 slice D — the box's own time follows the run clock.

Design rev 4, "Time / Into the box": the SQL engine runs in the box and evaluates time itself,
and shadowing `now()` is not enough (U3, executed: `current_timestamp`, `current_date`,
`localtimestamp`, `get_current_timestamp()`, `transaction_timestamp()` bypass a macro). The
agent recommendation: "a time-faking library preloaded in the box image for every run, reading
the run clock from a small read-only file in its own mount (e.g. `/clock`), readable by the
preload but outside the permission gate's read shapes. A natural run reads an offset of zero,
so the shape is the same." U4 (the preload under gVisor) is unprobed; no gVisor on this host.

CI has no box, so the CI half is STATIC, over the `docker run` argv the REAL `start_box`
composes (the recording docker fake, `_box665.RecordingDocker`) when the REAL `run.main` starts
a run through the dossier's composition — for a natural run and for an arm of it:

  * K1: every run's create command carries exactly one read-only bind whose TARGET lies outside
    the model view's three roots (`/runs/current`, `/defender`, `/agent`) — the clock mount —
    and an arm's is at the same target as a natural run's. Its source exposes none of the run's
    trees. The target is deliberately not named (the design says "e.g."): it is found as the one
    read-only bind outside the model roots — the rule `test_1092_box_mark_env._without_the_clock`
    exempts it by, so the two suites agree on which mount is the clock's — and every later
    assertion reads the target found. A clock mounted INSIDE a model root (say
    `/runs/current/.clock`) is no clock mount by this rule, and K1 fails on it.
  * K2: at the TOOL BOUNDARY (rev 5 C11: the contract is what the model hands a tool and what
    the box receives, not how the gate's own functions spell their inputs), MAIN and gather —
    real agents over `bind`-built deps and a recording box — are refused `read_file` and `cat`
    of the clock target and of a file under it, and no such call reaches the box. Positive
    control, same agents and box: the run's alert at its model path reads back, and its `cat`
    reaches the box.
  * K1 (content): the clock mount's SOURCE — a host file, so it is observable with no box —
    holds the run clock's reading once the run has started and its box has run a command: for
    a natural run, its clock source's reading; for an arm, the source's reading at the branch
    point (rev 5 C4), never the arm's own clock source's. An empty file nothing writes, or one
    holding the wall time or a zero offset, is a mount with no clock in it.
  * K3: the preload is configured for every run — on the create command (`LD_PRELOAD`) or by an
    INSTRUCTION of the box image recipe (an `ENV LD_PRELOAD=…`, or an instruction naming
    `/etc/ld.so.preload`), read the way BuildKit reads the recipe: a comment configures
    nothing — and an arm's box carries the same time configuration as a natural run's (same
    preload, same preload/clock variables, the clock mount at the same target), with a preload
    present on both sides so the comparison is never of two empty sets.

What K3 accepts is deliberately only "a preload is configured", never how the library gets into
the box: the design says "a time-faking library preloaded in the box image for every run,
reading the run clock from a small read-only file in its own mount", and the owner has not
decided how the image obtains it (OPEN: `test_1092_dockerfile` today pins the recipe word for
word — six instructions, no `ENV`, one `COPY` of the two lock files, the box extra exactly
`duckdb` and `pytz` — which leaves no recipe route for a preload at all; that conflict is the
owner's to settle, not this file's).

The live half (`live` marker, skipped in CI and here) is K4: inside a real box, the six SQL
spellings U3 found and python's own clock read the run clock, not the wall clock — for a
natural run, and for an arm, whose in-box time is the source's reading at the branch point plus
the arm's own seconds (rev 5 C4), never its own clock source's.

What the clock FILE holds is checked statically WITHOUT fixing its format or its rewrite
schedule, neither of which the design fixes (an offset — "a natural run reads an offset of zero"
— or an absolute time, in what spelling; and when the host rewrites it, since the run clock
pauses for oracle turns). K1 (content) reads the file at a point where the run clock has not
moved since the run started — after the box's first command, so a host that writes it per
command is read after a write — and accepts any common spelling that DECODES to the run clock's
reading there: an ISO-8601 time, epoch seconds or milliseconds, or a signed offset in
seconds (or `s`/`m`/`h`/`d` units) from the wall clock — the offset the box's own wall clock
needs to read the run clock, which is what K4 then asserts live. Contract-repair finding F-K1:
an empty file mounted at `/clock` and a preload named only in a Dockerfile comment passed every
static check here. Finding F2-K1: a file written once passed that read too, so a second natural
case moves the run clock between two box commands and reads the file after the second — still
no schedule fixed, only that the file then holds the run clock as it is at that point.

Slice B owns every other assertion about the box's mounts and environment; nothing here names
a model path.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import functools
import re
import shlex
import subprocess
from pathlib import Path
from typing import Any

import pytest

from defender.run_repository import RUN_LAYOUT, RunPaths
from defender.runtime import box as box_mod
from defender.tests import _1255_clock as C
from defender.tests import _1255_view as V
from defender.tests import _triplet_947 as T
from defender.tests._spec1092 import STOCK_ROOTFS
from defender.tests.e2e._box665 import RecordingDocker, reaped_after_create, requires_live_box

pytestmark = pytest.mark.e2e

START = C.SOURCE_START
L1, L2 = C.LESSONS[:2]
_PRELOAD_KEY = re.compile(r"PRELOAD|FAKETIME|CLOCK", re.IGNORECASE)


@pytest.fixture(autouse=True)
def _roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    T.isolate_learning_state(tmp_path, monkeypatch)


class Captured:
    """One `run.main` start through the recording docker: the create argv and what the
    investigation was handed (the run's folder and tenant)."""

    def __init__(self) -> None:
        self.docker = RecordingDocker()
        self.kwargs: dict[str, Any] = {}

    def investigate(self, **kw: Any) -> dict:
        self.kwargs = dict(kw)
        return {"output": "", "requests": 0, "truncated_by": None}

    @property
    def run_dir(self) -> Path:
        return Path(self.kwargs["run"].run_dir)

    def trees(self) -> tuple[Path, ...]:
        """The run's own bound trees, as host paths: the run folder (its input directory lies
        under it), the checkout, the tenant agent half."""
        return (self.run_dir, C.DEFENDER, Path(self.kwargs["tenant"].agent))

    def clock_mounts(self) -> list[dict]:
        """Every read-only bind whose TARGET lies outside the model view's three roots — the
        rule `test_1092_box_mark_env._without_the_clock` exempts the clock's mount by
        (`_1255_view.under_model_root`), so the two suites identify the same mount. By target,
        not by source: what the model can reach in the box is decided by where a mount lands,
        and a mount whose source is outside the trees but whose target is inside one would be
        readable by a plain `cat`."""
        return [m for m in self.docker.mounts()
                if m["readonly"] and not V.under_model_root(m["target"])]


def _within(path: Path, tree: Path) -> bool:
    return path == tree or tree in path.parents


def _start(argv: list[str]) -> Captured:
    """`run.main(argv)` up to the box start: the REAL lifecycle and `start_box` over the
    recording docker (a stock image, so the image resolver reads nothing); the investigation is
    a recorder (a static check needs no model turn)."""
    cap = Captured()
    out = C.run_main(argv, clock=C.FakeClock(START), main=None, investigate=cap.investigate,
                     start_box=functools.partial(box_mod.start_box, docker=cap.docker,
                                                 spec=box_mod.BoxSpec(rootfs=STOCK_ROOTFS)))
    assert out.exit == 0, f"run.main did not complete: exit={out.exit} refusal={out.refusal}"
    assert cap.docker.create_argv is not None, "no box was created"
    assert cap.kwargs, "the investigation was never reached"
    return cap


@pytest.fixture
def natural(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Captured:
    """A natural run's box start through `run.main`, from the fixture tenant's seed alert. A box
    fault must not turn into the host executor here."""
    base, seed = T.runs_base(tmp_path)
    tenant_id = T.mod("_tenant").read_tenant(base).tenant_id
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    monkeypatch.delenv(box_mod.BoxSpec.ENV_VAR, raising=False)
    return _start(C.natural_argv(RunPaths(seed).alert, tenant_id))


@pytest.fixture
def arm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, natural: Captured) -> Captured:
    """An arm's box start through `run.main --episode`. The arm forks a source RECORDED through
    the same composition (unboxed, `_1255_clock.record_source`) at its tool-calling response —
    a source this change can fork (N4 refuses older ones), so the arm reaches its box start on
    both sides of #1255. Red (class a) until `run_investigation` accepts `clock=`."""
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    tenant_id, source = C.record_source(tmp_path)
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    branch = C.branch_response(source, tool="read_file", arg_suffix=f"/{L2}.md")
    ep = C.control_episode(tmp_path, source, branch)
    return _start(C.arm_argv(tenant_id, ep.name, "a"))


def _trees_are_bound(cap: Captured) -> None:
    """Positive control for the clock-mount filter: the run's own trees ARE on the argv."""
    sources = {Path(m["source"]) for m in cap.docker.mounts()}
    assert cap.run_dir in sources, f"the run's own trees are not bound, so the filter proves nothing: {cap.docker.mounts()}"
    assert C.DEFENDER in sources, f"the run's own trees are not bound, so the filter proves nothing: {cap.docker.mounts()}"


def test_k1_a_natural_runs_box_carries_one_read_only_clock_mount(natural):
    """Into the box, every run: a natural run's create command carries exactly one read-only
    bind whose target lies outside the model view's three roots (the clock file's own mount),
    and its source exposes none of the run's trees. Positive control: the run's trees are bound.
    Today: the trees themselves are bound at host targets (slice B's model view moves them under
    the model roots), and no clock mount exists."""
    _trees_are_bound(natural)
    found = natural.clock_mounts()
    assert len(found) == 1, (
        f"the box needs exactly one read-only mount for the run clock's file: {found}")
    source = Path(found[0]["source"])
    assert not any(_within(tree, source) for tree in natural.trees()), (
        f"the clock mount's source {source} exposes one of the run's trees")


def test_k1_an_arms_box_carries_its_clock_mount_at_the_natural_runs_target(natural, arm):
    """Into the box, every run, same shape (P1/O1): an arm's create command carries exactly one
    clock mount too, read-only, at the SAME target as a natural run's — a different path would
    tell the model which kind of run it is in."""
    _trees_are_bound(arm)
    found = {"natural": natural.clock_mounts(), "arm": arm.clock_mounts()}
    assert all(len(m) == 1 for m in found.values()), (
        f"each run's box needs exactly one read-only mount for the run clock's file: {found}")
    assert found["natural"][0]["target"] == found["arm"][0]["target"], (
        f"an arm's clock mount sits elsewhere than a natural run's: {found}")
    source = Path(found["arm"][0]["source"])
    assert not any(_within(tree, source) for tree in arm.trees()), (
        f"the arm's clock mount source {source} exposes one of its trees")


#: Any ISO-8601-like time in the clock file (`T` or space, optional fraction and zone; a
#: libfaketime-style `@` before it is just a neighbour).
_ISO_IN_FILE = re.compile(
    r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?")
#: Any number in the clock file, with an optional sign and unit (`+139000000`, `-3.5d`, `1.9e9`
#: spelled out) — read as epoch seconds or milliseconds, or as an offset from the wall clock.
#: The units are libfaketime's relative spelling (`-86400`, `+2.5h`, `-1y`; a `y` is 365 days),
#: so a file in that format decodes (#1255 K3, owner decision 2026-10-16); its `x<rate>` /
#: `i<step>` modifiers carry no instant and are not read.
_NUMBER_IN_FILE = re.compile(r"(?<![\w.])([+-]?)(\d+(?:\.\d+)?)([smhdy]?)(?![\w.])")
_UNIT_SECONDS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "y": 365 * 86400}
#: How far a decoded reading may sit from the run clock's: the file is read a moment after it
#: was written, and an offset is applied to the wall clock at the READ.
_FILE_SLACK = dt.timedelta(minutes=2)


def _clock_file_readings(text: str, wall: dt.datetime) -> list[tuple[str, dt.datetime]]:
    """Every instant the clock file's text can be read as, with how: an absolute time in it,
    a number as epoch seconds or milliseconds, or a signed number of seconds (or `s`/`m`/`h`/`d`)
    as an offset from `wall`. The test's own decoding of the spellings the design leaves open;
    nothing about production's format is assumed beyond "an offset or an absolute time"."""
    out: list[tuple[str, dt.datetime]] = []
    for m in _ISO_IN_FILE.finditer(text):
        zone = m.group(4) or "Z"
        if zone != "Z" and ":" not in zone:
            zone = f"{zone[:3]}:{zone[3:]}"
        moment = C.instant(f"{m.group(1)}T{m.group(2)}{m.group(3) or ''}{zone}")
        if moment is not None:
            out.append(("an absolute time", moment))
    for m in _NUMBER_IN_FILE.finditer(text):
        sign, digits, unit = m.groups()
        value = float(digits) * _UNIT_SECONDS[unit] * (-1 if sign == "-" else 1)
        if not sign and not unit:
            for scale, how in ((1, "epoch seconds"), (1000, "epoch milliseconds")):
                with contextlib.suppress(OverflowError, OSError, ValueError):
                    out.append((how, dt.datetime.fromtimestamp(value / scale, dt.UTC)))
        with contextlib.suppress(OverflowError):
            out.append(("an offset from the wall clock", wall + dt.timedelta(seconds=value)))
    return out


def _clock_file_probe(docker: RecordingDocker, seen: dict[str, Any]) -> Any:
    """A MAIN turn (a callable over the request text) that, while the run is live and after its
    box has run the previous turn's command, reads the clock mount's SOURCE on the host — the
    one read-only bind outside the model roots (K1's rule), a file or a folder of files — and
    the wall clock at that read, into `seen`, then ends the run."""

    def probe(_text: str) -> Any:
        mounts = [m for m in docker.mounts()
                  if m["readonly"] and not V.under_model_root(m["target"])]
        seen["mounts"] = mounts
        seen["wall"] = dt.datetime.now(dt.UTC)
        if len(mounts) == 1:
            source = Path(mounts[0]["source"])
            files = [source] if source.is_file() else sorted(
                p for p in source.rglob("*") if p.is_file()) if source.is_dir() else []
            seen["files"] = [str(p) for p in files]
            seen["text"] = "\n".join(p.read_text(encoding="utf-8", errors="replace")
                                     for p in files)
        return C.DONE

    return probe


def _clock_file_after_a_command(argv: list[str], clock: C.FakeClock, *,
                                seconds_before: tuple[float, ...] = (0,),
                                command: str = f"cat {V.MODEL_ALERT}",
                                ) -> tuple[dict[str, Any], C.Launched, RecordingDocker]:
    """`run.main(argv)` through the dossier's composition over the recording docker, its MAIN a
    script of one box `command` per entry of `seconds_before` — the model taking that many
    run-clock seconds before it — then `_clock_file_probe`, which takes none. By default one
    `cat` of the run's alert at its model path (a command that reaches the box — K2's positive
    control) after no time at all."""
    docker = RecordingDocker()
    seen: dict[str, Any] = {}
    out = C.run_main(argv, clock=clock,
                     main=C.script(clock, *((s, C.bash(command)) for s in seconds_before),
                                   (0, _clock_file_probe(docker, seen))),
                     start_box=functools.partial(box_mod.start_box, docker=docker,
                                                 spec=box_mod.BoxSpec(rootfs=STOCK_ROOTFS)))
    return seen, out, docker


def _assert_clock_file_reads(seen: dict[str, Any], out: C.Launched, reading: dt.datetime,
                             not_reading: dt.datetime | None = None) -> None:
    """The clock file `seen` read decodes to `reading` (within `_FILE_SLACK`), and — when given —
    to nothing near `not_reading` (the arm's own clock source)."""
    assert "mounts" in seen, (
        f"the run never reached the probe turn: exit={out.exit} refusal={out.refusal} "
        f"summary={str(out.summary)[:300]}")
    assert len(seen["mounts"]) == 1, f"no single clock mount to read (K1): {seen['mounts']}"
    text = seen.get("text", "")
    assert text.strip(), (
        f"the clock mount's source holds nothing once the run is live and its box has run a "
        f"command ({seen.get('files')}): nothing writes the run clock into it")
    readings = _clock_file_readings(text, seen["wall"])
    near = [(how, m) for how, m in readings if abs(m - reading) <= _FILE_SLACK]
    assert near, (
        f"the clock file does not hold the run clock's reading {reading.isoformat()} in any "
        f"spelling (absolute time, epoch, or offset from the wall clock): {text[:200]!r} reads "
        f"as {[(how, m.isoformat()) for how, m in readings][:8]}")
    if not_reading is not None:
        wrong = [(how, m) for how, m in readings if abs(m - not_reading) <= _FILE_SLACK]
        assert not wrong, (
            f"the arm's clock file holds its own clock source's reading "
            f"{not_reading.isoformat()}: {text[:200]!r}")


def test_k1_a_natural_runs_clock_file_holds_the_run_clocks_reading(tmp_path, monkeypatch):
    """Into the box, every run (F-K1): the clock mount is a CLOCK — once a natural run is live
    and its box has run a command, the mount's source file, read on the host, holds the run
    clock's reading: its clock source's `START` (2031, years from the wall clock), as an
    absolute time or as the offset the box's wall clock needs (see the module docstring for
    the spellings accepted). An empty file nothing writes fails; so does the wall time, or an
    offset of zero from it.

    Positive control: K1's mount rule finds exactly one clock mount on this run's create
    command (the source read is that mount's). Today: no clock mount exists."""
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    monkeypatch.delenv(box_mod.BoxSpec.ENV_VAR, raising=False)
    base, seed = T.runs_base(tmp_path)
    tenant_id = T.mod("_tenant").read_tenant(base).tenant_id

    seen, out, _docker = _clock_file_after_a_command(
        C.natural_argv(RunPaths(seed).alert, tenant_id), C.FakeClock(START))

    _assert_clock_file_reads(seen, out, START)


def test_k1_an_arms_clock_file_holds_its_run_clocks_reading_not_its_sources(tmp_path,
                                                                           monkeypatch):
    """Into the box, an ARM (F-K1, rev 5 C4): the arm's clock mount source holds the ARM's run
    clock — the source's reading at the branch point (`R = START+610`), the arm having taken no
    seconds of its own — never its own clock source's reading (`ARM_START`, 2040) and not the
    wall clock. This is K4's arm demand made observable without a box: K4 then asserts live
    that the box's clocks read what this file says."""
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    tenant_id, source = C.record_source(tmp_path)
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    monkeypatch.delenv(box_mod.BoxSpec.ENV_VAR, raising=False)
    branch = C.branch_response(source, tool="read_file", arg_suffix=f"/{L2}.md")
    ep = C.control_episode(tmp_path, source, branch)

    seen, out, _docker = _clock_file_after_a_command(
        C.arm_argv(tenant_id, ep.name, "a"), C.FakeClock(C.ARM_START))

    _assert_clock_file_reads(seen, out, C.BRANCH_READING, not_reading=C.ARM_START)


#: How far the run clock moves between two box commands in the moving-clock K1 case: five times
#: the file check's slack, half the default wall-clock limit (no budget warning on the way).
_MOVE = 600
#: The run's alert by its run-relative path — the same file through the run folder before and
#: after slice B's mapping, so the moving-clock case asks nothing of the model view.
_RELATIVE_CAT = f"cat {RUN_LAYOUT.alert_input_dir}/alert.json"


def test_k1_a_natural_runs_clock_file_follows_the_run_clock_between_commands(tmp_path,
                                                                            monkeypatch):
    """Into the box, every run (F2-K1): the clock file follows the run clock — it is not written
    once. MAIN runs a box command at `START`, then takes `_MOVE` seconds of run-clock time and
    runs a second; read after the second, the mount's source decodes to `START + _MOVE` (the
    spellings and slack of `_assert_clock_file_reads`), not to `START`.

    Why the design asks it: rev 4 "Time": the run clock is the source "every time the model can
    see comes from … the SQL engine's `now()`, times in prompts and tool output"; "Into the
    box": "The SQL engine runs in the box and evaluates time itself", the preload "reading the
    run clock from a small read-only file in its own mount"; rev 5 C4: "The run clock governs
    model-visible times." So a command the box runs after the run clock moved must read the
    moved clock, and the file is the box's channel for it. No rewrite schedule is fixed: per
    command, on every reading, or continuously all pass — only "after the second command the
    file holds the run clock as it is then".

    Why this is not a CI artifact of the injected clock: the move here grows the gap between
    the run clock and the box's own wall clock by `_MOVE` between two commands. On a natural
    run in production that gap grows the same way when the host's wall clock steps back: rev 5
    C10 "A step back in the source is absorbed" (the run clock holds), while the box's wall
    clock steps back with the host's. A file left as it was then puts in-box `now()` earlier
    than times the model has already seen — rev 4 O4 "Every time the model can see agrees with
    every other one and never runs earlier than the history's last timestamp". So a writer
    that refreshes only at box start, or only when an oracle pause ends, is wrong in
    production too.

    A file written once (at box start or at the first command) decodes to `START` here and
    fails; `test_k1_a_natural_runs_clock_file_holds_the_run_clocks_reading` cannot see it, since
    it reads the file before the run clock has moved. An oracle-paused turn adds nothing in CI:
    on an injected clock the run clock does not move during a pause, so a written-once file
    and one that follows the clock read the same afterwards (K4 is live-only).

    Positive control: the script's move ran (the clock source advanced by `_MOVE`). Red (class
    a) until `run_investigation` accepts `clock=`."""
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    monkeypatch.delenv(box_mod.BoxSpec.ENV_VAR, raising=False)
    base, seed = T.runs_base(tmp_path)
    tenant_id = T.mod("_tenant").read_tenant(base).tenant_id
    clock = C.FakeClock(START)

    seen, out, _docker = _clock_file_after_a_command(
        C.natural_argv(RunPaths(seed).alert, tenant_id), clock,
        seconds_before=(0, _MOVE), command=_RELATIVE_CAT)

    assert _MOVE in clock.advances, (
        f"control: the model's {_MOVE} s between the two commands never ran: {clock.advances} "
        f"(exit={out.exit} refusal={out.refusal})")
    _assert_clock_file_reads(seen, out, C.at(START, _MOVE))


def _file_written(reading: dt.datetime, spelling: str) -> str:
    """The clock file's text for `reading` in one spelling the K1 file check accepts, written now
    (an offset is from the wall clock at the write)."""
    return {"iso": reading.isoformat(),
            "libfaketime absolute": "@" + reading.strftime("%Y-%m-%d %H:%M:%S"),
            "epoch seconds": f"{reading.timestamp():.0f}",
            "offset": f"{(reading - dt.datetime.now(dt.UTC)).total_seconds():+.0f}"}[spelling]


@pytest.mark.parametrize("spelling", ["iso", "libfaketime absolute", "epoch seconds", "offset"])
def test_k1_the_file_check_tells_a_clock_written_once_from_one_that_follows(spelling):
    """The instrument behind the moving-clock K1 case, over a fake writer and no run: a box
    command at `START`, the run clock moving `_MOVE` seconds, a second command, then the read.
    A writer that rewrites the file at each command passes `_assert_clock_file_reads` for
    `START + _MOVE`; one that wrote it only at the first command is refused — in every spelling
    the check decodes. Green today: it is the check's own discrimination."""
    clock = C.FakeClock(START)
    once = _file_written(clock(), spelling)        # both writers, at the first command
    clock.advance(_MOVE)
    follows = _file_written(clock(), spelling)     # only the one that follows, at the second
    mount = [{"source": "<clock file>", "target": "/clock", "readonly": True}]

    def check(text: str) -> None:
        seen = {"mounts": mount, "files": ["<clock file>"], "text": text,
                "wall": dt.datetime.now(dt.UTC)}
        _assert_clock_file_reads(seen, C.Launched(), clock())

    check(follows)
    with pytest.raises(AssertionError, match="does not hold the run clock's reading"):
        check(once)


def _role(name: str) -> tuple[Any, str]:
    """The role's definition as a run binds it, and its agent id."""
    from defender.runtime.driver import MAIN_DEF
    from defender.tests import _tenants1106

    return (MAIN_DEF, "main") if name == "main" else (
        _tenants1106.fixture_gather_def(), "gather:l-001")


def _answers_at_the_tool_boundary(defn: Any, agent_id: str, run_dir: Path,
                                  calls: list[tuple[str, dict]], log_dir: Path,
                                  ) -> tuple[list[tuple[str, str]], Any]:
    """Drive ONE real agent (`build_agent_core`: the real tools, hooks and gate) over deps
    `bind` builds for `run_dir`, its box a recording box (`test_959_downstream.Box`), through
    a scripted model that makes `calls` one per turn. Returns what each call came back as to
    the model — `("return", text)` or `("retry", text)`, `_1255_view.Recorder.answer_to` — and
    the box, whose `calls` are what reached it."""
    import asyncio
    from dataclasses import replace

    from pydantic_ai.models import override_allow_model_requests
    from pydantic_ai.models.function import FunctionModel
    from pydantic_ai.usage import UsageLimits

    from defender.hooks.budget_enforcer import DEFAULT_LIMITS
    from defender.runtime import driver, observe
    from defender.runtime.agent_definition import bind, effective_tools_for
    from defender.runtime.box_codec import BoxResult
    from defender.runtime.providers import BuiltModel
    from defender.runtime.run_state import RunState
    from defender.tests.e2e._replay_harness import Turn
    from defender.tests.test_959_downstream import Box

    model = V.Recorder([Turn(tool_calls=[call]) for call in calls] + [Turn(text="done")])
    box = Box(BoxResult(0, b"box-ran\n", b""))
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = observe.RequestLogger(log_dir / f"{agent_id.replace(':', '-')}.jsonl")
    agent = driver.build_agent_core(
        defn, deps_type=defn.deps_cls, instructions="probe", logger=logger, agent_id=agent_id,
        make_model=lambda name, effort: BuiltModel(FunctionModel(model), None),
        limits=DEFAULT_LIMITS)
    deps = replace(bind(replace(defn, tools=effective_tools_for(defn)), run_dir,
                        defender_dir=C.DEFENDER, box=box),
                   run_state=RunState(run_dir, run_dir.name))

    async def go() -> Any:
        with override_allow_model_requests(False):
            return await agent.run("go", deps=deps,
                                   usage_limits=UsageLimits(request_limit=len(calls) + 4))

    try:
        asyncio.run(go())
    finally:
        logger.close()
    return [model.answer_to(i + 1) for i in range(len(calls))], box


@pytest.mark.parametrize("role", ["main", "gather"])
def test_k2_the_gate_refuses_main_and_gather_a_read_of_the_clock_mount(natural, tmp_path, role):
    """Into the box: the clock file is "readable by the preload but outside the permission
    gate's read shapes" — held at the tool boundary (rev 5 C11). For the target K1 finds, the
    role's `read_file` of the target and of `<target>/clock` comes back refused, and its `cat`
    of each comes back refused WITHOUT reaching the box (a `cat` the box ran would have handed
    the model the clock's content). The role is a real agent over `bind`-built deps (C9) and a
    recording box.

    Positive control, same agent, deps and box: `read_file` of the run's alert at its model path
    (`/runs/current/alert_input/alert.json`) returns the alert's bytes, and its `cat` reaches
    the box — exactly one box call in all. Today: no single clock mount (K1), and the model path
    is not mapped (slice B / C9), so the control is refused too."""
    mounts = natural.clock_mounts()
    assert len(mounts) == 1, f"no single clock mount to check (K1): {mounts}"
    target = mounts[0]["target"].rstrip("/")
    subjects = (target, f"{target}/clock")
    calls = [*(("read_file", {"path": s}) for s in subjects),
             *(("bash", {"command": f"cat {s}"}) for s in subjects),
             ("read_file", {"path": V.MODEL_ALERT}), ("bash", {"command": f"cat {V.MODEL_ALERT}"})]
    defn, agent_id = _role(role)

    answers, box = _answers_at_the_tool_boundary(defn, agent_id, natural.run_dir, calls,
                                                 tmp_path / "logs")

    *clock_answers, alert_read, alert_cat = answers
    alert = RunPaths(natural.run_dir).alert.read_text(encoding="utf-8").strip()
    assert alert_read[0] == "return", (f"positive control: {role}'s read_file of the alert at {V.MODEL_ALERT} did not read it "
        f"back: {alert_read}")
    assert alert in alert_read[1], (f"positive control: {role}'s read_file of the alert at {V.MODEL_ALERT} did not read it "
        f"back: {alert_read}")
    assert alert_cat[0] == "return", (f"positive control: {role}'s cat of the alert did not reach the box exactly once "
        f"(answer {alert_cat}, box calls {[c['command'] for c in box.calls]})")
    assert len(box.calls) == 1, (f"positive control: {role}'s cat of the alert did not reach the box exactly once "
        f"(answer {alert_cat}, box calls {[c['command'] for c in box.calls]})")
    for (tool, args), (kind, text) in zip(calls[:4], clock_answers, strict=True):
        assert kind == "retry", (
            f"{role}'s {tool}({args}) of the run clock's mount came back as a result: {text!r}")
    assert not any(target in c["command"] for c in box.calls), (
        f"a {role} read of the run clock's mount reached the box: "
        f"{[c['command'] for c in box.calls]}")


def _env_assignments(rest: str) -> dict[str, str]:
    """An `ENV` instruction's assignments: `ENV K=V [K2=V2 …]` or the legacy `ENV K V…`."""
    words = shlex.split(rest)
    if words and "=" in words[0]:
        return dict(w.split("=", 1) for w in words if "=" in w)
    return {words[0]: rest.split(None, 1)[1].strip() if len(words) > 1 else ""} if words else {}


def _recipe_preload(instructions: list[str]) -> list[str]:
    """The box image recipe's INSTRUCTIONS that configure a preload: an `ENV` setting
    `LD_PRELOAD` to a non-empty value, or any other instruction naming `/etc/ld.so.preload`
    (the loader's own preload list). Read off the instructions BuildKit runs — continuations
    joined, whole comment lines dropped — never the file's text, so a comment that names a
    preload configures none (F-K1). How the preloaded library itself gets into the image is not
    asked (see the module docstring)."""
    found: list[str] = []
    for ins in instructions:
        keyword, _, rest = ins.partition(" ")
        if keyword.upper() == "ENV":
            if _env_assignments(rest).get("LD_PRELOAD", "").strip().strip("'\""):
                found.append(ins)
        elif "/etc/ld.so.preload" in rest:
            found.append(ins)
    return found


def _box_recipe_preload() -> list[str]:
    from defender.tests.test_1092_dockerfile import _instructions

    return _recipe_preload(_instructions(C.DEFENDER / "box.Dockerfile"))


def test_k3_the_recipe_reader_sees_instructions_not_comments(tmp_path):
    """The reader K3 decides by: a preload named only in a comment is no preload; an `ENV`
    instruction (either form) and a `RUN` writing the loader's preload list each are; an empty
    `LD_PRELOAD` is not. Over planted recipes, so it holds whatever the shipped recipe says.
    Green today: it is the instrument's own discrimination check."""
    from defender.tests.test_1092_dockerfile import _instructions

    assert _recipe_preload(["FROM python:3.11-slim", "RUN true"]) == []
    assert _recipe_preload(["ENV LD_PRELOAD=/usr/lib/faketime/libfaketime.so.1"])
    assert _recipe_preload(["ENV LD_PRELOAD /usr/lib/x.so"])
    assert _recipe_preload(["ENV A=1 LD_PRELOAD=/x.so"])
    assert _recipe_preload(["RUN echo /usr/lib/x.so > /etc/ld.so.preload"])
    assert _recipe_preload(["ENV LD_PRELOAD=''"]) == []
    recipe = tmp_path / "Dockerfile"
    recipe.write_text("FROM x\n# ENV LD_PRELOAD=/x.so: a time-faking library reading /clock\n"
                      "#   /etc/ld.so.preload\nRUN true\n", encoding="utf-8")
    assert _recipe_preload(_instructions(recipe)) == [], (
        "a preload named only in comments read as configured")
    recipe.write_text("FROM x\nENV LD_PRELOAD=/x.so\nRUN true\n", encoding="utf-8")
    assert _recipe_preload(_instructions(recipe)) == ["ENV LD_PRELOAD=/x.so"]


def test_k3_the_box_is_preloaded_for_every_run(natural):
    """Into the box: the time-faking preload is configured for every run — on the create
    command (`LD_PRELOAD`, non-empty) or by an instruction of the box image's recipe
    (`box.Dockerfile`, `_recipe_preload`). Positive control: the create command carries an
    environment."""
    env = natural.docker.env()
    assert env, "the create command carries no environment to inspect"
    in_image = _box_recipe_preload()
    assert in_image or env.get("LD_PRELOAD", "").strip(), (
        "no time-faking preload is configured for the box: neither the create command nor any "
        "instruction of the image recipe sets one (a comment configures nothing)")


def _time_configuration(cap: Captured) -> dict[str, Any]:
    """A run's box time configuration as its create command and image carry it: the preload
    (the create command's `LD_PRELOAD`, else the recipe's preload instructions), every
    preload/clock variable of the create environment, and the clock mount's target."""
    env = cap.docker.env()
    return {"preload": env.get("LD_PRELOAD", "").strip() or tuple(_box_recipe_preload()),
            "variables": {k: v for k, v in env.items() if _PRELOAD_KEY.search(k)},
            "clock mounts": sorted((m["target"], m["readonly"]) for m in cap.clock_mounts())}


def test_k3_an_arms_preload_and_clock_variables_are_the_natural_runs(natural, arm):
    """Into the box, same shape: an arm's box carries the same time configuration as a natural
    run's — the same preload, every preload or clock variable of the create command equal, the
    clock mount at the same target — and an arm differs only in what its clock FILE says.

    Not vacuous (F-K1): both sides must HAVE a preload configured before they are compared, so
    two boxes with no preload and no clock variables at all do not pass as "the same". Positive
    control: both create commands carry an environment."""
    env_n, env_a = natural.docker.env(), arm.docker.env()
    assert env_n, "a create command carries no environment to compare"
    assert env_a, "a create command carries no environment to compare"
    config = {"natural": _time_configuration(natural), "arm": _time_configuration(arm)}
    for side, conf in config.items():
        assert conf["preload"], (
            f"the {side} run's box has no time-faking preload configured — there is no time "
            f"configuration to compare: {conf}")
    assert config["natural"] == config["arm"], (
        f"an arm's box is configured differently from a natural run's: {config}")


# ---------------------------------------------------------------------------------------
# K4 — live: in a real box, every clock reads the run clock (U3, U4)
# ---------------------------------------------------------------------------------------

#: Every spelling U3 found: the two a macro shadows and the five that bypass one.
_SQL = ("SELECT now() AS a, today() AS b, current_timestamp AS c, current_date AS d, "
        "localtimestamp AS e, get_current_timestamp() AS f, transaction_timestamp() AS g "
        "FROM data")
_PY = ("python3 -c 'import datetime, time; "
       "print(datetime.datetime.now(datetime.timezone.utc).isoformat()); print(time.time())'")
_STAMP = re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
#: How far an in-box reading may sit from the run clock: the preload's own refresh and the
#: command's run time. The run clock here is five years from the wall clock.
_SLACK = dt.timedelta(minutes=2)


def _box_probe(out: C.Launched, seen: dict[str, Any]) -> Any:
    """A MAIN turn (a callable over the request text) that, while the run is live, runs the SQL
    and python time probes through the run's own box executor (`out.kwargs["box"]`, set before
    the driver runs) into `seen`, then ends the run."""
    from defender.runtime import bash_exec

    def probe(_text: str) -> Any:
        box, run_dir = out.kwargs["box"], Path(out.kwargs["run"].run_dir)
        seen["probed"] = True
        sql = f"printf '{{\"x\": 1}}' | defender-sql \"{_SQL}\""
        for name, cmd in (("sql", sql), ("py", _PY)):
            res = box.run_parsed(bash_exec.parse(cmd), command=cmd, cwd=run_dir, timeout=60)
            seen[name] = (res.rc, res.out, res.err)
        return C.DONE

    return probe


def _box_reads(seen: dict[str, Any], reading: dt.datetime, out: C.Launched) -> None:
    """Every in-box time the probe collected is `reading` (within `_SLACK`), and every date is
    `reading`'s."""
    assert seen.get("probed"), f"the probe never ran: {out.exit} {out.refusal}"
    rc, sql_out, err = seen["sql"]
    assert rc == 0, f"defender-sql failed in the box: {err}"
    stamps = [C.instant(s.replace(" ", "T")) for s in _STAMP.findall(sql_out)]
    assert len(stamps) >= 5, f"the SQL answer carries fewer timestamps than asked: {sql_out}"
    for stamp in stamps:
        assert stamp is not None, f"an in-box SQL time {stamp} is not the run clock's {reading}: {sql_out}"
        assert abs(stamp - reading) <= _SLACK, f"an in-box SQL time {stamp} is not the run clock's {reading}: {sql_out}"
    dates = set(_DATE.findall(sql_out))
    assert dates == {reading.date().isoformat()}, f"an in-box SQL date is not the run clock's: {dates}"
    rc, py_out, err = seen["py"]
    assert rc == 0, f"python failed in the box: {err}"
    iso, epoch = py_out.split()[:2]
    assert abs(C.instant(iso) - reading) <= _SLACK, f"python's clock in the box: {iso}"
    assert abs(dt.datetime.fromtimestamp(float(epoch), dt.UTC) - reading) <= _SLACK, (
        f"python's time.time() in the box: {epoch}")


@pytest.mark.live
@requires_live_box
def test_k4_live_in_box_time_reads_the_run_clock(tmp_path, monkeypatch):
    """U3/U4, live: inside a real box (default runtime) of a natural run whose clock source
    reads 2031, `defender-sql` answers every time spelling with the run clock's time, and
    python's own clock does too — not the wall clock. Probed through the run's own box
    executor from MAIN's first turn (no seconds taken: the run clock reads `START`), while the
    run is live."""
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    base, seed = T.runs_base(tmp_path)
    tenant_id = T.mod("_tenant").read_tenant(base).tenant_id
    clock = C.FakeClock(START)
    out = C.Launched()
    seen: dict[str, Any] = {}

    C.run_main(C.natural_argv(RunPaths(seed).alert, tenant_id), clock=clock,
               main=C.script(clock, (0, _box_probe(out, seen))), start_box=box_mod.start_box,
               out=out)

    _box_reads(seen, START, out)


@pytest.mark.live
@requires_live_box
def test_k4_live_an_arms_in_box_time_reads_its_run_clock_not_its_source(tmp_path, monkeypatch):
    """U3/U4 + Time + C4, live, on an ARM (R1-5): inside a real box of an arm whose own clock
    source reads 2040, every in-box time reads the ARM's run clock — the source's reading at
    the branch point (`R = START+610`) plus the arm's own 20 s — not the arm source's 2040 and
    not the wall clock. This is where the arm's clock file is shown to reflect `R` (see the
    module docstring: its content is not checked statically). Probed from the arm's first
    model request, through the arm's own box executor."""
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    tenant_id, source = C.record_source(tmp_path)
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    branch = C.branch_response(source, tool="read_file", arg_suffix=f"/{L2}.md")
    ep = C.control_episode(tmp_path, source, branch)
    arm_clock = C.FakeClock(C.ARM_START)
    out = C.Launched()
    seen: dict[str, Any] = {}

    C.run_main(C.arm_argv(tenant_id, ep.name, "a"), clock=arm_clock,
               main=C.script(arm_clock, (20, _box_probe(out, seen))), start_box=box_mod.start_box,
               out=out)

    _box_reads(seen, C.at(C.BRANCH_READING, 20), out)


@pytest.mark.parametrize("fault", ["missing", "wrong-token"])
def test_a_clock_mount_must_round_trip_before_the_box_is_returned(tmp_path, monkeypatch, fault):
    """A healthy run bind cannot certify an absent or misdirected clock bind.

    The daemon double keeps every ordinary startup read healthy and corrupts only reads
    through the clock mount. The clock must fail closed before a usable box escapes.
    """
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    docker = RecordingDocker(existing_token="self")
    clock_reads = []

    def faulty_clock_mount(argv, **kwargs):
        args = list(argv)
        clock_mounts = [m for m in docker.mounts()
                        if m["target"] == "/clock"] if docker.create_argv is not None else []
        if (len(args) > 1 and args[1] == "exec" and clock_mounts
                and Path(args[-1]).is_relative_to(Path("/clock"))):
            docker.calls.append(args)
            clock_reads.append(args)
            return subprocess.CompletedProcess(
                args, 1 if fault == "missing" else 0,
                stdout="" if fault == "missing" else "ANOTHER-CLOCK-TREE",
                stderr="missing clock bind" if fault == "missing" else "")
        return docker(args, **kwargs)

    with pytest.raises(box_mod.BoxFault):
        box_mod.start_box(run_dir, C.DEFENDER, docker=faulty_clock_mount,
                          spec=box_mod.BoxSpec(rootfs=STOCK_ROOTFS))
    assert clock_reads, "startup never verified the clock bind independently of the run bind"
    assert reaped_after_create(docker.calls), "a box with an unverified clock survived startup"
    clock_mount, = [m for m in docker.mounts() if m["target"] == "/clock"]
    assert not Path(clock_mount["source"]).exists(), "the failed startup leaked its clock tree"
