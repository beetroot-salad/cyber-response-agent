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
  * K3: the preload is configured for every run — on the create command (`LD_PRELOAD`) or in the
    box image recipe — and every preload/clock variable on the create command is the same for
    an arm as for a natural run (same shape).

The live half (`live` marker, skipped in CI and here) is K4: inside a real box, the six SQL
spellings U3 found and python's own clock read the run clock, not the wall clock — for a
natural run, and for an arm, whose in-box time is the source's reading at the branch point plus
the arm's own seconds (rev 5 C4), never its own clock source's.

What the clock FILE holds is not checked statically: the design fixes neither its format (an
offset — "a natural run reads an offset of zero" — or an absolute time, and in what spelling)
nor when the host rewrites it (the run clock pauses for oracle turns, so its content moves
during the run, after the box is created). A static assertion on its content would fix one of
those for the implementation, so that the arm's file reflects `R` is asserted live only, by
what the box's clocks read (K4).

Slice B owns every other assertion about the box's mounts and environment; nothing here names
a model path.
"""
from __future__ import annotations

import datetime as dt
import functools
import re
from pathlib import Path
from typing import Any

import pytest

from defender.run_repository import RunPaths
from defender.runtime import box as box_mod
from defender.tests import _1255_clock as C
from defender.tests import _1255_view as V
from defender.tests import _triplet_947 as T
from defender.tests._spec1092 import STOCK_ROOTFS
from defender.tests.e2e._box665 import RecordingDocker, requires_live_box

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
    assert cap.run_dir in sources and C.DEFENDER in sources, (
        f"the run's own trees are not bound, so the filter proves nothing: {cap.docker.mounts()}")


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
    assert alert_read[0] == "return" and alert in alert_read[1], (
        f"positive control: {role}'s read_file of the alert at {V.MODEL_ALERT} did not read it "
        f"back: {alert_read}")
    assert alert_cat[0] == "return" and len(box.calls) == 1, (
        f"positive control: {role}'s cat of the alert did not reach the box exactly once "
        f"(answer {alert_cat}, box calls {[c['command'] for c in box.calls]})")
    for (tool, args), (kind, text) in zip(calls[:4], clock_answers, strict=True):
        assert kind == "retry", (
            f"{role}'s {tool}({args}) of the run clock's mount came back as a result: {text!r}")
    assert not any(target in c["command"] for c in box.calls), (
        f"a {role} read of the run clock's mount reached the box: "
        f"{[c['command'] for c in box.calls]}")


def test_k3_the_box_is_preloaded_for_every_run(natural):
    """Into the box: the time-faking preload is configured for every run — on the create
    command (`LD_PRELOAD`) or in the box image's recipe (`box.Dockerfile`: `LD_PRELOAD` or
    `/etc/ld.so.preload`). Positive control: the create command carries an environment."""
    env = natural.docker.env()
    assert env, "the create command carries no environment to inspect"
    recipe = (C.DEFENDER / "box.Dockerfile").read_text(encoding="utf-8")
    in_image = "LD_PRELOAD" in recipe or "ld.so.preload" in recipe
    assert in_image or "LD_PRELOAD" in env, (
        "no time-faking preload is configured for the box: neither the create command nor the "
        "image recipe sets one")


def test_k3_an_arms_preload_and_clock_variables_are_the_natural_runs(natural, arm):
    """Into the box, same shape: every preload or clock variable the create command carries is
    identical for an arm and a natural run — an arm differs only in what its clock FILE says.
    Positive control: both create commands carry an environment.

    Its only teeth: IF an implementation configures the preload or the clock through the create
    command's environment, an arm's values equal a natural run's. With the preload baked into
    the image and the clock path fixed, no such variable exists and this holds trivially;
    `test_k3_the_box_is_preloaded_for_every_run` is the check that the preload exists at all."""
    env_n, env_a = natural.docker.env(), arm.docker.env()
    assert env_n and env_a, "a create command carries no environment to compare"
    clock_vars = {k for k in (*env_n, *env_a) if _PRELOAD_KEY.search(k)}
    assert {k: env_n.get(k) for k in clock_vars} == {k: env_a.get(k) for k in clock_vars}, (
        f"an arm's box is configured differently from a natural run's: "
        f"{ {k: (env_n.get(k), env_a.get(k)) for k in clock_vars} }")


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
        assert stamp is not None and abs(stamp - reading) <= _SLACK, (
            f"an in-box SQL time {stamp} is not the run clock's {reading}: {sql_out}")
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
