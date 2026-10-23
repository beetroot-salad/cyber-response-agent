"""Box clocks follow the run clock; clock mounts stay outside model read scope."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

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
from defender import box as box_mod
from defender.tests.support.runtime.state import _1255_clock as C
from defender.tests.support.runtime.state import _1255_view as V
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.storage._alert_plant import plant_alert
from defender.tests.support.sandbox._spec1092 import STOCK_ROOTFS
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
    """Create arguments and investigation inputs captured from a recording-daemon run."""

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
        """Host paths bound for the run, checkout, and tenant agent."""
        return (self.run_dir, C.DEFENDER, Path(self.kwargs["tenant"].agent))

    def clock_mounts(self) -> list[dict]:
        """Read-only mounts outside the model roots; only the clock belongs there."""
        return _clock_candidates(self.docker)


def _is_run_copy_stage(mount: dict) -> bool:
    """#1108 P4 (U9, O-A): the run copy's `stage/` — `agent/` plus one token — is the one
    other read-only bind outside the model roots a run's box carries by design (the token is
    read back at startup; `/agent` resolves into `stage/agent/`). It is told apart by where the
    design's data model puts it, `<T>/run-knowledge/<run id>/stage` (the copy is gone once the
    run ends, so its shape cannot be read afterwards)."""
    source = Path(mount["source"])
    return source.name == "stage" and source.parent.parent.name == "run-knowledge"


def _clock_candidates(docker: RecordingDocker) -> list[dict]:
    """Read-only mounts outside the model roots, the run copy's `stage/` aside; only the clock
    belongs there."""
    return [m for m in docker.mounts()
            if m["readonly"] and not V.under_model_root(m["target"])
            and not _is_run_copy_stage(m)]


def _within(path: Path, tree: Path) -> bool:
    return path == tree or tree in path.parents


def _start(argv: list[str]) -> Captured:
    """Start run.main with a recording daemon and capture the investigation inputs."""
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
    """A natural run's box start through `run.main`, from the fixture tenant's seed alert."""
    base, seed = location_path(T.runs_base)(tmp_path)
    tenant_id = T.current_tenant().id
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    monkeypatch.delenv(box_mod.BoxSpec.ENV_VAR, raising=False)
    return _start(C.natural_argv(RunPaths(seed).alert, tenant_id))


@pytest.fixture
def arm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Captured:
    """An arm's box start through `run.main --episode`."""
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


def test_natural_box_clock_mount_and_preload(natural):
    _trees_are_bound(natural)
    found = natural.clock_mounts()
    assert len(found) == 1, (
        f"the box needs exactly one read-only mount for the run clock's file: {found}")
    source = Path(found[0]["source"])
    assert not any(_within(tree, source) for tree in natural.trees()), (
        f"the clock mount's source {source} exposes one of the run's trees")

    env = natural.docker.env()
    assert env, "the create command carries no environment to inspect"
    in_image = _box_recipe_preload()
    assert in_image or env.get("LD_PRELOAD", "").strip(), (
        "no time-faking preload is configured for the box: neither the create command nor any "
        "instruction of the image recipe sets one (a comment configures nothing)")


def test_arm_box_clock_mount_and_preload_match_natural_run(natural, arm):
    _trees_are_bound(arm)
    found = {"natural": natural.clock_mounts(), "arm": arm.clock_mounts()}
    assert all(len(m) == 1 for m in found.values()), (
        f"each run's box needs exactly one read-only mount for the run clock's file: {found}")
    assert found["natural"][0]["target"] == found["arm"][0]["target"], (
        f"an arm's clock mount sits elsewhere than a natural run's: {found}")
    source = Path(found["arm"][0]["source"])
    assert not any(_within(tree, source) for tree in arm.trees()), (
        f"the arm's clock mount source {source} exposes one of its trees")

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


_ISO_IN_FILE = re.compile(
    r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?")
_NUMBER_IN_FILE = re.compile(r"(?<![\w.])([+-]?)(\d+(?:\.\d+)?)([smhdy]?)(?![\w.])")
_UNIT_SECONDS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "y": 365 * 86400}
_FILE_SLACK = dt.timedelta(minutes=2)


def _clock_file_readings(text: str, wall: dt.datetime) -> list[tuple[str, dt.datetime]]:
    """Interpret clock-file readings as absolute times, epochs, or wall offsets."""
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
    """Read the captured clock mount from a model turn after the box has run a command."""

    def probe(_text: str) -> Any:
        mounts = _clock_candidates(docker)
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
    """Run scripted box commands, then collect the clock mount and its file readings."""
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
    """Require the expected clock reading and reject the arm clock when supplied."""
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
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    monkeypatch.delenv(box_mod.BoxSpec.ENV_VAR, raising=False)
    base, seed = location_path(T.runs_base)(tmp_path)
    tenant_id = T.current_tenant().id

    seen, out, _docker = _clock_file_after_a_command(
        C.natural_argv(RunPaths(seed).alert, tenant_id), C.FakeClock(START))

    _assert_clock_file_reads(seen, out, START)


def test_k1_an_arms_clock_file_holds_its_run_clocks_reading_not_its_sources(tmp_path,
                                                                           monkeypatch):
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    tenant_id, source = C.record_source(tmp_path)
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    monkeypatch.delenv(box_mod.BoxSpec.ENV_VAR, raising=False)
    branch = C.branch_response(source, tool="read_file", arg_suffix=f"/{L2}.md")
    ep = C.control_episode(tmp_path, source, branch)

    seen, out, _docker = _clock_file_after_a_command(
        C.arm_argv(tenant_id, ep.name, "a"), C.FakeClock(C.ARM_START))

    _assert_clock_file_reads(seen, out, C.BRANCH_READING, not_reading=C.ARM_START)


_MOVE = 600
_RELATIVE_CAT = f"cat {RUN_LAYOUT.alert_input_dir}/alert.json"


def test_k1_a_natural_runs_clock_file_follows_the_run_clock_between_commands(tmp_path,
                                                                            monkeypatch):
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    monkeypatch.delenv(box_mod.BoxSpec.ENV_VAR, raising=False)
    base, seed = location_path(T.runs_base)(tmp_path)
    tenant_id = T.current_tenant().id
    clock = C.FakeClock(START)

    seen, out, _docker = _clock_file_after_a_command(
        C.natural_argv(RunPaths(seed).alert, tenant_id), clock,
        seconds_before=(0, _MOVE), command=_RELATIVE_CAT)

    assert _MOVE in clock.advances, (
        f"control: the model's {_MOVE} s between the two commands never ran: {clock.advances} "
        f"(exit={out.exit} refusal={out.refusal})")
    _assert_clock_file_reads(seen, out, C.at(START, _MOVE))


def _file_written(reading: dt.datetime, spelling: str) -> str:
    """Write the reading as an absolute time or an offset from the current wall clock."""
    return {"iso": reading.isoformat(),
            "libfaketime absolute": "@" + reading.strftime("%Y-%m-%d %H:%M:%S"),
            "epoch seconds": f"{reading.timestamp():.0f}",
            "offset": f"{(reading - dt.datetime.now(dt.UTC)).total_seconds():+.0f}"}[spelling]


@pytest.mark.parametrize("spelling", ["iso", "libfaketime absolute", "epoch seconds", "offset"])
def test_k1_the_file_check_tells_a_clock_written_once_from_one_that_follows(spelling):
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
    from defender.tests.support.tenancy import _tenants1106

    return (MAIN_DEF, "main") if name == "main" else (
        _tenants1106.fixture_gather_def(), "gather:l-001")


def _answers_at_the_tool_boundary(defn: Any, agent_id: str, run_dir: Path,
                                  calls: list[tuple[str, dict]], log_dir: Path,
                                  ) -> tuple[list[tuple[str, str]], Any]:
    """Invoke main or gather tools with real bound dependencies and capture their answers."""
    import asyncio
    from dataclasses import replace

    from pydantic_ai.models import override_allow_model_requests
    from pydantic_ai.models.function import FunctionModel
    from pydantic_ai.usage import UsageLimits

    from defender.hooks.budget_enforcer import DEFAULT_LIMITS
    from defender.runtime import driver, observe
    from defender.runtime.agent_definition import bind, effective_tools_for
    from defender.execution.box_codec import BoxResult
    from defender.runtime.providers import BuiltModel
    from defender.runtime.run_state import RunState
    from defender.tests.e2e._replay_harness import Turn
    from defender.tests.sandbox.test_959_downstream import Box

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
    """Read executable Dockerfile instructions that configure the preload."""
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
    from defender.tests.sandbox.test_1092_dockerfile import _instructions

    return _recipe_preload(_instructions(C.DEFENDER / "box.Dockerfile"))


def test_k3_the_recipe_reader_sees_instructions_not_comments(tmp_path):
    from defender.tests.sandbox.test_1092_dockerfile import _instructions

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


def _time_configuration(cap: Captured) -> dict[str, Any]:
    """Collect preload and clock settings from the create environment and image recipe."""
    env = cap.docker.env()
    return {"preload": env.get("LD_PRELOAD", "").strip() or tuple(_box_recipe_preload()),
            "variables": {k: v for k, v in env.items() if _PRELOAD_KEY.search(k)},
            "clock mounts": sorted((m["target"], m["readonly"]) for m in cap.clock_mounts())}


_SQL = ("SELECT now() AS a, today() AS b, current_timestamp AS c, current_date AS d, "
        "localtimestamp AS e, get_current_timestamp() AS f, transaction_timestamp() AS g "
        "FROM data")
_PY = ("python3 -c 'import datetime, time; "
       "print(datetime.datetime.now(datetime.timezone.utc).isoformat()); print(time.time())'")
_STAMP = re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_SLACK = dt.timedelta(minutes=2)


def _box_probe(out: C.Launched, seen: dict[str, Any]) -> Any:
    """Run SQL and Python time probes through the active run box."""
    from defender.execution import bash_exec

    def probe(_text: str) -> Any:
        box = out.kwargs["box"]
        seen["probed"] = True
        sql = f"printf '{{\"x\": 1}}' | defender-sql \"{_SQL}\""
        for name, cmd in (("sql", sql), ("py", _PY)):
            res = box.run_parsed(bash_exec.parse(cmd), command=cmd, cwd=Path(V.MODEL_RUN), timeout=60)
            seen[name] = (res.rc, res.out.decode("utf-8"), res.err.decode("utf-8"))
        return C.DONE

    return probe


def _box_reads(seen: dict[str, Any], reading: dt.datetime, out: C.Launched) -> None:
    """Every in-box time the probe collected is `reading` (within `_SLACK`), and every date is `reading`'s."""
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
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    base, seed = location_path(T.runs_base)(tmp_path)
    tenant_id = T.current_tenant().id
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
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    plant_alert(run_dir)
    healthy = RecordingDocker()
    box = box_mod.start_box(run_dir, C.DEFENDER, docker=healthy,
                            spec=box_mod.BoxSpec(rootfs=STOCK_ROOTFS))
    assert box is not None, "positive control: the run fixture cannot start a healthy box"
    box_mod.stop_box(box, docker=healthy)
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
