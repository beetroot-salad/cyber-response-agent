"""A box's share of the host: both launch paths cap memory (with no swap on top), CPU and process count, and on a live box a process past a cap stays inside it while `defender-sql` still answers under it."""
from __future__ import annotations

import dataclasses
import json
import os
import shlex
import shutil
import signal
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from defender import box as box_mod
from defender.execution import bash_exec
from defender.systems.circuit_breaker import error_class_for_exit
from defender.tests.e2e._spec771 import AliasProbeDocker
from defender.investigation import tools
from defender.tests.support.integrations._defender_sql import EXIT_INPUT_ERROR, EXIT_OK, run_sql_py
from defender.tests.support.runtime.state._1255_view import MODEL_RUN
from defender.tests.support.sandbox._docker import daemon_reachable, docker_runtimes, dood_anchor, is_dood
from defender.tests.support.storage._alert_plant import plant_alert
from defender.tests.support.tenancy._host1214 import TEST_TENANT

pytestmark = pytest.mark.e2e

DEFENDER = Path(__file__).resolve().parents[2]
EXEC_TIMEOUT = 90.0

#: How much the hog will hold at most: past the cap its test sets, and small enough that a cap
#: that stopped applying fails the test rather than exhausting the machine running it.
HOG_CEILING_MIB = 1024
HOG_CAP = "512m"
#: Above the cap by what the interpreter and the last step can account for.
HOG_MOST_MIB = 600
#: Well into the cap: below this, the hog failed for some other reason than memory.
HOG_LEAST_MIB = 256

#: Touches every page, so the memory is really held. Records its progress on the run tree, which
#: outlives the box, so the host can read how far it got even if the kill takes the whole box.
MEMORY_HOG = f"""\
import os
held = []
while len(held) < {HOG_CEILING_MIB // 16}:
    held.append(bytearray(b"x") * (16 << 20))
    with open("hog.progress", "w") as out:
        out.write(str(len(held) * 16))
        out.flush()
        os.fsync(out.fileno())
"""

#: Children outlive the parent, so they end as orphans the box's PID 1 must reap.
FORK_STORM_CHILD_SECONDS = 2
FORK_STORM = f"""\
import os, time
n = 0
try:
    while n < 1000:
        if os.fork() == 0:
            time.sleep({FORK_STORM_CHILD_SECONDS})
            os._exit(0)
        n += 1
except OSError:
    print("stopped", n)
"""


def _run_dir(base: Path) -> Path:
    run = base / f"run-limits-{uuid.uuid4().hex[:8]}"
    run.mkdir(parents=True)
    plant_alert(run, {"id": "a-limits"})
    return run


def _flag(argv: list[str], name: str) -> str:
    """The one value of `name`, which sits in option position, before the image."""
    at = [i for i, word in enumerate(argv) if word == name]
    assert len(at) == 1, f"{name} appears {len(at)} times in {argv}"
    assert at[0] + 1 < len(argv) - 4, f"{name} is not an option of `docker run`: {argv}"
    return argv[at[0] + 1]


def _investigation_argv(tmp_path: Path) -> list[str]:
    rec = AliasProbeDocker()
    box_mod.start_box(_run_dir(tmp_path), DEFENDER, docker=rec, tenant_id=TEST_TENANT)
    assert rec.create_argv is not None, "start_box never issued `docker run`"
    return rec.create_argv


def _lane_argv(tmp_path: Path) -> list[str]:
    src = tmp_path / "lane"
    src.mkdir()
    rec = AliasProbeDocker()
    box_mod.start_box(
        box_mod.BoxRequest(
            name="defender-tenant-limits-batch",
            mounts=(box_mod.Mount(source=src, target=src, writable=True),),
            workdir=src,
            spec=dataclasses.replace(box_mod.BoxSpec.from_env(os.environ), rootfs="python:3.11-slim"),
            tenant_id=TEST_TENANT,
        ),
        docker=rec,
    )
    assert rec.create_argv is not None, "start_box never issued `docker run`"
    return rec.create_argv


@pytest.mark.parametrize("argv_of", [_investigation_argv, _lane_argv], ids=["investigation", "lane"])
def test_every_launch_path_caps_memory_cpu_and_processes(argv_of, tmp_path):
    argv = argv_of(tmp_path)
    spec = box_mod.BoxSpec()
    assert _flag(argv, "--memory") == spec.memory
    assert _flag(argv, "--memory-swap") == spec.memory, "swap on top of the memory cap"
    assert _flag(argv, "--cpus") == spec.cpus
    assert _flag(argv, "--pids-limit") == str(spec.pids_limit)
    assert argv[-3:-1] == ["sh", "-c"], argv[-3:]
    assert argv[-1].endswith("; :"), (
        f"the shell must stay PID 1 to reap orphans, which would hold the box at its limit: {argv[-1]}")
    assert "--init" not in argv, "docker's init has the attached stream as its output"


@pytest.mark.parametrize("payload", [
    json.dumps({"a": "x" * (20 << 20)}),
    "\n".join(json.dumps({"a": "x" * 100}) for _ in range(250_000)),
], ids=["one-large-object", "many-lines-no-final-newline"])
def test_a_payload_past_the_engines_default_object_size_still_loads(payload):
    """The engine's object-size setting came down so the tool fits under the cap; both of these
    are over its 16 MiB default."""
    res = run_sql_py("SELECT count(*) AS n FROM data", stdin=payload)
    assert res.returncode == EXIT_OK, res.stderr


# ---- the SQL tool's and the helper's own limits, on the unsandboxed fallback ----------------

PAYLOAD_MAX = 64 << 20
#: Far over the result budget, on rows small enough that base code still prints them all.
OVERSIZED_RESULT_SQL = "SELECT repeat('x', 1024) AS s FROM range(64 * 1024)"
DECLARED = ("--rows", "values", "--names", "columns")


def _reason_lines(err: bytes | str) -> list[str]:
    text = err.decode("utf-8", "replace") if isinstance(err, bytes) else err
    return [line for line in text.splitlines() if line.strip()]


def _refusal_without_a_traceback(res) -> None:
    assert res.stdout == "", "a size failure is never an observation"
    assert "Traceback" not in res.stderr, res.stderr[-400:]
    # GAP G4: "all exit 2" is stated for the catch around the run, not for O1's check or O4's budget.
    assert res.returncode != EXIT_OK
    assert error_class_for_exit(tools._shim_exit_code(res.returncode)) == "agent-fixable", res.returncode


def test_o1_a_payload_over_the_maximum_is_refused_before_parsing_on_both_load_paths():
    """Bytes no parser accepts, so only a check before parsing can give the size message; one message. (O1)"""
    junk = "x" * (PAYLOAD_MAX + 1)
    undeclared = run_sql_py("SELECT 1 AS x", stdin=junk)
    declared = run_sql_py(*DECLARED, "SELECT 1 AS x", stdin=junk)
    for res in (undeclared, declared):
        _refusal_without_a_traceback(res)
        assert "not valid JSON" not in res.stderr, "the payload was parsed before its size was checked"
        # GAP G3: the design fixes no text, though P1 makes it the merge key; "narrow" is its own verb.
        assert "narrow" in res.stderr.lower(), res.stderr
    assert undeclared.stderr == declared.stderr, "one message, whichever load path"


def test_o4_a_result_over_the_budget_prints_nothing_and_the_tool_refuses():
    """Nothing partial on stdout; the refusal is the model's to fix. A small result still prints. (O4, O7)"""
    control = run_sql_py("SELECT repeat('x', 1024) AS s", stdin='{"a":1}')
    assert control.returncode == EXIT_OK, control.stderr
    assert "xxx" in control.stdout

    _refusal_without_a_traceback(run_sql_py(OVERSIZED_RESULT_SQL, stdin='{"a":1}'))


def _unboxed(tmp_path: Path, command: str) -> box_mod.BoxResult:
    return box_mod.unboxed_executor(env=dict(os.environ)).run_parsed(
        bash_exec.parse(command), command=command, cwd=tmp_path, timeout=EXEC_TIMEOUT)


def _writes(fd: int, mib: int, byte: str = "x") -> str:
    source = f"import os; [os.write({fd}, b'{byte}' * (1 << 20)) for _ in range({mib})]"
    return f"python3 -c {shlex.quote(source)}"


@pytest.mark.parametrize("printing", [
    f"head -c {box_mod.BOX_OUTPUT_LIMIT + 1} /dev/zero",
    f"{_writes(2, 40)} ; {_writes(2, 30)}",  # C13: neither pipeline is over alone
    f"{_writes(1, 40)} ; {_writes(2, 30)}",
], ids=["stdout", "stderr-across-pipelines", "both-streams"])
def test_o5_the_budget_spans_the_whole_command_and_stops_it_with_exit_75(tmp_path, printing):
    """No partial stdout, one reason line, no later pipeline; a smaller command is untouched. (O5)"""
    control = _unboxed(tmp_path, f"{_writes(1, 1)} ; touch ran-control")
    assert (control.rc, len(control.out)) == (0, 1 << 20), control.err
    assert (tmp_path / "ran-control").exists()

    res = _unboxed(tmp_path, f"{printing} ; touch later")
    assert res.rc == 75, res.err[-400:]
    assert res.out == b""
    assert not (tmp_path / "later").exists(), "a pipeline ran after the budget stopped the command"
    # GAP G5: is stderr already captured kept beside the reason, and on which side of it?
    assert len(_reason_lines(res.err)) == 1, res.err[:400]
    assert b"output" in res.err.lower(), res.err[:400]  # GAP G3: no fixed text to pin


def test_o5_output_that_is_not_utf8_crosses_as_its_own_bytes(tmp_path):
    """Raw bytes: no decode and re-encode, which expanded invalid UTF-8 threefold (C13). (O5)"""
    res = _unboxed(tmp_path, f"{_writes(1, 1, byte=chr(92) + 'xff')}")
    assert res.rc == 0, res.err
    assert res.out == b"\xff" * (1 << 20)


KILL_OR_CRASH = (signal.SIGKILL, signal.SIGSEGV, signal.SIGABRT, signal.SIGBUS)


@pytest.mark.parametrize("sig", KILL_OR_CRASH, ids=[s.name for s in KILL_OR_CRASH])
@pytest.mark.parametrize("last", ["cat", "head -c 3"], ids=["last-stage-cat", "last-stage-head"])
def test_o6_a_stage_dying_on_a_signal_gives_its_signal_a_reason_and_no_partial_output(tmp_path, sig, last):
    """Upstream of `head`, whose exit is 0, included; no later pipeline runs. (O6)"""
    stage = f"sh -c {shlex.quote(f'echo partial; kill -{int(sig)} $$')}"
    res = _unboxed(tmp_path, f"{stage} | {last} ; touch later")
    assert res.rc == -int(sig), res
    assert res.out == b""
    # GAP G9: this transport has no memory cap for the line to name; the design applies the helper here too.
    assert "memory" in res.err.decode(), res.err
    assert not (tmp_path / "later").exists()


def test_o6_control_sigpipe_is_the_normal_head_case_and_keeps_its_output(tmp_path):
    """`-13` upstream of `head` is not a kill: output kept, exit 0, the next pipeline runs. (O6)"""
    res = _unboxed(tmp_path, "yes | head -n 1 ; touch later")
    assert (res.rc, res.out) == (0, b"y\n"), res
    assert (tmp_path / "later").exists()


def test_o10_the_sql_skill_states_the_ceilings_the_exit_codes_and_the_dense_payload_caveat():
    """The model's own instructions carry what it needs to shrink a query. (O10)"""
    text = (DEFENDER / "skills" / "gather" / "defender-sql.md").read_text(encoding="utf-8")
    for needle in ("64 MiB", "32 MiB", "75", "dense"):
        assert needle in text, needle


# ---- live boxes ----------------------------------------------------------------------------

_NO_DAEMON = not daemon_reachable()
_DOOD = (not _NO_DAEMON) and is_dood()
_DOOD_ANCHOR = dood_anchor() if _DOOD else None

requires_box_daemon = pytest.mark.skipif(
    _NO_DAEMON or (_DOOD and _DOOD_ANCHOR is None),
    reason="no reachable Docker daemon, or no mount shared with it covering the repo tree",
)
RUNTIMES = pytest.mark.parametrize("runtime", ["runsc", "runc"])


@pytest.fixture
def base(tmp_path: Path) -> Iterator[Path]:
    root = tmp_path / "live" if _DOOD_ANCHOR is None else _DOOD_ANCHOR / f"tlimits-{uuid.uuid4().hex}"
    root.mkdir(parents=True)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


@pytest.fixture
def boxed(base: Path, runtime: str) -> Iterator:
    if runtime not in docker_runtimes():
        pytest.skip(f"the {runtime!r} runtime is not registered with this daemon")
    started: list[box_mod.BoxExecutor] = []

    def start(**limits: object) -> box_mod.BoxExecutor:
        box = box_mod.start_box(
            _run_dir(base), DEFENDER, spec=box_mod.BoxSpec(runtime=runtime, **limits),
            docker=box_mod.run_docker, tenant_id=TEST_TENANT,
        )
        assert box.sandboxed, "start_box returned the unsandboxed host fallback, not a box"
        started.append(box)
        return box

    try:
        yield start
    finally:
        for box in started:
            box_mod.stop_box(box)


def _sh(box: box_mod.BoxExecutor, command: str) -> box_mod.BoxResult:
    return box.run_parsed(bash_exec.parse(command), command=command, cwd=Path(MODEL_RUN),
                          timeout=EXEC_TIMEOUT)


def _program(box: box_mod.BoxExecutor, base: Path, name: str, source: str) -> box_mod.BoxResult:
    """Run `source` from a file on the run tree: the agent's path takes a command line."""
    (next(base.glob("run-limits-*")) / name).write_text(source, encoding="utf-8")
    return _sh(box, f"python3 {MODEL_RUN}/{name}")


@requires_box_daemon
@RUNTIMES
@pytest.mark.parametrize("memory", ["512m", box_mod.BoxSpec().memory])
def test_the_sql_tool_answers_a_small_query_under_the_cap(boxed, memory):
    """The engine reserves its load buffers from a limit it derives from this cap: oversized
    buffers refuse every query, reported as a payload that is not JSON."""
    res = _sh(boxed(memory=memory), """echo '{"a":1}' | defender-sql 'SELECT 41 + 1 AS x'""")
    assert res.rc == 0, res.err
    assert b'"x": 42' in res.out


@requires_box_daemon
@RUNTIMES
def test_a_process_past_the_memory_cap_is_stopped_at_the_cap(boxed, base, runtime):
    """Judged by how much the hog held, on either runtime. runc kills the one process and the
    box carries on. runsc holds every process's memory in one host process, so the kill may take
    the whole box."""
    box = boxed(memory=HOG_CAP)
    res = None
    try:
        res = _program(box, base, "hog.py", MEMORY_HOG)
    except box_mod.BoxFault:
        assert runtime == "runsc", "under runc the kill must take the process, not the box"
    progress = next(base.glob("run-limits-*")) / "hog.progress"
    assert progress.exists(), f"the hog never held its first step, so it proves nothing: {res}"
    held = int(progress.read_text(encoding="utf-8"))
    assert held >= HOG_LEAST_MIB, f"stopped at {held} MiB, well short of the cap: {res}"
    assert held <= HOG_MOST_MIB, f"held {held} MiB in a box capped at {HOG_CAP}: {res}"
    if runtime == "runc":
        assert res is not None
        assert res.rc == -9, f"expected the kernel's kill: {res}"
        assert "memory" in res.err.decode(), f"no reason line naming the cap (O6): {res}"
        assert _sh(box, "echo alive").rc == 0


def _refused_for_size(res: box_mod.BoxResult) -> None:
    assert res.rc == EXIT_INPUT_ERROR, res
    assert res.out == b"", "a size failure is never an observation (P2)"
    assert b"Traceback" not in res.err, res.err[-400:]
    assert b"not valid JSON" not in res.err, res.err[-400:]


#: C19: shapes far past the edge, where both sides of the near-edge flip are behind them (O2).
LOADS_OUT_OF_ROOM = {
    "memory": ("512m", lambda: "[{}" + ",{}" * ((21 << 20) - 1) + "]", ""),
    "scratch": (box_mod.BoxSpec().memory,
                lambda: '{"columns":["a","b","c","d"],"values":[[1,2,3,4]' + ",[1,2,3,4]" * (2 << 20) + "]}",
                " ".join(DECLARED)),
}


@requires_box_daemon
@RUNTIMES
@pytest.mark.parametrize("room", list(LOADS_OUT_OF_ROOM))
def test_o2_a_load_that_runs_out_of_room_below_the_maximum_is_a_size_refusal(boxed, base, room):
    """Under the maximum, over what the box can hold: a refusal, and the box carries on. (O2)"""
    memory, shape, args = LOADS_OUT_OF_ROOM[room]
    payload = shape()
    assert len(payload) < PAYLOAD_MAX, "this shape is for O1 past the maximum"
    box = boxed(memory=memory)
    (next(base.glob("run-limits-*")) / "payload.json").write_text(payload, encoding="utf-8")
    res = _sh(box, f"cat {MODEL_RUN}/payload.json | defender-sql {args} 'SELECT 1 AS x'")
    _refused_for_size(res)
    assert _sh(box, "echo alive").rc == 0


@requires_box_daemon
@RUNTIMES
def test_o3_a_query_needing_too_much_memory_is_one_refusal_without_engine_advice(boxed):
    """Names memory and how to shrink; advice about engine settings the model cannot act on is gone. (O3)"""
    box = boxed(memory="512m")
    res = _sh(box, """echo '{"a":1}' | defender-sql 'SELECT * FROM range(1000000000) t ORDER BY random()'""")
    _refused_for_size(res)
    assert "memory" in res.err.decode().lower(), res
    for engine_advice in (b"SET ", b"PRAGMA", b"duckdb.org", b"threads"):
        assert engine_advice not in res.err, res.err[-400:]
    assert len(_reason_lines(res.err)) == 1, res.err[-400:]


@requires_box_daemon
@RUNTIMES
def test_o6_the_helper_killed_with_the_box_running_is_a_result_and_the_box_carries_on(boxed):
    """A real exec 137 with no frame: the stage kills its parent, the helper. Rule 2, not a fault. (O6)"""
    box = boxed()
    source = "import os, signal; os.kill(os.getppid(), signal.SIGKILL)"
    res = _sh(box, f"python3 -c {shlex.quote(source)}")
    # GAP G1: -9 or 137? "that stage's signal" has no referent when the helper itself was killed.
    assert res.rc != 0, res
    assert res.out == b""
    assert "memory" in res.err.decode(), res
    assert _sh(box, "echo alive").rc == 0


@requires_box_daemon
@RUNTIMES
def test_a_fork_storm_stops_at_the_process_cap_and_its_slots_come_back(boxed, base, runtime):
    """runc refuses the fork, and the box's PID 1 reaps the orphans; unreaped, they hold the box
    at its limit for good. A second storm measures that: one small command can still fit between
    the zombies and the cap. Under runsc the cap reaches the box's one host process, so the box
    may die instead (seen in CI: the sandbox dropped its connection); the host's share holds."""
    box = boxed(pids_limit=64)
    try:
        first = _program(box, base, "storm.py", FORK_STORM)
        assert first.rc == 0, first.err
        assert first.out.startswith(b"stopped"), f"1000 processes in a box capped at 64: {first.out!r}"
        time.sleep(FORK_STORM_CHILD_SECONDS + 1)
        second = _program(box, base, "storm.py", FORK_STORM)
    except box_mod.BoxFault:
        assert runtime == "runsc", "under runc the cap must refuse the fork, not take the box"
        return
    assert second.rc == 0, f"the box is stuck at its process limit: {second}"
    forks = int(second.out.split()[1])
    assert forks >= 32, f"only {forks} of 64 slots came back: the orphans were not reaped"
