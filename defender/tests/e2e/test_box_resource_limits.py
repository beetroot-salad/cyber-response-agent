"""A box's share of the host: both launch paths cap memory (with no swap on top), CPU and process count, and on a live box a process past a cap stays inside it while `defender-sql` still answers under it."""
from __future__ import annotations

import dataclasses
import json
import os
import shutil
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from defender import box as box_mod
from defender.execution import bash_exec
from defender.tests.e2e._spec771 import AliasProbeDocker
from defender.tests.support.integrations._defender_sql import EXIT_OK, run_sql_py
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
    assert at[0] + 1 < len(argv) - 3, f"{name} is not an option of `docker run`: {argv}"
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
    assert "--init" in argv[:-3], "orphans would hold the box at its process limit"


@pytest.mark.parametrize("payload", [
    json.dumps({"a": "x" * (20 << 20)}),
    "\n".join(json.dumps({"a": "x" * 100}) for _ in range(250_000)),
], ids=["one-large-object", "many-lines-no-final-newline"])
def test_a_payload_past_the_engines_default_object_size_still_loads(payload):
    """The engine's object-size setting came down so the tool fits under the cap; both of these
    are over its 16 MiB default."""
    res = run_sql_py("SELECT count(*) AS n FROM data", stdin=payload)
    assert res.returncode == EXIT_OK, res.stderr


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
