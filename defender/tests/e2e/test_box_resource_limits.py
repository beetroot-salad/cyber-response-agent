"""A box's share of the host: both launch paths cap memory (with no swap on top), CPU and process count, and on a live box a command past a cap stays inside it while `defender-sql` still works under it."""
from __future__ import annotations

import dataclasses
import json
import os
import shutil
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

#: The integer form of the reported query (`range(1e11)` is a binder error: the engine has no
#: `range(DOUBLE)`, so it never allocates). The rows stream into Python objects, outside the
#: engine's own memory limit, so only the box's cap stops it.
TOO_LARGE = "SELECT * FROM range(100000000000)"


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


def test_a_payload_that_is_one_large_object_still_loads():
    """The engine's object-size setting follows the payload: an object filling it is the worst
    case, and past the engine's default of 16 MiB it must still load."""
    payload = json.dumps({"a": "x" * (20 << 20)})
    res = run_sql_py("SELECT length(a) AS n FROM data", stdin=payload)
    assert res.returncode == EXIT_OK, res.stderr
    assert json.loads(res.stdout) == [{"n": 20 << 20}]


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


def _sql(box: box_mod.BoxExecutor, query: str) -> box_mod.BoxResult:
    return _sh(box, f"""echo '{{"a":1}}' | defender-sql '{query}'""")


@requires_box_daemon
@RUNTIMES
@pytest.mark.parametrize("memory", ["512m", box_mod.BoxSpec().memory])
def test_the_sql_tool_answers_a_small_query_under_the_cap(boxed, memory):
    """The engine reserves its load buffers from a limit it derives from this cap: oversized
    buffers refuse every query, reported as a payload that is not JSON."""
    res = _sql(boxed(memory=memory), "SELECT 41 + 1 AS x")
    assert res.rc == 0, res.err
    assert b'"x": 42' in res.out


@requires_box_daemon
@RUNTIMES
def test_a_result_past_the_cap_does_not_succeed_and_leaves_the_box_usable_or_cleanly_gone(boxed, runtime):
    """runc kills the one process. runsc holds every process's memory in one host process, so
    the kill may take the whole box; that still holds the host's share, and the run sees a
    `BoxFault`, not a hang."""
    box = boxed(memory="512m")
    try:
        res = _sql(box, TOO_LARGE)
    except box_mod.BoxFault:
        assert runtime == "runsc", "under runc the kill must take the process, not the box"
        return
    assert res.rc != 0, "the query outgrew a 512m box and still answered: the cap is not enforced"
    assert res.rc == -9, f"expected the kernel's kill, the rc the tool's guidance names: {res}"
    assert _sql(box, "SELECT 1 AS x").rc == 0


@requires_box_daemon
@RUNTIMES
def test_a_fork_storm_stops_at_the_process_cap(boxed, base):
    box = boxed(pids_limit=64)
    run_dir = next(base.glob("run-limits-*"))
    (run_dir / "storm.py").write_text(
        "import os, time\n"
        "n = 0\n"
        "try:\n"
        "    while n < 1000:\n"
        "        if os.fork() == 0:\n"
        "            time.sleep(10)\n"
        "            os._exit(0)\n"
        "        n += 1\n"
        "except OSError:\n"
        "    print('stopped', n)\n",
        encoding="utf-8",
    )
    res = _sh(box, f"python3 {MODEL_RUN}/storm.py")
    assert res.rc == 0, res.err
    assert res.out.startswith(b"stopped"), f"1000 processes in a box capped at 64: {res.out!r}"
