"""#1170 follow-up on the risks PR #1467 named: the job network must be named outside dev (N5), the provider key is
never on `docker run`'s command line (N2), the worker's start sweep spares a live helper's container (A5), and a helper
that dies or fails on its own ends the row as the worker's error, not as the run's missing report."""
from __future__ import annotations

import os
import subprocess
import sys
import uuid

import pytest

from defender.job_socket import HELPER_FAILED, HELPER_LABEL, JOB_LABEL
from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.jobs._job_helper import ContainerStandIn, drive_helper, make_signer
from defender.tests.support.jobs._worker1342 import _child, _run_one
from defender.tests.support.jobs import _worker1342 as _shared

process_state = J.process_state
scene = J.scene
world = _shared.world
_no_database_address_in_the_workers_environment = _shared._no_database_address_in_the_workers_environment

_LINUX = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc, Linux only")


def _helper_run(scene, docker):
    inv = str(uuid.uuid4())
    scene.plant(inv)
    ran = drive_helper(scene, scene.argv("investigation", inv), docker=docker, signer=make_signer())
    assert ran.raised is None, ran.raised
    return inv


# --- N5: the job network ----------------------------------------------------------------------------------------------

@_LINUX
@pytest.mark.postgres
def test_n5_a_production_helper_with_no_job_network_starts_no_container_and_ends_the_row_as_a_start_failure(
        scene, monkeypatch):
    from defender.records.job_facts import BOX_START_FAILED

    monkeypatch.delenv("DEFENDER_JOB_NETWORK", raising=False)
    docker = ContainerStandIn(lambda c: 0)
    inv = _helper_run(scene, docker)

    assert docker.boxes == [], "a job container started on docker's default network"
    end = scene.end(inv)
    assert end is not None
    assert end.box == BOX_START_FAILED, end


@_LINUX
@pytest.mark.postgres
@pytest.mark.parametrize("deployment", ["dev", "production"])
def test_n5_the_hosts_own_network_is_refused_on_every_deployment(scene, monkeypatch, deployment):
    from defender.records.job_facts import BOX_START_FAILED

    monkeypatch.setenv("DEFENDER_DEPLOYMENT", deployment)
    monkeypatch.setenv("DEFENDER_JOB_NETWORK", "host")
    docker = ContainerStandIn(lambda c: 0)
    inv = _helper_run(scene, docker)

    assert docker.boxes == []
    assert scene.end(inv).box == BOX_START_FAILED


@_LINUX
@pytest.mark.postgres
def test_n5_a_dev_helper_with_no_job_network_joins_dockers_default_and_a_named_one_is_joined(scene, monkeypatch):
    monkeypatch.setenv("DEFENDER_DEPLOYMENT", "dev")
    monkeypatch.delenv("DEFENDER_JOB_NETWORK", raising=False)
    docker = ContainerStandIn(lambda c: 0)
    _helper_run(scene, docker)
    assert J.flag_values(docker.box.argv, "--network") == [], "control: dev with no network joins the default"

    monkeypatch.setenv("DEFENDER_JOB_NETWORK", "jobs-1170")
    named = ContainerStandIn(lambda c: 0)
    _helper_run(scene, named)
    assert J.flag_values(named.box.argv, "--network") == ["jobs-1170"]


# --- N2: the provider key off the command line ------------------------------------------------------------------------

@_LINUX
@pytest.mark.postgres
def test_n2_the_provider_key_reaches_the_container_but_never_the_docker_run_command_line(scene, monkeypatch, tmp_path):
    env_file = tmp_path / "keys" / ".env"
    env_file.parent.mkdir()
    env_file.write_text("ANTHROPIC_API_KEY=sk-ant-argv-1170\n", encoding="utf-8")
    monkeypatch.setenv("DEFENDER_ENV_FILE", str(env_file))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    docker = ContainerStandIn(lambda c: 0)
    _helper_run(scene, docker)

    assert docker.box.env.get("ANTHROPIC_API_KEY") == "sk-ant-argv-1170", "control: the key reached the job"
    assert not any("sk-ant-argv-1170" in word for word in docker.box.argv), "the key is on docker run's command line"
    assert "ANTHROPIC_API_KEY" in J.flag_values(docker.box.argv, "--env"), "the key is not named for docker to pass"


# --- A5: the start sweep spares a live helper's container -------------------------------------------------------------

class _ListingDocker:
    """`docker ps` answers `rows` (`<id> <helper label>`); every `rm` is recorded."""

    def __init__(self, rows: list[str]) -> None:
        self.rows, self.removed, self.listed = rows, [], []

    def __call__(self, argv, **_kw):
        argv = list(argv)
        if argv[1] == "ps":
            self.listed.append(argv)
            return subprocess.CompletedProcess(argv, 0, "".join(f"{r}\n" for r in self.rows), "")
        if argv[1] == "rm":
            self.removed.append(argv[-1])
        return subprocess.CompletedProcess(argv, 0, "", "")


@_LINUX
def test_a5_the_start_sweep_removes_only_job_containers_whose_helper_is_gone():
    from defender.tenancy import process_start
    from defender.worker._containers import DockerContainers

    me = f"{os.getpid()}-{process_start(os.getpid())}"
    gone = subprocess.Popen([sys.executable, "-c", "pass"])
    gone_label = f"{gone.pid}-{process_start(gone.pid)}"
    gone.wait()
    reused = f"{os.getpid()}-0"  # this pid, another start time: a reused pid
    docker = _ListingDocker([f"live {me}", f"dead {gone_label}", f"reused {reused}", "unlabelled ", "junk x-y"])

    DockerContainers(docker).remove_job_containers()

    assert JOB_LABEL in " ".join(docker.listed[0])
    assert HELPER_LABEL in " ".join(docker.listed[0])
    assert "live" not in docker.removed, "a live helper's container was removed"
    assert sorted(set(docker.removed)) == ["dead", "junk", "reused", "unlabelled"], docker.removed


@_LINUX
@pytest.mark.postgres
def test_a5_every_job_container_names_its_helper_by_pid_and_start_time(scene):
    from defender.tenancy import process_start

    docker = ContainerStandIn(lambda c: 0)
    _helper_run(scene, docker)
    assert J.parse_labels(docker.box.argv)[HELPER_LABEL] == f"{os.getpid()}-{process_start(os.getpid())}"


# --- the helper's own failure -----------------------------------------------------------------------------------------

@pytest.mark.anyio
@pytest.mark.postgres
@pytest.mark.parametrize("how", ["status", "signal"])
async def test_a_helper_that_fails_on_its_own_with_no_end_record_ends_the_row_as_the_workers_error(world, how):
    child = _child(world, exit=HELPER_FAILED) if how == "status" else _child(world, die_by=9)
    _inv, stored = await _run_one(world, child)

    assert (stored["stage"], stored["failure_reason"]) == ("failed", "worker_error"), stored
    assert "helper" in stored["failure_message"], stored["failure_message"]


@pytest.mark.anyio
@pytest.mark.postgres
async def test_control_a_job_that_exits_non_zero_with_no_end_record_is_still_no_report(world):
    _inv, stored = await _run_one(world, _child(world, exit=1))
    assert (stored["stage"], stored["failure_reason"]) == ("failed", "no_report"), stored


def test_the_helper_entry_exits_helper_failed_on_a_fault_of_its_own():
    """The helper's entry point, run as the worker runs it, on a claim token it would never mint: it refuses with
    `HELPER_FAILED`, which no job container's status reads as."""
    from pathlib import Path

    repo = str(Path(__file__).resolve().parents[3])
    env = {**os.environ, "DEFENDER_DATA_ROOT": "/nonexistent-1170", "DEFENDER_BOX_CLAIM": "not-a-claim",
           "PYTHONPATH": os.pathsep.join(p for p in (repo, os.environ.get("PYTHONPATH")) if p)}
    done = subprocess.run([sys.executable, "-m", "defender.job_host", "--kind", "investigation", "--job", "x",
                           "--tenant", str(uuid.uuid4()), "--parent-pid", str(os.getpid())],
                          capture_output=True, text=True, env=env, timeout=60, check=False)
    assert done.returncode == HELPER_FAILED, (done.returncode, done.stderr[-2000:])


def test_a_fault_escaping_the_helper_after_its_container_started_exits_helper_failed():
    """A fault that escapes `main` (the container already running: its wait, its exit hook, the cleanup) is not the
    job's status: the entry turns it into `HELPER_FAILED`; a status `main` returns is passed on as it is."""
    from defender.job_host._main import entry

    def crashes(_argv):
        raise RuntimeError("the helper's wait failed")

    assert entry(["--kind", "investigation"], run=crashes) == HELPER_FAILED
    assert entry(["--kind", "investigation"], run=lambda _argv: 3) == 3, "control: a job's own status passes through"
