"""#1170 follow-up on the risks PR #1467 named: a job container joins only a bridge network made for the jobs (N5), the
provider key is never on `docker run`'s command line (N2), the worker's start sweep spares a live helper's container
(A5), and the helper's exit status says only whether it served the job, so any other exit with no end record is the
worker's error, never the run's missing report."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid

import pytest

from defender.job_socket import HELPER_LABEL, JOB_LABEL
from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.jobs._job_helper import ContainerStandIn, drive_helper, make_signer
from defender.tests.support.jobs._worker1342 import _child, _run_one
from defender.tests.support.jobs import _worker1342 as _shared

process_state = J.process_state
scene = J.scene
world = _shared.world
_no_database_address_in_the_workers_environment = _shared._no_database_address_in_the_workers_environment

_LINUX = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc, Linux only")
_DEFAULT_BRIDGE = {"Name": "bridge", "Driver": "bridge", "Options": {"com.docker.network.bridge.default_bridge": "true"},
                   "Labels": {}}


def _helper_run(scene, docker):
    inv = str(uuid.uuid4())
    scene.plant(inv)
    ran = drive_helper(scene, scene.argv("investigation", inv), docker=docker, signer=make_signer())
    assert ran.raised is None, ran.raised
    return inv, ran


# --- N5: the job network, judged once at the worker's start -----------------------------------------------------------

class _NetworkDocker:
    """`docker network inspect <name>`: `answer` (a dict docker would print, None for no such network), or `fault`
    raised, as a daemon that does not answer."""

    def __init__(self, answer: dict | None = None, fault: BaseException | None = None, rc: int | None = None) -> None:
        self.answer, self.fault, self.rc, self.asked = answer, fault, rc, []

    def __call__(self, argv, **_kw):
        argv = list(argv)
        self.asked.append(argv)
        assert argv[1:3] == ["network", "inspect"], argv
        if self.fault is not None:
            raise self.fault
        if self.rc is not None:
            return subprocess.CompletedProcess(argv, self.rc, "", "Cannot connect to the Docker daemon\n")
        if self.answer is None:
            return subprocess.CompletedProcess(argv, 1, "", f"Error response from daemon: network {argv[-1]} not found\n")
        return subprocess.CompletedProcess(argv, 0, json.dumps(self.answer) + "\n", "")


def _bridge(name: str, **extra) -> dict:
    return {"Name": name, "Driver": "bridge", "Options": {}, "Labels": {}, **extra}


@pytest.mark.parametrize(("name", "docker"), [
    pytest.param(None, _NetworkDocker(), id="unset"),
    pytest.param("bridge", _NetworkDocker(_DEFAULT_BRIDGE), id="dockers-default-bridge"),
    pytest.param("host", _NetworkDocker({"Name": "host", "Driver": "host", "Options": {}}), id="host"),
    pytest.param("container:openbao", _NetworkDocker(None), id="another-containers"),
    pytest.param("none", _NetworkDocker({"Name": "none", "Driver": "null", "Options": {}}), id="none"),
    pytest.param("app_default", _NetworkDocker(_bridge("app_default", Labels={
        "com.docker.compose.network": "default", "com.docker.compose.project": "app"})), id="a-compose-projects"),
    pytest.param("jobs", _NetworkDocker(rc=1), id="docker-not-answering"),
    pytest.param("jobs", _NetworkDocker(fault=subprocess.TimeoutExpired(["docker"], 120)), id="docker-timing-out"),
    pytest.param("jobs", _NetworkDocker(fault=FileNotFoundError("docker")), id="no-docker"),
])
def test_n5_the_worker_refuses_to_start_unless_the_job_network_is_a_bridge_made_for_the_jobs(name, docker):
    from defender.worker._start import WorkerStartRefused, check_job_network

    environ = {} if name is None else {"DEFENDER_JOB_NETWORK": name}
    with pytest.raises(WorkerStartRefused, match="DEFENDER_JOB_NETWORK"):
        check_job_network(environ, docker)


def test_n5_control_the_worker_accepts_a_bridge_network_made_for_the_jobs():
    from defender.worker._start import check_job_network

    docker = _NetworkDocker(_bridge("jobs-1170"))
    assert check_job_network({"DEFENDER_JOB_NETWORK": "jobs-1170"}, docker) == "jobs-1170"
    assert [a[-1] for a in docker.asked] == ["jobs-1170"]


@_LINUX
@pytest.mark.postgres
def test_n5_a_helper_with_no_job_network_named_starts_no_container(scene, monkeypatch):
    from defender.records.job_facts import BOX_START_FAILED

    monkeypatch.delenv("DEFENDER_JOB_NETWORK", raising=False)
    docker = ContainerStandIn(lambda c: 0)
    inv, _ran = _helper_run(scene, docker)

    assert docker.boxes == [], "a job container started with no job network"
    end = scene.end(inv)
    assert end is not None
    assert end.box == BOX_START_FAILED, end


@_LINUX
@pytest.mark.postgres
def test_n5_the_helper_joins_the_job_network_it_is_given(scene, monkeypatch):
    monkeypatch.setenv("DEFENDER_JOB_NETWORK", "jobs-1170")
    docker = ContainerStandIn(lambda c: 0)
    _helper_run(scene, docker)
    assert J.flag_values(docker.box.argv, "--network") == ["jobs-1170"]


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
    from defender.tenancy import process_mark, process_start
    from defender.worker._containers import DockerContainers

    gone = subprocess.Popen([sys.executable, "-c", "pass"])
    gone_label = f"{gone.pid}-{process_start(gone.pid)}"
    gone.wait()
    reused = f"{os.getpid()}-0"  # this pid, another start time: a reused pid
    docker = _ListingDocker([f"live {process_mark()}", f"dead {gone_label}", f"reused {reused}", "unlabelled ",
                             "unreadable 123-None"])

    DockerContainers(docker).remove_job_containers()

    assert JOB_LABEL in " ".join(docker.listed[0])
    assert HELPER_LABEL in " ".join(docker.listed[0])
    assert "live" not in docker.removed, "a live helper's container was removed"
    assert sorted(set(docker.removed)) == ["dead", "reused", "unlabelled", "unreadable"], docker.removed


@_LINUX
@pytest.mark.postgres
def test_a5_every_job_container_names_its_helper_by_its_pid_and_start_time(scene):
    """The helper runs on this thread: its label is this process's pid and kernel start time (field 22 of
    `/proc/<pid>/stat`, counted past the command name, which may hold spaces)."""
    from pathlib import Path

    after_name = Path(f"/proc/{os.getpid()}/stat").read_text(encoding="utf-8").rsplit(")", 1)[1].split()
    docker = ContainerStandIn(lambda c: 0)
    _helper_run(scene, docker)
    assert J.parse_labels(docker.box.argv)[HELPER_LABEL] == f"{os.getpid()}-{after_name[19]}"


# --- the helper's exit status -----------------------------------------------------------------------------------------

@_LINUX
@pytest.mark.postgres
@pytest.mark.parametrize("rc", [0, 1, 137])
def test_a_helper_that_served_its_job_exits_0_whatever_its_containers_status(scene, rc):
    _inv, ran = _helper_run(scene, ContainerStandIn(lambda c: rc))
    assert ran.rc == 0, ran.rc


@pytest.mark.anyio
@pytest.mark.postgres
@pytest.mark.parametrize("ends", [
    pytest.param({"exit": 1}, id="exit-1"), pytest.param({"exit": 2}, id="exit-2-argument-refusal"),
    pytest.param({"exit": 247}, id="exit-247-killed-docker-run"), pytest.param({"die_by": 9}, id="dies-by-SIGKILL"),
])
async def test_a_helper_that_exits_non_zero_with_no_end_record_ends_the_row_as_the_workers_error(world, ends):
    _inv, stored = await _run_one(world, _child(world, **ends))

    assert (stored["stage"], stored["failure_reason"]) == ("failed", "worker_error"), stored
    assert "helper" in stored["failure_message"], stored["failure_message"]


@pytest.mark.anyio
@pytest.mark.postgres
async def test_control_a_helper_that_served_its_job_with_no_end_record_is_no_report(world):
    _inv, stored = await _run_one(world, _child(world, exit=0))
    assert (stored["stage"], stored["failure_reason"]) == ("failed", "no_report"), stored


class _RunsGoneAtTheRuntimeCheck(ContainerStandIn):
    """A daemon without the box runtime (the helper's own start failure, before any container), whose answer comes
    after the tenant's runs folder was swapped for a file: the start failure's end record cannot be written."""

    def __init__(self, runs) -> None:
        super().__init__(lambda c: 0, runtimes=("no-such-runtime",))
        self._runs = runs

    def __call__(self, argv, **kw):
        if list(argv)[1:2] == ["info"] and self._runs.is_dir():
            self._runs.rename(self._runs.with_name("runs-gone-1170"))
            self._runs.write_text("not a folder\n", encoding="utf-8")
        return super().__call__(argv, **kw)


@_LINUX
@pytest.mark.postgres
def test_a_helper_that_cannot_write_the_ending_it_decided_does_not_exit_0(scene):
    """An ending the helper decided before the container, whose record cannot be written, is the helper's failure:
    not exit 0, which the worker would read as a served job that left no report."""
    inv = str(uuid.uuid4())
    scene.plant(inv)
    docker = _RunsGoneAtTheRuntimeCheck(scene.runs)
    ran = drive_helper(scene, scene.argv("investigation", inv), docker=docker, signer=make_signer())

    assert docker.boxes == [], "control: no container started"
    assert not (scene.runs.with_name("runs-gone-1170") / f"{inv}.job-end.json").exists(), "control: no record"
    assert ran.rc != 0, (ran.rc, ran.raised)


def test_the_helper_entry_exits_non_zero_when_it_cannot_serve_the_job():
    """The helper's entry point, run as the worker runs it, on a claim token it would never mint: non-zero."""
    from pathlib import Path

    repo = str(Path(__file__).resolve().parents[3])
    env = {**os.environ, "DEFENDER_DATA_ROOT": "/nonexistent-1170", "DEFENDER_BOX_CLAIM": "not-a-claim",
           "PYTHONPATH": os.pathsep.join(p for p in (repo, os.environ.get("PYTHONPATH")) if p)}
    done = subprocess.run([sys.executable, "-m", "defender.job_host", "--kind", "investigation", "--job", "x",
                           "--tenant", str(uuid.uuid4()), "--parent-pid", str(os.getpid())],
                          capture_output=True, text=True, env=env, timeout=60, check=False)
    assert done.returncode != 0, done.stderr[-2000:]
