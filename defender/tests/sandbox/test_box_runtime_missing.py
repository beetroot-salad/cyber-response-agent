"""A box whose runtime the daemon has not registered is refused before any create, naming its remedy (#1484), on both
lanes; the refusal is decided by asking the daemon, never by a create's error text."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from defender import box as box_mod
from defender.box import BoxRequest, Mount
from defender.execution.box_codec import BoxFault
from defender.tests.support.sandbox._spec1092 import DockerFault, RecordingDocker, make_run_dir, plant_tree, subcommands
from defender.tests.support.tenancy._host1214 import TEST_TENANT

#: docker 27's create refusal for a runtime the daemon has not registered.
_NO_RUNSC = "docker: Error response from daemon: unknown or invalid runtime name: runsc\n"


class RuntimesDocker(RecordingDocker):
    """`RecordingDocker` whose daemon lists `runtimes` (`docker info`); `None` answers nothing usable."""

    def __init__(self, runtimes: tuple[str, ...] | None, **kw):
        super().__init__(**kw)
        self.runtimes = runtimes

    def __call__(self, argv, **kw) -> subprocess.CompletedProcess:
        argv = list(argv)
        if argv[1:2] == ["info"] and self.runtimes is not None:
            self.calls.append(argv)
            body = json.dumps({name: {"path": name} for name in self.runtimes})
            return subprocess.CompletedProcess(argv, 0, f"{body}\n", "")
        return super().__call__(argv, **kw)


def _request(root: Path, run_dir: Path) -> BoxRequest:
    return BoxRequest(name="defender-drain-1484", workdir=root, env={},
                      mounts=(Mount(source=run_dir, target=run_dir, writable=True),), tenant_id=TEST_TENANT)


def _start(lane: str, tmp_path: Path, docker):
    root = tmp_path / "tree"
    defender_dir = plant_tree(root, copy_code=False)
    run_dir = make_run_dir(tmp_path)
    if lane == "run-dir":
        return box_mod.start_box(run_dir, defender_dir, docker=docker, tenant_id=TEST_TENANT)
    return box_mod.start_box(_request(root, run_dir), docker=docker)


@pytest.fixture
def sandboxed(monkeypatch):
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    monkeypatch.delenv(box_mod.BoxSpec.ENV_VAR, raising=False)


@pytest.mark.parametrize("lane", ["run-dir", "request"])
def test_a_daemon_without_runsc_refuses_before_any_create_naming_gvisor_and_the_runtime_lever(tmp_path, sandboxed, lane):
    docker = RuntimesDocker(("runc", "io.containerd.runc.v2"))
    with pytest.raises(BoxFault) as e:
        _start(lane, tmp_path, docker)
    message = str(e.value)
    assert not {"run", "create"} & set(subcommands(docker.calls)), docker.calls
    assert "no runtime 'runsc' registered" in message, message
    assert "runsc install" in message, message
    assert "Upgrade from before #1170" in message, message
    assert "DEFENDER_BOX_RUNTIME=runc" in message, message


@pytest.mark.parametrize("runtimes", [("runc", "runsc"), None], ids=["registered", "daemon-cannot-say"])
def test_a_create_fault_past_the_runtime_check_keeps_the_create_s_own_words(tmp_path, sandboxed, runtimes):
    """Control: with runsc listed, or a daemon that cannot list its runtimes, the create is asked, and its fault is
    docker's own text, never the gVisor remedy."""
    docker = RuntimesDocker(runtimes, create=DockerFault(rc=125, stderr=_NO_RUNSC))
    with pytest.raises(BoxFault) as e:
        _start("run-dir", tmp_path, docker)
    assert "create" in subcommands(docker.calls), docker.calls
    assert str(e.value).startswith("could not create the box"), e.value
    assert "runsc install" not in str(e.value)


def test_runc_chosen_on_purpose_is_not_refused_by_a_daemon_without_runsc(tmp_path, monkeypatch):
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    monkeypatch.setenv(box_mod.BoxSpec.ENV_VAR, "runc")
    docker = RuntimesDocker(("runc",))
    box = _start("request", tmp_path, docker)
    assert box.name, "the box did not start"


def test_the_unsandboxed_opt_out_still_degrades_a_missing_runtime(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    monkeypatch.delenv(box_mod.BoxSpec.ENV_VAR, raising=False)
    box = _start("request", tmp_path, RuntimesDocker(("runc",)))
    assert box.name == "", "the opt-out did not degrade to the host"


# ---- the operator's run preflight (run.py) ---------------------------------------------------------------------------
def _ready_image_docker(runtimes: tuple[str, ...] | None) -> RuntimesDocker:
    """A daemon that holds the box image (`image inspect` answers 0, as `RecordingDocker` does) and lists `runtimes`."""
    return RuntimesDocker(runtimes)


def test_the_run_preflight_refuses_a_host_without_runsc_naming_the_remedy():
    from defender import run as run_py

    docker = _ready_image_docker(("runc",))
    refusal = run_py.box_host_refusal({}, docker)
    assert refusal is not None
    assert "no runtime 'runsc' registered" in refusal, refusal
    assert "DEFENDER_BOX_RUNTIME=runc" in refusal, refusal
    assert not {"run", "create"} & set(subcommands(docker.calls)), docker.calls


@pytest.mark.parametrize(("environ", "runtimes"), [
    ({}, ("runc", "runsc")),
    ({box_mod.BoxSpec.ENV_VAR: "runc"}, ("runc",)),
    ({"DEFENDER_ALLOW_UNSANDBOXED": "1"}, ("runc",)),
], ids=["runsc-registered", "runc-chosen", "unsandboxed-opt-out"])
def test_the_run_preflight_passes_a_host_that_can_start_the_box_or_need_not(environ, runtimes):
    from defender import run as run_py

    assert run_py.box_host_refusal(environ, _ready_image_docker(runtimes)) is None


def test_the_run_preflight_refuses_an_unknown_runtime_setting():
    from defender import run as run_py

    refusal = run_py.box_host_refusal({box_mod.BoxSpec.ENV_VAR: "crun"}, _ready_image_docker(("runc",)))
    assert refusal is not None
    assert "is not a known box runtime" in refusal, refusal


def test_the_operator_run_asks_the_host_preflight_and_a_job_container_s_run_does_not():
    """`main`'s default preflight is the host one; the job entries keep the role-models one (their box is their
    helper's)."""
    import inspect

    from defender import run as run_py

    def default(fn):
        return inspect.signature(fn).parameters["preflight"].default

    assert default(run_py.main) is run_py.preflight_run_host
    assert default(run_py.job_main) is run_py.preflight_role_models
    assert default(run_py.serve_job) is run_py.preflight_role_models
