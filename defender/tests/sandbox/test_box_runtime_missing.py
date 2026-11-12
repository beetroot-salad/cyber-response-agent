"""A box create refused because the daemon has no runtime of the box's name says so with its remedy (#1484), on
both lanes; any other create fault keeps the create's own stderr. Decided by asking the daemon, not by the
refusal's text."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from defender import box as box_mod
from defender.box import BoxRequest, Mount
from defender.execution.box_codec import BoxFault
from defender.tests.support.sandbox._spec1092 import DockerFault, RecordingDocker, make_run_dir, plant_tree
from defender.tests.support.tenancy._host1214 import TEST_TENANT

#: docker 27's create refusal for a runtime the daemon has not registered.
_NO_RUNSC = "docker: Error response from daemon: unknown or invalid runtime name: runsc\n"


class _RuntimesDocker(RecordingDocker):
    """`RecordingDocker` whose daemon has `runtimes` registered (`docker info`), its create refused with `stderr`."""

    def __init__(self, runtimes: tuple[str, ...], stderr: str = _NO_RUNSC):
        super().__init__(create=DockerFault(rc=125, stderr=stderr, cite="#1484 live re-record"))
        self.runtimes = runtimes

    def __call__(self, argv, **kw) -> subprocess.CompletedProcess:
        argv = list(argv)
        if argv[1:2] == ["info"]:
            self.calls.append(argv)
            body = json.dumps({name: {"path": name} for name in self.runtimes})
            return subprocess.CompletedProcess(argv, 0, f"{body}\n", "")
        return super().__call__(argv, **kw)


def _start(lane: str, tmp_path: Path, docker) -> None:
    root = tmp_path / "tree"
    defender_dir = plant_tree(root, copy_code=False)
    run_dir = make_run_dir(tmp_path)
    if lane == "run-dir":
        box_mod.start_box(run_dir, defender_dir, docker=docker, tenant_id=TEST_TENANT)
    else:
        box_mod.start_box(BoxRequest(name="defender-drain-1484", workdir=root, env={},
                                     mounts=(Mount(source=run_dir, target=run_dir, writable=True),),
                                     tenant_id=TEST_TENANT), docker=docker)


@pytest.fixture
def sandboxed(monkeypatch):
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    monkeypatch.delenv(box_mod.BoxSpec.ENV_VAR, raising=False)


@pytest.mark.parametrize("lane", ["run-dir", "request"])
def test_a_daemon_without_runsc_refuses_naming_gvisor_and_the_runtime_lever(tmp_path, sandboxed, lane):
    with pytest.raises(box_mod.BoxRuntimeMissing) as e:
        _start(lane, tmp_path, _RuntimesDocker(("runc",)))
    message = str(e.value)
    assert "'runsc' is not registered with Docker" in message, message
    assert "runsc install" in message, message
    assert "Upgrade from before #1170" in message, message
    assert "DEFENDER_BOX_RUNTIME=runc" in message, message


@pytest.mark.parametrize("lane", ["run-dir", "request"])
def test_a_create_fault_with_runsc_registered_keeps_the_create_s_own_stderr(tmp_path, sandboxed, lane):
    """Control: the same refusal text from a daemon that does list runsc is not called a missing runtime."""
    with pytest.raises(BoxFault) as e:
        _start(lane, tmp_path, _RuntimesDocker(("runc", "runsc")))
    assert not isinstance(e.value, box_mod.BoxRuntimeMissing)
    assert str(e.value).startswith("could not create the box"), e.value
    assert _NO_RUNSC.strip() in str(e.value)


def test_a_daemon_that_cannot_list_its_runtimes_keeps_the_create_s_own_stderr(tmp_path, sandboxed):
    """`docker info` answering nothing usable: the plain create fault, never a guessed remedy."""
    with pytest.raises(BoxFault) as e:
        _start("run-dir", tmp_path, RecordingDocker(create=DockerFault(rc=125, stderr=_NO_RUNSC)))
    assert not isinstance(e.value, box_mod.BoxRuntimeMissing)


def test_the_unsandboxed_opt_out_still_degrades_a_missing_runtime(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    monkeypatch.delenv(box_mod.BoxSpec.ENV_VAR, raising=False)
    root = tmp_path / "tree"
    run_dir = make_run_dir(tmp_path)
    plant_tree(root, copy_code=False)
    box = box_mod.start_box(BoxRequest(name="defender-drain-1484", workdir=root, env={},
                                       mounts=(Mount(source=run_dir, target=run_dir, writable=True),),
                                       tenant_id=TEST_TENANT), docker=_RuntimesDocker(("runc",)))
    assert box.name == "", "the opt-out did not degrade to the host"
