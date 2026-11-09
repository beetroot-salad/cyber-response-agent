"""#1446 review: every box a worker child's process tree starts carries that child's claim, so the worker
can remove whatever a killed or crashed child left (`box.CLAIM_LABEL`, `box.remove_claimed_containers`)."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from defender import box as box_mod
from defender.box import BoxRequest, BoxSpec, Mount
from defender.tests.support.sandbox._spec1092 import STOCK_ROOTFS, make_run_dir
from defender.tests.support.tenancy._host1214 import TEST_TENANT

CLAIM = "0123456789abcdef0123456789abcdef"


def _labels(argv: list[str]) -> list[str]:
    return [argv[i + 1] for i, flag in enumerate(argv) if flag == "--label"]


def _run_box_argv(tmp_path: Path) -> list[str]:
    run_dir = make_run_dir(tmp_path)
    defender = tmp_path / "srv" / "defender"
    return box_mod._create_argv("defender-run-claim", run_dir, defender, BoxSpec(rootfs=STOCK_ROOTFS), (),
                                lane=box_mod._run_lane_mounts(run_dir, defender, None)).argv


def _request_box_argv(tmp_path: Path) -> list[str]:
    run_dir = make_run_dir(tmp_path)
    request = BoxRequest(name="defender-oracle-claim", workdir=tmp_path / "wt", env={},
                         mounts=(Mount(source=run_dir, target=run_dir, writable=True),),
                         spec=BoxSpec(rootfs=STOCK_ROOTFS), tenant_id=TEST_TENANT)
    return box_mod._render_argv(request, ()).argv


@pytest.mark.parametrize("render", [_run_box_argv, _request_box_argv], ids=["run-box", "request-box"])
def test_a_box_started_under_a_worker_child_carries_its_claim_and_one_started_elsewhere_none(
        tmp_path, monkeypatch, render):
    """Both creates (a run box: an investigation's or a sibling's; a request box: an oracle's or a drain's) stamp the
    claim the process was handed; with none handed, no claim label at all."""
    monkeypatch.delenv(box_mod.CLAIM_ENV, raising=False)
    assert not [label for label in _labels(render(tmp_path / "a")) if label.startswith(f"{box_mod.CLAIM_LABEL}=")]
    monkeypatch.setenv(box_mod.CLAIM_ENV, CLAIM)
    assert f"{box_mod.CLAIM_LABEL}={CLAIM}" in _labels(render(tmp_path / "b"))


@pytest.mark.parametrize("value", ["", "not-a-claim", CLAIM.upper(), CLAIM + "0", f"{CLAIM} --privileged"])
@pytest.mark.parametrize("render", [_run_box_argv, _request_box_argv], ids=["run-box", "request-box"])
def test_a_claim_that_is_not_one_the_worker_mints_refuses_the_box_and_is_never_degraded(
        tmp_path, monkeypatch, render, value):
    """A box the worker could not find would outlive its child, so a malformed claim refuses the create, as a
    configuration fault the unsandboxed opt-out never degrades (`BoxStartConflict`)."""
    monkeypatch.setenv(box_mod.CLAIM_ENV, value)
    with pytest.raises(box_mod.BoxStartConflict):
        render(tmp_path)


class _Daemon:
    """Containers by name, each with its labels; `ps -aq --filter label=K=V` lists the matching ones."""

    def __init__(self, containers: dict[str, dict[str, str]]) -> None:
        self.containers = containers
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **_kw) -> subprocess.CompletedProcess:
        argv = list(argv)
        self.calls.append(argv)
        if argv[1] == "ps":
            key, _, value = argv[argv.index("--filter") + 1].removeprefix("label=").partition("=")
            names = [n for n, labels in self.containers.items() if labels.get(key) == value]
            return subprocess.CompletedProcess(argv, 0, stdout="".join(f"{n}\n" for n in names), stderr="")
        if argv[1] == "rm":
            self.containers.pop(argv[-1], None)
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="Error: No such object\n")


def test_the_claim_sweep_removes_every_container_of_the_claim_and_no_other():
    """Whatever state they are in: the child that held them is gone. Another child's, and an unclaimed one, stay."""
    other = "f" * 32
    daemon = _Daemon({
        "defender-run-sibling": {box_mod.CLAIM_LABEL: CLAIM},
        "defender-oracle-1": {box_mod.CLAIM_LABEL: CLAIM},
        "defender-run-another-job": {box_mod.CLAIM_LABEL: other},
        "defender-run-operator": {},
    })
    assert box_mod.remove_claimed_containers(CLAIM, docker=daemon) is None
    assert sorted(daemon.containers) == ["defender-run-another-job", "defender-run-operator"]


def test_the_claim_sweep_refuses_a_value_that_is_not_a_claim():
    """An empty or malformed value would filter on the wrong label value; it is refused before docker is asked."""
    daemon = _Daemon({})
    for value in ("", "x", CLAIM.upper()):
        with pytest.raises(ValueError, match="claim token"):
            box_mod.remove_claimed_containers(value, docker=daemon)
    assert daemon.calls == []


def test_the_workers_container_seam_sweeps_through_the_box_package_and_raises_what_it_could_not_remove():
    """`DockerContainers.remove_claimed`: the box package's sweep; a daemon that cannot list is a `BoxFault`."""
    from defender.worker._containers import DockerContainers

    daemon = _Daemon({"defender-run-sibling": {box_mod.CLAIM_LABEL: CLAIM}})
    DockerContainers(docker=daemon).remove_claimed(CLAIM)
    assert daemon.containers == {}

    def refusing(argv: list[str], **_kw) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="Cannot connect to the Docker daemon\n")

    with pytest.raises(box_mod.BoxFault):
        DockerContainers(docker=refusing).remove_claimed(CLAIM)
