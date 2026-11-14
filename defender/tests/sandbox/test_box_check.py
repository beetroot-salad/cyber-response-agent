"""#1469 S3: a sandboxed box create is preceded by a box check, proven by running a box (D1-D3, D5), over a fake daemon
whose check containers connect to the production listener's real socket (`support/sandbox/_box_check1469.py`).

Interfaces this contract picks (the code stage provides them): `box.BoxCheckFailed(BoxFault)`; the keyword `data_root` on
the run lane's `start_box`, on `BoxRequest` (optional), and on the oracle chain; the check's marker words `connected` /
`refused <errno>`; the check's docker call carrying `timeout=30`."""
from __future__ import annotations

import contextlib
import errno
import gc
import os
import re
import resource
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

from defender import box as box_mod
from defender.box import BoxRequest, BoxSpec, Mount
from defender.box import _lifecycle
from defender.execution.box_codec import BoxFault
from defender.tests.e2e._box665 import RecordingDocker, _cp
from defender.tests.support.sandbox import _box_check1469 as K
from defender.tests.support.sandbox._spec1092 import make_run_dir, plant_tree, subcommands
from defender.tests.support.tenancy._host1214 import TEST_TENANT

ROOTFS = "python:3.11-slim"
PINNED = BoxSpec(rootfs=ROOTFS)
RUNC = BoxSpec(rootfs=ROOTFS, runtime="runc")
LISTED = {"runc": {"path": "runc"}, "runsc": {"path": "/usr/bin/runsc", "runtimeArgs": ["--oci-seccomp"]}}
LANES = ["run-dir", "request", "oracle", "drain"]


#: Every fake daemon `_daemon` built in the running test, for the per-run invariants below.
_BUILT: list[RecordingDocker] = []


@pytest.fixture(autouse=True)
def sandboxed(monkeypatch):
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    monkeypatch.delenv(BoxSpec.ENV_VAR, raising=False)
    monkeypatch.delenv(box_mod.CLAIM_ENV, raising=False)


def _create_names_image(argv: list[str], image: str) -> bool:
    """Whether the box's create names `image` as its rootfs: the word before its `sh -c` command, where it has one."""
    at = [i for i in range(1, len(argv) - 1) if argv[i:i + 2] == ["sh", "-c"]]
    return argv[at[0] - 1] == image if at else image in argv


@pytest.fixture(autouse=True)
def every_check_run_keeps_its_invariants(sandboxed, monkeypatch):
    """(G-C) Over EVERY check container any test here ran, however it ended: its folder is gone afterwards; its rootfs is the
    one the box's own create resolved for that spec (read off the create, so no image is pinned here); its labels are exactly
    the process's claim and tenant, the claim label absent when the process has no claim. (D1, per-run invariants)"""
    _BUILT.clear()
    yield
    claim = os.environ.get(box_mod.CLAIM_ENV)
    expected = sorted([f"{box_mod.TENANT_LABEL}={TEST_TENANT}"] + ([f"{box_mod.CLAIM_LABEL}={claim}"] if claim else []))
    for docker in _BUILT:
        for run in docker.checks.runs:
            parsed = _parse(run.argv)
            assert not run.folder.exists(), f"the check folder outlived its check: {run.folder}"
            labels = sorted(v for f, v in parsed["flags"] if f == "--label")
            assert labels == expected, (labels, expected)
            if docker.create_argv is not None:
                assert _create_names_image(docker.create_argv, parsed["image"]), (parsed["image"], docker.create_argv)


def _failed() -> type:
    return box_mod.BoxCheckFailed


def _daemon(plan: K.CheckPlan | None = None, **kw) -> RecordingDocker:
    kw.setdefault("runtimes", LISTED)
    kw.setdefault("daemon_id", "daemon-1")
    docker = RecordingDocker(check=plan, **kw)
    _BUILT.append(docker)
    return docker


def _data_root(tmp_path: Path, name: str = "data") -> Path:
    root = tmp_path / name
    root.mkdir(parents=True, exist_ok=True)
    return root


def _request(tmp_path: Path, *, data_root: Path | None, spec: BoxSpec = PINNED, name: str = "defender-check-1469",
             require_sandbox: bool = False, mounts: tuple | None = None) -> BoxRequest:
    root = tmp_path / "tree"
    plant_tree(root, copy_code=False)
    run_dir = make_run_dir(tmp_path)
    kw = {} if data_root is None else {"data_root": data_root}
    return BoxRequest(name=name, workdir=root, env={}, spec=spec, tenant_id=TEST_TENANT, require_sandbox=require_sandbox,
                      mounts=mounts if mounts is not None else (Mount(source=run_dir, target=run_dir, writable=True),),
                      **kw)


def _start(lane: str, tmp_path: Path, docker, *, data_root: Any = ..., spec: BoxSpec = PINNED,
           require_sandbox: bool = False):
    """One box start on `lane`; `data_root` defaults to the tmp folder's `data`."""
    root = _data_root(tmp_path) if data_root is ... else data_root
    docker.forget_box()  # a test that starts boxes in turn on one fake daemon: each start finds its name free
    if lane == "run-dir":
        defender_dir = plant_tree(tmp_path / "tree", copy_code=False)
        kw = {} if root is None else {"data_root": root}
        return box_mod.start_box(make_run_dir(tmp_path), defender_dir, docker=docker, spec=spec, tenant_id=TEST_TENANT,
                                 require_sandbox=require_sandbox, **kw)
    if lane == "oracle":
        kw = {} if root is None else {"data_root": root}
        env = {"PATH": os.environ["PATH"], BoxSpec.ENV_VAR: spec.runtime}
        return box_mod.start_oracle_box(env=env, tenant_id=TEST_TENANT, folder=_data_root(tmp_path, "oracle"),
                                        docker=docker, **kw)
    return box_mod.start_box(_request(tmp_path, data_root=root, spec=spec, require_sandbox=require_sandbox or lane == "drain"),
                             docker=docker)


# --- D1: the verdicts, observed through the listener's own accept ------------------------------------------------------

@pytest.mark.parametrize("lane", LANES)
def test_d1_a_box_runtime_that_refuses_the_connect_and_a_control_that_connects_pass_and_the_create_follows(tmp_path, lane):
    """Pass: box-runtime run at its marker with no accept, control connected with an accept; the box is created. (D1, S3)"""
    docker = _daemon()
    try:
        box = _start(lane, tmp_path, docker)
    except box_mod.BoxStartRefused as refused:  # the oracle wraps its start fault
        pytest.fail(f"a healthy check refused the start: {refused}")
    assert box.sandboxed, "the box did not start sandboxed"
    assert docker.create_argv is not None, "no create followed the pass"
    box_runs, control_runs = docker.checks.box_runs(), docker.checks.control_runs()
    assert (len(box_runs), len(control_runs)) == (1, 1), docker.checks.runs
    assert control_runs[0].connected is True, docker.checks.runs
    assert box_runs[0].connected is False, docker.checks.runs
    assert docker.calls.index(box_runs[0].argv) < docker.calls.index(docker.create_argv), "the check followed the create"


@pytest.mark.parametrize("box_does", [K.LEAKS, K.ACCEPTS_BUT_SAYS_REFUSED])
@pytest.mark.parametrize("lane", ["run-dir", "request"])
def test_d1_a_box_runtime_run_the_listener_accepted_or_that_reported_connected_is_a_failed_check_and_nothing_is_created(
        tmp_path, lane, box_does):
    """Failed: the box runtime's run connected, or the host listener accepted during it, whatever the marker says: the
    remedy names the guarantee and the #1469 upgrade section; no create. (D1, D3, S3)"""
    docker = _daemon(K.CheckPlan(box=box_does))
    with pytest.raises(_failed()) as e:
        _start(lane, tmp_path, docker)
    assert docker.create_argv is None, "a box was created under a runtime that failed its check"
    assert "host socket" in str(e.value), e.value
    assert "Upgrade from before #1469" in str(e.value), e.value
    assert not {"create", "start"} & set(subcommands(docker.calls)), docker.calls


_HOST_LAYOUT = ("shared", "layout", "label", "selinux")  # loose: what a control that did not connect points the operator at


def _plain(message: object, docker: RecordingDocker, root: Path) -> str:
    """A refusal's words with every name and folder this run's check recorded (and the box's own name) replaced by a
    placeholder, so two refusals compare by what they say."""
    text = str(message)
    # The box's own name is only on a create, and a refusal has none: a name is replaced where there is one.
    names = {r.name for r in docker.checks.runs} | {docker.flag_value("--name") if docker.create_argv is not None else None}
    for run in docker.checks.runs:
        for folder in (str(run.folder), run.source):
            text = text.replace(folder, "<folder>")
    for name in sorted((n for n in names if n), key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text.replace(str(root), "<tmp>").lower()


def _refusal(plan: K.CheckPlan, tmp_path: Path, *, lane: str = "request") -> tuple[RecordingDocker, BoxFault | None]:
    docker = _daemon(plan)
    try:
        _start(lane, tmp_path, docker)
    except BoxFault as fault:
        return docker, fault
    return docker, None


@pytest.mark.parametrize("control", K.CELLS, ids=str)
@pytest.mark.parametrize("box", K.CELLS, ids=str)
def test_d1_the_verdict_is_d1_s_rule_over_every_marker_and_accept_of_the_box_run_and_the_control(tmp_path, box, control):
    """Every (marker x accept) of the box-runtime run against every one of the control: failed when the box run printed
    `connected` or the listener accepted; pass only when it refused unaccepted AND the control connected with an accept;
    else an inconclusive refusal whose words tell the box run's causes from the control's. (D1, D3)"""
    want = K.verdict(box, control)
    docker, fault = _refusal(K.CheckPlan(box=box, control=control), tmp_path)

    if want == "pass":
        assert fault is None, f"a healthy check refused the start: {fault}"
        assert docker.create_argv is not None, "no create followed the pass"
        return
    assert fault is not None, "a check that did not pass let the box start"
    assert docker.create_argv is None, "a box was created after a check that did not pass"
    assert not {"create", "start"} & set(subcommands(docker.calls)), docker.calls
    if want == "failed":
        assert isinstance(fault, _failed()), fault
        assert "host socket" in str(fault), fault
        assert "Upgrade from before #1469" in str(fault), fault
        return
    assert not isinstance(fault, _failed()), "an inconclusive check was reported as a leak"
    message = str(fault).lower()
    if box.marker == K.REFUSED:  # the box run is fine: the control is the cause
        # The reading chosen of D1's "a control that did not connect": every failed control names a host-layout cause.
        assert any(k in message for k in _HOST_LAYOUT), f"a control that did not connect names no host-layout cause: {fault}"
        if control.marker == K.REFUSED:
            assert re.search(r"\b111\b", _plain(fault, docker, tmp_path)), f"the control's refusal lost its errno: {fault}"
        return
    # The box-runtime run is the cause: its words differ from the same cell as the CONTROL's cause.
    mirror, other = _refusal(K.CheckPlan(box=K.SANDBOXES, control=box), tmp_path / "mirror")
    assert other is not None, "premise: the mirrored cell is refused"
    assert not isinstance(other, _failed()), "premise: the mirrored cell is inconclusive"
    assert _plain(fault, docker, tmp_path) != _plain(other, mirror, tmp_path / "mirror"), \
        f"a box-run cause and a control cause read the same: {fault}"


def test_d1_the_three_box_run_inconclusive_causes_read_differently(tmp_path):
    """No marker, did not start and timed out: three different messages once every recorded name and folder is replaced."""
    seen = {}
    for cell in (K.NO_MARKER, K.START_FAILS, K.HANGS):
        root = tmp_path / str(cell.marker)
        docker, fault = _refusal(K.CheckPlan(box=cell), root)
        assert fault is not None, cell
        assert not isinstance(fault, _failed()), (cell, fault)
        seen[cell.marker] = _plain(fault, docker, root)
    assert len(set(seen.values())) == 3, seen


def test_d1_the_timeout_is_thirty_seconds_and_removes_the_check_container_by_name(tmp_path):
    """A run that outlives the host's 30 s is cut with `docker rm -f <the check's name>`: the client's kill would leave it
    running. (D1, timeout)"""
    docker = _daemon(K.CheckPlan(box=K.HANGS))
    with pytest.raises(BoxFault):
        _start("request", tmp_path, docker)
    (hung,) = docker.checks.box_runs()
    assert hung.kwargs.get("timeout") == 30, hung.kwargs
    assert ["docker", "rm", "-f", hung.name] in docker.calls, docker.calls


class _NoImage(RecordingDocker):
    """A daemon that holds no image (`docker image inspect` fails), otherwise healthy."""

    def __call__(self, argv, **kw):  # noqa: ANN001
        if list(argv)[1:3] == ["image", "inspect"]:
            self.calls.append(list(argv))
            return _cp(1, "", "Error: No such image\n")
        return super().__call__(argv, **kw)


def _no_runtime() -> RecordingDocker:
    return _daemon(runtimes=("runc",))


def _no_image() -> RecordingDocker:
    docker = _NoImage(runtimes=LISTED, daemon_id="daemon-1")
    _BUILT.append(docker)
    return docker


def _name_taken() -> RecordingDocker:
    return _daemon(status="running")


@pytest.mark.parametrize(("refused_by", "make", "words"), [
    ("runtime-presence", _no_runtime, "no runtime 'runsc' registered"),
    ("image-presence", _no_image, "holds no image"),
    ("name-conflict", _name_taken, ""),
], ids=["runtime-presence", "image-presence", "name-conflict"])
@pytest.mark.parametrize("lane", ["run-dir", "request"])
def test_d1_every_pre_create_refusal_comes_before_the_check_and_is_never_read_as_inconclusive(
        tmp_path, lane, refused_by, make, words):
    """A missing runtime or image, or a name already taken, refuses with its own remedy before any check container runs.
    (D1, order)"""
    docker = make()
    with pytest.raises(BoxFault) as e:
        _start(lane, tmp_path, docker)
    assert words in str(e.value), e.value
    assert not isinstance(e.value, _failed()), e.value
    assert docker.checks.runs == [], f"a check ran before the {refused_by} refusal"
    assert docker.create_argv is None


def test_d1_an_uncovered_mount_of_the_box_refuses_before_the_check_runs(tmp_path):
    """A box bind on no shared mount is refused with the uncovered-mount remedy before any check container runs: the check
    follows every pre-create refusal. (D1, order)"""
    covered = tmp_path / "covered"
    mounts = ((covered, Path("/daemon/covered")),)
    docker = _daemon()
    with pytest.raises(BoxFault) as e:
        _lifecycle._start_boxed_request(_request(tmp_path, data_root=_data_root(covered)), docker, lambda _d: mounts)
    assert "shares with the docker daemon" in str(e.value), e.value
    assert docker.checks.runs == [], "a check ran before the uncovered-mount refusal"
    assert docker.create_argv is None


# --- D1: the check's argv ----------------------------------------------------------------------------------------------

_VALUED = {"--runtime", "--network", "--security-opt", "--ulimit", "--memory", "--memory-swap", "--cpus", "--pids-limit",
           "--name", "--label", "--mount"}
_BARE = {"--rm", "--read-only", "--pull=never"}


def _parse(argv: list[str]) -> dict:
    """The check's `docker run` as (flags, image, command), refusing any flag outside D1's set."""
    assert argv[:2] == ["docker", "run"], argv
    flags: list[tuple[str, str | None]] = []
    i = 2
    while argv[i].startswith("-"):
        flag = argv[i]
        if flag in _VALUED:
            flags.append((flag, argv[i + 1]))
            i += 2
        else:
            assert flag in _BARE, f"the check carries {flag}, which is no part of D1's set: {argv}"
            flags.append((flag, None))
            i += 1
    return {"flags": flags, "image": argv[i], "command": argv[i + 1:]}


def _normal(run: K.CheckRun) -> dict:
    parsed = _parse(run.argv)
    flags = [(f, "<name>" if f == "--name" else v.replace(run.source, "<folder>") if f == "--mount" else v)
             for f, v in parsed["flags"]]
    return {"flags": flags, "image": "<image>", "command": parsed["command"]}


def test_d1_the_check_is_the_boxs_confinement_its_image_labels_name_one_bind_and_the_connect_command(tmp_path, monkeypatch):
    """The check's argv is `--rm`, `_box_flags` with the runtime under check, the claim and tenant labels, a unique name,
    one read-write bind of the check folder at `/run/box-check`, the rootfs and the command; nothing else. (D1)"""
    monkeypatch.setenv(box_mod.CLAIM_ENV, "c" * 32)
    docker = _daemon()
    _start("request", tmp_path, docker)
    (run,) = docker.checks.box_runs()
    parsed = _parse(run.argv)
    flags = parsed["flags"]
    confinement = [(f, v) for f, v in flags if f not in ("--rm", "--name", "--label", "--mount")]
    tokens = _lifecycle._box_flags(PINNED)
    expected = [(tokens[i], tokens[i + 1]) if tokens[i] in _VALUED else (tokens[i], None) for i in range(len(tokens))
                if tokens[i].startswith("-")]
    assert confinement == expected, (confinement, expected)
    assert parsed["image"] == ROOTFS
    labels = sorted(v for f, v in flags if f == "--label")
    assert labels == sorted([f"{box_mod.TENANT_LABEL}={TEST_TENANT}", f"{box_mod.CLAIM_LABEL}={'c' * 32}"]), labels
    (mount,) = [v for f, v in flags if f == "--mount"]
    assert f"target={K.CHECK_TARGET}" in mount.split(","), mount
    assert "readonly" not in mount.split(","), mount
    assert K.CHECK_TARGET + "/" + K.SOCKET_NAME in " ".join(parsed["command"]), parsed["command"]
    names = {r.name for r in docker.checks.runs}
    assert len(names) == 2, names
    assert "" not in names, names
    assert docker.flag_value("--name") not in names, "the check reused the box's name"


def test_d1_without_a_claim_the_check_carries_the_tenant_label_alone(tmp_path):
    """No claim in the process: no `defender.claim` label on either check run, the tenant's label on both. (D1, labels)"""
    docker = _daemon()
    _start("request", tmp_path, docker)
    assert len(docker.checks.runs) == 2, docker.checks.runs
    for run in docker.checks.runs:
        labels = [v for f, v in _parse(run.argv)["flags"] if f == "--label"]
        assert labels == [f"{box_mod.TENANT_LABEL}={TEST_TENANT}"], labels


def test_d1_the_control_differs_from_the_box_runtime_run_only_by_the_runtime_and_the_name(tmp_path):
    """Same flags, bind, folder, image and command; `--runtime runc` named explicitly. (D1, control)"""
    docker = _daemon()
    _start("request", tmp_path, docker)
    (box,), (control,) = docker.checks.box_runs(), docker.checks.control_runs()
    assert box.runtime == "runsc"
    assert control.runtime == "runc"
    assert box.source == control.source, "the control used another folder"
    swap = lambda n: [(f, "<rt>" if f == "--runtime" else v) for f, v in n["flags"]]  # noqa: E731
    assert swap(_normal(box)) == swap(_normal(control))
    assert _normal(box)["command"] == _normal(control)["command"]
    assert box.name != control.name


def test_d1_for_equal_specs_the_check_is_the_same_for_a_run_lane_an_oracle_and_a_drain_box(tmp_path):
    """One pass proves every later box in the process, so the check cannot vary with the lane. (D1, D2)"""
    seen = {}
    for lane in LANES:
        docker = _daemon()
        _start(lane, tmp_path / lane, docker)
        seen[lane] = [_normal(r) for r in docker.checks.runs]
    assert all(v == seen["run-dir"] for v in seen.values()), seen


@pytest.mark.parametrize("lane", LANES)
def test_d5_no_docker_call_of_a_box_start_or_its_check_carries_an_annotation(tmp_path, lane):
    """gVisor honours a per-container `dev.gvisor.flag.host-uds` annotation the check cannot see: none appears. (D5)"""
    docker = _daemon()
    _start(lane, tmp_path, docker)
    assert docker.checks.runs, "control: the check ran"
    assert docker.create_argv, "control: the create ran"
    assert not [c for c in docker.calls if any(str(a).startswith("--annotation") for a in c)], docker.calls


# --- D1: the check folder and the data root ---------------------------------------------------------------------------

def test_d1_the_check_folder_is_a_fresh_open_folder_under_dot_box_checks_outside_every_bind_and_gone_afterwards(tmp_path):
    """`<data root>/.box-checks/<random>/` (0777, socket 0777, parent 0711) beside no bind of the box, per check; removed
    when the check ends. (D1, where the socket goes)"""
    root = _data_root(tmp_path)
    docker = _daemon()
    _start("request", tmp_path, docker, data_root=root)
    docker.runtimes = {**LISTED, "runsc": {"path": "/usr/bin/runsc", "runtimeArgs": ["--oci-seccomp", "--x"]}}
    _start("request", tmp_path / "again", docker, data_root=root)
    folders = {r.folder for r in docker.checks.runs}
    assert len(folders) == 2, "a second check reused the first one's folder"
    for run in docker.checks.runs:
        assert run.folder.parent == root / ".box-checks", run.folder
        assert (run.parent_mode, run.folder_mode, run.socket_mode) == (0o711, 0o777, 0o777), run
        assert not run.folder.exists(), "the check folder outlived its check"
    binds = [Path(m["source"]) for m in docker.mounts()]
    for run in docker.checks.runs:
        assert not any(b == run.folder or b.is_relative_to(run.folder) or run.folder.is_relative_to(b) for b in binds), binds
    assert list((root / ".box-checks").iterdir()) == []


def test_d1_a_data_root_past_the_socket_name_limit_still_passes_on_a_sandbox_and_fails_on_a_leak(tmp_path):
    """The host binds through a short descriptor path and the container connects at `/run/box-check/s`, so a 100+
    character data root cannot break either. (D1, long data root)"""
    root = _data_root(tmp_path, "d" * 60 + "/" + "e" * 60)
    assert len(str(root / ".box-checks" / ("x" * 32) / "s")) > 107
    ok = _daemon()
    _start("request", tmp_path, ok, data_root=root)
    assert ok.checks.control_runs()[0].connected is True, "the control could not connect through a long data root"
    assert str(root) not in " ".join(_parse(ok.checks.runs[0].argv)["command"])
    leaking = _daemon(K.CheckPlan(box=K.LEAKS))
    with pytest.raises(_failed()):
        _start("request", tmp_path / "leak", leaking, data_root=root)


def test_d1_the_check_folder_is_translated_through_shared_mounts_like_every_box_bind(tmp_path):
    """Under docker-outside-of-Docker the bind's source is the daemon's path for the folder; a data root on no shared mount
    is refused with the uncovered-mount remedy. (D1, translation)"""
    mounts = ((tmp_path, Path("/daemon/host")),)
    docker = _daemon(K.CheckPlan(daemon_view=((tmp_path, Path("/daemon/host")),)))
    request = _request(tmp_path, data_root=_data_root(tmp_path))
    _lifecycle._start_boxed_request(request, docker, lambda _d: mounts)
    assert docker.checks.runs
    assert all(r.source.startswith("/daemon/host/data/.box-checks/") for r in docker.checks.runs)
    assert docker.checks.control_runs()[0].connected is True

    lost = _daemon()
    with pytest.raises(BoxFault) as e:
        _lifecycle._start_boxed_request(_request(tmp_path / "b", data_root=Path("/elsewhere-1469")), lost, lambda _d: mounts)
    assert "shares with the docker daemon" in str(e.value), e.value
    assert lost.checks.runs == []
    assert lost.create_argv is None


def test_d1_the_run_lane_requires_its_data_root_at_once_even_for_a_runc_box(tmp_path):
    """Forgetting `data_root` on the run lane is a `TypeError` naming it, whatever the runtime. (D1, data root)"""
    defender_dir = plant_tree(tmp_path / "tree", copy_code=False)
    for spec in (PINNED, RUNC):
        with pytest.raises(TypeError, match="data_root"):
            box_mod.start_box(make_run_dir(tmp_path / spec.runtime), defender_dir, docker=_daemon(), spec=spec,
                              tenant_id=TEST_TENANT)


def test_d1_a_box_request_with_no_data_root_is_refused_as_inconclusive_under_runsc_and_starts_under_runc(tmp_path):
    """On `BoxRequest` the data root is optional; absent, a check cannot run, so a sandboxed start fails closed. (D1)"""
    docker = _daemon()
    with pytest.raises(BoxFault) as e:
        _start("request", tmp_path, docker, data_root=None)
    assert not isinstance(e.value, _failed())
    assert docker.create_argv is None
    assert docker.checks.runs == []
    assert "data root" in str(e.value).lower(), e.value
    runc = _daemon()
    assert _start("request", tmp_path / "runc", runc, data_root=None, spec=RUNC).name


@pytest.mark.parametrize("job", [False, True], ids=["run-dir-lane", "job-lane"])
def test_d1_with_the_opt_out_a_box_request_with_no_data_root_degrades_off_the_job_lane_and_still_refuses_on_it(
        tmp_path, monkeypatch, job):
    """No data root is inconclusive, so it follows D3's table: under `DEFENDER_ALLOW_UNSANDBOXED=1` the run-dir lane
    degrades to the host (no check, no create under `runsc`), the job lane (`require_sandbox`) refuses. (D1, D3)"""
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    docker = _daemon()
    if job:
        with pytest.raises(BoxFault) as e:
            _start("request", tmp_path, docker, data_root=None, require_sandbox=True)
        assert not isinstance(e.value, _failed()), e.value
        assert docker.create_argv is None
    else:
        box = _start("request", tmp_path, docker, data_root=None)
        assert box.sandboxed is False, "the opt-out did not degrade an inconclusive check"
    assert docker.checks.runs == []


@pytest.mark.parametrize("lane", ["run-dir", "request", "oracle", "drain"])
def test_d3_the_oracle_chain_and_the_run_lane_take_the_data_root_the_check_binds(tmp_path, lane):
    """The folder the check binds is under the data root the entry point handed in. (D1, data root)"""
    root = _data_root(tmp_path, "handed-in")
    docker = _daemon()
    _start(lane, tmp_path, docker, data_root=root)
    assert {r.folder.parent for r in docker.checks.runs} == {root / ".box-checks"}


# --- D2: once per process, per registration -----------------------------------------------------------------------------

def test_d2_one_check_per_process_per_seam_daemon_and_registration_and_every_create_asks_docker_info(tmp_path):
    """Two boxes on one seam and one registration run one check; each create asked `docker info`. (D2)"""
    docker = _daemon()
    _start("request", tmp_path / "a", docker)
    _start("request", tmp_path / "b", docker)
    assert (len(docker.checks.box_runs()), len(docker.checks.control_runs())) == (1, 1), docker.checks.runs
    assert subcommands(docker.calls).count("info") >= 2, docker.calls


def test_d2_a_changed_runtimes_entry_or_a_changed_daemon_id_runs_the_check_again(tmp_path):
    """The key is the seam, the daemon's ID and a hash of the runtime's `docker info` entry. (D2)"""
    docker = _daemon()
    _start("request", tmp_path / "a", docker)
    docker.runtimes = {**LISTED, "runsc": {"path": "/usr/bin/runsc", "runtimeArgs": ["--oci-seccomp", "--host-uds=open"]}}
    _start("request", tmp_path / "b", docker)
    assert len(docker.checks.box_runs()) == 2, "a re-registration was not re-checked"
    docker.daemon_id = "daemon-2"
    _start("request", tmp_path / "c", docker)
    assert len(docker.checks.box_runs()) == 3, "another daemon behind the same seam was not re-checked"
    _start("request", tmp_path / "d", docker)
    assert len(docker.checks.box_runs()) == 3


def test_d2_another_seam_is_checked_on_its_own(tmp_path):
    """The verdict is keyed by the seam's identity. (D2)"""
    first, second = _daemon(), _daemon()
    _start("request", tmp_path / "a", first)
    _start("request", tmp_path / "b", second)
    assert len(first.checks.box_runs()) == len(second.checks.box_runs()) == 1


def test_d2_the_key_is_the_seam_itself_so_twenty_fresh_seams_built_used_once_and_dropped_each_run_their_own_check(tmp_path):
    """A seam freed and a new one made may reuse its address: each of 20 in sequence, alike in daemon ID and registration,
    still runs its own check. (D2)"""
    for n in range(20):
        docker = RecordingDocker(runtimes=LISTED, daemon_id="daemon-1")
        box = _start("request", tmp_path / f"seam{n}", docker)
        assert (len(docker.checks.box_runs()), len(docker.checks.control_runs())) == (1, 1), (n, docker.checks.runs)
        del box, docker
        gc.collect()


@pytest.mark.parametrize("bad", [K.CheckPlan(box=K.LEAKS), K.CheckPlan(box=K.NO_MARKER)], ids=["failed", "inconclusive"])
def test_d2_a_refusal_is_not_kept_so_a_host_fixed_mid_process_is_seen_at_the_next_create(tmp_path, bad):
    """Only passes are kept: the same seam refuses twice (checked twice), then passes once the host is fixed. (D2)"""
    docker = _daemon(bad)
    for n in range(2):
        with pytest.raises(BoxFault):
            _start("request", tmp_path / f"r{n}", docker)
    assert len(docker.checks.box_runs()) == 2, "a refusal was kept"
    docker.checks.plan = K.CheckPlan()
    assert _start("request", tmp_path / "fixed", docker).name
    assert len(docker.checks.box_runs()) == 3


@pytest.mark.parametrize("docker_kw", [{"info_fails": True}, {"runtimes": None, "daemon_id": None}],
                         ids=["info-fails", "info-names-nothing"])
def test_d2_when_docker_info_cannot_answer_the_check_runs_and_its_pass_is_not_kept(tmp_path, docker_kw):
    """No key can be formed, so every create checks. (D2)"""
    docker = _daemon(**docker_kw)
    for n in range(2):
        assert _start("request", tmp_path / f"s{n}", docker).name
    assert len(docker.checks.box_runs()) == 2, docker.checks.runs


def test_d2_no_check_runs_under_runc(tmp_path):
    """`runc` is the declared no-sandbox mode: no check container, no data root needed. (D2, non-obligation)"""
    docker = _daemon()
    assert _start("request", tmp_path, docker, spec=RUNC).name
    assert docker.checks.runs == []


# --- D3: what each outcome does (the opt-out and the job lane) ------------------------------------------------------------

def _outcome(plan: K.CheckPlan, tmp_path: Path, lane: str, *, job: bool, opt_out: bool, monkeypatch):
    if opt_out:
        monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    docker = _daemon(plan)
    try:
        box = _start(lane, tmp_path, docker, require_sandbox=job)
    except BoxFault as fault:
        return ("failed" if isinstance(fault, _failed()) else "refused"), docker
    return ("started" if box.sandboxed else "degraded"), docker


@pytest.mark.parametrize("lane", ["run-dir", "request"])
@pytest.mark.parametrize("job", [False, True], ids=["run-dir-lane", "job-lane"])
@pytest.mark.parametrize("opt_out", [False, True], ids=["no-opt-out", "opt-out"])
def test_d3_table_pass_starts_failed_refuses_with_and_without_the_opt_out_and_inconclusive_degrades_only_off_the_job_lane(
        tmp_path, monkeypatch, lane, job, opt_out):
    """Every cell of D3's table. (D3)"""
    verdict, docker = _outcome(K.CheckPlan(), tmp_path / "pass", lane, job=job, opt_out=opt_out, monkeypatch=monkeypatch)
    assert verdict == "started"
    assert docker.create_argv is not None
    verdict, docker = _outcome(K.CheckPlan(box=K.LEAKS), tmp_path / "failed", lane, job=job, opt_out=opt_out,
                               monkeypatch=monkeypatch)
    assert verdict == "failed", "the opt-out let a leaking runtime through"
    assert docker.create_argv is None
    verdict, docker = _outcome(K.CheckPlan(box=K.NO_MARKER), tmp_path / "inconclusive", lane, job=job, opt_out=opt_out,
                               monkeypatch=monkeypatch)
    assert verdict == ("degraded" if opt_out and not job else "refused"), verdict
    assert docker.create_argv is None


def test_d3_a_failed_check_is_a_box_fault_that_is_no_start_conflict():
    """It is excluded from the opt-out by its own type, beside `BoxStartConflict`, never by being one. (D3)"""
    assert issubclass(_failed(), BoxFault)
    assert not issubclass(_failed(), box_mod.BoxStartConflict)


def test_d3_the_oracle_s_box_start_fault_carries_a_failed_check_in_its_chain(tmp_path):
    """An oracle attempt fails like any start fault: `start_oracle_box` refuses, the failed check stays in the cause
    chain and nothing is created. (D3, oracle)"""
    docker = _daemon(K.CheckPlan(box=K.LEAKS))
    with pytest.raises(box_mod.BoxStartRefused) as refused:
        _start("oracle", tmp_path, docker)
    assert isinstance(refused.value.__cause__, _failed()), refused.value.__cause__
    assert docker.create_argv is None


# --- D2 (G1): the registration key, over every input it is made of -----------------------------------------------------------

_BASE_ENTRY = {"path": "/usr/bin/runsc", "runtimeArgs": ["--oci-seccomp"], "status": {"features": {"v": 1}}}


def _listed(entry: dict | None = None, **others: dict) -> dict:
    return {"runc": {"path": "runc"}, **others, "runsc": _BASE_ENTRY if entry is None else entry}


class _InfoDaemon(RecordingDocker):
    """A healthy daemon whose `docker info` can fail one of its two questions (`{{.ID}}`, `{{json .Runtimes}}`) alone."""

    fail_info: tuple[str, ...] = ()

    def __call__(self, argv, **kw):  # noqa: ANN001
        argv = list(argv)
        if argv[1:2] == ["info"] and "--format" in argv and any(q in argv[argv.index("--format") + 1] for q in self.fail_info):
            self.calls.append(argv)
            return _cp(1, "", "Error: the daemon could not answer that\n")
        return super().__call__(argv, **kw)


#: (name, what the daemon answers instead, whether the `(ID, entry)` pair is the one that passed: True the same, False
#: another, None one half cannot be read). Written from the key's own words, not from how it is hashed.
_KEY_INPUTS = [
    ("path", {"runtimes": _listed({**_BASE_ENTRY, "path": "/opt/gvisor/runsc"})}, False),
    ("runtime-args", {"runtimes": _listed({**_BASE_ENTRY, "runtimeArgs": ["--oci-seccomp", "--host-uds=open"]})}, False),
    ("status", {"runtimes": _listed({**_BASE_ENTRY, "status": {"features": {"v": 2}}})}, False),
    ("daemon-id", {"daemon_id": "daemon-2"}, False),
    ("entry-key-order", {"runtimes": _listed(dict(reversed(list(_BASE_ENTRY.items()))))}, True),
    ("another-runtime-changed", {"runtimes": {"runc": {"path": "/elsewhere/runc"}, "runsc": _BASE_ENTRY}}, True),
    ("id-only", {"runtimes": None}, None),
    ("runtimes-only", {"daemon_id": None}, None),
    ("nonzero-exit", {"info_fails": True}, None),
    ("empty", {"runtimes": None, "daemon_id": None}, None),
    ("runtime-absent", {"runtimes": {}}, None),
    ("id-query-fails", {"fail_info": ("{{.ID}}",)}, None),
    ("runtimes-query-fails", {"fail_info": ("{{json .Runtimes}}",)}, None),
]


@pytest.mark.parametrize(("change", "same_pair"), [(c, same) for _n, c, same in _KEY_INPUTS],
                         ids=[n for n, _c, _s in _KEY_INPUTS])
def test_d2_the_check_runs_again_exactly_when_the_id_and_entry_pair_differs_or_a_half_cannot_be_read_and_an_unreadable_key_is_never_kept(
        tmp_path, change, same_pair):
    """After a pass on one `(daemon ID, runsc entry)` pair, ONE input changes (or `docker info` stops answering in part)
    and the box is created twice more: the first create re-checks unless the pair is the one that passed; the second
    re-checks only when a half cannot be read, whatever the first did: a pair that could not be named is never kept."""
    docker = _InfoDaemon(runtimes=_listed(), daemon_id="daemon-1")
    _BUILT.append(docker)
    _start("request", tmp_path / "pass", docker)
    assert len(docker.checks.box_runs()) == 1, "premise: the first create ran its check"
    for name, value in change.items():
        setattr(docker, name, value)
    seen = [len(docker.checks.box_runs())]
    for n in range(2):
        _start("request", tmp_path / f"again{n}", docker)
        seen.append(len(docker.checks.box_runs()))
    reran = [b - a for a, b in zip(seen, seen[1:], strict=False)]
    expected = [0, 0] if same_pair else [1, 0] if same_pair is False else [1, 1]
    assert reran == expected, (reran, expected)
    assert docker.create_argv is not None, "a create did not follow the check"


# --- D1 (G2): check containers are named once and none is left live -----------------------------------------------------------

class _LifecycleDaemon(RecordingDocker):
    """A daemon that models a check container's life: a name still live makes the next `docker run` with it exit 125
    (name in use); a run that outlives the host's timeout leaves its container live until `docker rm -f <name>`; a `--rm`
    run that ends is gone."""

    def __init__(self, **kw: Any) -> None:
        super().__init__(**kw)
        self.live: set[str] = set()
        self.run_names: list[str] = []

    def __call__(self, argv, **kw):  # noqa: ANN001
        argv = list(argv)
        if K.is_check_run(argv):
            name = K.flag_value(argv, "--name") or ""
            self.run_names.append(name)
            if name in self.live:
                self.calls.append(argv)
                return _cp(125, "", f'docker: Error response from daemon: Conflict. The container name "/{name}" is already in use\n')
            try:
                return super().__call__(argv, **kw)
            except subprocess.TimeoutExpired:
                self.live.add(name)
                raise
        if argv[1:2] == ["rm"]:
            self.live.difference_update(a for a in argv[2:] if not a.startswith("-"))
        return super().__call__(argv, **kw)


@pytest.mark.parametrize("hung", ["box", "control"])
def test_d1_a_hung_check_container_is_removed_and_a_second_check_after_it_reuses_no_name(tmp_path, hung):
    """Each run of a check hangs in turn; a second check follows on a healthy host: no check container is left live, no
    name was used twice (a live one would exit 125 'in use'), and within a check the box run and the control are named
    apart. (D1, timeout)"""
    docker = _LifecycleDaemon(runtimes=LISTED, daemon_id="daemon-1",
                              check=K.CheckPlan(box=K.HANGS) if hung == "box" else K.CheckPlan(control=K.HANGS))
    _BUILT.append(docker)
    with pytest.raises(BoxFault):
        _start("request", tmp_path / "hung", docker)
    assert docker.live == set(), f"the {hung} run's container was left live after the timeout: {docker.live}"
    docker.checks.plan = K.CheckPlan()
    assert _start("request", tmp_path / "second", docker).name, "the check after a hung one did not pass"
    assert docker.live == set(), docker.live
    assert len(docker.run_names) >= 3, docker.run_names
    assert "" not in docker.run_names, docker.run_names
    assert len(set(docker.run_names)) == len(docker.run_names), f"a check container name was used twice: {docker.run_names}"


# --- D1 (G3): the listener counts every connect, and the check never changes the process's folder ----------------------------

class _CwdWatch:
    """A thread that records every working folder the process has while it runs."""

    def __init__(self) -> None:
        self.seen: set[str] = set()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="cwd-watch")

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.seen.add(os.getcwd())
            except OSError as e:  # the folder it stood in is gone
                self.seen.add(f"<{e.__class__.__name__}>")

    def __enter__(self) -> _CwdWatch:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        self._thread.join()


@pytest.mark.parametrize("starved", [False, True], ids=["connect-returns-at-once", "listener-cannot-accept-meanwhile"])
@pytest.mark.parametrize("who", ["box-run", "control"])
def test_d1_a_connect_docker_returns_before_the_listener_accepts_is_still_counted_and_the_check_never_changes_the_working_folder(
        tmp_path, who, starved):
    """The fake daemon connects for real and returns the moment `connect()` does, so the stream may still be in the
    listener's backlog when the run ends (with `starved`, the process also has no descriptor to accept it with for the rest
    of the run, then gets them back). A box run so connected (it printed `refused`: only the listener knows) is a failed
    check; a control so connected passes: every completed connect is counted. Over many checks, with the process's working
    folder watched from another thread and a switch interval short enough for an accept thread to start late: a check
    never changes the folder the process stands in. (D1, listener; the working folder is process-wide)"""
    cell = K.Cell(K.REFUSED, True, wait=False, starved=starved)
    plan = K.CheckPlan(box=cell) if who == "box-run" else K.CheckPlan(control=K.Cell(K.CONNECTED, True, wait=False, starved=starved))
    here = os.getcwd()
    interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        with _CwdWatch() as watch:
            for n in range(3 if starved else 40):
                docker = _daemon(plan)
                if who == "box-run":
                    with pytest.raises(_failed(), match="host socket"):
                        _start("request", tmp_path / f"c{n}", docker)
                    assert docker.create_argv is None
                else:
                    assert _start("request", tmp_path / f"c{n}", docker).name, f"check {n}: a connected control went uncounted"
    finally:
        sys.setswitchinterval(interval)
    assert os.getcwd() == here
    assert watch.seen == {here}, f"the process's working folder was seen to change: {sorted(watch.seen)}"


# --- D1 (G4): the folder and its parent after every outcome ---------------------------------------------------------------------

_OUTCOMES = {
    "pass": K.CheckPlan(),
    "failed": K.CheckPlan(box=K.LEAKS),
    "inconclusive": K.CheckPlan(box=K.NO_MARKER),
    "box-run-times-out": K.CheckPlan(box=K.HANGS),
    "control-times-out": K.CheckPlan(control=K.HANGS),
    "box-does-not-start": K.CheckPlan(box=K.START_FAILS),
    "control-refused": K.CheckPlan(control=K.REFUSES),
}


@pytest.mark.parametrize("parent", ["fresh-data-root", "existing-0700"])
@pytest.mark.parametrize("outcome", sorted(_OUTCOMES))
def test_d1_whatever_the_check_ends_in_it_leaves_no_folder_and_made_its_parent_traverse_only_and_its_folder_and_socket_open_under_a_narrow_umask(
        tmp_path, outcome, parent):
    """Under `umask 077`, with a `.box-checks` that already exists as 0700 or none at all: the daemon sees the parent 0711,
    the check's folder and socket 0777, and afterwards `.box-checks` lists nothing, for every way a check can end. (D1)"""
    root = _data_root(tmp_path)
    if parent == "existing-0700":
        (root / ".box-checks").mkdir(mode=0o700)
        os.chmod(root / ".box-checks", 0o700)
    docker = _daemon(_OUTCOMES[outcome])
    before = os.umask(0o077)
    try:
        with contextlib.suppress(BoxFault):
            _start("request", tmp_path, docker, data_root=root)
    finally:
        os.umask(before)
    assert docker.checks.runs, "premise: the check ran"
    for run in docker.checks.runs:
        assert (run.parent_mode, run.folder_mode, run.socket_mode) == (0o711, 0o777, 0o777), (outcome, run)
        assert run.folder.parent == root / ".box-checks", run.folder
    assert (root / ".box-checks").is_dir()
    assert list((root / ".box-checks").iterdir()) == [], f"the check left {list((root / '.box-checks').iterdir())} behind"


@contextlib.contextmanager
def _descriptors_left(free: int):
    """This process has `free` file descriptors left to give: the soft limit is lowered to the highest one in use and every
    free number below it is taken but `free` of them. Everything is given back, and the limit restored, on exit, so a test
    asserts only after the `with` has closed. (Every test here runs in an xdist worker that may host others.)"""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    held: list[int] = []
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (max(int(n) for n in os.listdir("/proc/self/fd")) + 1, hard))
        while True:
            try:
                held.append(os.open(os.devnull, os.O_RDONLY))
            except OSError:
                break
        for _ in range(free):
            os.close(held.pop())
        yield
    finally:
        for fd in held:
            os.close(fd)
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))


def _open_descriptors() -> list[str]:
    return sorted(os.listdir("/proc/self/fd"), key=int)


@pytest.mark.parametrize("free", [0, 1], ids=["no-descriptor-for-the-folder", "one-descriptor-for-the-folder-none-for-the-socket"])
def test_d1_a_check_whose_listener_cannot_be_opened_for_want_of_descriptors_is_inconclusive_and_leaves_no_folder_and_no_descriptor(
        tmp_path, free):
    """The process is out of file descriptors when the check opens its listener (with `free=1` the folder's handle gets the
    last one and the socket none): the start is refused as a check that could not say (a `BoxFault`, not a failed check)
    naming the socket error, `.box-checks` lists nothing (removing the folder needs no descriptor of its own), no check
    container ran, no box was created, and no descriptor the failed open took is still open once the start has failed. (D1, G4)"""
    root = _data_root(tmp_path)
    docker = _daemon()
    request = _request(tmp_path, data_root=root, require_sandbox=True)
    before = _open_descriptors()
    caught: BaseException | None = None
    with _descriptors_left(free):
        try:
            box_mod.start_box(request, docker=docker)
        except BaseException as e:  # noqa: BLE001 — asserted below, once the descriptors are back
            caught = e
    after = _open_descriptors()
    assert isinstance(caught, BoxFault), f"a start with no descriptor for the check's listener ended in {caught!r}"
    assert not isinstance(caught, _failed()), f"an exhausted process is not a leaking runtime: {caught}"
    assert "could not open its socket" in str(caught), str(caught)
    assert os.strerror(errno.EMFILE) in str(caught), str(caught)
    assert docker.checks.runs == [], "a check container ran with no listener to watch it"
    assert docker.create_argv is None, "a box was created after a check that could not run"
    assert list((root / ".box-checks").iterdir()) == [], f"the check left {list((root / '.box-checks').iterdir())} behind"
    assert after == before, f"descriptors left open by the failed start: {sorted(set(after) - set(before), key=int)}"


# --- D1 (G7): every runtime but `runc` is checked ----------------------------------------------------------------------------------

@pytest.mark.parametrize("lane", ["run-dir", "request"])
@pytest.mark.parametrize("runtime", ["runsc-job", "kata", "runsc2"])
def test_d1_every_runtime_but_runc_runs_the_check_and_one_that_leaks_is_refused_unstarted(tmp_path, runtime, lane):
    """A runtime nobody meant to name is proven like `runsc`, not started unchecked: its leak is a failed check and no
    box is created; its pass starts the box after a check run under that very name. `runc` alone runs none. (S3, D1)"""
    listed = {**LISTED, runtime: {"path": f"/usr/bin/{runtime}"}}
    spec = BoxSpec(rootfs=ROOTFS, runtime=runtime)
    leaking = _daemon(K.CheckPlan(box=K.LEAKS), runtimes=listed)
    with pytest.raises(_failed()):
        _start(lane, tmp_path / "leak", leaking, spec=spec)
    assert leaking.create_argv is None, f"a box was created under {runtime} with no passing check"
    assert [r.runtime for r in leaking.checks.box_runs()] == [runtime]

    healthy = _daemon(runtimes=listed)
    assert _start(lane, tmp_path / "ok", healthy, spec=spec).name
    assert [r.runtime for r in healthy.checks.box_runs()] == [runtime]
    assert healthy.checks.control_runs()
    assert healthy.create_argv is not None

    runc = _daemon(K.CheckPlan(box=K.LEAKS))
    assert _start(lane, tmp_path / "runc", runc, spec=RUNC).name
    assert runc.checks.runs == []
