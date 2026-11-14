"""#1469 S3 on a real daemon with gVisor (CI's shards register `runsc` and `runsc-job`): the box check passes on `runsc`, and
fails when `runsc-job` (host sockets open) is presented as the box runtime. On CI a missing runtime fails rather than skips."""
from __future__ import annotations

import json
import os
import subprocess
import uuid

import pytest

from defender import box as box_mod
from defender.box import BoxSpec
from defender.tests.e2e._replay_harness import DEFENDER
from defender.tests.support.sandbox import _box_check1469 as K
from defender.tests.support.sandbox._docker import daemon_reachable, docker_runtimes, dood_anchor, is_dood
from defender.tests.support.sandbox._spec1092 import make_run_dir
from defender.tests.support.tenancy._host1214 import TEST_TENANT

pytestmark = pytest.mark.e2e

_ON_CI = bool(os.environ.get("CI"))
_NO_DAEMON = not daemon_reachable()
_DOOD = (not _NO_DAEMON) and is_dood()
_ANCHOR = dood_anchor() if _DOOD else None


@pytest.fixture
def gvisor():
    """On CI both registrations must be there (a missing one fails); elsewhere without gVisor the test skips."""
    if _NO_DAEMON:
        if _ON_CI:
            pytest.fail("CI has no reachable docker daemon")
        pytest.skip("no reachable docker daemon")
    if _DOOD and _ANCHOR is None:
        pytest.skip("docker-outside-of-Docker with no shared path: bind sources cannot be resolved here")
    have = docker_runtimes()
    missing = {"runsc", "runsc-job"} - have
    if missing and _ON_CI:
        pytest.fail(f"CI's daemon lacks the runtime(s) {sorted(missing)}: install-gvisor registers both (#1469)")
    if missing:
        pytest.skip(f"no gVisor here: {sorted(missing)} not registered")


@pytest.fixture
def where(tmp_path):
    base = (_ANCHOR / uuid.uuid4().hex) if _ANCHOR else tmp_path / "b"
    (base / "data").mkdir(parents=True)
    run_dir = make_run_dir(base)
    return base / "data", run_dir


class _PresentingRunscJobAsRunsc:
    """The real docker with `runsc-job` presented as the box runtime: the check's own `docker info` answer lists the
    `runsc-job` entry under `runsc`, and each run or create naming `runsc` names `runsc-job` (the control, `runc`, is
    untouched). The closed runtime set cannot stop it: the rename is in the seam."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, argv, **kw):  # noqa: ANN001 — DockerFn
        argv = list(argv)
        self.calls.append(list(argv))
        if argv[1:2] in (["run"], ["create"]) and "--runtime" in argv and argv[argv.index("--runtime") + 1] == "runsc":
            argv[argv.index("--runtime") + 1] = "runsc-job"
        done = box_mod.run_docker(argv, **kw)
        if argv[1:2] == ["info"] and "Runtimes" in " ".join(argv):
            listed = json.loads(done.stdout)
            listed["runsc"] = listed["runsc-job"]
            return subprocess.CompletedProcess(argv, done.returncode, json.dumps(listed) + "\n", done.stderr)
        return done

    @staticmethod
    def popen(argv, **kw):  # noqa: ANN001, ANN205
        return box_mod.run_docker.popen(argv, **kw)


class _Recording:
    """The real docker, recording each argv it is asked."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, argv, **kw):  # noqa: ANN001 — DockerFn
        self.calls.append(list(argv))
        return box_mod.run_docker(argv, **kw)

    def popen(self, argv, **kw):  # noqa: ANN001, ANN201
        self.calls.append(list(argv))
        return box_mod.run_docker.popen(argv, **kw)


def _check_runtimes(calls: list[list[str]]) -> list[str | None]:
    """The `--runtime` of each check container (a `docker run` binding the check folder) among `calls`, in order."""
    return [K.flag_value(c, "--runtime") for c in calls if K.is_check_run(c)]


def test_s3_the_box_check_passes_on_ci_s_runsc_and_the_box_starts(gvisor, where):
    """A box under the real `runsc` passes the check (a real listener, a real gVisor container, a real runc control) and is
    created: exactly one check under `runsc`, then exactly one control under `--runtime runc`. (#1469 S3, D1)"""
    data_root, run_dir = where
    seam = _Recording()
    box = box_mod.start_box(run_dir, DEFENDER, spec=BoxSpec(runtime="runsc"), docker=seam, tenant_id=TEST_TENANT,
                            data_root=data_root)
    try:
        assert box.sandboxed
    finally:
        box_mod.stop_box(box)
    assert _check_runtimes(seam.calls) == ["runsc", "runc"], seam.calls


def test_s3_the_box_check_fails_when_runsc_job_is_presented_as_the_box_runtime_and_no_box_is_created(
        gvisor, where, monkeypatch):
    """`runsc-job` lets a container connect to a host socket in its binds: as the box runtime it fails the check, before any
    create, and the opt-out does not degrade it. (#1469 S3, D3; the leak the check exists to see)"""
    data_root, run_dir = where
    seam = _PresentingRunscJobAsRunsc()
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    with pytest.raises(box_mod.BoxCheckFailed):
        box_mod.start_box(run_dir, DEFENDER, spec=BoxSpec(runtime="runsc"), docker=seam, tenant_id=TEST_TENANT,
                          data_root=data_root)
    assert not [c for c in seam.calls if c[1:2] == ["create"]], "a box was created under the leaking runtime"
    assert _check_runtimes(seam.calls)[:1] == ["runsc-job"], "control: the check ran under the presented runtime"
