"""D7/O8: distinct code and knowledge geography, no forge exposure, read-only probes."""
from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from defender.runtime import box
from defender.runtime.box import _lifecycle

from ._support import DEFENDER, TOKEN, ForgeHTTP, delivery, git, target


def test_drain_request_mounts_only_code_agent_and_explicit_lane(repo):
    d = delivery(repo, ForgeHTTP())
    wt = d.start_batch("box")
    request = d.box_request(wt, "box", writable_dirs=("lessons",))
    assert request.defender_dir == DEFENDER
    assert request.workdir == wt / "agent"
    assert {(m.source, m.target, m.writable) for m in request.mounts} == {
        (DEFENDER, DEFENDER, False), (wt / "agent", wt / "agent", False),
        (wt / "agent/lessons", wt / "agent/lessons", True)}
    assert request.env["DEFENDER_AGENT_DIR"] == str(wt / "agent")
    create = _lifecycle._render_argv(request, [], "probe-token")
    env = [create.argv[i + 1] for i, part in enumerate(create.argv) if part == "--env"]
    assert f"DEFENDER_DIR={DEFENDER}" in env
    assert f"PYTHONPATH={DEFENDER.parent}" in env
    assert any(e.startswith(f"PATH={DEFENDER / 'bin'}:") for e in env)
    assert f"DEFENDER_AGENT_DIR={wt / 'agent'}" in env
    assert TOKEN not in json.dumps(create.argv)
    assert str(repo[0].dir / "forge") not in json.dumps(create.argv)
    assert not any(m.source == wt or m.source.is_relative_to(wt / "settings") or
                   m.source.is_relative_to(wt / ".git") for m in request.mounts)


def test_explicit_defender_dir_also_owns_host_fallback_environment(tmp_path):
    code = tmp_path / "code/defender"
    request = box.BoxRequest(name="defender-test", defender_dir=code,
                             workdir=tmp_path / "tenant/agent")
    env = _lifecycle._host_fallback_env(request)
    assert env["DEFENDER_DIR"] == str(code)
    assert env["PATH"].split(":")[0] == str(code / "bin")
    assert env["PYTHONPATH"].split(":")[0] == str(code.parent)


def test_tenant_drain_refuses_unsandboxed_even_when_operator_opted_out(repo, monkeypatch):
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    d = delivery(repo, ForgeHTTP())
    wt = d.start_batch("no-box")
    request = d.box_request(wt, "no-box", writable_dirs=("lessons",))
    calls = []
    def unavailable(argv, **kwargs):
        calls.append(argv)
        raise OSError("daemon unavailable")
    with pytest.raises(box.BoxFault, match="daemon|sandbox|box"):
        d.start_box(request, docker=unavailable)
    assert calls


@pytest.mark.parametrize("which", ["agent", "defender"])
@pytest.mark.parametrize("fault", [None, "mismatch", "read-error"])
def test_readonly_probe_reads_existing_file_and_never_plants(tmp_path, which, fault):
    source = tmp_path / which
    source.mkdir()
    marker = ".tenant-id" if which == "agent" else "SKILL.md"
    expected = "blue\n" if which == "agent" else "fixed code file\n"
    (source / marker).write_text(expected)
    initial = {p.relative_to(source): p.read_bytes() for p in source.rglob("*") if p.is_file()}
    calls = []
    def readback(argv, **kwargs):
        calls.append(argv)
        # Detect even temporary plants while the probe is running.
        assert {p.relative_to(source): p.read_bytes() for p in source.rglob("*") if p.is_file()} == initial
        assert argv[-1] == str(source / marker)
        return subprocess.CompletedProcess(argv, 1 if fault == "read-error" else 0,
                                           "wrong\n" if fault == "mismatch" else expected, "read failed")
    mount = box.Mount(source=source, target=source, writable=False)
    if fault:
        with pytest.raises(box.BoxFault, match="read|match|probe"):
            _lifecycle._check_mount_sentinel(mount, readback, "defender-test")
    else:
        _lifecycle._check_mount_sentinel(mount, readback, "defender-test")
    assert calls
    assert {p.relative_to(source): p.read_bytes() for p in source.rglob("*") if p.is_file()} == initial


@pytest.mark.parametrize("wrong_readback", [False, True])
def test_drain_start_wires_real_lifecycle_readback_before_returning_executor(repo, tmp_path, wrong_readback):
    from dataclasses import replace
    from defender.tests._box1195 import FakeDaemon
    d = delivery(repo, ForgeHTTP())
    wt = d.start_batch("lifecycle")
    request = d.box_request(wt, "lifecycle", writable_dirs=("lessons",))
    request = replace(request, spec=box.BoxSpec(runtime="runc", rootfs="defender-box:test1108"))
    daemon = FakeDaemon(tmp_path)
    before = git(wt, "status", "--porcelain")
    reads = []
    def boundary(argv, **kwargs):
        if argv[:2] == ["docker", "exec"] and str(wt / "agent/.tenant-id") in argv:
            reads.append(argv)
            if wrong_readback:
                return subprocess.CompletedProcess(argv, 0, "another-tenant\n", "")
        return daemon(argv, **kwargs)
    if wrong_readback:
        with pytest.raises(box.BoxFault, match="match|read|tenant|probe"):
            d.start_box(request, docker=boundary)
        assert daemon.names() == []
    else:
        executor = d.start_box(request, docker=boundary)
        assert executor.sandboxed
        assert daemon.names() == [request.name]
        assert git(wt, "status", "--porcelain") == before
    assert reads, "startup must actually read the agent identity through the box"


@pytest.mark.parametrize("escape", ["../settings", "lessons/../../settings", "absolute", "symlink"])
def test_drain_request_refuses_writable_lane_outside_agent(repo, escape):
    """O8: writable mounts resolve inside the worktree's agent half."""
    d = delivery(repo, ForgeHTTP())
    wt = d.start_batch("mount-escape")
    if escape == "absolute":
        lane = str(wt / "settings")
    elif escape == "symlink":
        (wt / "agent/escape").symlink_to(wt / "settings", target_is_directory=True)
        lane = "escape"
    else:
        lane = escape
    assert (wt / "agent" / lane).resolve() == (wt / "settings").resolve()
    with pytest.raises(target().DeliveryRefused, match="path|agent|writ|mount|lane"):
        d.box_request(wt, "mount-escape", writable_dirs=(lane,))


@pytest.mark.parametrize("which", ["agent", "code"])
@pytest.mark.parametrize("contents", ["no-files", "unrelated-file"])
def test_drain_start_requires_fixed_probe_for_code_and_agent(repo, tmp_path, which, contents):
    """D7/O3: generic empty-data handling cannot bypass required code or tenant probes."""
    from dataclasses import replace
    from defender.tests._box1195 import FakeDaemon
    d = delivery(repo, ForgeHTTP())
    wt = d.start_batch("required-probe")
    request = d.box_request(wt, "required-probe", writable_dirs=("lessons",))
    if which == "code":
        source = tmp_path / "arbitrary-code-location"
        source.mkdir()
        request = replace(request, defender_dir=source, mounts=tuple(
            replace(mount, source=source, target=source) if mount.source == DEFENDER else mount
            for mount in request.mounts))
    else:
        source = wt / "agent"
        shutil.rmtree(source)
        (source / "lessons").mkdir(parents=True)
    if contents == "unrelated-file":
        (source / "unrelated.txt").write_text("not the required identity or product probe\n")
    request = replace(request, spec=box.BoxSpec(runtime="runc", rootfs="defender-box:test1108"))
    daemon = FakeDaemon(tmp_path)
    with pytest.raises(box.BoxFault, match="read|probe|tenant|SKILL|file"):
        d.start_box(request, docker=daemon)
    assert daemon.names() == []
