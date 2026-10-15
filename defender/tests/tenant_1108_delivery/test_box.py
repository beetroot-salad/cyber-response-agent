"""D7/O8: distinct code and knowledge geography, no forge exposure, read-only probes.

D7 as amended (issue comment 6190547938): every read-only `Mount` declares its kind (`code`,
`agent` or `data`); startup applies that kind's check and never infers one from a name or path.
A `code` mount is proven by reading back `<code_dir>/<box.CODE_CHECK_FILE>`, where `code_dir`
is the request's explicit `defender_dir` or the legacy `<workdir>/defender`.
"""
from __future__ import annotations

import json
import re
import shutil
import stat
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from defender.runtime import box
from defender.runtime.box import _lifecycle

from ._support import DEFENDER, TOKEN, ForgeHTTP, delivery, git, target

#: A pinned image, so these requests never resolve one from a made-up tree.
_PINNED = box.BoxSpec(runtime="runc", rootfs="defender-box:test1108")
_CHECK_BYTES = "made-up check bytes\n"


def _check_file() -> str:
    # Lazy: the contract must collect before the amended box package exists.
    return box.CODE_CHECK_FILE


def _snapshot(*roots: Path) -> dict:
    return {root: {p.relative_to(root).as_posix(): None if p.is_dir() else p.read_bytes()
                   for p in sorted(root.rglob("*"))} for root in roots}


class _Boundary:
    """`docker=` seam over the existing fake daemon. Scripted replies stand in for a daemon
    bound to another folder, keyed by the in-box read operand; every other call is the fake
    daemon's, whose `cat` reads the host path. The watched read-only sources are snapshotted at
    every call, so even a transient plant during startup is seen."""

    def __init__(self, base: Path, watched, replies=None):
        from defender.tests._box1195 import FakeDaemon
        self.daemon = FakeDaemon(base)
        self.watched = tuple(watched)
        self.before = _snapshot(*self.watched)
        self.replies = dict(replies or {})
        self.execs: list[list[str]] = []
        self.snapshots: list[dict] = []

    def __call__(self, argv, **kwargs):
        argv = [str(a) for a in argv]
        self.snapshots.append(_snapshot(*self.watched))
        if argv[1:2] == ["exec"]:
            self.execs.append(argv)
            if argv[-1] in self.replies:
                rc, out = self.replies[argv[-1]]
                return subprocess.CompletedProcess(argv, rc, out, "" if rc == 0 else "read failed")
        return self.daemon(argv, **kwargs)

    def operands(self) -> list[str]:
        return [argv[-1] for argv in self.execs]

    def assert_never_written(self) -> None:
        assert all(s == self.before for s in self.snapshots), "a read-only source changed during startup"
        assert _snapshot(*self.watched) == self.before


def _request(name: str, workdir: Path, *mounts, **extra) -> box.BoxRequest:
    return box.BoxRequest(name=name, workdir=workdir, env={}, mounts=tuple(mounts),
                          spec=_PINNED, **extra)


@pytest.fixture
def boxed_only(monkeypatch):
    # A startup fault must surface; the operator opt-out would turn it into a host executor.
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)


def test_code_check_file_is_one_box_constant_committed_in_the_product_tree():
    """D7 amendment 2: the box package owns the check file's name; the product commits the file."""
    assert box.CODE_CHECK_FILE == "MOUNT_CHECK"
    check = DEFENDER / box.CODE_CHECK_FILE
    assert stat.S_ISREG(check.lstat().st_mode), f"{check} must be a regular file, not a link"
    assert check.stat().st_size > 0, f"{check} is empty: an empty read-back proves nothing"
    git(DEFENDER.parent, "ls-files", "--error-unmatch", f"defender/{box.CODE_CHECK_FILE}")


def test_drain_request_mounts_only_code_agent_and_explicit_lane(repo):
    d = delivery(repo, ForgeHTTP())
    wt = d.start_batch("box")
    request = d.box_request(wt, "box", writable_dirs=("lessons",))
    assert request.defender_dir == DEFENDER
    assert request.workdir == wt / "agent"
    assert {(m.source, m.target, m.writable) for m in request.mounts} == {
        (DEFENDER, DEFENDER, False), (wt / "agent", wt / "agent", False),
        (wt / "agent/lessons", wt / "agent/lessons", True)}
    # D7 amendment 5: the tenant drain declares each read-only mount's kind.
    assert {m.source: m.kind for m in request.mounts if not m.writable} == {
        DEFENDER: "code", wt / "agent": "agent"}
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


@pytest.mark.parametrize("kind", ["agent", "code"])
@pytest.mark.parametrize("fault", [None, "mismatch", "read-error"])
def test_readonly_probe_reads_existing_file_and_never_plants(tmp_path, boxed_only, kind, fault):
    """D7 amendments 1-3, through the real request-lane start: the declared kind alone picks
    the existing file read back (neither folder is named for its kind); a wrong mapping or a
    read error refuses before a box is handed out, and the source is never written."""
    source = tmp_path / ("tenant-half" if kind == "agent" else "product-tree")
    source.mkdir()
    marker = ".tenant-id" if kind == "agent" else _check_file()
    expected = "blue\n" if kind == "agent" else _CHECK_BYTES
    (source / marker).write_text(expected, encoding="utf-8")
    (source / "unrelated.txt").write_text("not a probe\n", encoding="utf-8")
    probe = str(source / marker)
    reply = {None: (0, expected), "mismatch": (0, "wrong\n"), "read-error": (1, "")}[fault]
    boundary = _Boundary(tmp_path, [source], {probe: reply})
    extra = {"defender_dir": source} if kind == "code" else {}
    request = _request("defender-probe-1108", source,
                       box.Mount(source=source, target=source, kind=kind), **extra)
    if fault:
        with pytest.raises(box.BoxFault, match="read|match|probe|tenant|" + re.escape(_check_file())):
            box.start_box(request, docker=boundary)
        assert boundary.daemon.names() == [], "a refused box was left behind"
    else:
        executor = box.start_box(request, docker=boundary)
        assert executor.sandboxed
        assert boundary.daemon.names() == [request.name]
    assert probe in boundary.operands(), "startup never read the declared kind's file through the box"
    assert not any(op.endswith("/SKILL.md") for op in boundary.operands())
    boundary.assert_never_written()


@pytest.mark.parametrize("present", ["check-file-only", "skill-md-only"])
def test_code_probe_reads_the_check_file_and_no_longer_needs_skill_md(tmp_path, boxed_only, present):
    """D7 amendments 2 and 6: the legacy `<workdir>/defender` code dir passes on the check file
    alone, and SKILL.md without it refuses. Reads are the fake daemon's own host reads."""
    root = tmp_path / "checkout"
    code = root / "defender"
    code.mkdir(parents=True)
    if present == "check-file-only":
        (code / _check_file()).write_text(_CHECK_BYTES, encoding="utf-8")
    else:
        shutil.copyfile(DEFENDER / "SKILL.md", code / "SKILL.md")
    boundary = _Boundary(tmp_path, [root])
    request = _request("defender-code-1108", root, box.Mount(source=root, target=root, kind="code"))
    if present == "check-file-only":
        executor = box.start_box(request, docker=boundary)
        assert executor.sandboxed
        assert boundary.daemon.names() == [request.name]
        assert str(code / _check_file()) in boundary.operands()
    else:
        with pytest.raises(box.BoxFault, match="read|probe|missing|" + re.escape(_check_file())):
            box.start_box(request, docker=boundary)
        assert boundary.daemon.names() == []
    assert not any(op.endswith("/SKILL.md") for op in boundary.operands()), "SKILL.md is not a probe"
    boundary.assert_never_written()


@pytest.mark.parametrize("name", ["defender", "agent", "evidence"])
def test_readonly_mount_without_a_declared_kind_is_refused_at_startup(tmp_path, boxed_only, name):
    """D7 amendment 1: no declared kind, no box, whatever the folder is called or holds. The
    writable lane needs no kind, and the same mount declared `data` starts (controls)."""
    wt = tmp_path / "wt"
    source = wt / name  # `defender` here is also the legacy `<workdir>/defender`
    source.mkdir(parents=True)
    (source / _check_file()).write_text(_CHECK_BYTES, encoding="utf-8")
    (source / ".tenant-id").write_text("blue\n", encoding="utf-8")
    lane = tmp_path / "lane"
    lane.mkdir()
    declared = box.Mount(source=source, target=source, kind="data")

    def request(readonly):
        return _request("defender-kind-1108", wt, readonly,
                        box.Mount(source=lane, target=lane, writable=True))

    refused = _Boundary(tmp_path / "refused", [source])
    with pytest.raises(box.BoxFault, match="(?i)kind"):
        box.start_box(request(box.Mount(source=source, target=source)), docker=refused)
    assert refused.daemon.names() == [], "a refused box was left behind"
    refused.assert_never_written()

    accepted = _Boundary(tmp_path / "accepted", [source])
    assert box.start_box(request(declared), docker=accepted).sandboxed
    assert accepted.daemon.names() == ["defender-kind-1108"]
    accepted.assert_never_written()


@pytest.mark.parametrize("kind", ["defender", "tenant", ""])
def test_a_word_that_is_not_a_kind_is_refused_not_mapped(tmp_path, boxed_only, kind):
    """D7 amendment 1, failing closed: only `code`, `agent` and `data` are kinds. Refusal may
    come at construction or at startup, never as a started box."""
    wt = tmp_path / "wt"
    source = wt / "defender"
    source.mkdir(parents=True)
    (source / _check_file()).write_text(_CHECK_BYTES, encoding="utf-8")
    (source / ".tenant-id").write_text("blue\n", encoding="utf-8")
    box.Mount(source=source, target=source, kind="code")  # prerequisite: declared kinds exist
    boundary = _Boundary(tmp_path, [source])
    with pytest.raises((box.BoxFault, ValueError, TypeError)):
        request = _request("defender-kind-1108", wt, box.Mount(source=source, target=source, kind=kind))
        box.start_box(request, docker=boundary)
    assert boundary.daemon.names() == []
    boundary.assert_never_written()


@pytest.mark.parametrize(("case", "folder", "kind", "starts"), [
    ("data-at-legacy-code-dir", "defender", "data", True),
    ("data-named-agent", "agent", "data", True),
    ("agent-named-defender", "defender", "agent", True),
    ("code-not-named-defender", "srv-tree", "code", False),
    ("agent-not-named-agent", "tenant-half", "agent", False),
])
def test_startup_applies_the_declared_kind_never_the_folder_name(
        tmp_path, boxed_only, case, folder, kind, starts):
    """D7 amendment 1: the rule comes from the declared kind. Empty `data` folders named
    `defender` (at the legacy code dir) or `agent` start with nothing read (#665 Decision 9);
    an `agent` folder named `defender` needs only its identity; a `code` folder by any other
    name still needs the check file, and an `agent` one still needs `.tenant-id`."""
    wt = tmp_path / "wt"
    source = wt / folder
    source.mkdir(parents=True)
    extra = {}
    if case == "agent-named-defender":
        (source / ".tenant-id").write_text("blue\n", encoding="utf-8")
    elif case == "code-not-named-defender":
        shutil.copyfile(DEFENDER / "SKILL.md", source / "SKILL.md")
        (source / "unrelated.txt").write_text("not the check file\n", encoding="utf-8")
        extra = {"defender_dir": source}
    elif case == "agent-not-named-agent":
        (source / "unrelated.txt").write_text("not an identity\n", encoding="utf-8")
    boundary = _Boundary(tmp_path, [source])
    request = _request("defender-kind-1108", wt,
                       box.Mount(source=source, target=source, kind=kind), **extra)
    if not starts:
        with pytest.raises(box.BoxFault):
            box.start_box(request, docker=boundary)
        assert boundary.daemon.names() == []
        boundary.assert_never_written()
        return
    assert box.start_box(request, docker=boundary).sandboxed
    assert boundary.daemon.names() == [request.name]
    operands = boundary.operands()
    assert not any(op.endswith("/" + _check_file()) for op in operands), "a non-code mount got the code check"
    if kind == "data":
        assert not any(Path(op).is_relative_to(source) for op in operands), \
            "an empty data folder was read or asked for an identity"
    else:
        assert str(source / ".tenant-id") in operands
    boundary.assert_never_written()


@pytest.mark.parametrize("layout", [
    "legacy-inside", "explicit-nested", "check-at-mount-root-only", "explicit-outside",
    "legacy-outside",
])
def test_code_dir_is_the_request_code_root_and_lies_inside_the_code_mount(tmp_path, boxed_only, layout):
    """D7 amendment 2: `code_dir` is the explicit `defender_dir`, else `<workdir>/defender`;
    the check file is read there, not at the mount's root, and a `code_dir` outside the `code`
    mount refuses even when the host holds a check file there."""
    mount = tmp_path / "checkout"
    elsewhere = tmp_path / "elsewhere"
    for folder in (mount / "defender", mount / "nested-code", elsewhere / "defender"):
        folder.mkdir(parents=True)
    check = _check_file()
    (elsewhere / "defender" / check).write_text(_CHECK_BYTES, encoding="utf-8")
    workdir, extra, read = mount, {}, None
    if layout == "legacy-inside":
        (mount / "defender" / check).write_text(_CHECK_BYTES, encoding="utf-8")
        read = mount / "defender" / check
    elif layout == "explicit-nested":
        # The legacy dir holds none: only the explicit code root can satisfy the probe.
        (mount / "nested-code" / check).write_text(_CHECK_BYTES, encoding="utf-8")
        extra, read = {"defender_dir": mount / "nested-code"}, mount / "nested-code" / check
    elif layout == "check-at-mount-root-only":
        (mount / check).write_text(_CHECK_BYTES, encoding="utf-8")
    else:
        (mount / check).write_text(_CHECK_BYTES, encoding="utf-8")
        (mount / "defender" / check).write_text(_CHECK_BYTES, encoding="utf-8")
        if layout == "explicit-outside":
            extra = {"defender_dir": elsewhere / "defender"}
        else:
            workdir = elsewhere
    boundary = _Boundary(tmp_path, [mount, elsewhere])
    request = _request("defender-codedir-1108", workdir,
                       box.Mount(source=mount, target=mount, kind="code"), **extra)
    if read is None:
        with pytest.raises(box.BoxFault):
            box.start_box(request, docker=boundary)
        assert boundary.daemon.names() == []
    else:
        assert box.start_box(request, docker=boundary).sandboxed
        assert boundary.daemon.names() == [request.name]
        assert str(read) in boundary.operands()
    boundary.assert_never_written()


def test_oracle_runner_is_a_code_mount_holding_only_runner_files_and_starts_sandboxed(
        tmp_path, boxed_only):
    """D7 amendment 5: the oracle's runner is a `code` mount whose files are exactly
    `RUNNER_FILES` (three transport modules and the check file, no SKILL.md), built by the
    real runner maker and started through the real `start_box` with reads routed by the
    captured mount table."""
    from defender.runtime.box import _oracle
    from defender.tests._spec1092 import STOCK_ROOTFS
    from defender.tests.tenant_1108_p2._support import MountedReadDocker, tree_bytes

    check = f"defender/{_check_file()}"
    assert set(_oracle.RUNNER_FILES) == {
        "defender/runtime/__init__.py", "defender/runtime/bash_exec.py",
        "defender/runtime/box_codec.py", check}
    runner = _oracle._make_runner()
    try:
        before = tree_bytes(runner)
        assert {rel for rel, data in before.items() if data is not None} == set(_oracle.RUNNER_FILES)
        assert before[check] == (_oracle.CHECKOUT / check).read_bytes()
        scratch = tmp_path / "scratch"
        scratch.mkdir()
        request = replace(_oracle.oracle_box_request(scratch, runner, env={}),
                          spec=box.BoxSpec(rootfs=STOCK_ROOTFS))
        assert [(m.source, m.target, m.kind) for m in request.mounts if not m.writable] == [
            (runner, _oracle.CHECKOUT, "code")]
        docker = MountedReadDocker()
        executor = box.start_box(request, docker=docker)
        try:
            assert executor.sandboxed
            reads = [argv[-1] for argv in docker.calls if argv[1:2] == ["exec"] and "cat" in argv]
            assert str(_oracle.CHECKOUT / check) in reads, "the runner's code check was never read"
            assert not any(read.endswith("/SKILL.md") for read in reads)
        finally:
            box.stop_box(executor)
        assert tree_bytes(runner) == before, "startup wrote into the read-only runner"
    finally:
        shutil.rmtree(runner, ignore_errors=True)


@pytest.mark.parametrize("wrong_readback", [False, True])
def test_drain_start_wires_real_lifecycle_readback_before_returning_executor(repo, tmp_path, wrong_readback):
    from defender.tests._box1195 import FakeDaemon
    d = delivery(repo, ForgeHTTP())
    wt = d.start_batch("lifecycle")
    request = d.box_request(wt, "lifecycle", writable_dirs=("lessons",))
    request = replace(request, spec=box.BoxSpec(runtime="runc", rootfs="defender-box:test1108"))
    daemon = FakeDaemon(tmp_path)
    before = git(wt, "status", "--porcelain")
    reads, execs = [], []
    def boundary(argv, **kwargs):
        if argv[:2] == ["docker", "exec"]:
            execs.append([str(a) for a in argv])
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
        assert str(DEFENDER / box.CODE_CHECK_FILE) in [argv[-1] for argv in execs], \
            "startup must read the product check file through the box"
    assert reads, "startup must actually read the agent identity through the box"
    assert not any(argv[-1].endswith("/SKILL.md") for argv in execs)


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


def _with_code_at(request, source: Path):
    return replace(request, defender_dir=source, mounts=tuple(
        replace(mount, source=source, target=source) if mount.source == DEFENDER else mount
        for mount in request.mounts))


@pytest.mark.parametrize("which", ["agent", "code"])
@pytest.mark.parametrize("contents", ["no-files", "unrelated-file", "skill-md-only"])
def test_drain_start_requires_fixed_probe_for_code_and_agent(repo, tmp_path, which, contents):
    """D7/O3: generic empty-data handling cannot bypass required code or tenant probes, and
    SKILL.md is neither (D7 amendment 6)."""
    from defender.tests._box1195 import FakeDaemon
    d = delivery(repo, ForgeHTTP())
    wt = d.start_batch("required-probe")
    request = d.box_request(wt, "required-probe", writable_dirs=("lessons",))
    if which == "code":
        source = tmp_path / "arbitrary-code-location"
        source.mkdir()
        request = _with_code_at(request, source)
    else:
        source = wt / "agent"
        shutil.rmtree(source)
        (source / "lessons").mkdir(parents=True)
    if contents == "unrelated-file":
        (source / "unrelated.txt").write_text("not the required identity or product probe\n")
    elif contents == "skill-md-only":
        shutil.copyfile(DEFENDER / "SKILL.md", source / "SKILL.md")
    request = replace(request, spec=box.BoxSpec(runtime="runc", rootfs="defender-box:test1108"))
    daemon = FakeDaemon(tmp_path)
    with pytest.raises(box.BoxFault, match="read|probe|tenant|missing|file|" + re.escape(_check_file())):
        d.start_box(request, docker=daemon)
    assert daemon.names() == []


def test_drain_start_accepts_a_code_folder_holding_only_the_check_file(repo, tmp_path):
    """D7 amendment 6, positive arm: the tenant drain's code mount needs the product check
    file and nothing else, at an arbitrary code root."""
    from defender.tests._box1195 import FakeDaemon
    d = delivery(repo, ForgeHTTP())
    wt = d.start_batch("check-only")
    source = tmp_path / "arbitrary-code-location"
    source.mkdir()
    shutil.copyfile(DEFENDER / box.CODE_CHECK_FILE, source / box.CODE_CHECK_FILE)
    request = _with_code_at(d.box_request(wt, "check-only", writable_dirs=("lessons",)), source)
    request = replace(request, spec=_PINNED)
    daemon = FakeDaemon(tmp_path)
    executor = d.start_box(request, docker=daemon)
    assert executor.sandboxed
    assert daemon.names() == [request.name]
    assert sorted(p.name for p in source.iterdir()) == [box.CODE_CHECK_FILE]
