from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest

from defender import box
from defender.box import _lifecycle

from ._support import DEFENDER, LANES, TOKEN, ForgeHTTP, delivery, files_under, git

#: A pinned image, so these requests never resolve one from a made-up tree.
_PINNED = box.BoxSpec(runtime="runc", rootfs="defender-box:test1108")


def _check_file() -> str:
    # Lazy: the contract must collect before the amended box package exists.
    return box.CODE_CHECK_FILE


def _check_bytes() -> str:
    """Fresh bytes per test, so no constant (the product file's included) can stand in for
    the host's own read of the check file (adversary A09)."""
    return f"made-up check {secrets.token_hex(8)}\n"


def _snapshot(*roots: Path) -> dict:
    return {root: {p.relative_to(root).as_posix(): None if p.is_dir() else p.read_bytes()
                   for p in sorted(root.rglob("*"))} for root in roots}


class _Boundary:
    """`docker=` seam over the existing fake daemon. Scripted replies stand in for a daemon
    bound to another folder: `replies` by exact in-box read operand, `under` for any operand
    inside a folder. Every other call is the fake daemon's, whose `cat` reads the host path.
    The watched read-only sources are snapshotted at every call, so even a transient plant
    during startup is seen."""

    def __init__(self, base: Path, watched, replies=None, under=None, root=None, root_reply=None):
        from defender.tests.support.sandbox._box1195 import FakeDaemon
        self.daemon = FakeDaemon(base)
        self.watched = tuple(watched)
        self.before = _snapshot(*self.watched)
        self.replies = dict(replies or {})
        self.under = {Path(folder): reply for folder, reply in (under or {}).items()}
        self.root = None if root is None else Path(root)
        self.root_reply = root_reply
        self.root_reads: list[tuple[str, bytes | None]] = []
        self.execs: list[list[str]] = []
        self.snapshots: list[dict] = []

    def _scripted(self, operand: str):
        if self.root is not None and _at_root(operand, self.root):
            try:
                held = Path(operand).read_bytes()
            except OSError:
                held = None
            self.root_reads.append((operand, held))
            if callable(self.root_reply):
                return self.root_reply(held)
            if self.root_reply is not None:
                return self.root_reply
        if operand in self.replies:
            return self.replies[operand]
        path = Path(operand)
        for folder, reply in self.under.items():
            if path.is_absolute() and path.is_relative_to(folder):
                return reply
        return None

    def __call__(self, argv, **kwargs):
        argv = [str(a) for a in argv]
        self.snapshots.append(_snapshot(*self.watched))
        if argv[1:2] == ["exec"]:
            self.execs.append(argv)
            reply = self._scripted(argv[-1])
            if reply is not None:
                rc, out = reply
                return subprocess.CompletedProcess(argv, rc, out, "" if rc == 0 else "read failed")
        return self.daemon(argv, **kwargs)

    def operands(self) -> list[str]:
        return [argv[-1] for argv in self.execs]

    def assert_never_written(self) -> None:
        assert all(s == self.before for s in self.snapshots), "a read-only source changed during startup"
        assert _snapshot(*self.watched) == self.before


def _at_root(operand: str, root: Path) -> bool:
    """A read of an entry directly in a staged copy's root, other than its `agent/`."""
    path = Path(operand)
    return path.is_absolute() and path.parent == root and path.name != "agent"


def _copy(root: Path) -> Path:
    """A host-made copy root, as the host makes one: `agent/` and nothing else."""
    (root / "agent" / "lessons").mkdir(parents=True)
    (root / "agent" / ".tenant-id").write_text("blue\n", encoding="utf-8")
    (root / "agent" / "lessons" / "seed.md").write_text("seed\n", encoding="utf-8")
    return root


def _request(name: str, workdir: Path, *mounts, **extra) -> box.BoxRequest:
    return box.BoxRequest(name=name, workdir=workdir, env={}, mounts=tuple(mounts),
                          spec=_PINNED, **extra)


#: The request lane's two entries (adversary A24): the public `start_box`, and the request
#: lane `_oracle.start_oracle_box` reaches without it. Every kind rule must hold on both.
_ENTRIES = {
    "start_box": lambda request, docker: box.start_box(request, docker=docker),
    "request_lane": lambda request, docker: _lifecycle._start_boxed_request(request, docker),
}


@pytest.fixture(params=sorted(_ENTRIES))
def start(request, monkeypatch):
    # A startup fault must surface; the operator opt-out would turn it into a host executor.
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    return _ENTRIES[request.param]


def test_code_check_file_is_one_box_constant_committed_in_the_product_tree():
    """D7 amendment 2: the box package owns the check file's name; the product commits the
    file. Its bytes carry no information, but an empty read-back would prove nothing."""
    assert box.CODE_CHECK_FILE == "MOUNT_CHECK"
    check = DEFENDER / box.CODE_CHECK_FILE
    assert stat.S_ISREG(check.lstat().st_mode), f"{check} must be a regular file, not a link"
    assert check.stat().st_size > 0, f"{check} is empty: an empty read-back proves nothing"
    git(DEFENDER.parent, "ls-files", "--error-unmatch", f"defender/{box.CODE_CHECK_FILE}")


def _batch(repo, batch_id="box"):
    d = delivery(repo, ForgeHTTP())
    return d, d.start_batch(batch_id, lanes=LANES)


def test_drain_request_mounts_the_code_the_draft_root_staged_and_only_its_lanes(repo):
    d, batch = _batch(repo)
    tenant, draft = repo[0], batch.draft_root
    request = batch.box_request()
    assert request.defender_dir == DEFENDER
    assert request.workdir == draft / "agent"
    assert {(Path(m.source), Path(m.target), m.writable, m.kind) for m in request.mounts} == {
        (DEFENDER, DEFENDER, False, "code"), (draft, draft, False, "staged"),
        (draft / "agent/lessons", draft / "agent/lessons", True, None)}
    assert request.env["DEFENDER_AGENT_DIR"] == str(draft / "agent")
    host_only = (tenant.knowledge, tenant.worktrees, tenant.dir / "exports", tenant.dir / "forge")
    for mount in request.mounts:
        source = Path(mount.source)
        assert not any(source.is_relative_to(h) or h.is_relative_to(source) for h in host_only), source
    create = _lifecycle._render_argv(request, [], "probe-token")
    env = [create.argv[i + 1] for i, part in enumerate(create.argv) if part == "--env"]
    assert f"DEFENDER_DIR={DEFENDER}" in env
    assert f"PYTHONPATH={DEFENDER.parent}" in env
    assert any(e.startswith(f"PATH={DEFENDER / 'bin'}:") for e in env)
    assert f"DEFENDER_AGENT_DIR={draft / 'agent'}" in env
    rendered = json.dumps(create.argv)
    assert TOKEN not in rendered
    for path in host_only:
        assert str(path) not in rendered, path


def test_explicit_defender_dir_also_owns_host_fallback_environment(tmp_path):
    code = tmp_path / "code/defender"
    request = box.BoxRequest(name="defender-test", defender_dir=code,
                             workdir=tmp_path / "tenant/agent")
    env = _lifecycle._host_fallback_env(request)
    assert env["DEFENDER_DIR"] == str(code)
    assert env["PATH"].split(":")[0] == str(code / "bin")
    assert env["PYTHONPATH"].split(":")[0] == str(code.parent)


def _refusing(fault, root, tmp_path):
    """A fake daemon and a `docker=` over it that fails the start as `fault` names: no daemon
    at all, no box image on it, the create refused, the code mount's check file read back
    wrong, another draft's token read back at the root, or a lane's sentinel not read back.
    (`code-check-missing` is the request's own fault: see its case.)"""
    from defender.tests.support.sandbox._box1195 import FakeDaemon
    daemon = FakeDaemon(tmp_path)
    if fault == "create-refused":
        daemon.refuse_create()
    elif fault == "sentinel-refused":
        daemon.refuse_sentinel()

    def docker(argv, **kwargs):
        argv = [str(a) for a in argv]
        if fault == "daemon-unavailable":
            raise OSError("daemon unavailable")
        if fault == "image-missing" and argv[1:3] == ["image", "inspect"]:
            return subprocess.CompletedProcess(argv, 1, "", "Error: No such image")
        if fault == "code-check-mismatch" and argv[1:2] == ["exec"] and argv[-1].endswith(box.CODE_CHECK_FILE):
            return subprocess.CompletedProcess(argv, 0, "another tree's check\n", "")
        if fault == "wrong-token" and argv[1:2] == ["exec"] and _at_root(argv[-1], root):
            return subprocess.CompletedProcess(argv, 0, "another draft's token\n", "")
        return daemon(argv, **kwargs)
    return daemon, docker


_START_FAULTS = ["daemon-unavailable", "image-missing", "code-check-missing", "create-refused",
                 "code-check-mismatch", "wrong-token", "sentinel-refused"]


@pytest.mark.parametrize("fault", _START_FAULTS)
def test_a_drain_start_fault_raises_and_leaves_nothing_under_the_drafts(repo, tmp_path, monkeypatch, fault):
    """C3 / R5 / O-D: the tenant drain's start requires a sandbox."""
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    d, batch = _batch(repo, "no-box")
    drafts = batch.draft_root.parent
    request = replace(batch.box_request(), spec=_PINNED)
    if fault == "code-check-missing":
        code = tmp_path / "code-without-check"
        code.mkdir()
        request = replace(request, defender_dir=code, mounts=tuple(
            replace(m, source=code, target=code) if m.kind == "code" else m for m in request.mounts))
    before = _snapshot(drafts)
    daemon, docker = _refusing(fault, batch.draft_root, tmp_path)
    with pytest.raises(box.BoxFault):
        d.start_box(request, docker=docker)
    assert daemon.names() == []
    assert _snapshot(drafts) == before, "a start fault left something under drafts/"


def test_a_drain_box_started_and_stopped_leaves_the_drafts_as_they_were(repo, tmp_path):
    """C3 / R5: box start and teardown leave nothing under `<T>/drafts/`."""
    from defender.tests.support.sandbox._box1195 import FakeDaemon
    d, batch = _batch(repo, "started")
    drafts = batch.draft_root.parent
    before = _snapshot(drafts)
    daemon = FakeDaemon(tmp_path)
    executor = d.start_box(replace(batch.box_request(), spec=_PINNED), docker=daemon)
    assert executor.sandboxed
    box.stop_box(executor, docker=daemon)
    assert daemon.names() == []
    assert _snapshot(drafts) == before, "start and teardown left something under drafts/"


def test_a_request_that_requires_a_sandbox_never_falls_back_and_writes_no_marker(tmp_path, monkeypatch):
    """A request that requires a sandbox never falls back and writes no marker."""
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    tree = tmp_path / "tree"
    lane = tree / "lane"
    lane.mkdir(parents=True)
    before = _snapshot(tree)

    def unavailable(argv, **kwargs):
        raise OSError("daemon unavailable")

    def request(**extra):
        return _request("defender-required-1108", lane, box.Mount(source=lane, target=lane, writable=True),
                        **extra)
    with pytest.raises(box.BoxFault):
        box.start_box(request(require_sandbox=True), docker=unavailable)
    assert _snapshot(tree) == before, "a sandbox-required start fault left a marker"
    fallback = box.start_box(request(), docker=unavailable)
    assert fallback.sandboxed is False, "the opt-out is not live: the case is blind"


def test_the_oracle_start_requires_a_sandbox_and_leaves_no_stray_marker(tmp_path, monkeypatch):
    """C3: the #1224 oracle starts through `box.start_box` with `require_sandbox=True`."""
    from defender.box import _oracle
    from defender.tests.support.sandbox._box1195 import FakeDaemon

    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    wrong = FakeDaemon(tmp_path / "wrong")
    wrong.install(monkeypatch)
    wrong.refuse_sentinel()
    with pytest.raises(_oracle.BoxStartRefused):
        _oracle.start_oracle_box(env={"PATH": os.environ["PATH"], "DEFENDER_BOX_RUNTIME": "runc"})
    assert wrong.names() == []
    creates = [argv for argv in wrong.docker_calls() if argv[1:2] == ["run"]]
    assert creates, "the refused start never reached the daemon"
    sources = [part.split("source=", 1)[1].split(",", 1)[0]
               for part in creates[-1] if part.startswith("type=bind,")]
    scratch = [source for source in sources
               if Path(source).name.startswith("defender-oracle-") and Path(source).parent == Path(tempfile.gettempdir())]
    assert scratch, f"no scratch folder among the binds: {sources}"
    left = [f"{source}.scrub-verdict.json" for source in sources if Path(f"{source}.scrub-verdict.json").exists()]
    assert left == [], f"the oracle's refused start left a marker: {left}"


_TEXT_DIFFERENCES = ("newline-lost", "newline-added", "space-added")
_PROBE_CASES = [
    *((kind, fault) for kind in ("code", "data") for fault in (None, "mismatch", "read-error")),
    *((kind, fault) for kind in ("code", "data") for fault in (*_TEXT_DIFFERENCES, "crlf-on-host")),
]


@pytest.mark.parametrize(("kind", "fault"), _PROBE_CASES)
def test_readonly_probe_reads_existing_file_and_never_plants(tmp_path, start, kind, fault):
    """Readonly probe reads existing file and never plants."""
    folder, marker, expected = {
        "code": ("product-tree", _check_file(), _check_bytes()),
        "data": ("evidence-store", "result.json", f'{{"made-up": "{secrets.token_hex(8)}"}}\n'),
    }[kind]
    source = tmp_path / folder
    source.mkdir()
    on_host = expected.replace("\n", "\r\n") if fault == "crlf-on-host" else expected
    (source / marker).write_bytes(on_host.encode())
    if kind == "code":
        (source / "unrelated.txt").write_text("not a probe\n", encoding="utf-8")
    probe = str(source / marker)
    reply = {None: (0, expected), "crlf-on-host": (0, expected), "mismatch": (0, "wrong\n"),
             "read-error": (1, ""), "newline-lost": (0, expected.rstrip("\n")),
             "newline-added": (0, expected + "\n"),
             "space-added": (0, expected.rstrip("\n") + " \n")}[fault]
    boundary = _Boundary(tmp_path, [source], {probe: reply})
    extra = {"defender_dir": source} if kind == "code" else {}
    request = _request("defender-probe-1108", source,
                       box.Mount(source=source, target=source, kind=kind), **extra)
    if fault not in (None, "crlf-on-host"):
        with pytest.raises(box.BoxFault):
            start(request, boundary)
        assert boundary.daemon.names() == [], "a refused box was left behind"
    else:
        assert start(request, boundary).sandboxed
        assert boundary.daemon.names() == [request.name]
    assert probe in boundary.operands(), "startup never read the declared kind's file through the box"
    assert not any(op.endswith("/SKILL.md") for op in boundary.operands())
    boundary.assert_never_written()


@pytest.mark.parametrize("present", ["check-file-only", "skill-md-only"])
def test_code_probe_reads_the_check_file_and_no_longer_needs_skill_md(tmp_path, start, present):
    """D7 amendments 2 and 6: the legacy `<workdir>/defender` code dir passes on the check file
    alone, and SKILL.md without it refuses. Reads are the fake daemon's own host reads."""
    root = tmp_path / "checkout"
    code = root / "defender"
    code.mkdir(parents=True)
    if present == "check-file-only":
        (code / _check_file()).write_text(_check_bytes(), encoding="utf-8")
    else:
        shutil.copyfile(DEFENDER / "SKILL.md", code / "SKILL.md")
    boundary = _Boundary(tmp_path, [root])
    request = _request("defender-code-1108", root, box.Mount(source=root, target=root, kind="code"))
    if present == "check-file-only":
        assert start(request, boundary).sandboxed
        assert boundary.daemon.names() == [request.name]
        assert str(code / _check_file()) in boundary.operands()
    else:
        with pytest.raises(box.BoxFault, match="read|probe|missing|" + re.escape(_check_file())):
            start(request, boundary)
        assert boundary.daemon.names() == []
    assert not any(op.endswith("/SKILL.md") for op in boundary.operands()), "SKILL.md is not a probe"
    boundary.assert_never_written()


@pytest.mark.parametrize("contents", ["every-probe-file", "empty"])
@pytest.mark.parametrize("name", ["defender", "agent", "evidence"])
def test_readonly_mount_without_a_declared_kind_is_refused_at_startup(tmp_path, start, name, contents):
    wt = tmp_path / "wt"
    source = wt / name  # `defender` here is also the legacy `<workdir>/defender`
    source.mkdir(parents=True)
    if contents == "every-probe-file":
        (source / _check_file()).write_text(_check_bytes(), encoding="utf-8")
        (source / ".tenant-id").write_text("blue\n", encoding="utf-8")
    lane = tmp_path / "lane"
    lane.mkdir()
    declared = box.Mount(source=source, target=source, kind="data")

    def request(readonly):
        return _request("defender-kind-1108", wt, readonly,
                        box.Mount(source=lane, target=lane, writable=True))

    refused = _Boundary(tmp_path / "refused", [source])
    with pytest.raises(box.BoxFault, match="(?i)kind"):
        start(request(box.Mount(source=source, target=source)), refused)
    assert refused.daemon.names() == [], "a refused box was left behind"
    refused.assert_never_written()

    accepted = _Boundary(tmp_path / "accepted", [source])
    assert start(request(declared), accepted).sandboxed
    assert accepted.daemon.names() == ["defender-kind-1108"]
    accepted.assert_never_written()


_NOT_KINDS = ["defender", "tenant", "", "product", "checkout", "repo", "source", "identity",
              "evidence", "runs", "ro", "readonly", "none", "None", "Code", "CODE", " code",
              "code ", "codes", "Agent", "DATA", "agent", "Staged", "STAGED", " staged",
              "stage", "draft", "copy", "export"]


@pytest.mark.parametrize("kind", _NOT_KINDS)
def test_a_word_that_is_not_a_kind_is_refused_not_mapped(tmp_path, start, kind):
    """D7 amendment 1, failing closed. Refusal may come at construction or at startup, never
    as a started box."""
    wt = tmp_path / "wt"
    source = wt / "defender"
    source.mkdir(parents=True)
    (source / _check_file()).write_text(_check_bytes(), encoding="utf-8")
    (source / ".tenant-id").write_text("blue\n", encoding="utf-8")
    box.Mount(source=source, target=source, kind="code")  # prerequisite: declared kinds exist
    boundary = _Boundary(tmp_path, [source])
    with pytest.raises((box.BoxFault, ValueError, TypeError)):
        start(_request("defender-kind-1108", wt, box.Mount(source=source, target=source, kind=kind)),
              boundary)
    assert boundary.daemon.names() == []
    boundary.assert_never_written()


@pytest.mark.parametrize(("case", "folder", "kind", "starts"), [
    ("data-at-legacy-code-dir", "defender", "data", True),
    ("data-named-agent", "agent", "data", True),
    ("staged-named-defender", "defender", "staged", True),
    ("code-not-named-defender", "srv-tree", "code", False),
    ("staged-holding-no-agent", "tenant-half", "staged", False),
])
def test_startup_applies_the_declared_kind_never_the_folder_name(
        tmp_path, start, case, folder, kind, starts):
    """D7 amendments 1-2: the rule comes from the declared kind."""
    wt = tmp_path / "wt"
    source = wt / folder
    extra = {}
    if case == "staged-named-defender":
        _copy(source)
    else:
        source.mkdir(parents=True)
    if case == "code-not-named-defender":
        shutil.copyfile(DEFENDER / "SKILL.md", source / "SKILL.md")
        (source / "unrelated.txt").write_text("not the check file\n", encoding="utf-8")
        extra = {"defender_dir": source}
    elif case == "staged-holding-no-agent":
        (source / "unrelated.txt").write_text("not a copy of agent/\n", encoding="utf-8")
    watched = source / "agent" if case == "staged-named-defender" else source
    boundary = _Boundary(tmp_path, [watched], root=source if kind == "staged" else None)
    request = _request("defender-kind-1108", wt,
                       box.Mount(source=source, target=source, kind=kind), **extra)
    if not starts:
        with pytest.raises(box.BoxFault):
            start(request, boundary)
        assert boundary.daemon.names() == []
        if kind != "staged":
            boundary.assert_never_written()
        return
    assert start(request, boundary).sandboxed
    assert boundary.daemon.names() == [request.name]
    operands = boundary.operands()
    assert not any(op.endswith("/" + _check_file()) for op in operands), "a non-code mount got the code check"
    assert not any(op.endswith("/.tenant-id") for op in operands), "identity is checked at publish"
    if kind == "data":
        assert not any(Path(op).is_relative_to(source) for op in operands), \
            "an empty data folder was read or asked for an identity"
    else:
        assert boundary.root_reads, "the staged copy's token was never read back"
    boundary.assert_never_written()


#: Folder names a code mount may carry: the run layout's, the corpora's, the lanes' (A08).
_FOLDER_WORDS = ["data", "gather_raw", "lessons", "lessons-questioner", "runs", "evidence",
                 "agent", "knowledge", "skills", "settings", "scratch", "runner", "wt", "tmp",
                 "defender"]


@pytest.mark.parametrize("folder", _FOLDER_WORDS)
def test_a_code_mount_needs_its_check_file_whatever_its_folder_is_called(tmp_path, start, folder):
    """D7 amendments 1-2: no folder name exempts a `code` mount from its check (A08). Without
    the check file it refuses; with it, the same request starts reading it (control)."""
    source = tmp_path / "srv" / folder
    source.mkdir(parents=True)
    shutil.copyfile(DEFENDER / "SKILL.md", source / "SKILL.md")
    (source / "unrelated.txt").write_text("not the check file\n", encoding="utf-8")
    request = _request("defender-name-1108", source,
                       box.Mount(source=source, target=source, kind="code"), defender_dir=source)
    refused = _Boundary(tmp_path / "refused", [source])
    with pytest.raises(box.BoxFault):
        start(request, refused)
    assert refused.daemon.names() == []
    refused.assert_never_written()

    (source / _check_file()).write_text(_check_bytes(), encoding="utf-8")
    accepted = _Boundary(tmp_path / "accepted", [source])
    assert start(request, accepted).sandboxed
    assert str(source / _check_file()) in accepted.operands()
    accepted.assert_never_written()


_BOTH = ("checkout", "checkout/defender")
_CODE_DIR_LAYOUTS = {
    "legacy-inside": (("checkout/defender",), (), None, "checkout", "checkout/defender"),
    "explicit-nested": (("checkout/nested-code",), ("checkout/defender",), "checkout/nested-code",
                        "checkout", "checkout/nested-code"),
    "check-at-mount-root-only": (("checkout",), ("checkout/defender",), None, "checkout", None),
    "legacy-code-dir-absent": (("checkout",), (), None, "checkout", None),
    "explicit-code-dir-absent": (_BOTH, (), "checkout/missing", "checkout", None),
    "check-file-absent": ((), ("checkout/defender",), None, "checkout", None),
    "explicit-outside": (_BOTH, (), "elsewhere/defender", "checkout", None),
    "legacy-outside": (_BOTH, (), None, "elsewhere", None),
    "explicit-in-writable-lane": (_BOTH, (), "lane/defender", "checkout", None),
    "legacy-in-writable-lane": (_BOTH, (), None, "lane", None),
    "explicit-in-prefix-sibling": (_BOTH, (), "checkout-lane/defender", "checkout", None),
    "legacy-in-prefix-sibling": (_BOTH, (), None, "checkout-lane", None),
}


@pytest.mark.parametrize("layout", sorted(_CODE_DIR_LAYOUTS))
def test_code_dir_is_the_request_code_root_and_lies_inside_the_code_mount(tmp_path, start, layout):
    """Code dir is the request code root and lies inside the code mount."""
    planted, empty, code_root, workdir, read = _CODE_DIR_LAYOUTS[layout]
    mount, lane = tmp_path / "checkout", tmp_path / "lane"
    mount.mkdir()
    for folder in (*planted, "lane/defender", "checkout-lane/defender", "elsewhere/defender"):
        (tmp_path / folder).mkdir(parents=True, exist_ok=True)
        (tmp_path / folder / _check_file()).write_text(_check_bytes(), encoding="utf-8")
    for folder in empty:
        (tmp_path / folder).mkdir(parents=True)
    extra = {} if code_root is None else {"defender_dir": tmp_path / code_root}
    boundary = _Boundary(tmp_path, [mount, tmp_path / "checkout-lane", tmp_path / "elsewhere"])
    request = _request("defender-codedir-1108", tmp_path / workdir,
                       box.Mount(source=mount, target=mount, kind="code"),
                       box.Mount(source=lane, target=lane, writable=True), **extra)
    if read is None:
        with pytest.raises(box.BoxFault):
            start(request, boundary)
        assert boundary.daemon.names() == []
    else:
        assert start(request, boundary).sandboxed
        assert boundary.daemon.names() == [request.name]
        assert str(tmp_path / read / _check_file()) in boundary.operands()
    boundary.assert_never_written()


@pytest.mark.parametrize("second", ["code", "data"])
def test_a_request_declares_at_most_one_code_mount(tmp_path, start, second):
    first, other = tmp_path / "checkout", tmp_path / "other-checkout"
    for root in (first, other):
        for folder in (root, root / "defender"):
            folder.mkdir(exist_ok=True)
            (folder / _check_file()).write_text(_check_bytes(), encoding="utf-8")
    boundary = _Boundary(tmp_path, [first, other])
    request = _request("defender-twocode-1108", first,
                       box.Mount(source=first, target=first, kind="code"),
                       box.Mount(source=other, target=other, kind=second))
    if second == "code":
        with pytest.raises(box.BoxFault):
            start(request, boundary)
        assert boundary.daemon.names() == []
    else:
        assert start(request, boundary).sandboxed
        assert str(first / "defender" / _check_file()) in boundary.operands()
    boundary.assert_never_written()


@pytest.mark.parametrize("kind", ["code"])
def test_a_host_side_read_fault_is_a_box_fault(tmp_path, start, kind):
    source = tmp_path / "product-tree"
    marker = source / _check_file()
    marker.mkdir(parents=True)
    (source / "unrelated.txt").write_text("not a probe\n", encoding="utf-8")
    boundary = _Boundary(tmp_path, [source], {str(marker): (0, "blue\n")})
    extra = {"defender_dir": source}
    request = _request("defender-hostread-1108", source,
                       box.Mount(source=source, target=source, kind=kind), **extra)
    with pytest.raises(box.BoxFault):
        start(request, boundary)
    assert boundary.daemon.names() == []
    boundary.assert_never_written()


@pytest.mark.parametrize("fault", [False, True])
def test_writable_mount_keeps_its_planted_sentinel_read_back(tmp_path, start, fault):
    root = tmp_path / "checkout"
    lane = tmp_path / "lane"
    (root / "defender").mkdir(parents=True)
    (root / "defender" / _check_file()).write_text(_check_bytes(), encoding="utf-8")
    lane.mkdir()
    under = {lane: (0, "a different tree\n")} if fault else {}
    boundary = _Boundary(tmp_path, [root], under=under)
    request = _request("defender-lane-1108", root,
                       box.Mount(source=root, target=root, kind="code"),
                       box.Mount(source=lane, target=lane, writable=True))
    if fault:
        with pytest.raises(box.BoxFault):
            start(request, boundary)
        assert boundary.daemon.names() == []
    else:
        assert start(request, boundary).sandboxed
        assert list(lane.iterdir()) == [], "the planted sentinel was left behind"
        assert str(root / "defender" / _check_file()) in boundary.operands()
    assert any(Path(op).is_relative_to(lane) for op in boundary.operands() if op.startswith("/")), \
        "the writable lane was never read back"
    boundary.assert_never_written()


def test_oracle_production_start_reads_the_runner_check_and_refuses_a_wrong_mapping(
        tmp_path, monkeypatch):
    """Oracle production start reads the runner check and refuses a wrong mapping."""
    from defender.box import _oracle
    from defender.tests.support.sandbox._box1195 import FakeDaemon

    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    good = FakeDaemon(tmp_path / "good")
    good.install(monkeypatch)
    env = {"PATH": os.environ["PATH"], "DEFENDER_BOX_RUNTIME": "runc"}
    oracle = _oracle.start_oracle_box(env=env)
    try:
        assert oracle.sandboxed
        reads = [argv[-1] for argv in good.docker_calls() if argv[1:2] == ["exec"] and "cat" in argv]
        assert str(_oracle.CHECKOUT / "defender" / _check_file()) in reads
    finally:
        _oracle.stop_oracle_box(oracle)
    assert good.names() == []

    wrong = FakeDaemon(tmp_path / "wrong")
    wrong.install(monkeypatch)
    wrong.refuse_sentinel()
    with pytest.raises(_oracle.BoxStartRefused):
        _oracle.start_oracle_box(env={**env, "PATH": os.environ["PATH"]})
    assert wrong.names() == []
    creates = [argv for argv in wrong.docker_calls() if argv[1:2] == ["run"]]
    assert creates, "the refused start never reached the daemon"
    sources = [part.split("source=", 1)[1].split(",", 1)[0]
               for part in creates[-1] if part.startswith("type=bind,")]
    assert sources
    assert not any(Path(source).exists() for source in sources), "a refused start left its folders"


def test_oracle_runner_is_a_code_mount_holding_only_runner_files_and_starts_sandboxed(
        tmp_path, start):
    """Oracle runner is a code mount holding only runner files and starts sandboxed."""
    from defender.box import _oracle
    from defender.tests.support.sandbox._spec1092 import STOCK_ROOTFS
    from defender.tests.tenancy.tenant_1108_p2._support import MountedReadDocker, tree_bytes

    check = f"defender/{_check_file()}"
    assert set(_oracle.RUNNER_FILES) == {
        "defender/execution/__init__.py", "defender/execution/bash_exec.py",
        "defender/execution/box_codec.py", check}
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
        executor = start(request, docker)
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


def _token_then(more):
    return lambda held: (0, (held or b"").decode() + more)


def _token_half(held):
    text = (held or b"").decode()
    return 0, text[:len(text) // 2]


_TOKEN_FAULTS = {"another-copy": (0, "a token another copy holds\n"), "unreadable": (1, ""),
                 "empty": (0, ""), "token-then-more": _token_then("and another copy's\n"),
                 "token-half": _token_half}


@pytest.mark.parametrize("fault", [None, *sorted(_TOKEN_FAULTS)])
def test_a_staged_copy_starts_only_on_the_token_the_host_planted_for_this_start(
        tmp_path, start, fault):
    """A staged copy starts only on the token the host planted for this start."""
    root = _copy(tmp_path / "copy")
    boundary = _Boundary(tmp_path, [root / "agent"], root=root,
                         root_reply=None if fault is None else _TOKEN_FAULTS[fault])
    request = _request("defender-staged-1108", root, box.Mount(source=root, target=root, kind="staged"))
    if fault is None:
        assert start(request, boundary).sandboxed
        assert boundary.daemon.names() == [request.name]
        [(operand, held)] = boundary.root_reads
        assert held, "the token the box read back must be the host's planted, non-empty bytes"
    else:
        with pytest.raises(box.BoxFault):
            start(request, boundary)
        assert boundary.daemon.names() == [], "a refused box was left behind"
        assert boundary.root_reads, "startup never asked the box for the copy's token"
    assert not any(op.endswith("/.tenant-id") for op in boundary.operands())
    boundary.assert_never_written()


def test_a_staged_token_is_fresh_for_every_start(tmp_path, start):
    root = _copy(tmp_path / "copy")
    request = _request("defender-fresh-1108", root, box.Mount(source=root, target=root, kind="staged"))
    tokens = []
    for attempt in ("first", "second"):
        boundary = _Boundary(tmp_path / attempt, [root / "agent"], root=root)
        executor = start(request, boundary)
        assert executor.sandboxed
        [(operand, held)] = boundary.root_reads
        tokens.append(held)
        left = {p.name: p.read_bytes() for p in root.iterdir() if p.name != "agent"}
        assert left in ({}, {Path(operand).name: held}), f"the root kept more than this start's token: {left}"
        box.stop_box(executor)
    assert all(tokens), "each start plants non-empty token bytes"
    assert tokens[0] != tokens[1], "the token must be fresh per start"
    replay = _Boundary(tmp_path / "replay", [root / "agent"], root=root,
                       root_reply=(0, tokens[0].decode()))
    with pytest.raises(box.BoxFault):
        start(request, replay)
    assert replay.daemon.names() == []


@pytest.mark.parametrize("extra", ["stray-file", "git-dir", "agent-missing", "agent-is-a-link",
                                   "agent-is-a-file"])
def test_a_staged_root_holding_anything_but_agent_is_refused(tmp_path, start, extra):
    root = tmp_path / "copy"
    if extra in {"stray-file", "git-dir"}:
        _copy(root)
        if extra == "stray-file":
            (root / "stale.md").write_text("left by another copy\n", encoding="utf-8")
        else:
            (root / ".git").mkdir()
            (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    else:
        root.mkdir()
        if extra == "agent-is-a-link":
            elsewhere = _copy(tmp_path / "elsewhere")
            (root / "agent").symlink_to(elsewhere / "agent", target_is_directory=True)
        elif extra == "agent-is-a-file":
            (root / "agent").write_text("not a folder\n", encoding="utf-8")
        else:
            (root / "lessons").mkdir()
    refused = _Boundary(tmp_path / "refused", [], root=root)
    with pytest.raises(box.BoxFault):
        start(_request("defender-root-1108", root, box.Mount(source=root, target=root, kind="staged")),
              refused)
    assert refused.daemon.names() == []

    clean = _copy(tmp_path / "clean")
    accepted = _Boundary(tmp_path / "accepted", [clean / "agent"], root=clean)
    assert start(_request("defender-root-1108", clean,
                          box.Mount(source=clean, target=clean, kind="staged")), accepted).sandboxed


@pytest.mark.parametrize("fault", [False, True])
def test_a_lane_inside_a_staged_copy_keeps_its_planted_sentinel(tmp_path, start, fault):
    root = _copy(tmp_path / "copy")
    lane = root / "agent" / "lessons"
    boundary = _Boundary(tmp_path, [], under={lane: (0, "a different tree\n")} if fault else {},
                         root=root)
    request = _request("defender-lane-1108", root,
                       box.Mount(source=root, target=root, kind="staged"),
                       box.Mount(source=lane, target=lane, writable=True))
    if fault:
        with pytest.raises(box.BoxFault):
            start(request, boundary)
        assert boundary.daemon.names() == []
    else:
        assert start(request, boundary).sandboxed
        assert sorted(p.name for p in lane.iterdir()) == ["seed.md"], "the sentinel was left behind"
        assert boundary.root_reads
    assert any(Path(op).parent == lane for op in boundary.operands()), "the lane was never read back"


def test_a_staged_mount_is_never_writable(tmp_path, start):
    """A host-made copy's root is read-only in the box; a writable `staged` mount is refused
    at construction or startup, never started."""
    root = _copy(tmp_path / "copy")
    box.Mount(source=root, target=root, kind="staged")  # prerequisite: the kind exists
    boundary = _Boundary(tmp_path, [])
    with pytest.raises((box.BoxFault, ValueError, TypeError)):
        start(_request("defender-rwstaged-1108", root,
                       box.Mount(source=root, target=root, kind="staged", writable=True)), boundary)
    assert boundary.daemon.names() == []


@pytest.mark.parametrize("wrong", [None, "token", "settings-at-root"])
def test_drain_start_reads_the_code_check_and_the_drafts_token_before_returning_a_box(
        repo, tmp_path, wrong):
    """The tenant drain's own start: the product check file and the draft root's token are read
    back through the box before an executor is handed out."""
    from defender.tests.support.sandbox._box1195 import FakeDaemon
    d, batch = _batch(repo, "lifecycle")
    root = batch.draft_root
    request = replace(batch.box_request(), spec=_PINNED)
    if wrong == "settings-at-root":
        (root / "settings").mkdir()
        (root / "settings" / "lead-zero.yaml").write_text("not in a draft\n", encoding="utf-8")
    daemon = FakeDaemon(tmp_path)
    reads = []
    agent_before = files_under(root / "agent")
    status_before = git(repo[0].knowledge, "status", "--porcelain")
    drafts_before = _snapshot(root.parent)

    def boundary(argv, **kwargs):
        argv = [str(a) for a in argv]
        if argv[1:2] == ["exec"]:
            reads.append(argv[-1])
            if wrong == "token" and _at_root(argv[-1], root):
                return subprocess.CompletedProcess(argv, 0, "another draft's token\n", "")
        return daemon(argv, **kwargs)
    if wrong is not None:
        with pytest.raises(box.BoxFault):
            d.start_box(request, docker=boundary)
        assert daemon.names() == []
        assert _snapshot(root.parent) == drafts_before, "a refused start left something under drafts/"
    else:
        executor = d.start_box(request, docker=boundary)
        assert executor.sandboxed
        assert daemon.names() == [request.name]
        assert str(DEFENDER / box.CODE_CHECK_FILE) in reads, "the product check file was never read"
        assert files_under(root / "agent") == agent_before
    if wrong != "settings-at-root":
        assert [r for r in reads if _at_root(r, root)], "the draft's token was never read back"
    assert not any(r.endswith("/.tenant-id") or r.endswith("/SKILL.md") for r in reads)
    assert git(repo[0].knowledge, "status", "--porcelain") == status_before


def _with_code_at(request, source: Path):
    return replace(request, defender_dir=source, mounts=tuple(
        replace(mount, source=source, target=source) if mount.source == DEFENDER else mount
        for mount in request.mounts))


@pytest.mark.parametrize("contents", ["no-files", "unrelated-file", "skill-md-only"])
def test_drain_start_requires_the_code_check_file(repo, tmp_path, contents):
    """D7/O3: generic empty-data handling cannot bypass the required code probe, and SKILL.md
    is not it (D7 amendment 6)."""
    from defender.tests.support.sandbox._box1195 import FakeDaemon
    d, batch = _batch(repo, "required-probe")
    source = tmp_path / "arbitrary-code-location"
    source.mkdir()
    request = _with_code_at(batch.box_request(), source)
    if contents == "unrelated-file":
        (source / "unrelated.txt").write_text("not the product probe\n", encoding="utf-8")
    elif contents == "skill-md-only":
        shutil.copyfile(DEFENDER / "SKILL.md", source / "SKILL.md")
    request = replace(request, spec=_PINNED)
    daemon = FakeDaemon(tmp_path)
    with pytest.raises(box.BoxFault, match="read|probe|missing|file|" + re.escape(_check_file())):
        d.start_box(request, docker=daemon)
    assert daemon.names() == []


def test_drain_start_accepts_a_code_folder_holding_only_the_check_file(repo, tmp_path):
    """D7 amendment 6, positive arm: the tenant drain's code mount needs a check file and
    nothing else, at an arbitrary code root. Its bytes are fresh, never the product's (A09)."""
    from defender.tests.support.sandbox._box1195 import FakeDaemon
    d, batch = _batch(repo, "check-only")
    source = tmp_path / "arbitrary-code-location"
    source.mkdir()
    (source / box.CODE_CHECK_FILE).write_text(_check_bytes(), encoding="utf-8")
    request = replace(_with_code_at(batch.box_request(), source), spec=_PINNED)
    daemon = FakeDaemon(tmp_path)
    executor = d.start_box(request, docker=daemon)
    assert executor.sandboxed
    assert daemon.names() == [request.name]
    assert sorted(p.name for p in source.iterdir()) == [box.CODE_CHECK_FILE]


@pytest.mark.parametrize("which", ["code", "staged"])
def test_tenant_drain_entry_refuses_a_readonly_mount_without_a_kind(repo, tmp_path, which):
    from defender.tests.support.sandbox._box1195 import FakeDaemon
    d, batch = _batch(repo, "kindless")
    request = replace(batch.box_request(), spec=_PINNED, mounts=tuple(
        replace(mount, kind=None) if not mount.writable and mount.kind == which else mount
        for mount in batch.box_request().mounts))
    assert [m for m in request.mounts if not m.writable and m.kind is None]
    daemon = FakeDaemon(tmp_path)
    with pytest.raises(box.BoxFault, match="(?i)kind"):
        d.start_box(request, docker=daemon)
    assert daemon.names() == []
