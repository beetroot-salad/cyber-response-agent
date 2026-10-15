"""D7/O8: distinct code and knowledge geography, no forge exposure, read-only probes.

D7 as amended (issue comment 6190547938): every read-only `Mount` declares its kind (`code`,
`agent` or `data`); startup applies that kind's check and never infers one from a name or path.
A `code` mount is proven by reading back `<code_dir>/<box.CODE_CHECK_FILE>`, where `code_dir`
is the request's explicit `defender_dir` or the legacy `<workdir>/defender`, inside the one
mount declared `code`. Every rule holds on both request-lane entries (`_ENTRIES`).
"""
from __future__ import annotations

import json
import os
import re
import secrets
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

    def __init__(self, base: Path, watched, replies=None, under=None):
        from defender.tests._box1195 import FakeDaemon
        self.daemon = FakeDaemon(base)
        self.watched = tuple(watched)
        self.before = _snapshot(*self.watched)
        self.replies = dict(replies or {})
        self.under = {Path(folder): reply for folder, reply in (under or {}).items()}
        self.execs: list[list[str]] = []
        self.snapshots: list[dict] = []

    def _scripted(self, operand: str):
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


#: How the box's reply differs from the host file. Read-backs cross Docker's text channel,
#: which translates line endings, so the design compares line-ending-normalized text on both
#: sides: a host file with CRLF endings read back as LF starts (orchestrator decision); any
#: other difference refuses, a trailing newline lost or added or a space included.
_TEXT_DIFFERENCES = ("newline-lost", "newline-added", "space-added")
_PROBE_CASES = [
    *((kind, fault) for kind in ("agent", "code", "data") for fault in (None, "mismatch", "read-error")),
    *((kind, fault) for kind in ("code", "data") for fault in (*_TEXT_DIFFERENCES, "crlf-on-host")),
]


@pytest.mark.parametrize(("kind", "fault"), _PROBE_CASES)
def test_readonly_probe_reads_existing_file_and_never_plants(tmp_path, start, kind, fault):
    """D7 amendments 1-4: the declared kind alone picks the existing file read back (no folder
    is named for its kind); a wrong mapping or a read error refuses before a box is handed out,
    and the source is never written. `code` and `data` read-backs equal the host's own read:
    fresh bytes per test (A09), and a reply differing by one newline or space refuses (A10);
    only a CRLF/LF difference compares equal. `data` reads its first regular file, here its
    only one."""
    folder, marker, expected = {
        "agent": ("tenant-half", ".tenant-id", "blue\n"),
        "code": ("product-tree", _check_file(), _check_bytes()),
        "data": ("evidence-store", "result.json", f'{{"made-up": "{secrets.token_hex(8)}"}}\n'),
    }[kind]
    source = tmp_path / folder
    source.mkdir()
    on_host = expected.replace("\n", "\r\n") if fault == "crlf-on-host" else expected
    (source / marker).write_bytes(on_host.encode())
    if kind != "data":
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
    """D7 amendment 1: no declared kind, no box, whatever the folder is called or holds, an
    empty one included (A14). The writable lane needs no kind, and the same mount declared
    `data` starts (controls)."""
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


#: Words that are not kinds: the design's own folder names, near-synonyms, and case and
#: whitespace variants of the three kinds (A08/A17). Only `code`, `agent` and `data` are kinds.
_NOT_KINDS = ["defender", "tenant", "", "product", "checkout", "repo", "source", "identity",
              "evidence", "runs", "ro", "readonly", "none", "None", "Code", "CODE", " code",
              "code ", "codes", "Agent", "DATA"]


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
    ("agent-named-defender", "defender", "agent", True),
    ("code-not-named-defender", "srv-tree", "code", False),
    ("agent-not-named-agent", "tenant-half", "agent", False),
])
def test_startup_applies_the_declared_kind_never_the_folder_name(
        tmp_path, start, case, folder, kind, starts):
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
            start(request, boundary)
        assert boundary.daemon.names() == []
        boundary.assert_never_written()
        return
    assert start(request, boundary).sandboxed
    assert boundary.daemon.names() == [request.name]
    operands = boundary.operands()
    assert not any(op.endswith("/" + _check_file()) for op in operands), "a non-code mount got the code check"
    if kind == "data":
        assert not any(Path(op).is_relative_to(source) for op in operands), \
            "an empty data folder was read or asked for an identity"
    else:
        assert str(source / ".tenant-id") in operands
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
#: layout -> (folders holding a check file, empty folders, explicit code root, workdir, the
#: check file read on success). Every layout also has a check file in `lane/defender` (a
#: writable lane of the request), `checkout-lane/defender` (a prefix sibling of the code
#: mount) and `elsewhere/defender` (in no mount), where a wrong containment rule would look.
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
    """D7 amendment 2: `code_dir` is the explicit `defender_dir`, else `<workdir>/defender`,
    and must lie inside the mount declared `code`: not in another mount of the request, such
    as its writable lane (A15), and not in a folder whose path merely begins with the code
    mount's (`checkout-lane` is not inside `checkout`, A11). The check file is read there, not
    at the mount's root; an absent code dir or check file refuses, never skips (A16)."""
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
    """D7 amendment 2 as clarified by the orchestrator (A18): one request, at most one `code`
    mount; a second is refused at startup even when each holds a valid check file. The same
    folder declared `data` starts (control)."""
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


@pytest.mark.parametrize("kind", ["code", "agent"])
def test_a_host_side_read_fault_is_a_box_fault(tmp_path, start, kind):
    """A13: the host's own read of the probe file failing (here: a folder in its place) is a
    `BoxFault` like every other startup fault, with no box left. The box's side answers, so
    the refusal can only come from the host read or the comparison."""
    source = tmp_path / ("product-tree" if kind == "code" else "tenant-half")
    marker = source / (_check_file() if kind == "code" else ".tenant-id")
    marker.mkdir(parents=True)
    (source / "unrelated.txt").write_text("not a probe\n", encoding="utf-8")
    boundary = _Boundary(tmp_path, [source], {str(marker): (0, "blue\n")})
    extra = {"defender_dir": source} if kind == "code" else {}
    request = _request("defender-hostread-1108", source,
                       box.Mount(source=source, target=source, kind=kind), **extra)
    with pytest.raises(box.BoxFault):
        start(request, boundary)
    assert boundary.daemon.names() == []
    boundary.assert_never_written()


@pytest.mark.parametrize("fault", [False, True])
def test_writable_mount_keeps_its_planted_sentinel_read_back(tmp_path, start, fault):
    """D7 amendment 1 (A12): a writable mount is still proven by its planted sentinel. The
    request's `code` mount is valid, so a wrong mapping of the lane alone must refuse; in the
    control the lane is read back and left as it was."""
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
    """D7 amendment 5 on the oracle's own start (A24): `start_oracle_box`, with the fake
    daemon as the `docker` on PATH, starts sandboxed after reading the runner's check file
    through the box; a daemon answering other bytes for every read refuses with no box left
    and both folders discarded."""
    from defender.runtime.box import _oracle
    from defender.tests._box1195 import FakeDaemon

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
    """D7 amendment 5: the oracle's runner is a `code` mount whose files are exactly
    `RUNNER_FILES` (three transport modules and the check file, no SKILL.md), built by the
    real runner maker and started through each request-lane entry with reads routed by the
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
    """D7 amendment 6, positive arm: the tenant drain's code mount needs a check file and
    nothing else, at an arbitrary code root. Its bytes are fresh, never the product's (A09)."""
    from defender.tests._box1195 import FakeDaemon
    d = delivery(repo, ForgeHTTP())
    wt = d.start_batch("check-only")
    source = tmp_path / "arbitrary-code-location"
    source.mkdir()
    (source / box.CODE_CHECK_FILE).write_text(_check_bytes(), encoding="utf-8")
    request = _with_code_at(d.box_request(wt, "check-only", writable_dirs=("lessons",)), source)
    request = replace(request, spec=_PINNED)
    daemon = FakeDaemon(tmp_path)
    executor = d.start_box(request, docker=daemon)
    assert executor.sandboxed
    assert daemon.names() == [request.name]
    assert sorted(p.name for p in source.iterdir()) == [box.CODE_CHECK_FILE]


@pytest.mark.parametrize("which", ["code", "agent"])
def test_tenant_drain_entry_refuses_a_readonly_mount_without_a_kind(repo, tmp_path, which):
    """D7 amendment 1 on the tenant drain's own start (A24): its request with one read-only
    mount's kind removed is refused, no box left; the unaltered request is the control in
    `test_drain_start_wires_real_lifecycle_readback_before_returning_executor`."""
    from defender.tests._box1195 import FakeDaemon
    d = delivery(repo, ForgeHTTP())
    wt = d.start_batch("kindless")
    request = d.box_request(wt, "kindless", writable_dirs=("lessons",))
    request = replace(request, spec=_PINNED, mounts=tuple(
        replace(mount, kind=None) if not mount.writable and mount.kind == which else mount
        for mount in request.mounts))
    assert [m for m in request.mounts if not m.writable and m.kind is None]
    daemon = FakeDaemon(tmp_path)
    with pytest.raises(box.BoxFault, match="(?i)kind"):
        d.start_box(request, docker=daemon)
    assert daemon.names() == []
