"""Amendment 2 (issue comment 6195623857): the host publishes immutable `TenantExport`s from
git objects, under one per-tenant lock that no network I/O or box window holds.

O-B (input side): an export holds `agent/` and `settings/` at exactly one commit, and
`current_export` names that commit and folder without git. O-D (input side): a tree entry that
is not a regular blob, or an `agent/.tenant-id` not naming this tenant through `_tenant`'s
parser, publishes nothing. O-F: an export never changes once published; mutations of one
clone never interleave, and the lock is free while the host talks to the network or a box
runs."""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest

from ._support import (
    DEFENDER,
    LANES,
    ForgeHTTP,
    LockAudit,
    LockHolder,
    advance_remote,
    agent_blobs,
    bounded,
    build_tenant,
    configured_origin,
    delivery,
    files_under,
    forge_pulls,
    fresh_process_env,
    git,
    git_config_home,
    index_entry,
    lock_probe,
    merge_on_remote,
    opened,
    push_to_remote,
    quiet,
    running_in,
    target,
)

def _current(tenant):
    export = target().current_export(tenant)
    return export.commit, export.path


def _exports(tenant):
    """The export folders and the `current` pointer; other files (a lock, say) are not
    exports and are not counted."""
    folder = tenant.dir / "exports"
    if not folder.exists():
        return []
    return sorted(p.name for p in folder.iterdir()
                  if p.name == "current" or (p.is_dir() and not p.is_symlink()))


def _timed(attempt):
    started = time.monotonic()
    result = bounded(attempt, seconds=10)
    return time.monotonic() - started, result


def _stats(root):
    return {p: (st.st_ino, st.st_mtime_ns) for p in sorted(Path(root).rglob("*"))
            for st in [os.lstat(p)]}


def _knowledge_files(checkout):
    return {rel: data for rel, data in files_under(checkout).items()
            if rel.split("/", 1)[0] in {"agent", "settings"}}


def test_publish_writes_the_commits_blobs_and_points_current_at_them(repo, tmp_path):
    """Flow 1: fetch, fast-forward, then `<T>/exports/<commit>/` holding exactly the commit's
    `agent/` and `settings/` blobs, byte for byte, and `current` naming it. Written from git
    objects: `export-ignore` and `export-subst` (which `git archive` applies) and checkout's
    line-ending conversion (which a copy of the clone's files carries) leave the bytes alone.
    Publishing again at the same commit changes nothing (no file of the export is rewritten
    in place under a reader: every inode and mtime stays) and leaves no other folder."""
    tenant = repo[0]
    planted = {}

    def edit(checkout):
        (checkout / ".gitattributes").write_text(
            "agent/lessons/ignored.md export-ignore\nagent/lessons/subst.md export-subst\n"
            "*.md text eol=crlf\n", encoding="utf-8")
        for rel, data in {"agent/lessons/ignored.md": b"kept by an export from git objects\n",
                          "agent/lessons/subst.md": b"$Format:%H$\n",
                          "agent/lessons/blob.bin": b"\x00\xff\r\n raw bytes\n",
                          "agent/lessons/merged.md": b"human-reviewed merge\n"}.items():
            (checkout / rel).write_bytes(data)
        planted.update(_knowledge_files(checkout))

    commit = push_to_remote(repo, tmp_path, edit)
    d = delivery(repo, ForgeHTTP())
    export = d.publish()
    assert export.commit == commit
    assert git(tenant.knowledge, "rev-parse", "HEAD") == commit, "publish fast-forwards the clone"
    assert export.path == tenant.dir / "exports" / commit
    assert files_under(export.path) == planted
    # Precondition of the discrimination above: the clone's own checkout converted endings.
    assert (tenant.agent / "lessons/merged.md").read_bytes() == b"human-reviewed merge\r\n"
    assert _current(tenant) == (commit, export.path)

    stats = _stats(export.path)
    again = d.publish()
    assert (again.commit, again.path) == (commit, export.path)
    assert files_under(export.path) == planted
    assert _stats(export.path) == stats, "a re-publish rewrote the export in place"
    assert _exports(tenant) == sorted([commit, "current"])


def test_a_later_publish_leaves_every_earlier_export_as_it_was(repo, tmp_path):
    """O-F: advancing the clone never changes files a reader of an earlier export holds; the
    `current` pointer is replaced by a rename (a new inode), never rewritten in place."""
    tenant = repo[0]
    d = delivery(repo, ForgeHTTP())
    first = d.publish()
    before = files_under(first.path)
    stats = {p: (s.st_ino, s.st_mtime_ns, s.st_mode)
             for p in first.path.rglob("*") for s in [os.lstat(p)]}
    pointer = tenant.dir / "exports" / "current"
    pointer_inode = os.lstat(pointer).st_ino

    newer = advance_remote(repo, tmp_path)
    second = d.publish()
    assert second.commit == newer != first.commit
    assert second.path == tenant.dir / "exports" / newer
    assert files_under(second.path)["agent/lessons/merged.md"] == b"human-reviewed merge\n"
    assert files_under(first.path) == before
    assert {p: (s.st_ino, s.st_mtime_ns, s.st_mode)
            for p in first.path.rglob("*") for s in [os.lstat(p)]} == stats
    assert _current(tenant) == (newer, second.path)
    assert os.lstat(pointer).st_ino != pointer_inode, "`current` must be replaced atomically"


def test_current_export_reads_the_pointer_without_git(repo, tmp_path, monkeypatch):
    """O-B, for P4's git-less runs: `current_export(tenant)` answers from the files alone. With
    the clone's `.git` gone and no program on PATH it returns the published (commit, folder),
    spawning no process (an audit hook sees every spawn; its positive control below)."""
    tenant = repo[0]
    export = delivery(repo, ForgeHTTP()).publish()
    spawned, active = [], [True]

    def audit(event, args):
        if active[0] and event in {"subprocess.Popen", "os.posix_spawn", "os.exec", "os.spawn",
                                   "os.system"}:
            spawned.append(event)
    sys.addaudithook(audit)
    try:
        subprocess.run([sys.executable, "-c", "pass"], check=True)
        assert spawned, "the audit hook must see a spawn"
        spawned.clear()
        empty = tmp_path / "no-programs"
        empty.mkdir()
        monkeypatch.setenv("PATH", str(empty))
        shutil.rmtree(tenant.knowledge / ".git")
        got = target().current_export(tenant)
    finally:
        active[0] = False
    assert (got.commit, got.path) == (export.commit, export.path)
    assert spawned == [], "current_export spawned a process"


@pytest.mark.parametrize("damage", ["never-published", "pointer-removed", "pointer-empty",
                                    "pointer-escapes", "export-missing"])
def test_current_export_refuses_a_pointer_that_names_no_export(repo, tmp_path, damage):
    """Fail closed: no pointer, an empty one, one leading out of `exports/` (here toward the
    tenant's `forge/`), or one naming a folder that is gone is refused, naming the export."""
    tenant = repo[0]
    if damage != "never-published":
        export = delivery(repo, ForgeHTTP()).publish()
        pointer = tenant.dir / "exports" / "current"
        if damage == "pointer-removed":
            pointer.unlink()
        elif damage == "pointer-empty":
            pointer.write_bytes(b"")
        elif damage == "pointer-escapes":
            pointer.write_text("../forge\n", encoding="utf-8")
        else:
            export.path.rename(tmp_path / "moved-away")
    with pytest.raises(target().DeliveryRefused, match="(?i)export|current|publish"):
        target().current_export(tenant)


#: Tree entries that are not regular blobs (K2: git stores and emits links), under each half.
_NOT_BLOBS = {
    "file-link-in-agent": ("120000", "agent/lessons/link.md", b"/etc/passwd"),
    "dir-link-in-agent": ("120000", "agent/linked", b"../settings"),
    "link-in-settings": ("120000", "settings/link.yaml", b"../agent/.tenant-id"),
    "submodule-in-agent": ("160000", "agent/lessons/sub", None),
    "submodule-in-settings": ("160000", "settings/sub", None),
}


@pytest.mark.parametrize("entry", sorted(_NOT_BLOBS))
def test_publish_refuses_a_tree_entry_that_is_not_a_regular_blob(repo, tmp_path, entry):
    """O-D on the input side: a link or a submodule under `agent/` or `settings/` refuses the
    publish. Nothing is published: `current` keeps naming the earlier export and no folder
    for the refused commit (or a partial one) appears."""
    tenant = repo[0]
    d = delivery(repo, ForgeHTTP())
    first = d.publish()
    mode, path, data = _NOT_BLOBS[entry]

    def edit(checkout):
        if data is None:
            index_entry(checkout, mode, path, blob=git(checkout, "rev-parse", "HEAD"))
        else:
            index_entry(checkout, mode, path, data=data)
    refused = push_to_remote(repo, tmp_path, edit, stage=False)
    assert git(repo[1], "ls-tree", "main", "--", path).split()[0] == mode
    with pytest.raises(target().DeliveryRefused):
        d.publish()
    assert _current(tenant) == (first.commit, first.path)
    assert _exports(tenant) == sorted([first.commit, "current"])
    assert not (tenant.dir / "exports" / refused).exists()


def test_publish_accepts_an_executable_blob(repo, tmp_path):
    """Control for the refusal above: a 100755 blob is a regular blob, exported by its bytes."""
    commit = push_to_remote(repo, tmp_path, lambda checkout: index_entry(
        checkout, "100755", "agent/lessons/tool.md", data=b"#!/bin/sh\n"), stage=False)
    export = delivery(repo, ForgeHTTP()).publish()
    assert export.commit == commit
    assert (export.path / "agent/lessons/tool.md").read_bytes() == b"#!/bin/sh\n"


@pytest.mark.parametrize(("marker", "accepted"), [
    (b"blue\n", True), (b"blue\r\n", True), (b"blue", True),
    (b"red\n", False), (b"BLUE\n", False), (b"blue\n\n", False), (b" blue\n", False),
    (None, False),
])
def test_publish_requires_the_tenant_id_to_name_this_tenant_through_its_parser(
        repo, tmp_path, marker, accepted):
    """Identity is checked once, at publish, through `_tenant`'s sole tenant-id parser,
    `parse_tenant_id_bytes` (an id plus at most one LF or CRLF). A CRLF or missing final
    newline is the same tenant; another tenant, another case, a blank line, a leading space
    or no marker at all publishes nothing."""
    tenant = repo[0]
    d = delivery(repo, ForgeHTTP())
    first = d.publish()

    def edit(checkout):
        (checkout / "agent/lessons/merged.md").write_text("beside the marker\n", encoding="utf-8")
        if marker is None:
            (checkout / "agent/.tenant-id").unlink()
        else:
            (checkout / "agent/.tenant-id").write_bytes(marker)
    commit = push_to_remote(repo, tmp_path, edit)
    if accepted:
        export = d.publish()
        assert export.commit == commit
        assert (export.path / "agent/.tenant-id").read_bytes() == marker
        return
    with pytest.raises(target().DeliveryRefused, match="(?i)tenant"):
        d.publish()
    assert _current(tenant) == (first.commit, first.path)
    assert _exports(tenant) == sorted([first.commit, "current"])


def test_a_second_taker_of_the_tenant_lock_fails_fast_naming_the_holder(repo, tmp_path):
    """Flow 6 / O-F: while another process holds the tenant's lock, publish and start_batch
    refuse at once with `LockBusy` (a `DeliveryRefused`) naming the holder's pid, the fastest
    of three attempts taking no more than a second longer than the same publish with the
    lock free (a non-blocking try, not a wait for the holder); nothing is
    fast-forwarded, published or drafted meanwhile. Another tenant's publish is unaffected (one
    lock per tenant, under its own folder, not under `forge/`). Released, the lock is taken
    again (control)."""
    tenant = repo[0]
    d = delivery(repo, ForgeHTTP())
    first = d.publish()
    # The same fetch-then-lock path with the lock free, timed: the busy refusal may cost no
    # more than that plus a margin far below any wait for the holder.
    baseline = min(_timed(d.publish)[0] for _ in range(2))
    head = git(tenant.knowledge, "rev-parse", "HEAD")
    newer = advance_remote(repo, tmp_path)
    red_tenant, red_remote, _ = build_tenant(tmp_path, "red", root=tenant.data_root)
    mod = target()
    with LockHolder(tenant, tmp_path / "holder") as holder:
        for attempt in (d.publish, lambda: d.start_batch("busy", lanes=LANES)):
            times = []
            for _ in range(3):
                elapsed, (_, error, hung) = _timed(attempt)
                assert not hung, "a second taker waited on the lock instead of failing fast"
                assert isinstance(error, mod.LockBusy), error
                assert isinstance(error, mod.DeliveryRefused)
                assert str(holder.pid) in str(error), "the refusal must name the holder"
                times.append(elapsed)
            assert min(times) < baseline + 1.0, \
                f"a second taker waited ({min(times):.2f} s against {baseline:.2f} s with the lock free)"
        assert git(tenant.knowledge, "rev-parse", "HEAD") == head
        assert _current(tenant) == (first.commit, first.path)
        assert _exports(tenant) == sorted([first.commit, "current"])
        drafts = tenant.dir / "drafts"
        assert not drafts.exists() or not any(drafts.iterdir()), \
            "a draft or its temporary was made under a busy lock"
        assert git(tenant.knowledge, "for-each-ref", "--format=%(refname)", "refs/heads") == "refs/heads/main"
        red_forge = ForgeHTTP(origin=configured_origin(red_tenant.knowledge))
        red = mod.TenantDelivery.open(red_tenant, defender_dir=DEFENDER, client=red_forge.client)
        assert red.publish().commit == git(red_remote, "rev-parse", "main")
    assert sorted(p.name for p in (tenant.dir / "forge").iterdir()) == ["git-credentials"], \
        "the lock (or anything else) landed in forge/, which stays the credential's alone"
    assert d.publish().commit == newer


def test_the_tenant_lock_is_free_during_network_io_and_box_windows(http_repo, tmp_path):
    """Flow 6: the lock is held for the fast-forward, the export, `info/attributes` and the
    draft only. Probed from another process at each moment the host waits on something else,
    on every route: `open()`'s repository and protection reads, a publish's fetch, a batch
    (its fetch and push on a real smart-HTTP remote, its PR lookup and request, the box's
    create and its window), the retained branch's delivery (its PR lookup and request and
    any git it runs) and, once a human has merged that PR, the revert of its lesson (its
    push, its PR request and any fetch). The probe's own positive control sees a held lock
    as busy."""
    from defender.runtime import box
    from defender.tests._box1195 import FakeDaemon

    tenant = http_repo[0]
    server = http_repo[3]
    probes, phase = {}, ["open"]
    server.on_service = lambda service: probes.setdefault((phase[0], service), lock_probe(tenant))

    def on_request(request):
        if "/pulls" in request.url.path:
            probes.setdefault((phase[0], f"pr-{request.method.lower()}"), lock_probe(tenant))
        if request.url.path.endswith("/branches/main"):
            probes.setdefault((phase[0], "protection"), lock_probe(tenant))
        if request.url.path.endswith("/repos/tenants/blue"):
            probes.setdefault((phase[0], "repository"), lock_probe(tenant))
    http = ForgeHTTP(on_request=on_request)
    with LockHolder(tenant, tmp_path / "holder"):
        assert "busy" in lock_probe(tenant), "the probe must see a held lock"
    d = delivery(http_repo, http)
    advance_remote(http_repo, tmp_path)
    phase[0] = "publish"
    server.rearm()
    d.publish()
    push_to_remote(http_repo, tmp_path, lambda checkout: (checkout / "agent/lessons/later.md").write_text(
        "a later human merge\n", encoding="utf-8"))
    phase[0] = "batch"
    server.rearm()
    batch = d.start_batch("io", lanes=LANES)
    probes["batch", "after-start-batch"] = lock_probe(tenant)

    daemon = FakeDaemon(tmp_path)

    def docker(argv, **kwargs):
        if [str(a) for a in argv[1:2]] == ["run"]:
            probes.setdefault(("batch", "box-create"), lock_probe(tenant))
        return daemon(argv, **kwargs)
    request = replace(batch.box_request(), spec=box.BoxSpec(runtime="runc",
                                                            rootfs="defender-box:test1108"))
    executor = d.start_box(request, docker=docker)
    probes["batch", "box-window"] = lock_probe(tenant)
    box.stop_box(executor)

    (batch.draft_root / "agent/lessons/io.md").write_text("written in the window\n",
                                                          encoding="utf-8")
    batch.commit(batch.change_set(), "claim")
    http.fail_create = True
    with pytest.raises(target().DeliveryRefused):
        d.finish(batch)
    http.fail_create = False

    phase[0] = "deliver"
    server.rearm()
    opened(d.deliver("io"))

    merge_on_remote(http_repo, tmp_path, batch.branch)
    phase[0] = "revert"
    server.rearm()
    assert d.revert("agent/lessons/io.md", "io") == forge_pulls(http_repo[1])[-1]["html_url"]

    required = {("open", "repository"), ("open", "protection"), ("publish", "git-upload-pack"),
                ("batch", "git-upload-pack"), ("batch", "git-receive-pack"), ("batch", "pr-post"),
                ("batch", "after-start-batch"), ("batch", "box-create"), ("batch", "box-window"),
                ("deliver", "pr-post"), ("revert", "git-receive-pack"), ("revert", "pr-post")}
    assert required <= set(probes), sorted(required - set(probes))
    assert all(result.get("free") for result in probes.values()), probes


def _under(root, path):
    """`path`'s parts below `root` (an absolute path, `str` or `bytes`), or `None` outside it."""
    try:
        full = os.path.abspath(os.fsdecode(path))
    except TypeError:
        return None
    # Resolve the folder, never the entry itself: `current` may be a link.
    full = os.path.join(os.path.realpath(os.path.dirname(full)), os.path.basename(full))
    rel = os.path.relpath(full, root)
    return None if rel == os.pardir or rel.startswith(os.pardir + os.sep) else Path(rel).parts


def _at(path, dir_fd):
    """`path` as named relative to the folder descriptor `dir_fd` (`None` or -1: none), read
    back through `/proc/self/fd`."""
    if dir_fd is None or dir_fd < 0 or not isinstance(path, (str, bytes, os.PathLike)):
        return path
    name = os.fsdecode(path)
    return name if os.path.isabs(name) else os.path.join(os.readlink(f"/proc/self/fd/{dir_fd}"), name)


def _writes(flags):
    return flags is not None and bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))


def test_the_export_and_current_are_written_under_the_tenant_lock(repo, tmp_path):
    """Flow 1 / O-F: the export's folder and files and the `current` pointer are written while
    this process holds the tenant lock, so a publisher that fetched an older commit can never
    point `current` back at it after another published a newer one. Probed from another
    process (`LockAudit`) before the first write of an export file opened by name (a file in a
    folder under `exports/`), before every rename or link into `exports/` (by name or relative
    to a folder descriptor), and before every write of `current`; the probe's positive
    control comes first. Every probe sees the lock busy, and `current` was among them. (An
    `os.open` relative to a folder descriptor is audited without the descriptor, so export
    files written that way are not seen; only `current` is required.)"""
    tenant = repo[0]
    d = delivery(repo, ForgeHTTP())
    d.publish()
    exports = os.path.realpath(tenant.dir / "exports")
    seen = set()

    def pick(event, args):
        if event == "open" and _writes(args[2]):
            parts = _under(exports, args[0])
        elif event in {"os.rename", "os.link"}:
            parts = _under(exports, _at(args[1], args[3]))
        elif event == "os.symlink":
            parts = _under(exports, _at(args[1], args[2]))
        else:
            return None
        if not parts or parts[0] == os.curdir:
            return None
        if parts == ("current",):
            return "current"
        if len(parts) == 1:
            return None if event == "open" else f"{event}:{parts[0]}"
        if "export-file" in seen:
            return None
        seen.add("export-file")
        return "export-file"
    audit = LockAudit(tenant, pick)
    control = Path(exports) / "p3-control"
    control.mkdir()
    with LockHolder(tenant, tmp_path / "holder"), audit:
        (control / "held").write_bytes(b"")
    seen.clear()
    with audit:
        (control / "free").write_bytes(b"")
    shutil.rmtree(control)
    assert [next(iter(verdict)) for _, verdict in audit.probes] == ["busy", "free"], \
        f"the probe must fire on a write under exports/ and tell held from free: {audit.probes}"
    seen.clear()
    audit.probes.clear()
    advance_remote(repo, tmp_path)
    with audit:
        export = d.publish()
    assert export.commit == git(tenant.knowledge, "rev-parse", "HEAD")
    labels = [label for label, _ in audit.probes]
    assert "current" in labels, f"no write of `current` was seen: {labels}"
    assert all("busy" in verdict for _, verdict in audit.probes), audit.probes


_INTERRUPTED_PUBLISH = """
import json, os, resource, signal, sys
from pathlib import Path
from defender.tests import _tenants1106 as tenants
from defender.tests.tenant_1108_delivery._support import DEFENDER, ForgeHTTP, target
root, tenant_id, marker, size, limit = (Path(sys.argv[1]), sys.argv[2], sys.argv[3], int(sys.argv[4]),
                                        int(sys.argv[5]))
mod = target()
tenant = tenants.accept(root, tenant_id)
d = mod.TenantDelivery.open(tenant, defender_dir=DEFENDER, client=ForgeHTTP().client)
clone = os.path.abspath(tenant.knowledge)
in_clone = os.path.join(clone, "agent", "lessons", marker)
signal.signal(signal.SIGXFSZ, signal.SIG_DFL)  # a write past the limit kills, as a power cut would
armed = []

def fast_forwarded():
    try:
        return os.stat(in_clone).st_size == size
    except OSError:
        return False

def cut_off(event, args):
    # Once the clone's checkout holds the whole marker (the fast-forward is done), the next
    # file this process opens for writing anywhere outside the clone (by name, relative to a
    # folder descriptor, unnamed, or by descriptor) or the next program it starts arms a cap
    # of `limit` bytes per file: the marker, the only file over it, is cut off part-written
    # and the process (or its program) dies of SIGXFSZ. Nothing here ever raises into the
    # code under test.
    try:
        if armed or event not in ("open", "subprocess.Popen", "os.posix_spawn", "os.exec", "os.spawn"):
            return
        if event == "open":
            flags = args[2]
            if not flags or not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT):
                return
            if isinstance(args[0], (str, bytes, os.PathLike)):
                path = os.path.abspath(os.fsdecode(args[0]))
                if path == clone or path.startswith(clone + os.sep):
                    return
        if not fast_forwarded():
            return
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, resource.getrlimit(resource.RLIMIT_FSIZE)[1]))
        armed.append(event)
    except Exception:
        return
sys.addaudithook(cut_off)
try:
    print(json.dumps({"published": d.publish().commit}))
except mod.DeliveryRefused as refused:
    print(json.dumps({"refused": str(refused)}))
"""

#: The marker's bytes (well over the cap; every other file of the export is far under it).
_MARKER_BYTES = b"the export is cut off in here\n" * 8192
_WRITE_CAP = 64 * 1024


def test_a_publish_cut_off_mid_export_leaves_no_partial_export(repo, tmp_path):
    """Flow 1 / O-B: an export is written to a temporary folder and renamed into place, so a
    publish cut off mid-export leaves no `exports/<commit>` and `current` on the earlier
    export. The cut, in another process: once the fast-forward has checked the new commit's
    marker file out in the clone, the next file write outside the clone (however opened:
    by name, staged under another name, unnamed, relative to a folder descriptor) or the next
    program started caps every later file write below the marker's size, so the marker is
    left part-written and the process dies of SIGXFSZ, or its program does and it refuses.
    The next publish, finding whatever was left, publishes the commit whole and exact:
    nothing part-written is reused, no stale lock is in the way."""
    tenant = repo[0]
    d = delivery(repo, ForgeHTTP())
    first = d.publish()
    marker = "p3-interrupted-here.md"
    planted = {}

    def edit(checkout):
        (checkout / "agent/lessons" / marker).write_bytes(_MARKER_BYTES)
        (checkout / "agent/lessons/after.md").write_bytes(b"written after the marker, or before\n")
        planted.update(_knowledge_files(checkout))
    newer = push_to_remote(repo, tmp_path, edit)
    assert all(len(data) < _WRITE_CAP for rel, data in planted.items() if not rel.endswith(marker))
    exports = tenant.dir / "exports"
    proc = subprocess.run([sys.executable, "-c", _INTERRUPTED_PUBLISH, str(tenant.data_root),
                           str(tenant.id), marker, str(len(_MARKER_BYTES)), str(_WRITE_CAP)],
                          capture_output=True, text=True, timeout=300, check=False,
                          env=fresh_process_env(tenant, tmp_path / "cut"))
    assert proc.returncode == -signal.SIGXFSZ or '"refused"' in proc.stdout, \
        f"the publish was never cut off mid-export: {proc.returncode} {proc.stdout} {proc.stderr}"
    assert not os.path.lexists(exports / newer), "a cut-off publish left a partial export"
    assert _current(tenant) == (first.commit, first.path)
    export = d.publish()
    assert (export.commit, export.path) == (newer, exports / newer)
    assert files_under(export.path) == planted
    assert _current(tenant) == (newer, export.path)


_PAUSED_PUBLISH = """
import json, os, sys, time
from pathlib import Path
from defender.tests import _tenants1106 as tenants
from defender.tests.tenant_1108_delivery._support import DEFENDER, ForgeHTTP, lock_probe, target
root, tenant_id, marker, ready, go, trace = (Path(sys.argv[1]), sys.argv[2], sys.argv[3],
                                             Path(sys.argv[4]), Path(sys.argv[5]), Path(sys.argv[6]))
mod = target()
tenant = tenants.accept(root, tenant_id)
d = mod.TenantDelivery.open(tenant, defender_dir=DEFENDER, client=ForgeHTTP().client)
clone = os.path.abspath(tenant.knowledge)
current = os.path.join(os.path.realpath(tenant.dir / "exports"), "current")
in_clone = os.path.join(clone, "agent", "lessons", marker)
SPAWNS = ("subprocess.Popen", "os.posix_spawn", "os.exec", "os.spawn")
state = {"inside": False, "done": False, "paused": False, "unprobed": 0}
probes = []

def record(moment, verdict):
    probes.append([moment, verdict])
    with open(trace, "a", encoding="utf-8") as out:
        out.write(json.dumps([moment, verdict]) + "\\n")

def resolved(path, dir_fd=None):
    name = os.fsdecode(path)
    if dir_fd is not None and dir_fd >= 0 and not os.path.isabs(name):
        name = os.path.join(os.readlink(f"/proc/self/fd/{dir_fd}"), name)
    name = os.path.abspath(name)
    return os.path.join(os.path.realpath(os.path.dirname(name)), os.path.basename(name))

def kind(event, args):
    if event in SPAWNS:
        return "spawn"
    if event == "open":
        if not args[2] or not args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT):
            return None
        if not isinstance(args[0], (str, bytes, os.PathLike)):
            return "write"
        path = resolved(args[0])
        if path == clone or path.startswith(clone + os.sep):
            return None
        return "current" if path == current else "write"
    if event in ("os.rename", "os.link"):
        return "current" if resolved(args[1], args[3]) == current else "write"
    if event == "os.symlink":
        return "current" if resolved(args[1], args[2]) == current else "write"
    return None

def watch(event, args):
    # From the end of the fast-forward (the clone holds the marker) to the write of `current`,
    # every file this process writes outside the clone and every program it starts is a
    # moment of its export: probe the lock from another process there. The first such moment
    # also pauses the publish until `go` exists. Nothing here raises into the code under test.
    if state["inside"] or state["done"]:
        return
    state["inside"] = True
    try:
        moment = kind(event, args)
        if moment is None or not os.path.exists(in_clone):
            return
        if len(probes) < 60 or moment == "current":
            record(moment, lock_probe(tenant))
        else:
            state["unprobed"] += 1
        if not state["paused"]:
            state["paused"] = True
            ready.write_text("paused", encoding="utf-8")
            deadline = time.monotonic() + 120
            while not go.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
        if moment == "current":
            state["done"] = True
    except Exception as crash:
        try:
            record("crash", {"crashed": repr(crash)})
        except Exception:
            probes.append(["crash", {"crashed": repr(crash)}])
    finally:
        state["inside"] = False
sys.addaudithook(watch)
out = {}
try:
    out["published"] = d.publish().commit
except mod.DeliveryRefused as refused:
    out["refused"] = str(refused)
out["probes"] = probes
out["unprobed"] = state["unprobed"]
print(json.dumps(out))
"""


def test_two_publishers_never_interleave_so_current_never_goes_back(repo, tmp_path):
    """Flow 1 / O-F, seam-free (adversary round 2, R1): the fast-forward, the whole export
    (its body wherever it is staged, not only what lands in `exports/`) and `current` are
    one hold of the tenant lock. A first publisher runs in another process. From the end of
    its fast-forward (the older commit's marker checked out in the clone) to its write of
    `current`, every file it writes outside the clone and every program it starts is probed
    from a third process (at most 60 moments, and always the write of `current`; the probe's
    positive control, run from the publisher's own environment, comes first): each sees the
    lock busy, and the write of `current` was among them. At the first of those moments it
    is paused; meanwhile the remote moves to a newer commit and a second publisher refuses
    at once with `LockBusy`. The first resumes and publishes the older commit whole; a
    later publish then publishes the newer one. So
    `current` never moves back from a newer commit to an older one: an export body written
    with the lock released (the second publisher getting in between) fails here."""
    tenant = repo[0]
    d = delivery(repo, ForgeHTTP())
    d.publish()
    marker = "p3-paused-here.md"
    older = push_to_remote(repo, tmp_path, lambda c: (c / "agent/lessons" / marker).write_bytes(b"older\n"),
                           message="the older commit, with the marker")
    ready, go, trace = tmp_path / "paused", tmp_path / "go", tmp_path / "probes.jsonl"
    env = fresh_process_env(tenant, tmp_path / "first")
    # Positive control: the probe, run from the publisher's own environment, tells a held
    # lock from a free one.
    control = [sys.executable, "-c", "import json, sys; from pathlib import Path; "
               "from defender.tests import _tenants1106 as t; "
               "from defender.tests.tenant_1108_delivery._support import lock_probe; "
               "print(json.dumps(lock_probe(t.accept(Path(sys.argv[1]), sys.argv[2]))))",
               str(tenant.data_root), str(tenant.id)]
    with LockHolder(tenant, tmp_path / "holder"):
        held = subprocess.run(control, capture_output=True, text=True, env=env, timeout=120, check=False)
    free = subprocess.run(control, capture_output=True, text=True, env=env, timeout=120, check=False)
    assert [next(iter(json.loads(proc.stdout.strip().splitlines()[-1]))) for proc in (held, free)] == \
        ["busy", "free"], (held.stdout, held.stderr, free.stdout, free.stderr)
    out_path, err_path = tmp_path / "first.out", tmp_path / "first.err"
    with open(out_path, "wb") as out_file, open(err_path, "wb") as err_file:
        first = subprocess.Popen([sys.executable, "-c", _PAUSED_PUBLISH, str(tenant.data_root),
                                  str(tenant.id), marker, str(ready), str(go), str(trace)],
                                 stdout=out_file, stderr=err_file, env=env)
    try:
        deadline = time.monotonic() + 120
        while not ready.exists() and first.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert ready.exists(), ("the first publisher never reached its export: probes "
                                f"{trace.read_text(encoding='utf-8') if trace.exists() else '[]'}, "
                                f"stdout {out_path.read_bytes()!r}, stderr {err_path.read_bytes()!r}")
        newer = advance_remote(repo, tmp_path)
        _, error, hung = bounded(d.publish, seconds=30)
    finally:
        go.write_text("go", encoding="utf-8")
        try:
            first.wait(timeout=120)
        except subprocess.TimeoutExpired:
            first.kill()
            first.wait(timeout=60)
    assert first.returncode == 0, err_path.read_bytes()
    result = json.loads(out_path.read_bytes().decode().strip().splitlines()[-1])
    probes, unprobed = result.pop("probes"), result.pop("unprobed")
    assert [moment for moment, verdict in probes if "busy" not in verdict] == [], \
        f"the lock was free during the export: {probes} ({unprobed} moments past the cap unprobed)"
    assert "current" in [moment for moment, _ in probes], \
        f"the write of `current` was not seen: {probes} ({unprobed} moments past the cap unprobed)"
    assert not hung, "the second publisher waited for the first instead of failing fast"
    assert isinstance(error, target().LockBusy), f"a second publish went ahead mid-export: {error!r}"
    assert result == {"published": older}, result
    assert _current(tenant)[0] == older
    later = d.publish()
    assert later.commit == newer
    assert _current(tenant) == (newer, later.path)


def _named(path, dir_fd=None):
    """`path` (relative to the folder descriptor `dir_fd`, if any) as an absolute name, or
    `None` for anything that is not a name."""
    if not isinstance(path, (str, bytes, os.PathLike)):
        return None
    return os.path.abspath(_at(path, dir_fd))


def _under_drafts(tenant):
    """`pick` for `LockAudit`: one probe per kind of change under `<T>/drafts/` (`build`: a
    folder made or a file opened for writing; `rename`: a rename or link into it; `sweep`: a
    removal) and for the clone's `$GIT_DIR/info/attributes` (`attributes`: opened for
    writing, or renamed or linked onto; a file written beside it, a temporary, counts too)."""
    info = os.path.realpath(tenant.knowledge / ".git" / "info")
    folder = os.path.join(os.path.realpath(tenant.dir), "drafts")
    seen = set()

    def pick(event, args):
        if event == "open" and _writes(args[2]):
            name, label = _named(args[0]), "build"
        elif event == "os.mkdir":
            name, label = _named(args[0], args[2]), "build"
        elif event in {"os.rename", "os.link"}:
            name, label = _named(args[1], args[3]), "rename"
        elif event in {"os.remove", "os.rmdir", "shutil.rmtree"}:
            name, label = _named(args[0], args[1]), "sweep"
        else:
            return None
        if name is None:
            return None
        if os.path.dirname(name) == info and (label != "sweep" or name.endswith("/attributes")):
            label = "attributes"
        elif not (name == folder or name.startswith(folder + os.sep)):
            return None
        if label in seen:
            return None
        seen.add(label)
        return label
    return pick


def test_the_draft_and_info_attributes_are_written_under_the_tenant_lock(repo, tmp_path):
    """C2 / O-F: the lock covers the `* -filter` write to the clone's `info/attributes` and
    the draft's build, rename and sweep (and never a commit: that case is in
    `test_delivery.py`). Probed from another process (`LockAudit`) before the first write of
    `info/attributes` in `open()` and the first publish, and, on a batch start with a stale
    temporary in `drafts/`, before the first build step, removal and rename under
    `<T>/drafts/` (by name or relative to a folder descriptor); the probe's positive control
    comes first. Every probe sees the lock busy, and each of the four was among them."""
    tenant = repo[0]
    audit = LockAudit(tenant, _under_drafts(tenant))
    control = tenant.dir / "drafts" / ".p3-control"
    control.mkdir(parents=True)
    with LockHolder(tenant, tmp_path / "holder"), audit:
        (control / "held").write_bytes(b"")
    shutil.rmtree(control)
    assert [next(iter(verdict)) for _, verdict in audit.probes] == ["busy"], \
        f"the probe must fire on a write under drafts/ and see a held lock: {audit.probes}"
    audit = LockAudit(tenant, _under_drafts(tenant))
    with audit:
        d = delivery(repo, ForgeHTTP())
        d.publish()
    stale = tenant.dir / "drafts" / ".stale-0a1b2c" / "agent" / "lessons"
    stale.mkdir(parents=True)
    (stale / "seed.md").write_bytes(b"left by a build that never finished\n")
    advance_remote(repo, tmp_path)
    with audit:
        batch = d.start_batch("drafted", lanes=LANES)
    labels = [label for label, _ in audit.probes]
    assert {"attributes", "build", "rename", "sweep"} <= set(labels), audit.probes
    assert all("busy" in verdict for _, verdict in audit.probes), audit.probes
    assert sorted(p.name for p in (tenant.dir / "drafts").iterdir()) == ["drafted"]
    assert files_under(batch.draft_root / "agent") == files_under(batch.export.path / "agent")


#: A clean and smudge filter driver that logs every run and passes the bytes through, named
#: by the tenant's own attributes: in the clone's config, `main`'s `.gitattributes`, and the
#: operator's `$GIT_DIR/info/attributes`.
_SPY = '#!/bin/sh\necho "$1 $2" >> {log}\ncat\n'


def _install_spy_filter(clone, scratch):
    log = scratch / "p3spy.log"
    spy = scratch / "p3spy.sh"
    spy.write_text(_SPY.format(log=log), encoding="utf-8")
    spy.chmod(0o755)
    git(clone, "config", "filter.p3spy.clean", f"{spy} clean %f")
    git(clone, "config", "filter.p3spy.smudge", f"{spy} smudge %f")
    return log


def _operator_attributes(clone, line):
    """The operator appends `line` to the clone's `$GIT_DIR/info/attributes`."""
    info = Path(clone) / ".git" / "info" / "attributes"
    info.parent.mkdir(exist_ok=True)
    with open(info, "a", encoding="utf-8") as out:
        out.write(line)


def test_no_tenant_named_filter_runs_on_the_host(repo, tmp_path):
    """R4 / O-C: no filter driver the tenant names runs on the host during any delivery
    call, the clone's fast-forward included. The clone's config defines a clean and smudge
    driver that logs each run; `main`'s `.gitattributes` names it for every lesson, and so
    does the operator's `$GIT_DIR/info/attributes`, before the first call and again (a line
    after whatever the code wrote there) before the second publish. Across `open`, two
    publishes that each check new lessons out, a batch start, a claim, a reset, finish and
    the revert of a merged lesson, the driver never runs; the clone stays clean and each
    export is exactly its commit's blobs. (Positive control: a checkout by the fixtures'
    git, with the same attributes, runs it.)"""
    tenant, remote = repo[0], repo[1]
    clone = tenant.knowledge
    log = _install_spy_filter(clone, tmp_path)

    def human(checkout):
        (checkout / ".gitattributes").write_text("*.md filter=p3spy\n", encoding="utf-8")
        (checkout / "agent/lessons/filtered.md").write_bytes(b"checked out by the fast-forward\n")
    push_to_remote(repo, tmp_path, human)
    control, scratch = tmp_path / "spy-control", tmp_path / "spy-control-log"
    scratch.mkdir()
    git(tmp_path, "clone", "-n", remote, control)
    _install_spy_filter(control, scratch)
    git(control, "checkout", "-f", "HEAD", "--", ".")
    assert (scratch / "p3spy.log").exists(), "the spy filter never ran: the probe is blind"
    _operator_attributes(clone, "*.md filter=p3spy\n")

    http = ForgeHTTP()
    d = delivery(repo, http)
    first = d.publish()
    assert files_under(first.path / "agent") == agent_blobs(clone, first.commit)
    _operator_attributes(clone, "*.md filter=p3spy\n")
    push_to_remote(repo, tmp_path, lambda c: (c / "agent/lessons/later.md").write_bytes(b"a later lesson\n"))
    second = d.publish()
    assert files_under(second.path / "agent") == agent_blobs(clone, second.commit)
    batch = d.start_batch("filtered", lanes=LANES)
    (batch.draft_root / "agent/lessons/claimed.md").write_bytes(b"a claim\n")
    batch.commit(batch.change_set(), "claim")
    batch.reset()
    opened(d.finish(batch))
    merge_on_remote(repo, tmp_path, batch.branch)
    d.revert("agent/lessons/claimed.md", "claimed")
    assert not log.exists(), f"a tenant-named filter ran on the host: {log.read_text(encoding='utf-8')}"
    assert git(clone, "status", "--porcelain") == ""


def test_a_crlf_operator_clone_still_publishes(repo, tmp_path):
    """R4: `* -filter` turns filters off and nothing else: git's own `eol` and `ident` keep
    applying, since operator clones may be CRLF. With `main`'s `.gitattributes` asking for
    `text eol=crlf ident` on lessons, the clone's checkout is CRLF; it stays clean, publishes,
    and publishes again after a later human merge, each export exactly its commit's blobs."""
    tenant = repo[0]
    clone = tenant.knowledge

    def human(checkout):
        (checkout / ".gitattributes").write_text("*.md text eol=crlf ident\n", encoding="utf-8")
        (checkout / "agent/lessons/human.md").write_bytes(b"$Id$\na human's lesson\n")
    push_to_remote(repo, tmp_path, human)
    d = delivery(repo, ForgeHTTP())
    first = d.publish()
    assert (tenant.agent / "lessons/human.md").read_bytes().endswith(b"a human's lesson\r\n"), \
        "the clone's checkout is not CRLF: git's own `eol` stopped applying (an attribute source " \
        "hiding `main`'s `.gitattributes`), or the case is blind"
    assert files_under(first.path / "agent") == agent_blobs(clone, first.commit)
    newer = push_to_remote(repo, tmp_path, lambda c: (c / "agent/lessons/later.md").write_bytes(b"later\n"))
    second = d.publish()
    assert second.commit == newer
    assert files_under(second.path / "agent") == agent_blobs(clone, newer)
    assert (tenant.agent / "lessons/later.md").read_bytes() == b"later\r\n"
    assert git(clone, "status", "--porcelain") == ""


# ---------------------------------------------------------------------------------------
# O-F: git's own upkeep never runs over the clone
# ---------------------------------------------------------------------------------------

#: A maintenance task the clone's own config forces on every `maintenance run --auto`: it
#: writes a commit-graph, so a run leaves a file behind whatever environment the code under
#: test gives its git (choice 20).
_FORCED_TASK = (("maintenance.commit-graph.enabled", "true"),
                ("maintenance.commit-graph.auto", "-1"))


def _graphs(checkout):
    info = Path(checkout) / ".git" / "objects" / "info"
    return sorted(p.name for p in info.glob("commit-graph*"))


def _upkeep_locks(checkout):
    git_dir = Path(checkout) / ".git"
    return [p.name for p in (git_dir / "objects" / "maintenance.lock", git_dir / "gc.pid")
            if os.path.lexists(p)]


#: A process the scan's positive controls start: it holds open the file `P3_HOLD` names, if
#: any, says it is ready, and sleeps.
_SLEEPER = ("import os, time; hold = os.environ.get('P3_HOLD'); "
            "held = hold and open(hold, 'rb'); print('ready', flush=True); time.sleep(60)")


def test_no_git_upkeep_runs_over_the_clone_from_a_delivery_call(repo, tmp_path, monkeypatch):
    """O-F: the clone changes only by what a call itself does. Git's automatic upkeep
    (`maintenance run --auto` after a fetch, commit or merge; detached on git >= 2.47) is not
    that: detached, it holds `maintenance.lock` and writes after the call has returned, racing
    the next operation on the clone; in the foreground, it rewrites the clone inside a fetch or
    commit the tenant lock does not cover. So after `open`, `publish`, `start_batch`, `commit`,
    `reset` and `finish`: no process the call started still runs (choice 20: none outlives
    its call), no upkeep lock stands in the clone, and no upkeep has run there. How the code
    turns upkeep off is not pinned.

    The clone's own config forces a task that writes a commit-graph, so a run is seen after the
    fact whatever environment the code gives its git. A process is seen by its working folder,
    an open file or a path on its command line under the tenant's folders. A run that starts
    late shows at the next call's check; after `finish`, the last, the case waits 2 s for one.
    Positive controls: with this process's environment as it is (the fixtures' `no_upkeep`
    never reaches it), a plain fetch in a clone armed the same way leaves the graph; the scan
    sees a process by each of the three."""
    for name, value in git_config_home(tmp_path).create().env().items():
        monkeypatch.setenv(name, value)
    tenant, remote = repo[0], repo[1]
    clone = tenant.knowledge

    control = tmp_path / "upkeep-control"
    git(tmp_path, "clone", remote, control)
    for key, value in _FORCED_TASK:
        git(control, "config", key, value)
    # lint-raw-git: positive control, a git with this process's own environment as the code
    # under test inherits it (the fixtures' `git` turns upkeep off).
    subprocess.run(["git", "fetch", "origin"], cwd=control, env=dict(os.environ), check=True,
                   capture_output=True, timeout=60)
    assert quiet(control) == []
    assert _graphs(control), "a plain fetch here must run git's upkeep, or the probe is blind"
    for how, cwd, args, hold in (("working folder", clone, [], {}),
                                 ("open file", "/", [], {"P3_HOLD": str(clone / ".git" / "HEAD")}),
                                 ("command line", "/", [str(clone / ".git")], {})):
        sleeper = subprocess.Popen([sys.executable, "-c", _SLEEPER, *args], cwd=cwd,
                                   env={**os.environ, **hold}, stdout=subprocess.PIPE)
        try:
            sleeper.stdout.readline()
            assert sleeper.pid in [pid for pid, _ in running_in(tenant.dir)], \
                f"the scan must see a process whose {how} is in the clone"
        finally:
            sleeper.kill()
            sleeper.wait()
            sleeper.stdout.close()

    for key, value in _FORCED_TASK:
        git(clone, "config", key, value)
    roots = [tenant.dir]

    def probe(call, fn, settle=0.0):
        result = fn()
        running, locks, during = running_in(*roots), _upkeep_locks(clone), _graphs(clone)
        left = quiet(*roots)
        deadline = time.monotonic() + settle
        while not (late := _graphs(clone)) and time.monotonic() < deadline:
            time.sleep(0.05)
        ran = "before it returned" if during else "after it returned" if late else ""
        found = {what: got for what, got in (
            ("still running at return", running), ("upkeep locks in the clone", locks),
            ("upkeep's commit-graph written in the clone", ran),
            ("still running a minute later", left)) if got}
        assert found == {}, f"{call} left git's upkeep over the clone: {found}"
        return result

    http = ForgeHTTP()
    d = probe("open", lambda: delivery(repo, http))
    advance_remote(repo, tmp_path)
    probe("publish", d.publish)
    push_to_remote(repo, tmp_path, lambda checkout: (checkout / "agent/lessons/later.md")
                   .write_text("a later human merge\n", encoding="utf-8"))
    batch = probe("start_batch", lambda: d.start_batch("upkeep", lanes=LANES))
    roots += [batch.draft_root]
    (batch.draft_root / "agent/lessons/upkeep.md").write_text("written in the window\n",
                                                              encoding="utf-8")
    probe("commit", lambda: batch.commit(batch.change_set(), "claim"))
    probe("reset", batch.reset)
    opened(probe("finish", lambda: d.finish(batch), settle=2.0))
