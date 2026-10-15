"""Amendment 2 (issue comment 6195623857): the host publishes immutable `TenantExport`s from
git objects, under one per-tenant lock that no network I/O or box window holds.

O-B (input side): an export holds `agent/` and `settings/` at exactly one commit, and
`current_export` names that commit and folder without git. O-D (input side): a tree entry that
is not a regular blob, or an `agent/.tenant-id` not naming this tenant through `_tenant`'s
parser, publishes nothing. O-F: an export never changes once published; mutations of one
clone never interleave, and the lock is free while the host talks to the network or a box
runs."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from dataclasses import replace

import pytest

from ._support import (
    DEFENDER,
    LANES,
    ForgeHTTP,
    LockHolder,
    advance_remote,
    bounded,
    build_tenant,
    delivery,
    files_under,
    git,
    index_entry,
    lock_probe,
    push_to_remote,
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


def _knowledge_files(checkout):
    return {rel: data for rel, data in files_under(checkout).items()
            if rel.split("/", 1)[0] in {"agent", "settings"}}


def test_publish_writes_the_commits_blobs_and_points_current_at_them(repo, tmp_path):
    """Flow 1: fetch, fast-forward, then `<T>/exports/<commit>/` holding exactly the commit's
    `agent/` and `settings/` blobs, byte for byte, and `current` naming it. Written from git
    objects: `export-ignore` and `export-subst` (which `git archive` applies) and checkout's
    line-ending conversion (which a copy of the clone's files carries) leave the bytes alone.
    Publishing again at the same commit changes nothing and leaves no other folder."""
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

    again = d.publish()
    assert (again.commit, again.path) == (commit, export.path)
    assert files_under(export.path) == planted
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
    `parse_tenant_id_bytes` (an id plus at most one LF or CRLF). A CRLF or missing final newline is the
    same tenant; another tenant, another case, a blank line, a leading space or no marker at
    all publishes nothing."""
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
    refuse at once with `LockBusy` (a `DeliveryRefused`) naming the holder's pid; nothing is
    fast-forwarded, published or cut meanwhile. Another tenant's publish is unaffected (one
    lock per tenant, under its own folder, not under `forge/`). Released, the lock is taken
    again (control)."""
    tenant = repo[0]
    d = delivery(repo, ForgeHTTP())
    first = d.publish()
    head = git(tenant.knowledge, "rev-parse", "HEAD")
    newer = advance_remote(repo, tmp_path)
    red_tenant, red_remote, _ = build_tenant(tmp_path, "red", root=tenant.data_root)
    mod = target()
    with LockHolder(tenant, tmp_path / "holder") as holder:
        for attempt in (d.publish, lambda: d.start_batch("busy", lanes=LANES)):
            started = time.monotonic()
            _, error, hung = bounded(attempt, seconds=10)
            assert not hung, "a second taker waited on the lock instead of failing fast"
            assert isinstance(error, mod.LockBusy), error
            assert isinstance(error, mod.DeliveryRefused)
            assert str(holder.pid) in str(error), "the refusal must name the holder"
            assert time.monotonic() - started < 5, "a second taker must fail fast, not wait"
        assert git(tenant.knowledge, "rev-parse", "HEAD") == head
        assert _current(tenant) == (first.commit, first.path)
        assert _exports(tenant) == sorted([first.commit, "current"])
        assert not tenant.worktrees.exists() or not any(tenant.worktrees.iterdir())
        assert len(git(tenant.knowledge, "worktree", "list", "--porcelain").split("\nworktree ")) == 1, \
            "a batch worktree was cut under a busy lock"
        assert not (tenant.dir / "drafts" / "busy").exists()
        red = mod.TenantDelivery.open(red_tenant, defender_dir=DEFENDER, client=ForgeHTTP().client)
        assert red.publish().commit == git(red_remote, "rev-parse", "main")
    assert sorted(p.name for p in (tenant.dir / "forge").iterdir()) == ["git-credentials"], \
        "the lock (or anything else) landed in forge/, which stays the credential's alone"
    assert d.publish().commit == newer


def test_the_tenant_lock_is_free_during_network_io_and_box_windows(http_repo, tmp_path):
    """Flow 6: the lock is held for fast-forward, export and worktree creation only. Probed
    from another process at each moment the host waits on something else, on every route: a
    batch (its fetch and push on a real smart-HTTP remote, its PR request, the box's create
    and its window), the retained branch's delivery (its PR request and any git it runs) and
    a revert (its push, its PR request and any fetch). The probe's own positive control sees
    a held lock as busy."""
    from defender.runtime import box
    from defender.tests._box1195 import FakeDaemon

    tenant = http_repo[0]
    server = http_repo[3]
    probes, phase = {}, ["batch"]
    server.on_service = lambda service: probes.setdefault((phase[0], service), lock_probe(tenant))

    def on_request(request):
        if request.url.path.endswith("/pulls"):
            probes.setdefault((phase[0], f"pr-{request.method.lower()}"), lock_probe(tenant))
    http = ForgeHTTP(on_request=on_request)
    with LockHolder(tenant, tmp_path / "holder"):
        assert "busy" in lock_probe(tenant), "the probe must see a held lock"
    d = delivery(http_repo, http)
    advance_remote(http_repo, tmp_path)
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
    assert d.deliver("io").endswith("/pulls/7")

    phase[0] = "revert"
    server.rearm()
    assert d.revert("agent/lessons/seed.md", "seed").endswith("/pulls/7")

    required = {("batch", "git-upload-pack"), ("batch", "git-receive-pack"), ("batch", "pr-post"),
                ("batch", "after-start-batch"), ("batch", "box-create"), ("batch", "box-window"),
                ("deliver", "pr-post"), ("revert", "git-receive-pack"), ("revert", "pr-post")}
    assert required <= set(probes), sorted(required - set(probes))
    assert all(result.get("free") for result in probes.values()), probes
