"""O7/O7b/O8/O9 and amendment 2's O-C/O-D/O-F: real tenant git and HTTP delivery through the
dormant entry seam.

A batch is a host-only worktree at the export commit plus a git-free `Draft` copy of its
`agent/`. A box writes only the draft. Per claim the host derives a `ChangeSet` (draft against
worktree: regular files in the batch's lanes, nothing else), the commit-maker, the only maker
of tenant commits, commits it in the worktree, and a reset re-syncs the draft. Every push
route (finish, retained deliver, revert) sends only commit-maker commits."""
from __future__ import annotations

import json
import os
import shutil
import socket
import stat
import sys
from types import SimpleNamespace

import httpx
import pytest

from defender import _io

from ._support import (
    DEFENDER,
    FORK,
    LANES,
    MERGE_STYLES,
    TOKEN,
    ForgeHTTP,
    advance_remote,
    bounded,
    delivery,
    files_under,
    git,
    git_bytes,
    git_subcommand,
    in_a_later_process,
    install_planting_hook,
    merge_on_remote,
    merged_agent_lesson,
    odd_entries,
    plain_file,
    plant_raw_commit,
    pr_row,
    push_to_remote,
    target,
)


def _name_status(cwd, commit):
    rows = git(cwd, "diff-tree", "--no-commit-id", "--name-status", "-r", commit).splitlines()
    return {row.split("\t", 1)[1]: row.split("\t", 1)[0] for row in rows}


def _modes(cwd, commit, prefix="agent"):
    rows = git(cwd, "ls-tree", "-r", commit, "--", prefix).splitlines()
    return {row.split("\t", 1)[1]: row.split()[0] for row in rows}


def _changes(change_set):
    return {change.path: change.content for change in change_set}


def _branches(remote):
    return git(remote, "for-each-ref", "--format=%(refname)", "refs/heads").splitlines()


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------------------
# The batch: a host-only worktree and a git-free draft, at the export commit
# ---------------------------------------------------------------------------------------

def test_start_batch_cuts_a_host_only_worktree_and_a_git_free_draft_at_the_export_commit(
        repo, tmp_path):
    """Flow 3 and O7b: the batch starts from a fresh publish, so a human merge on the remote
    reaches the clone, the export, the worktree and the draft. The worktree is a worktree of
    the tenant clone under the layout's worktree base; the draft at `<T>/drafts/<batch>`
    holds exactly `agent/`, byte-equal to the worktree's and the export's, with no `.git` and
    no link anywhere."""
    tenant = repo[0]
    expected = advance_remote(repo, tmp_path)
    batch = delivery(repo, ForgeHTTP()).start_batch("fresh", lanes=LANES)
    assert batch.export.commit == expected
    current = target().current_export(tenant)
    assert (current.commit, current.path) == (batch.export.commit, batch.export.path)
    assert git(tenant.knowledge, "rev-parse", "HEAD") == expected
    assert (tenant.agent / "lessons/merged.md").read_text(encoding="utf-8") == "human-reviewed merge\n"

    worktree = batch.worktree
    assert worktree.is_relative_to(tenant.worktrees)
    assert git(worktree, "rev-parse", "HEAD") == expected
    common = git(worktree, "rev-parse", "--path-format=absolute", "--git-common-dir")
    assert os.path.realpath(common) == os.path.realpath(tenant.knowledge / ".git")
    assert git(worktree, "status", "--porcelain") == ""

    assert batch.draft_root == tenant.dir / "drafts" / "fresh"
    assert sorted(p.name for p in batch.draft_root.iterdir()) == ["agent"]
    assert not [p for p in batch.draft_root.rglob(".git")]
    assert odd_entries(batch.draft_root) == []
    assert files_under(batch.draft_root / "agent") == files_under(worktree / "agent") \
        == files_under(batch.export.path / "agent")
    assert _changes(batch.change_set()) == {}


@pytest.mark.parametrize("state", ["dirty", "untracked", "diverged"])
def test_refresh_refuses_local_state_without_creating_batch(repo, tmp_path, state):
    """O7b: a clone with local edits or a diverged `main` refuses, naming the state; nothing
    is fast-forwarded, published, cut or copied."""
    tenant = repo[0]
    d = delivery(repo, ForgeHTTP())
    advance_remote(repo, tmp_path)
    p = tenant.agent / "lessons/seed.md"
    if state == "untracked":
        p = tenant.agent / "lessons/untracked.md"
    p.write_text("local\n", encoding="utf-8")
    if state == "diverged":
        git(tenant.knowledge, "add", ".")
        git(tenant.knowledge, "commit", "-m", "local divergence")
    before = git(tenant.knowledge, "rev-parse", "HEAD")
    with pytest.raises(target().DeliveryRefused, match="dirty|diverg|fast.forward|untracked"):
        d.start_batch("refused", lanes=LANES)
    assert git(tenant.knowledge, "rev-parse", "HEAD") == before
    assert not tenant.worktrees.exists() or not list(tenant.worktrees.glob("*"))
    assert not (tenant.dir / "drafts" / "refused").exists()
    with pytest.raises(target().DeliveryRefused):
        target().current_export(tenant)


def test_publishing_after_a_batch_starts_never_changes_its_draft_or_worktree(repo, tmp_path):
    """O-F: a later publish (another drain, or `tenant.py setup`) advances the clone and
    `current`, yet the running batch's draft, worktree and export stay exactly as they were."""
    tenant = repo[0]
    batch = delivery(repo, ForgeHTTP()).start_batch("pinned", lanes=LANES)
    draft = files_under(batch.draft_root)
    head = git(batch.worktree, "rev-parse", "HEAD")
    export = files_under(batch.export.path)
    newer = advance_remote(repo, tmp_path)
    other = target().TenantDelivery.open(tenant, defender_dir=DEFENDER, client=ForgeHTTP().client)
    assert other.publish().commit == newer
    assert target().current_export(tenant).commit == newer
    assert files_under(batch.draft_root) == draft
    assert git(batch.worktree, "rev-parse", "HEAD") == head
    assert files_under(batch.export.path) == export
    assert _changes(batch.change_set()) == {}


# ---------------------------------------------------------------------------------------
# ChangeSet: the draft against the worktree, regular files in the lanes, nothing else
# ---------------------------------------------------------------------------------------

def test_change_set_is_the_draft_against_the_worktree_and_commits_as_plain_files(repo, tmp_path):
    """O-C/O-D: added, changed and deleted regular files in a lane become `AgentChange`s
    (repo-relative path, exact bytes, `None` for a deletion). The commit-maker commits exactly
    them on the export commit, each blob as written and every mode 100644, even for a file the
    box left executable or one already executable in the base."""
    def edit(checkout):
        _write(checkout / "agent/lessons/merged.md", "human-reviewed merge\n")
        _write(checkout / "agent/lessons/tool.md", "#!/bin/sh\n")
        (checkout / "agent/lessons/tool.md").chmod(0o755)
    base = push_to_remote(repo, tmp_path, edit)
    assert _modes(repo[1], base, "agent/lessons/tool.md") == {"agent/lessons/tool.md": "100755"}
    batch = delivery(repo, ForgeHTTP()).start_batch("derive", lanes=LANES)
    lane = batch.draft_root / "agent/lessons"
    (lane / "seed.md").write_bytes(b"seed, revised\r\n")
    (lane / "merged.md").unlink()
    (lane / "tool.md").write_bytes(b"#!/bin/sh\necho revised\n")
    (lane / "deep").mkdir()
    (lane / "deep/new.md").write_bytes(b"\x00binary\xff\n")
    (lane / "new.md").write_bytes(b"new lesson\n")
    (lane / "new.md").chmod(0o755)
    expected = {"agent/lessons/seed.md": b"seed, revised\r\n", "agent/lessons/merged.md": None,
                "agent/lessons/tool.md": b"#!/bin/sh\necho revised\n",
                "agent/lessons/deep/new.md": b"\x00binary\xff\n",
                "agent/lessons/new.md": b"new lesson\n"}
    change_set = batch.change_set()
    assert _changes(change_set) == expected
    assert all(isinstance(c.path, str) and (c.content is None or isinstance(c.content, bytes))
               for c in change_set)

    sha = batch.commit(change_set, "claim one")
    wt = batch.worktree
    assert git(wt, "rev-parse", "HEAD") == sha
    assert git(wt, "rev-parse", f"{sha}^") == batch.export.commit
    assert _name_status(wt, sha) == {"agent/lessons/seed.md": "M", "agent/lessons/merged.md": "D",
                                     "agent/lessons/tool.md": "M", "agent/lessons/deep/new.md": "A",
                                     "agent/lessons/new.md": "A"}
    assert set(_modes(wt, sha, "agent/lessons").values()) == {"100644"}
    for path, content in expected.items():
        if content is not None:
            assert git_bytes(wt, "cat-file", "blob", f"{sha}:{path}") == content


#: Human content on `main` that would make git change bytes on their way into a blob: a
#: root `.gitattributes` (outside every lane, so no claim can touch it) and, for the filter,
#: a driver the clone's own configuration defines.
_BYTE_CHANGERS = {
    "eol-and-ident": ("*.md text eol=crlf ident\n", None),
    "clean-filter": ("*.md filter=p3upper\n", "tr a-z A-Z"),
}


@pytest.mark.parametrize("changer", sorted(_BYTE_CHANGERS))
def test_the_commit_maker_stores_the_boxs_bytes_whatever_mains_attributes_say(repo, tmp_path, changer):
    """O-C: the commit-maker stores each changed file's bytes exactly as the box wrote them. A
    `.gitattributes` on `main` asking for line-ending normalisation and `$Id$` collapsing, or
    a clean filter whose driver the clone's configuration defines, changes nothing in the
    committed blob (a commit made with `git add` would store converted bytes)."""
    attributes, driver = _BYTE_CHANGERS[changer]
    push_to_remote(repo, tmp_path, lambda c: _write(c / ".gitattributes", attributes))
    if driver is not None:
        git(repo[0].knowledge, "config", "filter.p3upper.clean", driver)
    batch = delivery(repo, ForgeHTTP()).start_batch("bytes", lanes=LANES)
    data = b"Line One\r\n$Id: 0123456789abcdef $\r\nlower case, mixed endings\n"
    (batch.draft_root / "agent/lessons/exact.md").write_bytes(data)
    sha = batch.commit(batch.change_set(), "exact bytes")
    assert _name_status(batch.worktree, sha) == {"agent/lessons/exact.md": "A"}
    assert git_bytes(batch.worktree, "cat-file", "blob", f"{sha}:agent/lessons/exact.md") == data


def _mknod(lane):
    try:
        os.mknod(lane / "dev.md", stat.S_IFCHR | 0o600, os.makedev(1, 3))
    except PermissionError:
        pytest.skip("creating a device node needs CAP_MKNOD; the FIFO and socket rows remain")


def _oversized(lane):
    with open(lane / "big.md", "wb") as big:
        big.truncate(_io.READ_LIMIT + 1)


def _write_bytes_name(lane, name):
    """A file whose name is raw bytes no UTF-8 decoding accepts (untrusted box output)."""
    with open(os.path.join(os.fsencode(lane), name), "wb") as out:
        out.write(b"a lesson under a name git cannot be given as text\n")


def _replace(entry, plant):
    """Replace an existing draft entry (a file, or a whole subdirectory) by `plant(entry)`."""
    if entry.is_dir() and not entry.is_symlink():
        shutil.rmtree(entry)
    else:
        entry.unlink()
    plant(entry)


#: Box output a claim must refuse whole, each beside a valid in-lane change: `(entry) ->
#: plant(lane, agent, outside, worktree)`. A symlinked directory is listed by `os.walk` among
#: `dirnames` and not descended, so a naive derivation skips it silently; `agent/.tenant-id`
#: is also outside every lane. The FIFO and socket rows are planted by the test itself. The
#: `replace-*` rows put the entry where a file (or a subdirectory) of the base already is, so
#: a reset that copies the worktree's file onto it writes through the link, or blocks on the
#: FIFO, instead of replacing the entry.
_REFUSED_OUTPUT = {
    "file-link-absolute": lambda lane, agent, outside, wt: (lane / "link.md").symlink_to(outside / "secret.md"),
    "file-link-into-worktree": lambda lane, agent, outside, wt: (lane / "link.md").symlink_to(
        os.path.relpath(wt / "settings/lead-zero.yaml", lane)),
    "dir-link": lambda lane, agent, outside, wt: (lane / "linked").symlink_to(outside, target_is_directory=True),
    "fifo": lambda lane, agent, outside, wt: os.mkfifo(lane / "pipe.md"),
    "socket": None,
    "device": lambda lane, agent, outside, wt: _mknod(lane),
    "oversized": lambda lane, agent, outside, wt: _oversized(lane),
    "out-of-lane-file": lambda lane, agent, outside, wt: _write(agent / "notes.md", "outside every lane\n"),
    "out-of-lane-deletion": lambda lane, agent, outside, wt: (agent / "AGENT.md").unlink(),
    "lane-prefix-sibling": lambda lane, agent, outside, wt: _write(
        agent / "lessons-questioner/x.md", "a sibling whose name begins with the lane's\n"),
    "tenant-id": lambda lane, agent, outside, wt: _write(agent / ".tenant-id", "red\n"),
    "gitattributes": lambda lane, agent, outside, wt: _write(lane / ".gitattributes", "* filter=planted\n"),
    "gitignore-nested": lambda lane, agent, outside, wt: _write(lane / "deep/.gitignore", "*\n"),
    "gitmodules": lambda lane, agent, outside, wt: _write(lane / ".gitmodules", '[submodule "x"]\n\tpath = x\n'),
    "gitattributes-deletion": lambda lane, agent, outside, wt: (lane / ".gitattributes").unlink(),
    "replace-file-with-link": lambda lane, agent, outside, wt: _replace(
        lane / "seed.md", lambda e: e.symlink_to(outside / "secret.md")),
    "replace-dir-with-link": lambda lane, agent, outside, wt: _replace(
        lane / "deep", lambda e: e.symlink_to(outside, target_is_directory=True)),
    "replace-file-with-fifo": lambda lane, agent, outside, wt: _replace(lane / "seed.md", os.mkfifo),
    "non-utf8-name": lambda lane, agent, outside, wt: _write_bytes_name(lane, b"\xff\xfe.md"),
}

#: Base content a row needs before the batch starts (pushed as a human merge).
_REFUSED_BASE = {
    "gitattributes-deletion": {"agent/lessons/.gitattributes": "* -text\n"},
    "replace-dir-with-link": {"agent/lessons/deep/x.md": "a planted subdirectory\n"},
}


@pytest.mark.parametrize("entry", sorted(_REFUSED_OUTPUT))
def test_a_claim_holding_anything_but_in_lane_regular_files_is_refused_whole(
        repo, tmp_path, monkeypatch, entry):
    """O-C/O-D: a link (to a file or a directory), FIFO, socket, device or oversized file, a
    name that is not UTF-8 (refused, never a crash: orchestrator ruling), a
    path outside the lanes (a prefix sibling of one included), `agent/.tenant-id`, or a
    `.gitattributes`/`.gitignore`/`.gitmodules` at any depth (added or deleted), new or put in
    place of a base file or subdirectory, refuses the claim: nothing is skipped and nothing
    committed, no link is followed, nothing blocks. After a reset the draft equals the
    worktree again, every base file back as a regular file with the worktree's bytes, and the
    host folder a link pointed at is intact."""
    if entry in _REFUSED_BASE:
        def base(checkout):
            for rel, text in _REFUSED_BASE[entry].items():
                _write(checkout / rel, text)
        push_to_remote(repo, tmp_path, base)
    batch = delivery(repo, ForgeHTTP()).start_batch("inert", lanes=LANES)
    agent = batch.draft_root / "agent"
    lane = agent / "lessons"
    outside = tmp_path / "host-folder"
    outside.mkdir()
    (outside / "secret.md").write_text("host only\n", encoding="utf-8")
    _write(lane / "valid.md", "a valid change beside it\n")
    sockets = []
    if entry == "socket":
        monkeypatch.chdir(lane)
        sockets.append(socket.socket(socket.AF_UNIX))
        sockets[0].bind("sock.md")
    else:
        _REFUSED_OUTPUT[entry](lane, agent, outside, batch.worktree)
    fifos = [lane / "pipe.md", lane / "seed.md"]
    head = git(batch.worktree, "rev-parse", "HEAD")
    try:
        _, error, hung = bounded(batch.change_set, fifos=fifos)
    finally:
        for listener in sockets:
            listener.close()
    assert not hung, "deriving the change set blocked on box output"
    assert isinstance(error, target().DeliveryRefused), error
    assert git(batch.worktree, "rev-parse", "HEAD") == head
    assert git(batch.worktree, "status", "--porcelain") == ""

    _, error, hung = bounded(batch.reset, fifos=fifos)
    assert not hung, "the reset blocked on box output"
    assert error is None, error
    assert files_under(outside) == {"secret.md": b"host only\n"}, "a reset wrote through a link"
    for rel, data in files_under(batch.worktree / "agent").items():
        assert plain_file(agent / rel, data), f"the reset left agent/{rel} other than the worktree's file"
    assert odd_entries(agent) == []
    assert files_under(agent) == files_under(batch.worktree / "agent")
    assert _changes(batch.change_set()) == {}


def _gitdir_file(lane, clone):
    _write(lane / ".git", f"gitdir: {clone / '.git'}\n")


def _nested_repository(lane, clone):
    nested = lane / "sub"
    _write(nested / "x.md", "a repository of its own\n")
    git(nested, "init", "-q", "-b", "main")
    git(nested, "add", ".")
    git(nested, "commit", "-q", "-m", "nested")


@pytest.mark.parametrize("plant", [_gitdir_file, _nested_repository], ids=["gitdir-file", "repository"])
def test_git_metadata_in_a_lane_never_becomes_a_commit(repo, plant):
    """O-C/O-D: a `.git` in a lane, as a `gitdir:` file naming the host's tenant clone or as
    a nested repository's directory, is refused at derivation or at commit: the worktree's
    tree gains no gitlink (mode 160000), its HEAD does not move, it stays clean, and the
    tenant clone is untouched."""
    batch = delivery(repo, ForgeHTTP()).start_batch("nested", lanes=LANES)
    clone = repo[0].knowledge
    lane = batch.draft_root / "agent/lessons"
    _write(lane / "valid.md", "a valid change beside it\n")
    plant(lane, clone)
    head, clone_head = git(batch.worktree, "rev-parse", "HEAD"), git(clone, "rev-parse", "HEAD")
    with pytest.raises(target().DeliveryRefused):
        batch.commit(batch.change_set(), "nested repository")
    assert git(batch.worktree, "rev-parse", "HEAD") == head
    assert git(batch.worktree, "status", "--porcelain") == ""
    assert "160000" not in git(batch.worktree, "ls-tree", "-r", "HEAD")
    assert git(clone, "rev-parse", "HEAD") == clone_head
    assert git(clone, "status", "--porcelain") == ""


@pytest.mark.parametrize("shape", ["list-of-changes", "tuple-of-changes", "bare-change",
                                   "path-list", "mapping"])
def test_the_commit_maker_takes_nothing_but_a_change_set(repo, shape):
    """O-C: the commit-maker's sole input is a `ChangeSet`; anything else, however close in
    shape, is refused before the worktree changes. A real `ChangeSet` commits (control)."""
    mod = target()
    batch = delivery(repo, ForgeHTTP()).start_batch("only", lanes=LANES)
    change = mod.AgentChange("agent/lessons/x.md", b"x\n")
    not_a_change_set = {"list-of-changes": [change], "tuple-of-changes": (change,),
                        "bare-change": change, "path-list": ["agent/lessons/x.md"],
                        "mapping": {"agent/lessons/x.md": b"x\n"}}[shape]
    head = git(batch.worktree, "rev-parse", "HEAD")
    with pytest.raises((TypeError, mod.DeliveryRefused)):
        batch.commit(not_a_change_set, "not a change set")
    assert git(batch.worktree, "rev-parse", "HEAD") == head
    assert git(batch.worktree, "status", "--porcelain") == ""
    sha = batch.commit(mod.ChangeSet((change,)), "a change set")
    assert _name_status(batch.worktree, sha) == {"agent/lessons/x.md": "A"}


def _mutable_containers(root, depth=4):
    """Every list, dict, set or bytearray reachable from `root` through containers, instance
    attributes and slots, `depth` levels down."""
    found, stack, seen = [], [(root, depth)], set()
    while stack:
        obj, left = stack.pop()
        if id(obj) in seen or isinstance(obj, (str, bytes, int, float, type(None))):
            continue
        seen.add(id(obj))
        if isinstance(obj, (list, dict, set, bytearray)):
            found.append(obj)
        if left == 0:
            continue
        inner = list(obj.values()) if isinstance(obj, dict) else \
            list(obj) if isinstance(obj, (list, tuple, set, frozenset)) else []
        inner += list(getattr(obj, "__dict__", {}).values())
        inner += [getattr(obj, name) for cls in type(obj).__mro__
                  for name in getattr(cls, "__slots__", ()) if hasattr(obj, name)]
        stack.extend((item, left - 1) for item in inner)
    return found


def test_a_change_set_cannot_change_once_built(repo):
    """O-C by construction (design: "immutable"): neither a built `ChangeSet` nor an
    `AgentChange` in it lets an attribute be reassigned, and nothing reachable from a change
    set is a mutable container, so nothing is slipped in after it was checked. Whatever a
    mutation attempt achieves, the commit-maker checks what it is handed: a settings file
    pushed into any mutable container found never reaches a commit."""
    batch = delivery(repo, ForgeHTTP()).start_batch("frozen", lanes=LANES)
    _write(batch.draft_root / "agent/lessons/ok.md", "ok\n")
    built = batch.change_set()
    [change] = list(built)
    reassigned = []
    for obj, name, value in [(change, "path", "settings/rogue.yaml"), (change, "content", b"x\n"),
                             *((built, name, None) for name in getattr(built, "__dict__", {}))]:
        try:
            setattr(obj, name, value)
        except (AttributeError, TypeError):
            continue
        reassigned.append(f"{type(obj).__name__}.{name}")
    mutable = _mutable_containers(built)
    for container in mutable:
        if isinstance(container, list):
            container.append(SimpleNamespace(path="settings/rogue.yaml", content=b"smuggled\n"))
    _, error, _ = bounded(lambda: batch.commit(built, "claim"))
    if error is None:
        assert "settings/rogue.yaml" not in _name_status(batch.worktree, "HEAD")
    assert reassigned == [], "an attribute of a built change set was reassigned"
    assert mutable == [], "a built change set holds a mutable container"
    assert error is None, error
    assert _name_status(batch.worktree, "HEAD") == {"agent/lessons/ok.md": "A"}


@pytest.mark.parametrize(("path", "content"), [
    ("agent/.tenant-id", b"red\n"), ("settings/rogue.yaml", b"x\n"), ("product.py", b"x\n"),
    ("agent/../settings/rogue.yaml", b"x\n"), ("agent/lessons/../.tenant-id", b"red\n"),
    ("/abs/agent/lessons/x.md", b"x\n"), (" agent/lessons/x.md", b"x\n"),
    ("\tagent/lessons/x.md", b"x\n"), ("\nagent/lessons/x.md", b"x\n"),
    ("agent/lessons/.gitattributes", b"* filter=planted\n"),
    ("agent/lessons/deep/.gitignore", b"*\n"), ("agent/.gitmodules", b"[submodule]\n"),
    ("agent/notes.md", b"outside every lane\n"), ("agent/lessons-questioner/x.md", b"x\n"),
    ("agent/AGENT.md", None), ("agent/lessons/x.md", "text, not bytes"),
])
def test_no_change_set_commits_outside_the_lanes_or_touches_a_forbidden_name(repo, path, content):
    """O-C, for change sets not derived from a draft (revert's, P4's connect): a path outside
    `agent/`, outside the batch's lanes, a traversal, a whitespace-led name, `agent/.tenant-id`
    or a git control file at any depth, or content that is not bytes, is refused at
    construction or at commit; the valid change beside it is not committed either."""
    mod = target()
    batch = delivery(repo, ForgeHTTP()).start_batch("bounded", lanes=LANES)
    head = git(batch.worktree, "rev-parse", "HEAD")
    with pytest.raises((mod.DeliveryRefused, ValueError, TypeError)):
        batch.commit(mod.ChangeSet((mod.AgentChange("agent/lessons/ok.md", b"ok\n"),
                                    mod.AgentChange(path, content))), "forbidden")
    assert git(batch.worktree, "rev-parse", "HEAD") == head
    assert git(batch.worktree, "status", "--porcelain") == ""


def test_claims_commit_and_reset_one_after_another_within_one_batch(repo):
    """Flow 3's per-claim loop: change set, commit, reset, several times in one batch, a
    refused claim among them; each commit holds exactly its claim and builds on the last, and
    finish pushes the last one as the batch branch and opens its PR against `main`."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("loop", lanes=LANES)
    lane = batch.draft_root / "agent/lessons"
    wt = batch.worktree
    shas = []

    _write(lane / "a.md", "a, first\n")
    shas.append(batch.commit(batch.change_set(), "claim 1"))
    batch.reset()
    assert files_under(batch.draft_root / "agent") == files_under(wt / "agent")
    assert _changes(batch.change_set()) == {}

    _write(lane / "a.md", "a, second\n")
    (lane / "seed.md").unlink()
    shas.append(batch.commit(batch.change_set(), "claim 2"))
    batch.reset()

    (lane / "link.md").symlink_to("/etc/passwd")
    with pytest.raises(target().DeliveryRefused):
        batch.change_set()
    batch.reset()
    assert _changes(batch.change_set()) == {}

    _write(lane / "b.md", "b\n")
    shas.append(batch.commit(batch.change_set(), "claim 4"))

    assert [git(wt, "rev-parse", f"{sha}^") for sha in shas] == [batch.export.commit, *shas[:2]]
    assert [_name_status(wt, sha) for sha in shas] == [
        {"agent/lessons/a.md": "A"},
        {"agent/lessons/a.md": "M", "agent/lessons/seed.md": "D"},
        {"agent/lessons/b.md": "A"}]
    assert d.finish(batch).endswith("/pulls/7")
    assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == shas[-1]
    assert git(repo[1], "rev-parse", "main") == batch.export.commit
    assert [(c["base"], c["head"]) for c in http.creates] == [("main", batch.branch)]


def test_a_claim_reset_resyncs_the_draft_and_never_follows_box_links(repo, tmp_path):
    """Flow 3: a reset makes the draft byte-equal to the worktree's `agent/` again: box
    additions gone, deletions and edits restored, links and FIFOs removed without following
    them (the host folder a link named keeps its files) and without blocking. A committed
    file the box replaced by a link or a FIFO, and a committed subdirectory it replaced by a
    directory link, come back as regular files with the worktree's bytes."""
    batch = delivery(repo, ForgeHTTP()).start_batch("reset", lanes=LANES)
    lane = batch.draft_root / "agent/lessons"
    for name in ("a.md", "edited.md", "fifo.md", "deep/b.md"):
        _write(lane / name, "committed\n")
    batch.commit(batch.change_set(), "claim")
    outside = tmp_path / "host-folder"
    outside.mkdir()
    (outside / "keep.md").write_text("host\n", encoding="utf-8")
    _write(lane / "edited.md", "changed after the commit\n")
    _write(lane / "stray.md", "stray\n")
    _write(lane / "fresh/stray.md", "stray\n")
    (lane / "seed.md").unlink()
    (lane / "linked").symlink_to(outside, target_is_directory=True)
    os.mkfifo(lane / "pipe")
    _replace(lane / "a.md", lambda e: e.symlink_to(outside / "keep.md"))
    _replace(lane / "fifo.md", os.mkfifo)
    _replace(lane / "deep", lambda e: e.symlink_to(outside, target_is_directory=True))
    _, error, hung = bounded(batch.reset, fifos=[lane / "pipe", lane / "fifo.md"])
    assert not hung, "the reset blocked on box output"
    assert error is None, error
    assert files_under(outside) == {"keep.md": b"host\n"}, "the reset wrote through a link"
    for name in ("a.md", "edited.md", "fifo.md", "deep/b.md"):
        assert plain_file(lane / name, b"committed\n"), name
    assert odd_entries(batch.draft_root) == []
    assert files_under(batch.draft_root / "agent") == files_under(batch.worktree / "agent")


# ---------------------------------------------------------------------------------------
# Push routes: finish, retained deliver, revert send only commit-maker commits
# ---------------------------------------------------------------------------------------

def test_finish_pushes_the_commit_maker_branch_and_opens_its_pr_without_product_write(repo):
    """O7: the commit lands on the tenant remote's batch branch, the PR opens against the
    tenant repo's `main` at the forge's repository API, and neither tenant `main` nor the
    product repository changes. Finish sends the batch branch alone: other branches and tags
    in the clone (a `lessons/` one included) never reach the remote."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    tenant, remote, _ = repo
    product_head = git(DEFENDER, "rev-parse", "HEAD")
    batch = d.start_batch("one", lanes=LANES)
    _write(batch.draft_root / "agent/lessons/new.md", "review me\n")
    sha = batch.commit(batch.change_set(), "learning")
    for rogue in ("refs/heads/lessons/rogue", "refs/heads/rogue", "refs/tags/rogue"):
        plant_raw_commit(tenant.knowledge, rogue, "agent/lessons/rogue.md", b"never sent\n",
                         base=batch.export.commit)
    assert d.finish(batch) == "http://forge.invalid:3000/tenants/blue/pulls/7"
    assert git(remote, "rev-parse", f"refs/heads/{batch.branch}") == sha
    assert git(remote, "for-each-ref", "--format=%(refname)").splitlines() == \
        sorted([f"refs/heads/{batch.branch}", "refs/heads/main"]), "finish sent more than its branch"
    assert git(remote, "rev-parse", "main") == batch.export.commit
    assert [(c["base"], c["head"]) for c in http.creates] == [("main", batch.branch)]
    assert all(r.url.path.startswith("/api/v1/repos/tenants/blue/") for r in http.requests)
    assert git(DEFENDER, "rev-parse", "HEAD") == product_head


@pytest.mark.parametrize("how", ["on-top", "amend", "only-raw", "forbidden-path"])
def test_finish_refuses_a_branch_holding_a_commit_the_commit_maker_did_not_make(repo, how):
    """O-C: a commit laid on the batch branch (the clone's `refs/heads/<batch.branch>`, which
    finish pushes) by anything but the commit-maker refuses the finish before any push: on
    top of a commit-maker commit, amending it, alone, or touching a forbidden path. It is
    written by plumbing, under the last commit's exact message, author and committer, so
    nothing in the commit itself tells it apart, and no worktree or hook is involved. No
    remote branch, no PR."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("foreign", lanes=LANES)
    if how != "only-raw":
        _write(batch.draft_root / "agent/lessons/made.md", "made by the commit-maker\n")
        batch.commit(batch.change_set(), "commit-maker claim")
    path = "settings/rogue.yaml" if how == "forbidden-path" else "agent/lessons/raw.md"
    plant_raw_commit(repo[0].knowledge, f"refs/heads/{batch.branch}", path,
                     b"raw git, not the commit-maker\n", amend=how == "amend",
                     base=batch.export.commit)
    with pytest.raises(target().DeliveryRefused):
        d.finish(batch)
    assert _branches(repo[1]) == ["refs/heads/main"]
    assert not http.creates


def test_a_foreign_commit_beneath_a_later_commit_maker_commit_is_refused(repo):
    """O-C: provenance covers every commit the branch would send, not only its tip. A
    commit-maker claim, then a commit laid on the batch branch by plumbing (the claim's
    message and identities), then another commit-maker claim: the second commit or the
    finish refuses, so a check of the tip alone cannot pass. Nothing reaches the remote and
    no PR is requested."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("sandwich", lanes=LANES)
    lane = batch.draft_root / "agent/lessons"
    _write(lane / "first.md", "first claim\n")
    batch.commit(batch.change_set(), "claim one")
    batch.reset()
    planted = plant_raw_commit(repo[0].knowledge, f"refs/heads/{batch.branch}",
                               "agent/lessons/raw.md", b"raw git, not the commit-maker\n",
                               base=batch.export.commit)
    _write(lane / "second.md", "second claim\n")

    def claim_two_then_finish():
        batch.commit(batch.change_set(), "claim two")
        return d.finish(batch)
    with pytest.raises(target().DeliveryRefused):
        claim_two_then_finish()
    assert _branches(repo[1]) == ["refs/heads/main"]
    assert planted not in git(repo[1], "rev-list", "--all").split()
    assert not http.creates


@pytest.mark.parametrize("planted", [None, "on-top", "amended"])
def test_retained_branch_delivery_pushes_only_commit_maker_commits(repo, planted):
    """O-C on the retained route: finish pushed the branch but PR creation failed; a later
    drain (a new delivery object) delivers the retained branch, opening the PR. A commit laid
    on that branch meanwhile by anything but the commit-maker (its message, author and
    committer copied exactly, an allowed path) refuses the delivery: the remote keeps the
    commit-maker's commit and no PR is requested."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("retained", lanes=LANES)
    _write(batch.draft_root / "agent/lessons/new.md", "retained\n")
    sha = batch.commit(batch.change_set(), "retained")
    http.fail_create = True
    with pytest.raises(target().DeliveryRefused, match="503|forge|PR|pull"):
        d.finish(batch)
    assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == sha
    http.fail_create = False
    posts = len(http.creates)
    if planted is not None:
        plant_raw_commit(repo[0].knowledge, f"refs/heads/{batch.branch}", "agent/lessons/raw.md",
                         b"raw git, not the commit-maker\n", amend=planted == "amended")
    later = target().TenantDelivery.open(repo[0], defender_dir=DEFENDER, client=http.client)
    if planted is None:
        assert later.deliver("retained").endswith("/pulls/7")
        assert len(http.creates) == posts + 1
    else:
        with pytest.raises(target().DeliveryRefused):
            later.deliver("retained")
        assert len(http.creates) == posts
    assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == sha


@pytest.mark.parametrize("planted", [None, "on-top"])
def test_a_later_process_delivers_a_retained_branch_by_the_commit_maker_record(repo, planted):
    """O-C, provenance across processes: finish pushed the branch but its PR request failed;
    a delivery opened in a fresh process (a later drain) delivers the retained branch,
    opening the PR, so the commit-maker's record outlives this process (where it lives is
    not pinned). With a commit laid on the branch by plumbing meanwhile, that later process
    refuses and requests no PR; the remote keeps the commit-maker's commit."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("retained", lanes=LANES)
    _write(batch.draft_root / "agent/lessons/new.md", "retained\n")
    sha = batch.commit(batch.change_set(), "retained")
    http.fail_create = True
    with pytest.raises(target().DeliveryRefused, match="503|forge|PR|pull"):
        d.finish(batch)
    if planted:
        plant_raw_commit(repo[0].knowledge, f"refs/heads/{batch.branch}", "agent/lessons/raw.md",
                         b"raw git, not the commit-maker\n", base=batch.export.commit)
    later = in_a_later_process(repo[0], "deliver", "retained")
    if planted is None:
        assert later.get("url", "").endswith("/pulls/7"), later
        assert [(c["base"], c["head"]) for c in later["creates"]] == [("main", batch.branch)]
    else:
        assert "refused" in later, later
        assert later["creates"] == []
    assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == sha


#: Where the forge's transport fails: `(request) -> fault?` on the route under test.
_TRANSPORT_FAULTS = {
    "protection-read": lambda request: request.url.path.endswith("/branches/main"),
    "pr-listing": lambda request: request.url.path.endswith("/pulls") and request.method == "GET",
    "pr-create": lambda request: request.method == "POST",
}


@pytest.mark.parametrize("where", sorted(_TRANSPORT_FAULTS))
def test_a_forge_transport_fault_is_a_refusal_and_the_branch_is_retained(repo, where):
    """Refusal contract (deck #678): the forge unreachable mid-request (a connection error,
    not an HTTP status) is a `DeliveryRefused`, never an `httpx` exception escaping
    delivery. At `open()` nothing is opened; during finish, the pushed branch is retained
    and a later delivery, the forge back, opens its PR."""
    http = ForgeHTTP()
    matches = _TRANSPORT_FAULTS[where]

    def fault(request):
        return httpx.ConnectError("forge unreachable", request=request) if matches(request) else None
    if where == "protection-read":
        http.fault = fault
        with pytest.raises(target().DeliveryRefused):
            delivery(repo, http)
        return
    d = delivery(repo, http)
    batch = d.start_batch("unreachable", lanes=LANES)
    _write(batch.draft_root / "agent/lessons/new.md", "retained through a fault\n")
    sha = batch.commit(batch.change_set(), "claim")
    http.fault = fault
    with pytest.raises(target().DeliveryRefused):
        d.finish(batch)
    assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == sha
    http.fault = None
    assert delivery(repo, http).deliver("unreachable").endswith("/pulls/7")
    assert {c["head"] for c in http.creates} == {batch.branch}


#: Open PRs that are not this batch's: `(name, row for our branch name)`.
_NOT_OUR_PR = {
    "fork-same-name": lambda branch: pr_row(5, branch, repo=FORK),
    "another-batch": lambda branch: pr_row(5, "lessons/another-batch"),
    "longer-name": lambda branch: pr_row(5, branch + "-2"),
    "shorter-name": lambda branch: pr_row(5, branch[:-1]),
}


@pytest.mark.parametrize("other", sorted(_NOT_OUR_PR))
def test_finish_and_deliver_answer_only_with_the_pr_for_their_own_head(repo, other):
    """O-G through delivery: a PR is this batch's only when its head is exactly the batch's
    branch in this repository. A fork's open PR with our branch name, another batch's open
    `lessons/` PR, and open PRs whose head names extend or truncate ours are not ours, even
    listed first: finish opens our own PR; deliver then returns our open PR, listed after the
    other, without opening another."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("forked", lanes=LANES)
    http.pages = {1: [_NOT_OUR_PR[other](batch.branch)]}
    _write(batch.draft_root / "agent/lessons/new.md", "ours\n")
    batch.commit(batch.change_set(), "ours")
    assert d.finish(batch).endswith("/pulls/7")
    assert [c["head"] for c in http.creates] == [batch.branch]
    http.pages = {1: [_NOT_OUR_PR[other](batch.branch), pr_row(8, batch.branch)]}
    assert d.deliver("forked").endswith("/pulls/8")
    assert len(http.creates) == 1


#: git subcommands that make a commit, and those that send commits to a remote. A merge
#: that may only fast-forward makes none.
_MAKES_COMMITS = {"commit", "commit-tree", "cherry-pick", "revert", "am", "rebase", "merge"}
_SENDS_COMMITS = {"push", "send-pack"}
def _census(events, kinds):
    return {phase for phase, sub, args in events
            if sub in kinds and not (sub == "merge" and "--ff-only" in args)}


def test_only_the_commit_maker_makes_commits_and_only_the_push_routes_push(repo, tmp_path):
    """O-C census, executed at the public boundary (no private name is pinned): every git
    process delivery spawns is recorded under the public call it ran in, across a whole
    drain (publish, batch, box request, claim, reset, finish, retained deliver) and, once a
    human has merged it (unobserved), the revert of its lesson.
    A commit is made only under the commit-maker (`commit`) and the revert; commits are sent
    only by finish, deliver and revert. An audit hook sees every spawn; its positive control
    comes first."""
    http = ForgeHTTP()
    events, phase, active = [], ["control"], [True]

    def audit(event, args):
        if active[0] and event == "subprocess.Popen":
            sub, argv = git_subcommand(args[1])
            if sub is not None:
                events.append((phase[0], sub, argv))

    def under(name, call):
        phase[0] = name
        return call()
    sys.addaudithook(audit)
    try:
        git(repo[0].knowledge, "rev-parse", "HEAD")
        assert [(p, sub) for p, sub, _ in events] == [("control", "rev-parse")], events
        events.clear()
        d = under("open", lambda: delivery(repo, http))
        under("publish", d.publish)
        batch = under("start_batch", lambda: d.start_batch("census", lanes=LANES))
        under("box_request", batch.box_request)
        _write(batch.draft_root / "agent/lessons/census.md", "one claim\n")
        change_set = under("change_set", batch.change_set)
        under("commit", lambda: batch.commit(change_set, "claim"))
        under("reset", batch.reset)
        http.fail_create = True
        with pytest.raises(target().DeliveryRefused):
            under("finish", lambda: d.finish(batch))
        http.fail_create = False
        under("deliver", lambda: d.deliver("census"))
        active[0] = False
        merge_on_remote(repo, tmp_path, batch.branch)
        active[0] = True
        under("revert", lambda: d.revert("agent/lessons/census.md", "census"))
    finally:
        active[0] = False
    assert _census(events, _MAKES_COMMITS) == {"commit", "revert"}, events
    sent = _census(events, _SENDS_COMMITS)
    assert {"finish", "revert"} <= sent <= {"finish", "deliver", "revert"}, events


def _revert_commit(remote, http, main):
    """The one commit the revert's PR offers: its head branch's tip, directly on `main`."""
    [create] = http.creates
    assert create["base"] == "main"
    tip = git(remote, "rev-parse", f"refs/heads/{create['head']}")
    assert git(remote, "rev-parse", f"{tip}^") == main
    assert git(remote, "rev-parse", "main") == main
    return tip


#: A lesson the commit-maker wrote and a human merged, for the revert cases.
_LEARNED = "agent/lessons/learned.md"


def _reverted(repo, lesson, name):
    """Revert `lesson` through a fresh delivery object; returns the revert's one commit on
    the remote (directly on `main`, which does not move)."""
    remote = repo[1]
    http = ForgeHTTP()
    d = delivery(repo, http)
    main = git(remote, "rev-parse", "main")
    assert d.revert(lesson, name).endswith("/pulls/7")
    return _revert_commit(remote, http, main)


def _refused_revert(repo, lesson, name):
    """Revert `lesson`, expecting `DeliveryRefused` with nothing pushed or requested."""
    remote = repo[1]
    http = ForgeHTTP()
    d = delivery(repo, http)
    main, branches = git(remote, "rev-parse", "main"), _branches(remote)
    with pytest.raises(target().DeliveryRefused):
        d.revert(lesson, name)
    assert _branches(remote) == branches
    assert git(remote, "rev-parse", "main") == main
    assert not http.creates


@pytest.mark.parametrize("style", MERGE_STYLES)
def test_revert_deletes_a_lesson_the_commit_maker_created(repo, tmp_path, style):
    """Flow 4, choice 5: a lesson the commit-maker created, merged by a human (merge commit,
    squash or rebase: the style must not matter) and unchanged on `main` since (another file
    changed there meanwhile), reverts to what was there before the agent's change, which is
    nothing: a deletion, as exactly one commit-maker commit on `main`, pushed to its own
    branch with a PR against `main`; `main` itself does not move."""
    merged_agent_lesson(repo, tmp_path, "created", _LEARNED, b"the agent's lesson\n", style)
    advance_remote(repo, tmp_path)
    tip = _reverted(repo, _LEARNED, "learned")
    assert _name_status(repo[1], tip) == {_LEARNED: "D"}


@pytest.mark.parametrize("style", MERGE_STYLES)
def test_revert_restores_what_a_lesson_held_before_the_commit_maker_changed_it(repo, tmp_path, style):
    """Flow 4, choice 5: a lesson the commit-maker changed, merged by a human in any style and
    unchanged on `main` since, reverts to its bytes from just before the agent's change, mode
    100644, as one commit-maker commit on `main` with a PR against `main`."""
    merged_agent_lesson(repo, tmp_path, "changed", "agent/lessons/seed.md",
                        b"seed, as the agent rewrote it\n", style)
    tip = _reverted(repo, "agent/lessons/seed.md", "seed")
    assert _name_status(repo[1], tip) == {"agent/lessons/seed.md": "M"}
    assert git_bytes(repo[1], "cat-file", "blob", f"{tip}:agent/lessons/seed.md") == b"seed\n"
    assert _modes(repo[1], tip, "agent/lessons/seed.md") == {"agent/lessons/seed.md": "100644"}


@pytest.mark.parametrize("history", [(b"first\n", b"second\n"), (b"first\n", b"second\n", b"first\n")],
                         ids=["changed-once", "back-to-the-first-bytes"])
def test_revert_undoes_only_the_latest_of_several_commit_maker_changes(repo, tmp_path, history):
    """Choice 5 (orchestrator ruling): the commit-maker created a lesson, then changed it in
    later batches, all merged. The revert undoes the most recent change whose bytes equal
    `main`'s, restoring the bytes from just before it: the previous batch's, never a
    deletion. When the agent came back to its first bytes, an earlier change matches `main`
    too; the most recent one is undone."""
    for number, words in enumerate(history):
        merged_agent_lesson(repo, tmp_path, f"batch-{number}", _LEARNED, words)
    tip = _reverted(repo, _LEARNED, "learned")
    assert _name_status(repo[1], tip) == {_LEARNED: "M"}
    assert git_bytes(repo[1], "cat-file", "blob", f"{tip}:{_LEARNED}") == history[-2]


def test_revert_undoes_one_lesson_of_a_claim_that_wrote_several(repo, tmp_path):
    """Flow 4 / O-C: a revert is a change set for the one lesson named, made by the
    commit-maker, never an undoing of the agent's whole commit. One claim created two lessons
    and changed the seed, merged; reverting one created lesson deletes it alone, leaving the
    other lesson and the seed as `main` holds them."""
    writer = delivery(repo, ForgeHTTP())
    batch = writer.start_batch("several", lanes=LANES)
    lane = batch.draft_root / "agent/lessons"
    (lane / "learned.md").write_bytes(b"one of the claim's lessons\n")
    (lane / "other.md").write_bytes(b"another of the claim's lessons\n")
    (lane / "seed.md").write_bytes(b"seed, as the same claim rewrote it\n")
    batch.commit(batch.change_set(), "learning several")
    writer.finish(batch)
    merge_on_remote(repo, tmp_path, batch.branch)
    tip = _reverted(repo, _LEARNED, "learned")
    assert _name_status(repo[1], tip) == {_LEARNED: "D"}


def test_revert_ignores_a_later_commit_maker_change_whose_pr_is_still_open(repo, tmp_path):
    """Choice 5 (orchestrator ruling): the change a revert undoes is the most recent
    commit-maker change to the lesson whose resulting bytes equal `main`'s. The commit-maker
    created a lesson (merged), then a later batch changed it and finished, its PR still open.
    That unmerged change does not match `main` and is skipped: the revert undoes the merged
    creation, deleting the lesson."""
    merged_agent_lesson(repo, tmp_path, "created", _LEARNED, b"the agent's merged words\n")
    writer = delivery(repo, ForgeHTTP())
    batch = writer.start_batch("unmerged", lanes=LANES)
    (batch.draft_root / _LEARNED).write_bytes(b"the agent's unmerged words\n")
    batch.commit(batch.change_set(), "learning unmerged")
    assert writer.finish(batch).endswith("/pulls/7")
    tip = _reverted(repo, _LEARNED, "learned")
    assert _name_status(repo[1], tip) == {_LEARNED: "D"}


def test_revert_proceeds_when_main_again_holds_exactly_the_agents_bytes(repo, tmp_path):
    """Choice 5 (orchestrator ruling): the test is content, not history. A human edits the
    agent's lesson on `main` and later restores it to the agent's exact bytes; `main` again
    holds what the commit-maker wrote, so the revert proceeds, restoring the bytes from just
    before the agent's change."""
    agent_bytes = b"seed, as the agent rewrote it\n"
    merged_agent_lesson(repo, tmp_path, "changed", "agent/lessons/seed.md", agent_bytes)
    push_to_remote(repo, tmp_path, lambda c: _write(c / "agent/lessons/seed.md", "a human's edit\n"))
    push_to_remote(repo, tmp_path, lambda c: (c / "agent/lessons/seed.md").write_bytes(agent_bytes))
    tip = _reverted(repo, "agent/lessons/seed.md", "seed")
    assert git_bytes(repo[1], "cat-file", "blob", f"{tip}:agent/lessons/seed.md") == b"seed\n"


def test_revert_recreates_a_lesson_the_commit_maker_deleted(repo, tmp_path):
    """Choice 5 (orchestrator ruling): a merged commit-maker deletion follows the same rule.
    `main`'s state for the lesson (absent) equals that change's result, so the revert
    recreates the bytes from just before it, mode 100644, as one commit-maker commit with a
    PR against `main`."""
    merged_agent_lesson(repo, tmp_path, "deleted", "agent/lessons/seed.md", None)
    tip = _reverted(repo, "agent/lessons/seed.md", "seed")
    assert _name_status(repo[1], tip) == {"agent/lessons/seed.md": "A"}
    assert git_bytes(repo[1], "cat-file", "blob", f"{tip}:agent/lessons/seed.md") == b"seed\n"
    assert _modes(repo[1], tip, "agent/lessons/seed.md") == {"agent/lessons/seed.md": "100644"}


@pytest.mark.parametrize(("path", "edit"), [
    (_LEARNED, b"a human's later edit\n"), ("agent/lessons/seed.md", b"a human's later edit\n"),
    ("agent/lessons/seed.md", b"the human's words\n"),
], ids=["agent-created", "agent-changed", "same-length-edit"])
def test_revert_refuses_a_lesson_changed_on_main_since_the_commit_maker_wrote_it(
        repo, tmp_path, path, edit):
    """Flow 4, choice 5 (user decision): revert proceeds only while `main`'s bytes for the
    lesson equal those of the commit-maker's latest change to it, byte for byte (a human
    edit of the same length is an edit). A human edit on `main` after the merge refuses the
    revert (`DeliveryRefused`): nothing is pushed, no PR is requested, and `main` is
    unchanged."""
    agent_words = b"the agent's words\n"
    assert len(agent_words) == len(b"the human's words\n")
    merged_agent_lesson(repo, tmp_path, "written", path, agent_words)
    push_to_remote(repo, tmp_path, lambda c: (c / path).write_bytes(edit))
    _refused_revert(repo, path, "written")


@pytest.mark.parametrize("path", ["agent/lessons/seed.md", "agent/lessons/merged.md"],
                         ids=["seeded", "human-merged"])
def test_revert_refuses_a_lesson_the_commit_maker_never_wrote(repo, tmp_path, path):
    """Choice 5 (orchestrator ruling): a lesson only humans wrote (the tenant's seed, or one a
    human merged later) has no commit-maker change to undo; its revert is refused with
    nothing pushed or requested."""
    advance_remote(repo, tmp_path)
    _refused_revert(repo, path, "human")


def test_a_later_process_reverts_by_the_commit_maker_record(repo, tmp_path):
    """Choice 5 across processes: the commit-maker changed a lesson here and a human merged
    it; a delivery opened in a fresh process finds that change from the commit-maker's
    record alone and reverts it, restoring the earlier bytes as one commit on `main` with a
    PR against `main`."""
    remote = repo[1]
    merged_agent_lesson(repo, tmp_path, "changed", "agent/lessons/seed.md", b"seed, as the agent rewrote it\n")
    main = git(remote, "rev-parse", "main")
    later = in_a_later_process(repo[0], "revert", "agent/lessons/seed.md", "seed")
    assert later.get("url", "").endswith("/pulls/7"), later
    [create] = later["creates"]
    assert create["base"] == "main"
    tip = git(remote, "rev-parse", f"refs/heads/{create['head']}")
    assert git(remote, "rev-parse", f"{tip}^") == main
    assert git(remote, "rev-parse", "main") == main
    assert _name_status(remote, tip) == {"agent/lessons/seed.md": "M"}
    assert git_bytes(remote, "cat-file", "blob", f"{tip}:agent/lessons/seed.md") == b"seed\n"


def test_a_later_process_refuses_to_revert_a_lesson_changed_on_main(repo, tmp_path):
    """Choice 5 across processes: after a human edit on `main` of the commit-maker's merged
    lesson, a revert from a fresh process refuses with nothing pushed or requested."""
    remote = repo[1]
    merged_agent_lesson(repo, tmp_path, "written", _LEARNED, b"the agent's words\n")
    push_to_remote(repo, tmp_path, lambda c: _write(c / _LEARNED, "a human's later edit\n"))
    main, branches = git(remote, "rev-parse", "main"), _branches(remote)
    later = in_a_later_process(repo[0], "revert", _LEARNED, "written")
    assert "refused" in later, later
    assert later["creates"] == []
    assert _branches(remote) == branches
    assert git(remote, "rev-parse", "main") == main


def test_revert_refuses_a_commit_laid_on_its_branch_by_a_clone_hook(repo, tmp_path):
    """O-C on the revert route: something else lays a commit (the commit-maker's own message
    and identities, an allowed lesson) on the revert's branch right after the commit-maker
    moves it; here that is the clone's `reference-transaction` hook. If the hook ran (its
    marker exists), the revert refuses before any push or PR. An implementation that runs
    git without the clone's hooks (`core.hooksPath`, say) never sees the commit, and its
    revert completes normally instead; the hook-free case is the next test."""
    tenant, remote, _ = repo
    merged_agent_lesson(repo, tmp_path, "learned", _LEARNED, b"the agent's lesson\n")
    http = ForgeHTTP()
    d = delivery(repo, http)
    branches = _branches(remote)
    marker = tmp_path / "planted"
    install_planting_hook(tenant.knowledge, git(remote, "rev-parse", "main"), marker,
                          "agent/lessons/raw.md", b"raw git, not the commit-maker\n")
    _, error, hung = bounded(lambda: d.revert(_LEARNED, "learned"))
    assert not hung
    if marker.exists():
        assert isinstance(error, target().DeliveryRefused), error
        assert _branches(remote) == branches
        assert not http.creates
    else:
        assert error is None, f"the revert refused though nothing was laid on its branch: {error}"
        assert len(http.creates) == 1


def test_a_retried_revert_never_sends_a_commit_laid_on_its_branch(repo, tmp_path):
    """O-C on the revert route, with no hook: a revert pushes its branch, then its PR request
    fails. A commit is then laid by plumbing on that branch in the clone (the revert commit's
    exact message and identities, an allowed lesson). However the retried revert ends (how a
    retry ends is not pinned here), the laid commit never reaches the remote. (An
    implementation that names each revert's branch afresh never meets the laid commit, and
    one that removes the branch when its PR request fails leaves nothing to lay it on; both
    pass vacuously, as the README records.)"""
    tenant, remote, _ = repo
    merged_agent_lesson(repo, tmp_path, "learned", _LEARNED, b"the agent's lesson\n")
    http = ForgeHTTP()
    d = delivery(repo, http)
    before = set(_branches(remote))
    http.fail_create = True
    with pytest.raises(target().DeliveryRefused, match="503|forge|PR|pull"):
        d.revert(_LEARNED, "learned")
    remaining = sorted(set(_branches(remote)) - before)
    if not remaining:
        return  # the failed request left no branch to lay a commit on (choice 16)
    branch = remaining[0]
    made = git(remote, "rev-parse", branch)
    planted = plant_raw_commit(tenant.knowledge, branch, "agent/lessons/raw.md",
                               b"raw git, not the commit-maker\n", base=made)
    http.fail_create = False
    _, _error, hung = bounded(lambda: d.revert(_LEARNED, "learned"))
    assert not hung
    assert planted not in git(remote, "rev-list", "--all").split()


@pytest.mark.parametrize("path", ["agent/.tenant-id", "settings/lead-zero.yaml",
                                  "agent/lessons/absent.md", "agent/lessons/../.tenant-id"])
def test_revert_refuses_a_path_that_is_not_a_lesson_on_main(repo, path):
    """O-C: a revert's change set obeys the same rules: `agent/.tenant-id`, a settings file, a
    traversal, or a lesson absent from `main` that no commit-maker change deleted, is refused,
    with nothing pushed or requested."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    with pytest.raises(target().DeliveryRefused):
        d.revert(path, "x")
    assert _branches(repo[1]) == ["refs/heads/main"]
    assert not http.creates


# ---------------------------------------------------------------------------------------
# Kept: open() refusals (O9), protection (A10), the credential single read (O8), ambient git
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize(("fault", "reason"), [("unversioned", "version|git"), ("local-origin", "network|origin"), ("credentials", "credential"), ("main", "main")])
def test_delivery_refuses_unusable_tenant_with_named_reason(repo, fault, reason):
    tenant, _, credentials = repo
    if fault == "unversioned":
        shutil.rmtree(tenant.knowledge / ".git")
    elif fault == "local-origin":
        git(tenant.knowledge, "remote", "set-url", "origin", "/tmp/local.git")
    elif fault == "credentials":
        credentials.unlink()
    else:
        git(tenant.knowledge, "branch", "-m", "other")
        git(tenant.knowledge, "update-ref", "-d", "refs/remotes/origin/main")
    with pytest.raises(target().DeliveryRefused, match=reason):
        delivery(repo, ForgeHTTP())


@pytest.mark.parametrize("entry", ["https://bot:secret@forge.invalid:3000", "http://bot:secret@other.invalid:3000", "http://bot:secret@forge.invalid:3001"])
def test_credentials_require_scheme_host_and_port_agreement_before_http(repo, entry):
    repo[2].write_text(entry + "\n", encoding="utf-8")
    http = ForgeHTTP()
    with pytest.raises(target().DeliveryRefused, match="credential|origin"):
        delivery(repo, http)
    assert http.requests == []


@pytest.mark.parametrize(("origin", "entry"), [
    ("http://FORGE.Invalid:3000/tenants/blue.git", f"http://bot:{TOKEN}@forge.invalid:3000"),
    ("http://forge.invalid/tenants/blue.git", f"http://bot:{TOKEN}@forge.invalid:80"),
    ("http://forge.invalid:80/tenants/blue.git", f"http://bot:{TOKEN}@forge.invalid"),
])
def test_credentials_agree_with_an_equivalent_spelling_of_the_origin(repo, origin, entry):
    """O-G with O8: agreement compares the one parsed address (host case folded, default port
    explicit), so equivalent spellings agree and the token authenticates the API."""
    tenant, remote, credentials = repo
    git(tenant.knowledge, "remote", "set-url", "origin", origin)
    git(tenant.knowledge, "config", f"url.{remote}.insteadOf", origin)
    credentials.write_text(entry + "\n", encoding="utf-8")
    http = ForgeHTTP()
    delivery(repo, http)
    assert http.requests
    assert all(TOKEN in r.headers.get("Authorization", "") for r in http.requests)


@pytest.mark.parametrize("protection", [{"protected": False, "user_can_push": False}, {"protected": True, "user_can_push": True}, {"protected": True}, {"user_can_push": False}, {"protected": "true", "user_can_push": False}, {"protected": True, "user_can_push": 0},
                                        None, [], "main", 1, True])
def test_main_requires_known_protected_and_bot_cannot_push(repo, protection):
    http = ForgeHTTP()
    http.protection = protection
    with pytest.raises(target().DeliveryRefused, match="protect|push|main"):
        delivery(repo, http)
    assert not http.creates


def test_credentials_loaded_once_and_token_not_in_representation(repo):
    reads = []
    active = [True]
    credential_path = str(repo[2])

    def audit(event, args):
        if not active[0] or event != "open" or not isinstance(args[0], (str, bytes, os.PathLike)):
            return
        if os.fsdecode(args[0]) != credential_path:
            return
        mode, flags = args[1:3]
        if (mode is not None and ("r" in mode or "+" in mode)) or (
            mode is None and flags & os.O_ACCMODE != os.O_WRONLY
        ):
            reads.append(args)
    sys.addaudithook(audit)
    try:
        # Positive control proves this instrumentation detects the actual reader primitive.
        repo[2].read_bytes()
        assert len(reads) == 1
        reads.clear()
        http = ForgeHTTP()
        d = delivery(repo, http)
        repo[2].write_text("http://bot:changed@forge.invalid:3000\n", encoding="utf-8")
        batch = d.start_batch("once", lanes=LANES)
        _write(batch.draft_root / "agent/lessons/new.md", "new")
        batch.commit(batch.change_set(), "new")
        d.finish(batch)
        assert len(http.requests) >= 2
        assert all(TOKEN in r.headers.get("Authorization", "") for r in http.requests)
        assert TOKEN not in repr(d)
        assert TOKEN not in repr(batch)
        assert TOKEN not in json.dumps(batch.box_request().env)
        assert len(reads) == 1, "the credential file has one process-local read for the drain"
    finally:
        active[0] = False


@pytest.mark.parametrize("ambient", ["git-dir", "work-tree", "both"])
def test_delivery_git_context_cannot_be_redirected_by_ambient_repository(repo, tmp_path, monkeypatch, ambient):
    """O7 under amendment 2: inherited `GIT_DIR`/`GIT_WORK_TREE` cannot redirect publish, the
    batch, the commit-maker, finish, retained delivery or, once a human has merged the PR,
    the revert of its lesson into another repository."""
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    git(foreign, "init", "-b", "main")
    (foreign / "foreign-only.md").write_text("another repository\n", encoding="utf-8")
    git(foreign, "add", ".")
    git(foreign, "commit", "-m", "foreign seed")
    foreign_head = git(foreign, "rev-parse", "HEAD")
    expected = git(repo[0].knowledge, "rev-parse", "HEAD")
    http = ForgeHTTP()

    def redirect(env):
        if ambient in {"git-dir", "both"}:
            env.setenv("GIT_DIR", str(foreign / ".git"))
        if ambient in {"work-tree", "both"}:
            env.setenv("GIT_WORK_TREE", str(foreign))
    with monkeypatch.context() as env:
        redirect(env)
        d = delivery(repo, http)
        batch = d.start_batch("ambient", lanes=LANES)
        assert (batch.draft_root / "agent/lessons/seed.md").read_text(encoding="utf-8") == "seed\n"
        assert not (batch.worktree / "foreign-only.md").exists()
        _write(batch.draft_root / "agent/lessons/ambient.md", "tenant authored\n")
        sha = batch.commit(batch.change_set(), "tenant ambient context")
        http.fail_create = True
        with pytest.raises(target().DeliveryRefused, match="503|forge|PR|pull"):
            d.finish(batch)
        http.fail_create = False
        assert d.deliver("ambient").endswith("/pulls/7")
    assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == sha
    assert git(repo[0].knowledge, "rev-parse", f"refs/heads/{batch.branch}") == sha
    assert git(repo[1], "rev-parse", "main") == expected
    merged = merge_on_remote(repo, tmp_path, batch.branch)
    with monkeypatch.context() as env:
        redirect(env)
        assert d.revert("agent/lessons/ambient.md", "ambient").endswith("/pulls/7")
    revert_head = http.creates[-1]["head"]
    tip = git(repo[1], "rev-parse", f"refs/heads/{revert_head}")
    assert git(repo[1], "rev-parse", f"{tip}^") == merged == git(repo[1], "rev-parse", "main")
    assert _name_status(repo[1], tip) == {"agent/lessons/ambient.md": "D"}
    assert git(repo[0].knowledge, "show", f"{sha}:agent/lessons/ambient.md") == "tenant authored"
    assert _name_status(repo[0].knowledge, sha) == {"agent/lessons/ambient.md": "A"}
    assert git(foreign, "rev-parse", "HEAD") == foreign_head
    assert not (foreign / "agent").exists()
    assert _branches(foreign) == ["refs/heads/main"]
