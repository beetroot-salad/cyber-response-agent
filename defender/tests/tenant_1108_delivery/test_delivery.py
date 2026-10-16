"""O7/O7b/O8/O9, amendment 2's O-C/O-D/O-F and amendment 3's C1/C2: real tenant git and HTTP
delivery through the dormant entry seam.

A batch is a branch in the tenant clone plus a git-free `Draft` copy of the export commit's
`agent/` (amendment 3, C2: no batch worktree). A box writes only the draft. Per claim the host
derives a `ChangeSet` (the draft against the blobs of the branch's tip, or of the export commit
before the first claim: regular files in the batch's lanes, nothing else); the commit-maker,
the only maker of tenant commits, writes it as git objects and moves the branch by a
compare-and-swap, never touching `main`, the clone's index or its checkout; a reset re-syncs
the draft. Every push route (finish, retained deliver, revert) sends only commit-maker commits.
Truth comes from `main`'s content and the forge's PRs (C1): a batch's PR is the one whose head
commit is one of the batch's and whose head repository is the base repository, and finish and
deliver answer `open` (with its URL), `merged`, `closed` or `nothing to deliver`."""
from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import stat
import subprocess
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
    NAMESAKE,
    RENAMED,
    SIBLING_FORK,
    TOKEN,
    ForgeHTTP,
    LockHolder,
    advance_remote,
    agent_blobs,
    batch_base,
    bounded,
    branch_tip,
    close_on_remote,
    delivery,
    files_under,
    forge_pulls,
    fresh_process_env,
    git,
    git_bytes,
    git_subcommand,
    in_a_later_process,
    install_planting_hook,
    merge_on_remote,
    merged_agent_lesson,
    odd_entries,
    opened,
    plain_file,
    plant_raw_commit,
    pr_row,
    push_object,
    push_to_remote,
    remote_refs,
    set_pull_state,
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


def _branches(cwd):
    return git(cwd, "for-each-ref", "--format=%(refname)", "refs/heads").splitlines()


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _clone_state(clone):
    """What the commit-maker never touches: the clone's `HEAD`, `main`, index entries and
    status."""
    return (git(clone, "rev-parse", "HEAD"), git(clone, "rev-parse", "refs/heads/main"),
            git(clone, "ls-files", "-s"), git(clone, "status", "--porcelain"))


def _drafts(tenant):
    """The entries of `<T>/drafts/` (none when it does not exist)."""
    folder = tenant.dir / "drafts"
    return sorted(os.listdir(folder)) if folder.exists() else []


def _temps(tenant):
    """The temporary entries of `<T>/drafts/`: a leading dot is outside the batch-id grammar."""
    return [name for name in _drafts(tenant) if name.startswith(".")]


def _worktrees(clone):
    """Every working tree git knows for `clone`, by real path."""
    return [os.path.realpath(line.split(" ", 1)[1])
            for line in git(clone, "worktree", "list", "--porcelain").splitlines()
            if line.startswith("worktree ")]


# ---------------------------------------------------------------------------------------
# The batch: a branch in the clone and a git-free draft of the export commit (C2)
# ---------------------------------------------------------------------------------------

def test_start_batch_makes_a_git_free_draft_of_the_export_commit_and_no_checkout(repo, tmp_path):
    """Flow 3, O7b and C2: the batch starts from a fresh publish, so a human merge on the
    remote reaches the clone, the export and the draft. A batch is a branch in the tenant
    clone plus a draft: no worktree is made (the clone is git's only working tree and nothing
    lies under the layout's worktree base), and the branch does not exist until the first
    commit makes it. The draft at `<T>/drafts/<batch>` holds exactly `agent/`, byte-equal to
    the export commit's `agent/` blobs and to the export, with no `.git` and no link
    anywhere, and no temporary entry is left beside it."""
    tenant = repo[0]
    clone = tenant.knowledge
    expected = advance_remote(repo, tmp_path)
    batch = delivery(repo, ForgeHTTP()).start_batch("fresh", lanes=LANES)
    assert batch.export.commit == expected
    current = target().current_export(tenant)
    assert (current.commit, current.path) == (batch.export.commit, batch.export.path)
    assert git(clone, "rev-parse", "HEAD") == expected
    assert (tenant.agent / "lessons/merged.md").read_text(encoding="utf-8") == "human-reviewed merge\n"

    assert _worktrees(clone) == [os.path.realpath(clone)], "a batch worktree was made"
    assert not tenant.worktrees.exists() or not any(tenant.worktrees.iterdir())
    assert branch_tip(clone, batch.branch) is None, "the batch's branch exists before any commit"
    assert git(clone, "status", "--porcelain") == ""

    assert batch.draft_root == tenant.dir / "drafts" / "fresh"
    assert _drafts(tenant) == ["fresh"], "a temporary entry was left beside the draft"
    assert sorted(p.name for p in batch.draft_root.iterdir()) == ["agent"]
    assert not list(batch.draft_root.rglob(".git"))
    assert odd_entries(batch.draft_root) == []
    assert files_under(batch.draft_root / "agent") == agent_blobs(clone, expected) \
        == files_under(batch.export.path / "agent")
    assert _changes(batch.change_set()) == {}


@pytest.mark.parametrize("state", ["dirty", "untracked", "diverged"])
def test_refresh_refuses_local_state_without_creating_batch(repo, tmp_path, state):
    """O7b: a clone with local edits or a diverged `main` refuses, naming the state; nothing
    is fast-forwarded or published, and no branch, draft or temporary entry is made."""
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
    assert _branches(tenant.knowledge) == ["refs/heads/main"]
    assert _drafts(tenant) == []
    with pytest.raises(target().DeliveryRefused):
        target().current_export(tenant)


def test_publishing_after_a_batch_starts_never_changes_its_draft_or_branch(repo, tmp_path):
    """O-F: a later publish (another drain, or `tenant.py setup`) advances the clone and
    `current`, yet the running batch's draft, its branch and its export stay exactly as they
    were."""
    tenant = repo[0]
    batch = delivery(repo, ForgeHTTP()).start_batch("pinned", lanes=LANES)
    _write(batch.draft_root / "agent/lessons/pinned.md", "claimed before the publish\n")
    sha = batch.commit(batch.change_set(), "claim")
    batch.reset()
    draft = files_under(batch.draft_root)
    export = files_under(batch.export.path)
    newer = advance_remote(repo, tmp_path)
    other = target().TenantDelivery.open(tenant, defender_dir=DEFENDER, client=ForgeHTTP().client)
    assert other.publish().commit == newer
    assert target().current_export(tenant).commit == newer
    assert files_under(batch.draft_root) == draft
    assert branch_tip(tenant.knowledge, batch.branch) == sha
    assert files_under(batch.export.path) == export
    assert _changes(batch.change_set()) == {}


# ---------------------------------------------------------------------------------------
# ChangeSet: the draft against the batch's base, regular files in the lanes, nothing else
# ---------------------------------------------------------------------------------------

def test_change_set_is_the_draft_against_the_batch_base_and_commits_as_plain_files(repo, tmp_path):
    """O-C/O-D: added, changed and deleted regular files in a lane become `AgentChange`s
    (repo-relative path, exact bytes, `None` for a deletion). The commit-maker commits exactly
    them on the export commit, as the batch branch's first commit, each blob as written and
    every mode 100644, even for a file the box left executable or one already executable in
    the base."""
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
    clone = repo[0].knowledge
    assert branch_tip(clone, batch.branch) == sha
    assert git(clone, "rev-parse", f"{sha}^") == batch.export.commit
    assert _name_status(clone, sha) == {"agent/lessons/seed.md": "M", "agent/lessons/merged.md": "D",
                                        "agent/lessons/tool.md": "M", "agent/lessons/deep/new.md": "A",
                                        "agent/lessons/new.md": "A"}
    assert set(_modes(clone, sha, "agent/lessons").values()) == {"100644"}
    for path, content in expected.items():
        if content is not None:
            assert git_bytes(clone, "cat-file", "blob", f"{sha}:{path}") == content


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
    clone = repo[0].knowledge
    if driver is not None:
        git(clone, "config", "filter.p3upper.clean", driver)
    batch = delivery(repo, ForgeHTTP()).start_batch("bytes", lanes=LANES)
    data = b"Line One\r\n$Id: 0123456789abcdef $\r\nlower case, mixed endings\n"
    (batch.draft_root / "agent/lessons/exact.md").write_bytes(data)
    sha = batch.commit(batch.change_set(), "exact bytes")
    assert _name_status(clone, sha) == {"agent/lessons/exact.md": "A"}
    assert git_bytes(clone, "cat-file", "blob", f"{sha}:agent/lessons/exact.md") == data


@pytest.mark.parametrize("attributes", ["*.md text eol=crlf\n", "*.md text eol=crlf ident\n"],
                         ids=["eol", "eol-and-ident"])
def test_claim_after_claim_the_box_sees_exactly_the_committed_bytes(repo, tmp_path, attributes):
    """O-B/O-C across claims (the honest implementer's probe): with `main`'s `.gitattributes`
    converting line endings (and expanding `$Id$`) on checkout, the draft is made, diffed and
    reset from git's bytes, never from a checkout. The draft starts as exactly the export
    commit's `agent/` blobs (and the export). Claim 1 (an LF edit of a base file and a new
    file holding `$Id$`) is exactly the box's changes, committed as the box's bytes; after
    the reset the draft is exactly the committed blobs. Claim 2 with no edit by the box is an
    empty change set (no phantom change from checkout bytes). Claim 3 appends to the new
    file: exactly that change, committed as the box's bytes, and the reset again leaves the
    committed blobs. Reading the draft and the base both from a checkout would hand the box
    CRLF bytes for a file it wrote with LF."""
    def human(checkout):
        _write(checkout / ".gitattributes", attributes)
        (checkout / "agent/lessons/human.md").write_bytes(b"a human's lesson\n")
    push_to_remote(repo, tmp_path, human)
    batch = delivery(repo, ForgeHTTP()).start_batch("crlf", lanes=LANES)
    # Precondition: a checkout here converts (the clone's own checkout of the new lesson).
    assert (repo[0].agent / "lessons/human.md").read_bytes() == b"a human's lesson\r\n"
    agent, clone = batch.draft_root / "agent", repo[0].knowledge
    assert files_under(agent) == agent_blobs(clone, batch.export.commit) == files_under(batch.export.path / "agent")

    claim1 = {"agent/lessons/seed.md": b"seed, revised by the box\n",
              "agent/lessons/new.md": b"$Id$\nwritten by the box with LF\n"}
    for rel, data in claim1.items():
        (batch.draft_root / rel).write_bytes(data)
    change_set = batch.change_set()
    assert _changes(change_set) == claim1
    first = batch.commit(change_set, "claim one")
    assert {f"agent/{rel}": data for rel, data in agent_blobs(clone, first).items() if f"agent/{rel}" in claim1} == claim1
    batch.reset()
    assert files_under(agent) == agent_blobs(clone, first), "the reset handed the box other bytes than committed"

    assert _changes(batch.change_set()) == {}, "a claim with no edit by the box is not empty"

    claim3 = {"agent/lessons/new.md": claim1["agent/lessons/new.md"] + b"and appended\n"}
    (batch.draft_root / "agent/lessons/new.md").write_bytes(claim3["agent/lessons/new.md"])
    change_set = batch.change_set()
    assert _changes(change_set) == claim3
    third = batch.commit(change_set, "claim three")
    assert git(clone, "rev-parse", f"{third}^") == first
    assert agent_blobs(clone, third)["lessons/new.md"] == claim3["agent/lessons/new.md"]
    batch.reset()
    assert files_under(agent) == agent_blobs(clone, third)


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
#: plant(lane, agent, outside, clone)`. A symlinked directory is listed by `os.walk` among
#: `dirnames` and not descended, so a naive derivation skips it silently; `agent/.tenant-id`
#: is also outside every lane. The FIFO and socket rows are planted by the test itself. The
#: `replace-*` rows put the entry where a file (or a subdirectory) of the base already is, so
#: a reset that copies the base's file onto it writes through the link, or blocks on the
#: FIFO, instead of replacing the entry.
_REFUSED_OUTPUT = {
    "file-link-absolute": lambda lane, agent, outside, clone: (lane / "link.md").symlink_to(outside / "secret.md"),
    "file-link-into-clone": lambda lane, agent, outside, clone: (lane / "link.md").symlink_to(
        os.path.relpath(clone / "settings/lead-zero.yaml", lane)),
    "dir-link": lambda lane, agent, outside, clone: (lane / "linked").symlink_to(outside, target_is_directory=True),
    "fifo": lambda lane, agent, outside, clone: os.mkfifo(lane / "pipe.md"),
    "socket": None,
    "device": lambda lane, agent, outside, clone: _mknod(lane),
    "oversized": lambda lane, agent, outside, clone: _oversized(lane),
    "out-of-lane-file": lambda lane, agent, outside, clone: _write(agent / "notes.md", "outside every lane\n"),
    "out-of-lane-deletion": lambda lane, agent, outside, clone: (agent / "AGENT.md").unlink(),
    "lane-prefix-sibling": lambda lane, agent, outside, clone: _write(
        agent / "lessons-questioner/x.md", "a sibling whose name begins with the lane's\n"),
    "tenant-id": lambda lane, agent, outside, clone: _write(agent / ".tenant-id", "red\n"),
    "gitattributes": lambda lane, agent, outside, clone: _write(lane / ".gitattributes", "* filter=planted\n"),
    "gitignore-nested": lambda lane, agent, outside, clone: _write(lane / "deep/.gitignore", "*\n"),
    "gitmodules": lambda lane, agent, outside, clone: _write(lane / ".gitmodules", '[submodule "x"]\n\tpath = x\n'),
    "gitattributes-deletion": lambda lane, agent, outside, clone: (lane / ".gitattributes").unlink(),
    "replace-file-with-link": lambda lane, agent, outside, clone: _replace(
        lane / "seed.md", lambda e: e.symlink_to(outside / "secret.md")),
    "replace-dir-with-link": lambda lane, agent, outside, clone: _replace(
        lane / "deep", lambda e: e.symlink_to(outside, target_is_directory=True)),
    "replace-file-with-fifo": lambda lane, agent, outside, clone: _replace(lane / "seed.md", os.mkfifo),
    "non-utf8-name": lambda lane, agent, outside, clone: _write_bytes_name(lane, b"\xff\xfe.md"),
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
    committed (no branch is made), no link is followed, nothing blocks, and the clone is as it
    was. After a reset the draft equals the base's `agent/` blobs again, every base file back
    as a regular file with git's bytes, and the host folder a link pointed at is intact."""
    if entry in _REFUSED_BASE:
        def base(checkout):
            for rel, text in _REFUSED_BASE[entry].items():
                _write(checkout / rel, text)
        push_to_remote(repo, tmp_path, base)
    clone = repo[0].knowledge
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
        _REFUSED_OUTPUT[entry](lane, agent, outside, clone)
    fifos = [lane / "pipe.md", lane / "seed.md"]
    base, state = batch_base(clone, batch), _clone_state(clone)
    try:
        _, error, hung = bounded(batch.change_set, fifos=fifos)
    finally:
        for listener in sockets:
            listener.close()
    assert not hung, "deriving the change set blocked on box output"
    assert isinstance(error, target().DeliveryRefused), error
    assert branch_tip(clone, batch.branch) is None
    assert _clone_state(clone) == state

    _, error, hung = bounded(batch.reset, fifos=fifos)
    assert not hung, "the reset blocked on box output"
    assert error is None, error
    assert files_under(outside) == {"secret.md": b"host only\n"}, "a reset wrote through a link"
    blobs = agent_blobs(clone, base)
    for rel, data in blobs.items():
        assert plain_file(agent / rel, data), f"the reset left agent/{rel} other than git's blob"
    assert odd_entries(agent) == []
    assert files_under(agent) == blobs
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
    a nested repository's directory, is refused at derivation or at commit: no commit is made
    (the batch's branch does not appear) and the tenant clone is untouched."""
    batch = delivery(repo, ForgeHTTP()).start_batch("nested", lanes=LANES)
    clone = repo[0].knowledge
    lane = batch.draft_root / "agent/lessons"
    _write(lane / "valid.md", "a valid change beside it\n")
    plant(lane, clone)
    state = _clone_state(clone)
    with pytest.raises(target().DeliveryRefused):
        batch.commit(batch.change_set(), "nested repository")
    assert branch_tip(clone, batch.branch) is None
    assert _clone_state(clone) == state


@pytest.mark.parametrize("shape", ["list-of-changes", "tuple-of-changes", "bare-change",
                                   "path-list", "mapping"])
def test_the_commit_maker_takes_nothing_but_a_change_set(repo, shape):
    """O-C: the commit-maker's sole input is a `ChangeSet`; anything else, however close in
    shape, is refused before any branch moves. A real `ChangeSet` commits (control)."""
    mod = target()
    clone = repo[0].knowledge
    batch = delivery(repo, ForgeHTTP()).start_batch("only", lanes=LANES)
    change = mod.AgentChange("agent/lessons/x.md", b"x\n")
    not_a_change_set = {"list-of-changes": [change], "tuple-of-changes": (change,),
                        "bare-change": change, "path-list": ["agent/lessons/x.md"],
                        "mapping": {"agent/lessons/x.md": b"x\n"}}[shape]
    state = _clone_state(clone)
    with pytest.raises((TypeError, mod.DeliveryRefused)):
        batch.commit(not_a_change_set, "not a change set")
    assert branch_tip(clone, batch.branch) is None
    assert _clone_state(clone) == state
    sha = batch.commit(mod.ChangeSet((change,)), "a change set")
    assert _name_status(clone, sha) == {"agent/lessons/x.md": "A"}


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
    clone = repo[0].knowledge
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
    tip = branch_tip(clone, batch.branch)
    if tip is not None:
        assert "settings/rogue.yaml" not in _name_status(clone, tip)
    assert reassigned == [], "an attribute of a built change set was reassigned"
    assert mutable == [], "a built change set holds a mutable container"
    assert error is None, error
    assert _name_status(clone, tip) == {"agent/lessons/ok.md": "A"}


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
    clone = repo[0].knowledge
    batch = delivery(repo, ForgeHTTP()).start_batch("bounded", lanes=LANES)
    state = _clone_state(clone)
    with pytest.raises((mod.DeliveryRefused, ValueError, TypeError)):
        batch.commit(mod.ChangeSet((mod.AgentChange("agent/lessons/ok.md", b"ok\n"),
                                    mod.AgentChange(path, content))), "forbidden")
    assert branch_tip(clone, batch.branch) is None
    assert _clone_state(clone) == state


def test_claims_commit_and_reset_one_after_another_within_one_batch(repo):
    """Flow 3's per-claim loop: change set, commit, reset, several times in one batch, a
    refused claim among them; each commit holds exactly its claim and builds on the last, and
    finish pushes the last one as the batch branch and opens its PR against `main`."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("loop", lanes=LANES)
    lane = batch.draft_root / "agent/lessons"
    clone = repo[0].knowledge
    shas = []

    _write(lane / "a.md", "a, first\n")
    shas.append(batch.commit(batch.change_set(), "claim 1"))
    batch.reset()
    assert files_under(batch.draft_root / "agent") == agent_blobs(clone, shas[0])
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

    assert [git(clone, "rev-parse", f"{sha}^") for sha in shas] == [batch.export.commit, *shas[:2]]
    assert [_name_status(clone, sha) for sha in shas] == [
        {"agent/lessons/a.md": "A"},
        {"agent/lessons/a.md": "M", "agent/lessons/seed.md": "D"},
        {"agent/lessons/b.md": "A"}]
    opened(d.finish(batch))
    assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == shas[-1]
    assert git(repo[1], "rev-parse", "main") == batch.export.commit
    assert [(c["base"], c["head"]) for c in http.creates] == [("main", batch.branch)]


def test_a_claim_reset_resyncs_the_draft_and_never_follows_box_links(repo, tmp_path):
    """Flow 3: a reset makes the draft byte-equal to the branch tip's `agent/` blobs again:
    box additions gone, deletions and edits restored, links and FIFOs removed without
    following them (the host folder a link named keeps its files) and without blocking. A
    committed file the box replaced by a link or a FIFO, and a committed subdirectory it
    replaced by a directory link, come back as regular files with git's bytes."""
    batch = delivery(repo, ForgeHTTP()).start_batch("reset", lanes=LANES)
    lane = batch.draft_root / "agent/lessons"
    for name in ("a.md", "edited.md", "fifo.md", "deep/b.md"):
        _write(lane / name, "committed\n")
    sha = batch.commit(batch.change_set(), "claim")
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
    assert files_under(batch.draft_root / "agent") == agent_blobs(repo[0].knowledge, sha)


# ---------------------------------------------------------------------------------------
# The commit-maker: git objects and a compare-and-swap on its own branch, no lock (C2)
# ---------------------------------------------------------------------------------------

def test_the_first_commit_makes_the_branch_and_never_takes_one_over(repo):
    """C2: the commit-maker moves the batch's branch by compare-and-swap, and the first commit
    expects no branch at all: it creates it. A branch laid under that name before the first
    commit (by plumbing, on the export commit) refuses the commit; it is never built on or
    overwritten, so the laid commit stays the branch's tip. Nothing is pushed or requested."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    clone = repo[0].knowledge
    batch = d.start_batch("taken-over", lanes=LANES)
    laid = plant_raw_commit(clone, f"refs/heads/{batch.branch}", "agent/lessons/raw.md",
                            b"raw git, not the commit-maker\n", base=batch.export.commit)
    _write(batch.draft_root / "agent/lessons/new.md", "the first claim\n")
    with pytest.raises(target().DeliveryRefused):
        batch.commit(batch.change_set(), "the first claim")
    assert branch_tip(clone, batch.branch) == laid
    assert _branches(repo[1]) == ["refs/heads/main"]
    assert not http.creates


def test_the_commit_maker_takes_no_lock_and_leaves_main_the_index_and_the_checkout_alone(
        repo, tmp_path):
    """C2 / O-F (narrowed): the commit-maker writes git objects and moves its own branch by
    compare-and-swap, with no lock (a lock there would fall inside a box window). While
    another process holds the tenant's lock, two claims' change sets, commits and resets all
    succeed, and the clone's `HEAD`, `main`, index entries and status are exactly as before:
    the commit-maker never touches `main`, the clone's index or its checkout."""
    tenant = repo[0]
    clone = tenant.knowledge
    batch = delivery(repo, ForgeHTTP()).start_batch("lockless", lanes=LANES)
    state = _clone_state(clone)
    with LockHolder(tenant, tmp_path / "holder"):
        for number in (1, 2):
            _write(batch.draft_root / f"agent/lessons/claim-{number}.md", f"claim {number}\n")
            (batch.draft_root / "agent/lessons/seed.md").write_bytes(f"seed, claim {number}\n".encode())
            for step in (lambda: batch.commit(batch.change_set(), "claim"), batch.reset):
                _, error, hung = bounded(step)
                assert not hung, "the commit-maker waited on the tenant's lock"
                assert error is None, error
    assert _clone_state(clone) == state
    tip = branch_tip(clone, batch.branch)
    assert git(clone, "rev-parse", f"{tip}^^") == batch.export.commit
    assert agent_blobs(clone, tip)["lessons/seed.md"] == b"seed, claim 2\n"
    assert files_under(batch.draft_root / "agent") == agent_blobs(clone, tip)


# ---------------------------------------------------------------------------------------
# The draft's lifecycle: built under the lock, renamed into place, never retried (C2, R3)
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("left", ["draft", "branch"])
def test_start_batch_refuses_an_id_whose_draft_or_branch_exists(repo, left):
    """C2: `start_batch` refuses at once, before any box could run, an id whose draft is still
    there (a batch never discarded) or whose branch exists in the clone (its draft discarded,
    its commits deliver's to pick up), from the same delivery object or another. The draft,
    the branch and the drafts folder are left as they were."""
    tenant = repo[0]
    clone = tenant.knowledge
    d = delivery(repo, ForgeHTTP())
    batch = d.start_batch("taken", lanes=LANES)
    if left == "branch":
        _write(batch.draft_root / "agent/lessons/new.md", "committed\n")
        batch.commit(batch.change_set(), "claim")
        batch.discard()
    tip, drafts = branch_tip(clone, batch.branch), _drafts(tenant)
    draft = files_under(batch.draft_root) if left == "draft" else None
    for again in (d, delivery(repo, ForgeHTTP())):
        with pytest.raises(target().DeliveryRefused):
            again.start_batch("taken", lanes=LANES)
    assert branch_tip(clone, batch.branch) == tip
    assert _drafts(tenant) == drafts
    if draft is not None:
        assert files_under(batch.draft_root) == draft


def test_discard_removes_the_draft_and_deliver_picks_up_the_branch(repo):
    """C2: `Batch.discard()` removes the draft and leaves no temporary entry; the branch and
    its commits stay, and a branch with commits is deliver's to pick up: a later delivery
    object pushes it and opens its PR."""
    tenant = repo[0]
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("discarded", lanes=LANES)
    _write(batch.draft_root / "agent/lessons/new.md", "committed, then discarded\n")
    sha = batch.commit(batch.change_set(), "claim")
    batch.discard()
    assert not os.path.lexists(batch.draft_root)
    assert _drafts(tenant) == []
    assert branch_tip(tenant.knowledge, batch.branch) == sha
    opened(delivery(repo, http).deliver("discarded"))
    assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == sha


@pytest.mark.parametrize("by", ["publish", "start_batch"])
def test_stale_draft_temporaries_are_swept_and_drafts_are_kept(repo, by):
    """C2: a leading dot is outside the batch-id grammar, so `<T>/drafts/.<anything>` is a
    temporary of a build that never finished. The next publish, or batch start, sweeps every
    one (a folder holding a part-built draft, an empty folder) and keeps every draft."""
    tenant = repo[0]
    d = delivery(repo, ForgeHTTP())
    kept = d.start_batch("kept", lanes=LANES)
    drafts = tenant.dir / "drafts"
    _write(drafts / ".killed-1a2b3c/agent/lessons/seed.md", "a part-built draft\n")
    (drafts / ".empty-4d5e6f").mkdir()
    draft = files_under(kept.draft_root)
    if by == "publish":
        d.publish()
    else:
        d.start_batch("next", lanes=LANES)
    assert _temps(tenant) == [], "a stale temporary was left in drafts/"
    assert _drafts(tenant) == sorted(["kept", *(["next"] if by == "start_batch" else [])])
    assert files_under(kept.draft_root) == draft


_BUILD = """
import json, os, resource, signal, sys
from pathlib import Path
from defender.tests import _tenants1106 as tenants
from defender.tests.tenant_1108_delivery._support import (
    DEFENDER, LANES, ForgeHTTP, configured_origin, target)
root, tenant_id, remote, batch_id, cap, mode = (Path(sys.argv[1]), sys.argv[2], sys.argv[3],
                                                sys.argv[4], int(sys.argv[5]), sys.argv[6])
mod = target()
tenant = tenants.accept(root, tenant_id)
http = ForgeHTTP(remote=remote, origin=configured_origin(tenant.knowledge))
d = mod.TenantDelivery.open(tenant, defender_dir=DEFENDER, client=http.client)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
if mode == "crash":
    d.start_batch(batch_id, lanes=LANES)
    os.kill(os.getpid(), signal.SIGKILL)
drafts = os.path.realpath(tenant.dir / "drafts")
# "fail": a write past the cap fails (EFBIG) and the build fails inside this process;
# "kill": it kills the process (SIGXFSZ), as SIGKILL or a power cut would.
signal.signal(signal.SIGXFSZ, signal.SIG_IGN if mode == "fail" else signal.SIG_DFL)
SPAWNS = ("subprocess.Popen", "os.posix_spawn", "os.exec", "os.spawn")
armed = []

def at(path, dir_fd):
    name = os.fsdecode(path)
    if dir_fd is None or dir_fd < 0 or os.path.isabs(name):
        return os.path.abspath(name)
    return os.path.join(os.readlink(f"/proc/self/fd/{dir_fd}"), name)

def in_drafts(path):
    return path == drafts or path.startswith(drafts + os.sep)

def cut_off(event, args):
    # From the first folder made, file opened for writing, or program started for the drafts
    # folder on, every file write is capped at `cap` bytes; only the big lesson is over it.
    # Nothing here raises into the code under test.
    try:
        if armed:
            return
        if event == "os.mkdir":
            hit = in_drafts(at(args[0], args[2]))
        elif event == "open":
            hit = bool(args[2]) and bool(args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT)) \\
                and isinstance(args[0], (str, bytes, os.PathLike)) and in_drafts(at(args[0], None))
        elif event in SPAWNS:
            hit = drafts in repr(args)
        else:
            return
        if hit:
            resource.setrlimit(resource.RLIMIT_FSIZE, (cap, resource.getrlimit(resource.RLIMIT_FSIZE)[1]))
            armed.append(event)
    except Exception:
        return
sys.addaudithook(cut_off)
try:
    batch = d.start_batch(batch_id, lanes=LANES)
    print(json.dumps({"started": str(batch.draft_root), "armed": armed}))
except Exception as failed:
    print(json.dumps({"failed": repr(failed), "armed": armed}))
"""

#: A lesson well over the cap (every other file a draft holds is far under it).
_BIG_LESSON = b"a lesson too big for the cap\n" * 8192
_CAP = 64 * 1024


def _build_elsewhere(repo, tmp_path, batch_id, mode):
    """`start_batch(batch_id)` in a freshly started process: `fail` caps file writes once the
    build begins under `drafts/` so the big lesson's write fails there; `kill` makes it kill
    the process instead; `crash` kills the process right after `start_batch` returned."""
    tenant = repo[0]
    proc = subprocess.run([sys.executable, "-c", _BUILD, str(tenant.data_root), str(tenant.id),
                           str(repo[1]), batch_id, str(_CAP), mode], capture_output=True,
                          text=True, timeout=300, check=False,
                          env=fresh_process_env(tenant, tmp_path / f"build-{mode}"))
    lines = proc.stdout.strip().splitlines()
    return proc.returncode, json.loads(lines[-1]) if lines else {}, proc.stderr


def _publish_big_lesson(repo, tmp_path, d):
    """A human merge of the big lesson, published here: a later build copies it into its
    draft, and no later publish writes it again."""
    push_to_remote(repo, tmp_path, lambda c: (c / "agent/lessons/big.md").write_bytes(_BIG_LESSON))
    export = d.publish()
    assert (export.path / "agent/lessons/big.md").read_bytes() == _BIG_LESSON
    return export


def test_a_draft_build_that_fails_leaves_nothing_and_its_id_can_be_retried(repo, tmp_path):
    """R3: the draft is built under the lock in `<T>/drafts/.<id>-<rand>` and renamed into
    place. A build that fails inside its own process (in another process here: once the build
    has begun under `drafts/`, the write of the one lesson over a file-size cap fails with
    EFBIG) leaves no draft, no temporary entry and no branch, and a retry of that id succeeds,
    its draft exactly the export's `agent/`."""
    tenant = repo[0]
    d = delivery(repo, ForgeHTTP())
    export = _publish_big_lesson(repo, tmp_path, d)
    code, out, err = _build_elsewhere(repo, tmp_path, "retried", "fail")
    assert code == 0, err
    assert out.get("armed"), f"the build never began under drafts/: {out} {err}"
    assert "failed" in out, f"the build was never cut off: {out}"
    assert _drafts(tenant) == [], "a failed build left its draft or its temporary"
    assert _branches(tenant.knowledge) == ["refs/heads/main"]
    batch = d.start_batch("retried", lanes=LANES)
    assert files_under(batch.draft_root / "agent") == files_under(export.path / "agent")


@pytest.mark.parametrize("by", ["publish", "start_batch"])
def test_a_killed_draft_build_leaves_only_a_temporary_the_next_publish_or_start_sweeps(
        repo, tmp_path, by):
    """R3: a build killed mid-write (the write of the lesson over a file-size cap kills its
    process, as SIGKILL or a power cut would) leaves no `drafts/<id>`, only temporary entries,
    and no lock in the way: the next publish, or the next batch start, sweeps them."""
    tenant = repo[0]
    d = delivery(repo, ForgeHTTP())
    _publish_big_lesson(repo, tmp_path, d)
    code, out, err = _build_elsewhere(repo, tmp_path, "killed", "kill")
    assert code == -signal.SIGXFSZ or "failed" in out, \
        f"the build was never cut off: {code} {out} {err}"
    assert _drafts(tenant) == _temps(tenant), "a killed build left a draft in place"
    if by == "publish":
        d.publish()
    else:
        d.start_batch("next", lanes=LANES)
    assert _temps(tenant) == [], "the killed build's temporary was never swept"
    assert _drafts(tenant) == ([] if by == "publish" else ["next"])


def test_a_crash_after_the_draft_exists_leaves_its_id_refused_for_good(repo, tmp_path):
    """R3: batch ids are never retried. A process killed right after `start_batch` returned
    leaves a complete draft; every later `start_batch` of that id refuses (a publish between
    attempts changes nothing), and the draft stays as it was. Another id starts."""
    tenant = repo[0]
    code, out, err = _build_elsewhere(repo, tmp_path, "crashed", "crash")
    assert code == -signal.SIGKILL, f"{code} {out} {err}"
    draft = files_under(tenant.dir / "drafts" / "crashed")
    assert "agent/lessons/seed.md" in draft, draft
    d = delivery(repo, ForgeHTTP())
    for _ in range(2):
        with pytest.raises(target().DeliveryRefused):
            d.start_batch("crashed", lanes=LANES)
        d.publish()
    assert files_under(tenant.dir / "drafts" / "crashed") == draft
    assert d.start_batch("other", lanes=LANES).draft_root == tenant.dir / "drafts" / "other"




# ---------------------------------------------------------------------------------------
# Push routes: finish, retained deliver, revert send only commit-maker commits
# ---------------------------------------------------------------------------------------

def test_finish_pushes_the_commit_maker_branch_and_opens_its_pr_without_product_write(repo):
    """O7: the commit lands on the tenant remote's batch branch, the PR opens against the
    tenant repo's `main` at the forge's repository API, and neither tenant `main` nor the
    product repository changes. Finish sends the batch branch alone: other branches and tags
    in the clone (a `lessons/` one included) never reach the remote. Every request goes to
    our repository's API at the origin's address."""
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
    assert opened(d.finish(batch)) == "http://forge.invalid:3000/tenants/blue/pulls/7"
    assert git(remote, "rev-parse", f"refs/heads/{batch.branch}") == sha
    assert [line.split()[0] for line in remote_refs(remote)] == \
        sorted([f"refs/heads/{batch.branch}", "refs/heads/main"]), "finish sent more than its branch"
    assert git(remote, "rev-parse", "main") == batch.export.commit
    assert [(c["base"], c["head"]) for c in http.creates] == [("main", batch.branch)]
    api = "/api/v1/repos/tenants/blue"
    assert all(r.url.path == api or r.url.path.startswith(api + "/") for r in http.requests)
    assert http.foreign == []
    assert git(DEFENDER, "rev-parse", "HEAD") == product_head


@pytest.mark.parametrize("how", ["on-top", "amend", "only-raw", "forbidden-path"])
def test_finish_refuses_a_branch_holding_a_commit_the_commit_maker_did_not_make(repo, how):
    """O-C: a commit laid on the batch branch (the clone's `refs/heads/<batch.branch>`, which
    finish pushes) by anything but the commit-maker refuses the finish before any push: on
    top of a commit-maker commit, amending it, alone, or touching a forbidden path. It is
    written by plumbing, under the last commit's exact message, author and committer, so
    nothing in the commit itself tells it apart, and no hook is involved. No remote branch,
    no PR."""
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
        opened(later.deliver("retained"))
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
    later = in_a_later_process(repo, "deliver", "retained")
    if planted is None:
        assert later.get("status") == "open", later
        assert later["url"].endswith("/pulls/7"), later
        assert [(c["base"], c["head"]) for c in later["creates"]] == [("main", batch.branch)]
    else:
        assert "refused" in later, later
        assert later["creates"] == []
    assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == sha


def _lay_pr(repo, http, row):
    """Add `row` to the forge, its head commit first put on the remote under
    `refs/pull/N/head`, where the forge holds every PR's head (a fork's included)."""
    push_object(repo, row["head"]["sha"], f"refs/pull/{row['number']}/head")
    return http.add_pr(row)


#: Where the forge's transport fails: `(request) -> fault?` on the route under test.
_TRANSPORT_FAULTS = {
    "protection-read": lambda request: request.url.path.endswith("/branches/main"),
    "pr-lookup": lambda request: request.method == "GET" and "/pulls" in request.url.path,
    "pr-create": lambda request: request.method == "POST",
}


@pytest.mark.parametrize("where", sorted(_TRANSPORT_FAULTS))
def test_a_forge_transport_fault_is_a_refusal_and_a_later_deliver_opens_the_pr(repo, where):
    """Refusal contract (deck #678): the forge unreachable mid-request (a connection error,
    not an HTTP status) is a `DeliveryRefused`, never an `httpx` exception escaping delivery.
    At `open()` nothing is opened. Finish looks the batch's PR up before any push (C1), so a
    fault in the lookup (a listing, or one PR read) pushes nothing and requests nothing; a
    fault in the PR request leaves the pushed branch. Either way a later deliver, the forge
    back, pushes and opens the PR. The lookup has something to read: the remote holds the
    batch's commit as a fork PR's head (`refs/pull/5/head`, PR 5), which is not ours."""
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
    _write(batch.draft_root / "agent/lessons/new.md", "delivered through a fault\n")
    sha = batch.commit(batch.change_set(), "claim")
    _lay_pr(repo, http, pr_row(5, batch.branch, repo=FORK, sha=sha))
    http.fault = fault
    with pytest.raises(target().DeliveryRefused):
        d.finish(batch)
    assert any(matches(r) for r in http.requests), "the faulted request was never made"
    if where == "pr-lookup":
        assert _branches(repo[1]) == ["refs/heads/main"], "finish pushed before its lookup"
        assert not http.creates
    else:
        assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == sha
    http.fault = None
    opened(delivery(repo, http).deliver("unreachable"))
    assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == sha
    assert [row["number"] for row in forge_pulls(repo[1]) if row["head"].get("repo_id") == 11] == [7]


#: PR rows that are not this batch's, `(branch, our commit, another commit) -> row`: our
#: commit at the head of a fork, of a sibling fork, of a namesake (our full name, another
#: repository id), of a row with no head repository (a deleted fork: D-fork); our branch name
#: in our repository at another commit, merged or closed; another batch's open PR.
_NOT_OUR_PR = {
    "fork-at-our-commit": lambda branch, ours, other: pr_row(5, branch, repo=FORK, sha=ours),
    "sibling-fork-at-our-commit": lambda branch, ours, other: pr_row(5, branch, repo=SIBLING_FORK, sha=ours),
    "namesake-at-our-commit": lambda branch, ours, other: pr_row(5, branch, repo=NAMESAKE, sha=ours),
    "no-head-repository-at-our-commit": lambda branch, ours, other: pr_row(5, branch, repo=None, sha=ours),
    "our-name-merged-at-another-commit": lambda branch, ours, other: pr_row(5, branch, sha=other, merged=True),
    "our-name-closed-at-another-commit": lambda branch, ours, other: pr_row(5, branch, sha=other, state="closed"),
    "another-batch-open": lambda branch, ours, other: pr_row(5, "lessons/another-batch", sha=other),
}


@pytest.mark.parametrize("other", sorted(_NOT_OUR_PR))
def test_finish_and_deliver_answer_only_with_the_pr_for_their_own_head(repo, other):
    """C1 / O-G through delivery: a PR is this batch's only when its head commit is one of the
    batch's commit-maker commits and its head repository id is the base repository's (from
    `GET /repos/{o}/{r}`); the branch name and the full name play no part. Each row here,
    listed and held under `refs/pull/5/head` before ours exists, is not ours: finish pushes
    and opens our own PR (7), and deliver then answers it, open, without opening another."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("forked", lanes=LANES)
    _write(batch.draft_root / "agent/lessons/new.md", "ours\n")
    sha = batch.commit(batch.change_set(), "ours")
    _lay_pr(repo, http, _NOT_OUR_PR[other](batch.branch, sha, batch.export.commit))
    opened(d.finish(batch))
    assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == sha
    assert [c["head"] for c in http.creates] == [batch.branch]
    opened(d.deliver("forked"))
    assert len(http.creates) == 1


def _branch_deleted(row):
    """`row` as Forgejo 15 lists a PR whose head branch was deleted: `head.ref`
    `refs/pull/N/head`, no label, `head.sha` kept."""
    row["head"].update(ref=f"refs/pull/{row['number']}/head", label="")
    return row


#: Rows that ARE this batch's PR, `(branch, the batch's commits) -> row`, and the status they
#: give: under a renamed repository (another full name, the same id) and another branch name;
#: merged with its branch deleted; merged or closed at the batch's earlier commit.
_OUR_PR = {
    "renamed-repository-open": (
        lambda branch, shas: pr_row(5, "lessons/elsewhere", repo=RENAMED, sha=shas[-1]), "open"),
    "branch-deleted-merged": (
        lambda branch, shas: _branch_deleted(pr_row(5, branch, sha=shas[-1], merged=True)), "merged"),
    "earlier-commit-merged": (lambda branch, shas: pr_row(5, branch, sha=shas[0], merged=True), "merged"),
    "earlier-commit-closed": (lambda branch, shas: pr_row(5, branch, sha=shas[0], state="closed"), "closed"),
}


@pytest.mark.parametrize("row", sorted(_OUR_PR))
def test_the_batchs_pr_is_known_by_its_head_commit_and_repository_id(repo, row):
    """C1 / D-closed: the batch's PR is the row whose head commit is one of the batch's
    commit-maker commits (its last or an earlier one) and whose head repository id is the
    base's, whatever its branch name or the repository's full name, and also as Forgejo lists
    a merged PR whose branch was deleted. Finish and deliver answer that PR's status (`open`
    with its URL, `merged`, `closed`); having had a PR, the batch is pushed nowhere and no PR
    is opened."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("known", lanes=LANES)
    shas = []
    for number in (1, 2):
        _write(batch.draft_root / f"agent/lessons/claim-{number}.md", "claimed\n")
        shas.append(batch.commit(batch.change_set(), f"claim {number}"))
        batch.reset()
    make, status = _OUR_PR[row]
    _lay_pr(repo, http, make(batch.branch, shas))
    for result in (d.finish(batch), d.deliver("known")):
        assert result.status == status, result
        if status == "open":
            assert result.url.endswith("/pulls/5"), result.url
    assert _branches(repo[1]) == ["refs/heads/main"], "a batch the forge already had a PR for was pushed"
    assert not http.creates


# ---------------------------------------------------------------------------------------
# Statuses: finish and deliver answer from the forge's PR, looked up before any push (R2)
# ---------------------------------------------------------------------------------------

def test_finishing_twice_answers_the_one_open_pr(repo):
    """C1 / D-closed: once the forge has a PR for the batch, a retry pushes nothing and opens
    nothing: a second finish, and a deliver, answer `open` with the same URL; one PR request
    in all, the remote's refs as the first finish left them."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("twice", lanes=LANES)
    _write(batch.draft_root / "agent/lessons/new.md", "finished twice\n")
    batch.commit(batch.change_set(), "claim")
    url = opened(d.finish(batch))
    refs = remote_refs(repo[1])
    assert opened(d.finish(batch)) == url
    assert opened(d.deliver("twice")) == url
    assert len(http.creates) == 1
    assert remote_refs(repo[1]) == refs


def test_a_batch_with_no_commit_has_nothing_to_deliver(repo):
    """C1: a batch whose branch holds no commit-maker commit past its base (here no claim was
    committed, so it has no branch at all) answers `nothing to deliver`; nothing is pushed
    and no PR is requested."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("idle", lanes=LANES)
    assert d.finish(batch).status == "nothing to deliver"
    assert _branches(repo[1]) == ["refs/heads/main"]
    assert not http.creates


@pytest.mark.parametrize("delete_branch", [False, True], ids=["branch-kept", "branch-deleted"])
@pytest.mark.parametrize("style", MERGE_STYLES)
def test_a_merged_batch_answers_merged_and_is_never_delivered_again(repo, tmp_path, style, delete_branch):
    """R2 (D-closed): once a human has merged the batch's PR (merge commit, squash or rebase;
    its branch deleted or kept), finish and deliver, in this process or a later one, answer
    `merged`: nothing is pushed (a deleted branch is not pushed again) and no PR is opened.
    After a merge commit `main` holds the batch's commits, so history alone would say there
    is nothing to deliver; after a squash or a rebase it holds none of them, so history alone
    would push again and open a second PR."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("merged", lanes=LANES)
    _write(batch.draft_root / "agent/lessons/new.md", "merged by a human\n")
    batch.commit(batch.change_set(), "claim")
    opened(d.finish(batch))
    merge_on_remote(repo, tmp_path, batch.branch, style, delete_branch=delete_branch)
    refs = remote_refs(repo[1])
    assert d.finish(batch).status == "merged"
    assert d.deliver("merged").status == "merged"
    later = in_a_later_process(repo, "deliver", "merged")
    assert later.get("status") == "merged", later
    assert later["creates"] == []
    assert len(http.creates) == 1
    assert remote_refs(repo[1]) == refs


@pytest.mark.parametrize("delete_branch", [False, True], ids=["branch-kept", "branch-deleted"])
def test_a_closed_batch_answers_closed_and_is_never_delivered_again(repo, delete_branch):
    """R2 (D-closed): a PR closed unmerged is a rejection. Finish and deliver, in this
    process or a later one, answer `closed`: nothing is pushed (a deleted branch is not
    pushed again) and no PR is opened."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("closed", lanes=LANES)
    _write(batch.draft_root / "agent/lessons/new.md", "rejected by a human\n")
    batch.commit(batch.change_set(), "claim")
    opened(d.finish(batch))
    set_pull_state(repo[1], batch.branch, merged=False, delete_branch=delete_branch)
    refs = remote_refs(repo[1])
    assert d.finish(batch).status == "closed"
    assert d.deliver("closed").status == "closed"
    later = in_a_later_process(repo, "deliver", "closed")
    assert later.get("status") == "closed", later
    assert later["creates"] == []
    assert len(http.creates) == 1
    assert remote_refs(repo[1]) == refs


def test_a_reused_batch_id_is_not_mistaken_for_its_old_pr(repo, tmp_path):
    """R2: a batch id used again, once its draft is discarded and its local branch gone, while
    its old branch remains on the remote and its old PR is merged: the new batch's finish is
    never answered with the old PR (merged, closed, or its URL). Provenance rows carry their
    batch's base, so the old commit is not the new batch's. (Whether that finish pushes and
    opens a PR, or refuses, is not pinned.)"""
    http = ForgeHTTP()
    d = delivery(repo, http)
    clone = repo[0].knowledge
    old = d.start_batch("reused", lanes=LANES)
    _write(old.draft_root / "agent/lessons/old.md", "the first use of the id\n")
    old.commit(old.change_set(), "claim")
    old_url = opened(d.finish(old))
    merge_on_remote(repo, tmp_path, old.branch)
    old.discard()
    git(clone, "update-ref", "-d", f"refs/heads/{old.branch}")
    new = d.start_batch("reused", lanes=LANES)
    _write(new.draft_root / "agent/lessons/new.md", "the second use of the id\n")
    new.commit(new.change_set(), "claim")
    result, error, hung = bounded(lambda: d.finish(new))
    assert not hung
    if not isinstance(error, target().DeliveryRefused):
        assert error is None, error
        assert result.status == "open", result
        assert result.url != old_url, "the new batch was answered with its old PR"




#: git subcommands that make a commit, and those that send commits to a remote. A merge
#: that may only fast-forward makes none.
_MAKES_COMMITS = {"commit", "commit-tree", "cherry-pick", "revert", "am", "rebase", "merge"}
_SENDS_COMMITS = {"push", "send-pack"}
#: git subcommands that write a checkout (or the clone's own index along with it). The
#: fast-forward, a merge that may only fast-forward, is the one checkout left (C2).
_TOUCHES_CHECKOUT = {"checkout", "switch", "restore", "checkout-index", "reset", "stash", "clean",
                     "merge", "pull", "rebase", "cherry-pick", "revert", "worktree"}


def _census(events, kinds):
    return {phase for phase, sub, args in events
            if sub in kinds and not (sub == "merge" and "--ff-only" in args)}


def _checkouts(events):
    return {phase for phase, sub, args in events
            if sub in _TOUCHES_CHECKOUT or (sub == "read-tree" and {"-u", "--reset"} & set(args))}


def test_only_the_commit_maker_makes_commits_and_only_the_push_routes_push(repo, tmp_path):
    """O-C census, executed at the public boundary (no private name is pinned): every git
    process delivery spawns is recorded under the public call it ran in, across a whole
    drain (publish, batch, box request, claim, reset, finish, retained deliver) and, once a
    human has merged it (unobserved), the revert of its lesson.
    A commit is made only under the commit-maker (`commit`) and the revert; commits are sent
    only by finish, deliver and revert. C2: no `git worktree` runs at all, and a checkout is
    written only by the fast-forward (publish, start_batch, and a revert that publishes):
    never by a claim, a reset, finish or deliver. An audit hook sees every spawn; its
    positive control comes first."""
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
    assert not [e for e in events if e[1] == "worktree"], "a git worktree was made or listed"
    assert _checkouts(events) <= {"publish", "start_batch", "revert"}, events


# ---------------------------------------------------------------------------------------
# Revert: the newest agent change `main` still holds, peeled back one at a time (C1, R1, R9)
# ---------------------------------------------------------------------------------------

def _revert_commit(remote, http, main, url):
    """The one commit the revert's PR offers: its head branch's tip, directly on `main`, which
    does not move. `url` must be that PR's (the open row the revert's one request made)."""
    [create] = http.creates
    assert create["base"] == "main"
    rows = [row for row in forge_pulls(remote) if row["state"] == "open" and row["head"]["ref"] == create["head"]]
    assert [row["html_url"] for row in rows] == [url], (url, rows)
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
    return _revert_commit(remote, http, main, d.revert(lesson, name))


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


def _on_main(repo, path):
    """The bytes the remote's `main` holds at `path`, or `None` when it holds none."""
    if not git(repo[1], "ls-tree", "--name-only", "main", "--", path):
        return None
    return git_bytes(repo[1], "cat-file", "blob", f"main:{path}")


def _revert_and_merge(repo, tmp_path, lesson, name, style):
    """Revert `lesson`, then merge the revert's PR as a human would in `style` (its branch
    deleted after a squash or a rebase, kept after a merge commit). Returns what `main` then
    holds for the lesson."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    _revert_commit(repo[1], http, git(repo[1], "rev-parse", "main"), d.revert(lesson, name))
    merge_on_remote(repo, tmp_path, http.creates[-1]["head"], style, delete_branch=style != "merge")
    return _on_main(repo, lesson)


_FIRST, _SECOND = b"the agent's first words\n", b"the agent's second words\n"


def _agent_wrote(repo, tmp_path, *history):
    """The commit-maker wrote `_LEARNED` once per entry of `history`, each batch merged."""
    for number, words in enumerate(history):
        merged_agent_lesson(repo, tmp_path, f"batch-{number}", _LEARNED, words)


@pytest.mark.parametrize("style", MERGE_STYLES)
def test_revert_peels_back_through_the_agents_changes_to_none_left(repo, tmp_path, style):
    """R1 (D-peel): each revert undoes the newest agent change whose result `main` still holds
    exactly and which has no merged revert. Merged is the forge's word on the revert's PR,
    found by its head commit, whatever the merge style. The agent wrote A, then B, then A
    again, each merged; reverting (each revert's PR merged in turn) gives B, then A, then no
    lesson, then a refusal: an agent change whose bytes come back is never undone twice, and
    revert commits are not agent changes to undo."""
    _agent_wrote(repo, tmp_path, _FIRST, _SECOND, _FIRST)
    peeled = [_revert_and_merge(repo, tmp_path, _LEARNED, "learned", style) for _ in range(3)]
    assert peeled == [_SECOND, _FIRST, None]
    _refused_revert(repo, _LEARNED, "learned")


def test_a_revert_whose_pr_was_closed_refuses_the_next_and_skips_nothing(repo, tmp_path):
    """R1 with D-closed: a revert PR closed unmerged is a rejection. The agent wrote A, B, A
    (each merged); the first revert (back to B) has its PR closed. The next revert of that
    lesson refuses, with nothing pushed or requested: it does not skip to an older change
    (the agent's first change matches `main` too, and undoing it would delete the lesson)."""
    _agent_wrote(repo, tmp_path, _FIRST, _SECOND, _FIRST)
    http = ForgeHTTP()
    delivery(repo, http).revert(_LEARNED, "learned")
    close_on_remote(repo, http.creates[-1]["head"])
    _refused_revert(repo, _LEARNED, "learned")


def test_a_revert_whose_pr_is_open_answers_that_pr(repo, tmp_path):
    """R1: while a revert's PR is open, the next revert of that lesson (from a new delivery
    object) answers that PR's URL: nothing is pushed and no second PR is requested."""
    _agent_wrote(repo, tmp_path, _FIRST, _SECOND)
    url = delivery(repo, ForgeHTTP()).revert(_LEARNED, "learned")
    refs = remote_refs(repo[1])
    again = ForgeHTTP()
    assert delivery(repo, again).revert(_LEARNED, "learned") == url
    assert not again.creates
    assert remote_refs(repo[1]) == refs


@pytest.mark.parametrize("failure", ["pr-request", "push"])
def test_a_revert_that_never_got_a_pr_is_made_again(repo, tmp_path, failure):
    """R1: a revert whose PR request failed (503), or whose push the remote refused (its
    `pre-receive` hook), never had a PR, so the next revert of that lesson makes the same
    revert again: one PR whose one commit, directly on `main`, restores the same bytes."""
    _agent_wrote(repo, tmp_path, _FIRST, _SECOND)
    http = ForgeHTTP()
    d = delivery(repo, http)
    hook = repo[1] / "hooks" / "pre-receive"
    if failure == "push":
        hook.parent.mkdir(exist_ok=True)
        hook.write_text("#!/bin/sh\necho 'p3: the remote refused this push' >&2\nexit 1\n",
                        encoding="utf-8")
        hook.chmod(0o755)
    else:
        http.fail_create = True
    with pytest.raises(target().DeliveryRefused):
        d.revert(_LEARNED, "learned")
    hook.unlink(missing_ok=True)
    retry = ForgeHTTP()
    main = git(repo[1], "rev-parse", "main")
    tip = _revert_commit(repo[1], retry, main, delivery(repo, retry).revert(_LEARNED, "learned"))
    assert git_bytes(repo[1], "cat-file", "blob", f"{tip}:{_LEARNED}") == _FIRST


@pytest.mark.parametrize("style", MERGE_STYLES)
def test_a_lesson_created_then_changed_within_one_batch_reverts_to_absent(repo, tmp_path, style):
    """R9: the record holds one row per lesson per batch, its net change. A lesson one claim
    created (A) and a later claim of the same batch changed (B), merged in any style (`main`
    never holds A), reverts to absent: a deletion. Bytes `main` never held are never
    restored."""
    writer = delivery(repo, ForgeHTTP())
    batch = writer.start_batch("written-twice", lanes=LANES)
    for words in (_FIRST, _SECOND):
        (batch.draft_root / _LEARNED).write_bytes(words)
        batch.commit(batch.change_set(), "claim")
        batch.reset()
    opened(writer.finish(batch))
    merge_on_remote(repo, tmp_path, batch.branch, style)
    tip = _reverted(repo, _LEARNED, "learned")
    assert _name_status(repo[1], tip) == {_LEARNED: "D"}


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
    assert writer.finish(batch).status == "open"
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
    ("agent/lessons/seed.md", b"the agent's words\nand a human's addition\n"),
], ids=["agent-created", "agent-changed", "same-length-edit", "appended-edit"])
def test_revert_refuses_a_lesson_changed_on_main_since_the_commit_maker_wrote_it(
        repo, tmp_path, path, edit):
    """Flow 4, choice 5 (user decision): revert proceeds only while `main`'s bytes for the
    lesson equal those of the commit-maker's latest change to it, byte for byte: a human
    edit of the same length is an edit, and so is one that appends to the agent's bytes. A
    human edit on `main` after the merge refuses the revert (`DeliveryRefused`): nothing is
    pushed, no PR is requested, and `main` is unchanged."""
    agent_words = b"the agent's words\n"
    assert len(agent_words) == len(b"the human's words\n")
    assert b"the agent's words\nand a human's addition\n".startswith(agent_words)
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
    later = in_a_later_process(repo, "revert", "agent/lessons/seed.md", "seed")
    assert "url" in later, later
    [create] = later["creates"]
    assert create["base"] == "main"
    assert later["url"] == forge_pulls(remote)[-1]["html_url"]
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
    later = in_a_later_process(repo, "revert", _LEARNED, "written")
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
    exact message and identities, an allowed lesson). However the retried revert ends (R1
    asks it to make the revert again; that is pinned by its own case), the laid commit never
    reaches the remote. (An implementation that names each revert's branch afresh never meets
    the laid commit, and one that removes the branch when its PR request fails leaves nothing
    to lay it on; both pass vacuously, as the README records.)"""
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


@pytest.mark.parametrize("entry", ["https://bot:secret@forge.invalid:3000", "http://bot:secret@other.invalid:3000", "http://bot:secret@forge.invalid:3001",
                                   "http://bot:secret@forge.invalid%3a3001", "http://bot:secret@other.invalid%3a3000"])
def test_credentials_require_scheme_host_and_port_agreement_before_http(repo, entry):
    """O8/O-G: a credential entry for another scheme, host or port refuses before any HTTP
    request, in git's credential-store spelling too (`host%3aport`, C5)."""
    repo[2].write_text(entry + "\n", encoding="utf-8")
    http = ForgeHTTP()
    with pytest.raises(target().DeliveryRefused, match="credential|origin"):
        delivery(repo, http)
    assert http.requests == []


@pytest.mark.parametrize(("origin", "entry"), [
    ("http://FORGE.Invalid:3000/tenants/blue.git", f"http://bot:{TOKEN}@forge.invalid:3000"),
    ("http://forge.invalid/tenants/blue.git", f"http://bot:{TOKEN}@forge.invalid:80"),
    ("http://forge.invalid:80/tenants/blue.git", f"http://bot:{TOKEN}@forge.invalid"),
    ("http://forge.invalid:3000/tenants/blue.git", f"http://bot:{TOKEN}@forge.invalid%3a3000"),
    ("http://forge.invalid:3000/tenants/blue.git", f"http://bot:{TOKEN}@forge.invalid%3A3000"),
], ids=["host-case", "default-port-in-entry", "default-port-in-origin", "store-spelling",
        "store-spelling-upper"])
def test_credentials_agree_with_an_equivalent_spelling_of_the_origin(repo, origin, entry):
    """O-G with O8: agreement compares the one parsed address (host case folded, default port
    explicit), so equivalent spellings agree and the token authenticates the API at that
    address. C5: git's credential store writes the host and port as `host%3aport`, and that
    spelling agrees too."""
    tenant, remote, credentials = repo
    git(tenant.knowledge, "remote", "set-url", "origin", origin)
    git(tenant.knowledge, "config", f"url.{remote}.insteadOf", origin)
    credentials.write_text(entry + "\n", encoding="utf-8")
    http = ForgeHTTP()
    delivery(repo, http)
    assert http.requests
    assert http.foreign == []
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
        assert "foreign-only.md" not in files_under(batch.draft_root)
        _write(batch.draft_root / "agent/lessons/ambient.md", "tenant authored\n")
        sha = batch.commit(batch.change_set(), "tenant ambient context")
        http.fail_create = True
        with pytest.raises(target().DeliveryRefused, match="503|forge|PR|pull"):
            d.finish(batch)
        http.fail_create = False
        opened(d.deliver("ambient"))
    assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == sha
    assert git(repo[0].knowledge, "rev-parse", f"refs/heads/{batch.branch}") == sha
    assert git(repo[1], "rev-parse", "main") == expected
    merged = merge_on_remote(repo, tmp_path, batch.branch)
    with monkeypatch.context() as env:
        redirect(env)
        url = d.revert("agent/lessons/ambient.md", "ambient")
    assert url == forge_pulls(repo[1])[-1]["html_url"]
    revert_head = http.creates[-1]["head"]
    tip = git(repo[1], "rev-parse", f"refs/heads/{revert_head}")
    assert git(repo[1], "rev-parse", f"{tip}^") == merged == git(repo[1], "rev-parse", "main")
    assert _name_status(repo[1], tip) == {"agent/lessons/ambient.md": "D"}
    assert git(repo[0].knowledge, "show", f"{sha}:agent/lessons/ambient.md") == "tenant authored"
    assert _name_status(repo[0].knowledge, sha) == {"agent/lessons/ambient.md": "A"}
    assert git(foreign, "rev-parse", "HEAD") == foreign_head
    assert not (foreign / "agent").exists()
    assert _branches(foreign) == ["refs/heads/main"]
