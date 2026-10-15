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

import pytest

from defender import _io

from ._support import (
    DEFENDER,
    FORK,
    LANES,
    TOKEN,
    ForgeHTTP,
    advance_remote,
    bounded,
    delivery,
    files_under,
    git,
    git_bytes,
    install_planting_hook,
    odd_entries,
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
    """O-F: a later publish (another drain, a setup update) advances the clone and `current`,
    yet the running batch's draft, worktree and export stay exactly as they were."""
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


def _mknod(lane):
    try:
        os.mknod(lane / "dev.md", stat.S_IFCHR | 0o600, os.makedev(1, 3))
    except PermissionError:
        pytest.skip("creating a device node needs CAP_MKNOD; the FIFO and socket rows remain")


def _oversized(lane):
    with open(lane / "big.md", "wb") as big:
        big.truncate(_io.READ_LIMIT + 1)


#: Box output a claim must refuse whole, each beside a valid in-lane change: `(entry) ->
#: plant(lane, agent, outside, worktree)`. A symlinked directory is listed by `os.walk` among
#: `dirnames` and not descended, so a naive derivation skips it silently; `agent/.tenant-id`
#: is also outside every lane. The FIFO and socket rows are planted by the test itself.
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
}


@pytest.mark.parametrize("entry", sorted(_REFUSED_OUTPUT))
def test_a_claim_holding_anything_but_in_lane_regular_files_is_refused_whole(
        repo, tmp_path, monkeypatch, entry):
    """O-C/O-D: a link (to a file or a directory), FIFO, socket, device or oversized file, a
    path outside the lanes (a prefix sibling of one included), `agent/.tenant-id`, or a
    `.gitattributes`/`.gitignore`/`.gitmodules` at any depth (added or deleted) refuses the
    claim: nothing is skipped and nothing committed, no link is followed, nothing blocks.
    After a reset the draft equals the worktree again and the host folder a link pointed at
    is intact."""
    if entry == "gitattributes-deletion":
        push_to_remote(repo, tmp_path, lambda c: _write(c / "agent/lessons/.gitattributes", "* -text\n"))
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
    head = git(batch.worktree, "rev-parse", "HEAD")
    try:
        _, error, hung = bounded(batch.change_set, fifos=[lane / "pipe.md"] if entry == "fifo" else [])
    finally:
        for listener in sockets:
            listener.close()
    assert not hung, "deriving the change set blocked on box output"
    assert isinstance(error, target().DeliveryRefused), error
    assert git(batch.worktree, "rev-parse", "HEAD") == head
    assert git(batch.worktree, "status", "--porcelain") == ""

    batch.reset()
    assert odd_entries(agent) == []
    assert files_under(agent) == files_under(batch.worktree / "agent")
    assert _changes(batch.change_set()) == {}
    assert files_under(outside) == {"secret.md": b"host only\n"}


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
    them (the host folder a link named keeps its files) and without blocking."""
    batch = delivery(repo, ForgeHTTP()).start_batch("reset", lanes=LANES)
    lane = batch.draft_root / "agent/lessons"
    _write(lane / "a.md", "committed\n")
    batch.commit(batch.change_set(), "claim")
    outside = tmp_path / "host-folder"
    outside.mkdir()
    (outside / "keep.md").write_text("host\n", encoding="utf-8")
    _write(lane / "a.md", "changed after the commit\n")
    _write(lane / "stray.md", "stray\n")
    _write(lane / "deep/stray.md", "stray\n")
    (lane / "seed.md").unlink()
    (lane / "linked").symlink_to(outside, target_is_directory=True)
    os.mkfifo(lane / "pipe")
    _, error, hung = bounded(batch.reset, fifos=[lane / "pipe"])
    assert not hung, "the reset blocked on box output"
    assert error is None, error
    assert odd_entries(batch.draft_root) == []
    assert files_under(batch.draft_root / "agent") == files_under(batch.worktree / "agent")
    assert files_under(outside) == {"keep.md": b"host\n"}


# ---------------------------------------------------------------------------------------
# Push routes: finish, retained deliver, revert send only commit-maker commits
# ---------------------------------------------------------------------------------------

def test_finish_pushes_the_commit_maker_branch_and_opens_its_pr_without_product_write(repo):
    """O7: the commit lands on the tenant remote's batch branch, the PR opens against the
    tenant repo's `main` at the forge's repository API, and neither tenant `main` nor the
    product repository changes."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    tenant, remote, _ = repo
    product_head = git(DEFENDER, "rev-parse", "HEAD")
    batch = d.start_batch("one", lanes=LANES)
    _write(batch.draft_root / "agent/lessons/new.md", "review me\n")
    sha = batch.commit(batch.change_set(), "learning")
    assert d.finish(batch) == "http://forge.invalid:3000/tenants/blue/pulls/7"
    assert git(remote, "rev-parse", f"refs/heads/{batch.branch}") == sha
    assert git(remote, "rev-parse", "main") == batch.export.commit
    assert [(c["base"], c["head"]) for c in http.creates] == [("main", batch.branch)]
    assert all(r.url.path.startswith("/api/v1/repos/tenants/blue/") for r in http.requests)
    assert git(DEFENDER, "rev-parse", "HEAD") == product_head


@pytest.mark.parametrize("how", ["on-top", "amend", "only-raw", "forbidden-path"])
def test_finish_refuses_a_branch_holding_a_commit_the_commit_maker_did_not_make(repo, how):
    """O-C: a `git commit` in the batch worktree by anything but the commit-maker (reusing the
    last commit's message and author, touching an allowed lesson, or a forbidden path) refuses
    the finish before any push: no remote branch, no PR."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("foreign", lanes=LANES)
    wt = batch.worktree
    if how != "only-raw":
        _write(batch.draft_root / "agent/lessons/made.md", "made by the commit-maker\n")
        batch.commit(batch.change_set(), "commit-maker claim")
    path = "settings/rogue.yaml" if how == "forbidden-path" else "agent/lessons/raw.md"
    _write(wt / path, "raw git, not the commit-maker\n")
    git(wt, "add", path)
    if how == "amend":
        git(wt, "commit", "--amend", "-C", "HEAD")
    else:
        git(wt, "commit", "-C", "HEAD")
    with pytest.raises(target().DeliveryRefused):
        d.finish(batch)
    assert _branches(repo[1]) == ["refs/heads/main"]
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


def test_finish_and_deliver_ignore_a_fork_pr_with_the_same_branch_name(repo):
    """O-G through delivery: a fork's open PR whose head has our branch name is not ours.
    Finish opens our own PR; deliver then returns our open PR without opening another."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("forked", lanes=LANES)
    http.pages = {1: [pr_row(5, batch.branch, repo=FORK)]}
    _write(batch.draft_root / "agent/lessons/new.md", "ours\n")
    batch.commit(batch.change_set(), "ours")
    assert d.finish(batch).endswith("/pulls/7")
    assert len(http.creates) == 1
    http.pages = {1: [pr_row(5, batch.branch, repo=FORK), pr_row(8, batch.branch)]}
    assert d.deliver("forked").endswith("/pulls/8")
    assert len(http.creates) == 1


@pytest.mark.parametrize("history", ["added-once", "modified-later"])
def test_revert_builds_its_change_set_from_history_and_pushes_one_commit_maker_commit(
        repo, tmp_path, history):
    """Flow 4: a lesson revert restores the lesson's prior content (before the latest commit
    that changed it on `main`), or deletes it when that commit added it, as exactly one
    commit on `main` with mode 100644, pushed to its own branch with a PR against `main`."""
    remote = repo[1]
    if history == "modified-later":
        push_to_remote(repo, tmp_path, lambda c: _write(c / "agent/lessons/seed.md", "seed, merged edit\n"))
    http = ForgeHTTP()
    d = delivery(repo, http)
    main = git(remote, "rev-parse", "main")
    assert d.revert("agent/lessons/seed.md", "seed").endswith("/pulls/7")
    [create] = http.creates
    assert create["base"] == "main"
    tip = git(remote, "rev-parse", f"refs/heads/{create['head']}")
    assert git(remote, "rev-parse", f"{tip}^") == main
    if history == "added-once":
        assert _name_status(remote, tip) == {"agent/lessons/seed.md": "D"}
    else:
        assert _name_status(remote, tip) == {"agent/lessons/seed.md": "M"}
        assert git_bytes(remote, "cat-file", "blob", f"{tip}:agent/lessons/seed.md") == b"seed\n"
        assert _modes(remote, tip, "agent/lessons/seed.md") == {"agent/lessons/seed.md": "100644"}
    assert git(remote, "rev-parse", "main") == main


def test_revert_refuses_a_commit_the_commit_maker_did_not_make(repo, tmp_path):
    """O-C on the revert route: something else lays a commit (the commit-maker's own message
    and identities, an allowed lesson) on the revert's branch right after the commit-maker
    moves it; the revert refuses before any push or PR. The clone's `reference-transaction`
    hook is that something; its marker proves it fired."""
    tenant, remote, _ = repo
    http = ForgeHTTP()
    d = delivery(repo, http)
    marker = tmp_path / "planted"
    install_planting_hook(tenant.knowledge, git(remote, "rev-parse", "main"), marker,
                          "agent/lessons/raw.md", b"raw git, not the commit-maker\n")
    with pytest.raises(target().DeliveryRefused):
        d.revert("agent/lessons/seed.md", "seed")
    assert marker.exists(), "the revert's commit never reached a branch, so nothing was laid on it"
    assert _branches(remote) == ["refs/heads/main"]
    assert not http.creates


@pytest.mark.parametrize("path", ["agent/.tenant-id", "settings/lead-zero.yaml",
                                  "agent/lessons/absent.md", "agent/lessons/../.tenant-id"])
def test_revert_refuses_a_path_that_is_not_a_lesson_on_main(repo, path):
    """O-C: a revert's change set obeys the same rules: `agent/.tenant-id`, a settings file, a
    traversal or a lesson that is not on `main` is refused, with nothing pushed or requested."""
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
    batch, the commit-maker, finish or retained delivery into another repository."""
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    git(foreign, "init", "-b", "main")
    (foreign / "foreign-only.md").write_text("another repository\n", encoding="utf-8")
    git(foreign, "add", ".")
    git(foreign, "commit", "-m", "foreign seed")
    foreign_head = git(foreign, "rev-parse", "HEAD")
    expected = git(repo[0].knowledge, "rev-parse", "HEAD")
    http = ForgeHTTP()
    with monkeypatch.context() as env:
        if ambient in {"git-dir", "both"}:
            env.setenv("GIT_DIR", str(foreign / ".git"))
        if ambient in {"work-tree", "both"}:
            env.setenv("GIT_WORK_TREE", str(foreign))
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
    assert git(repo[0].knowledge, "show", f"{sha}:agent/lessons/ambient.md") == "tenant authored"
    assert _name_status(repo[0].knowledge, sha) == {"agent/lessons/ambient.md": "A"}
    assert git(foreign, "rev-parse", "HEAD") == foreign_head
    assert not (foreign / "agent").exists()
    assert _branches(foreign) == ["refs/heads/main"]
