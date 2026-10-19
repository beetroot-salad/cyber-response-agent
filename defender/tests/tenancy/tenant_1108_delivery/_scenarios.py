"""Shared setup and independent observations for batch, delivery and revert tests."""
from __future__ import annotations

import importlib

import json

import os

import shutil



import stat

import subprocess

import sys


import httpx

import pytest

from defender import _io

from ._support import (
    FORK,
    NAMESAKE,
    RENAMED,
    SIBLING_FORK,
    ForgeHTTP,
    delivery,
    forge_pulls,
    fresh_process_env,
    git,
    git_bytes,
    merge_on_remote,
    merged_agent_lesson,
    opened,
    pr_row,
    push_object,
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


_BYTE_CHANGERS = {
    "eol-and-ident": ("*.md text eol=crlf ident\n", None),
    "clean-filter": ("*.md filter=p3upper\n", "tr a-z A-Z"),
}


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


_REFUSED_BASE = {
    "gitattributes-deletion": {"agent/lessons/.gitattributes": "* -text\n"},
    "replace-dir-with-link": {"agent/lessons/deep/x.md": "a planted subdirectory\n"},
}


def _gitdir_file(lane, clone):
    _write(lane / ".git", f"gitdir: {clone / '.git'}\n")


def _nested_repository(lane, clone):
    nested = lane / "sub"
    _write(nested / "x.md", "a repository of its own\n")
    git(nested, "init", "-q", "-b", "main")
    git(nested, "add", ".")
    git(nested, "commit", "-q", "-m", "nested")


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


_BUILD = """
import json, os, resource, signal, sys
from pathlib import Path
from defender.tests.support.tenancy import _tenants1106 as tenants
from defender.tests.tenancy.tenant_1108_delivery._support import (
    DEFENDER, LANES, ForgeHTTP, configured_origin, target, fixture_identity)
root, tenant_id, remote, batch_id, cap, mode = (Path(sys.argv[1]), sys.argv[2], sys.argv[3],
                                                sys.argv[4], int(sys.argv[5]), sys.argv[6])
mod = target()
tenant = tenants.accept(root, tenant_id)
http = ForgeHTTP(remote=remote, origin=configured_origin(tenant.knowledge))
d = mod.TenantDelivery.open(tenant, defender_dir=DEFENDER, client=http.client, identity=fixture_identity(str(tenant.id)), origin=configured_origin(tenant.knowledge))
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


def _lay_pr(repo, http, row):
    """Add `row` to the forge, its head commit first put on the remote under
    `refs/pull/N/head`, where the forge holds every PR's head (a fork's included)."""
    push_object(repo, row["head"]["sha"], f"refs/pull/{row['number']}/head")
    return http.add_pr(row)


_TRANSPORT_FAULTS = {
    "protection-read": lambda request: request.url.path.endswith("/branches/main"),
    "pr-lookup": lambda request: request.method == "GET" and "/pulls" in request.url.path,
    "pr-create": lambda request: request.method == "POST",
}


_NOT_OUR_PR = {
    "fork-at-our-commit": lambda branch, ours, other: pr_row(5, branch, repo=FORK, sha=ours),
    "sibling-fork-at-our-commit": lambda branch, ours, other: pr_row(5, branch, repo=SIBLING_FORK, sha=ours),
    "namesake-at-our-commit": lambda branch, ours, other: pr_row(5, branch, repo=NAMESAKE, sha=ours),
    "no-head-repository-at-our-commit": lambda branch, ours, other: pr_row(5, branch, repo=None, sha=ours),
    "our-name-merged-at-another-commit": lambda branch, ours, other: pr_row(5, branch, sha=other, merged=True),
    "our-name-closed-at-another-commit": lambda branch, ours, other: pr_row(5, branch, sha=other, state="closed"),
    "another-batch-open": lambda branch, ours, other: pr_row(5, "lessons/another-batch", sha=other),
}


def _branch_deleted(row):
    """`row` as Forgejo 15 lists a PR whose head branch was deleted: `head.ref`
    `refs/pull/N/head`, no label, `head.sha` kept."""
    row["head"].update(ref=f"refs/pull/{row['number']}/head", label="")
    return row


_OUR_PR = {
    "renamed-repository-open": (
        lambda branch, shas: pr_row(5, "lessons/elsewhere", repo=RENAMED, sha=shas[-1]), "open"),
    "branch-deleted-merged": (
        lambda branch, shas: _branch_deleted(pr_row(5, branch, sha=shas[-1], merged=True)), "merged"),
    "earlier-commit-merged": (lambda branch, shas: pr_row(5, branch, sha=shas[0], merged=True), "merged"),
    "earlier-commit-closed": (lambda branch, shas: pr_row(5, branch, sha=shas[0], state="closed"), "closed"),
}


_MAKES_COMMITS = {"commit", "commit-tree", "cherry-pick", "revert", "am", "rebase", "merge"}


_SENDS_COMMITS = {"push", "send-pack"}


_TOUCHES_CHECKOUT = {"checkout", "switch", "restore", "checkout-index", "reset", "stash", "clean",
                     "merge", "pull", "rebase", "cherry-pick", "revert"}


_WORKTREE_MADE = {"add", "move"}


def _census(events, kinds):
    return {phase for phase, sub, args in events
            if sub in kinds and not (sub == "merge" and "--ff-only" in args)}


def _after(sub, args):
    """The words of a spawned git's argv after its subcommand `sub`."""
    return args[args.index(sub) + 1:] if sub in args else []


def _worktree_made(sub, args):
    verb = next((a for a in _after(sub, args) if not a.startswith("-")), None)
    return sub == "worktree" and verb in _WORKTREE_MADE


def _checkouts(events):
    return {phase for phase, sub, args in events
            if sub in _TOUCHES_CHECKOUT or (sub == "read-tree" and "-u" in _after(sub, args))
            or _worktree_made(sub, args)}


def _revert_commit(remote, http, main, result):
    """The one commit the revert's PR offers: its head branch's tip, directly on `main`, which
    does not move. `result` (the revert's) must be `opened`, with that PR's URL (the open row
    the revert's one request made)."""
    url = opened(result, None)
    [create] = http.creates
    assert create["base"] == "main"
    rows = [row for row in forge_pulls(remote) if row["state"] == "open" and row["head"]["ref"] == create["head"]]
    assert [row["html_url"] for row in rows] == [url], (url, rows)
    tip = git(remote, "rev-parse", f"refs/heads/{create['head']}")
    assert git(remote, "rev-parse", f"{tip}^") == main
    assert git(remote, "rev-parse", "main") == main
    return tip


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


class _AnswerLost(ForgeHTTP):
    """A forge that creates the PR asked for and then loses its answer (a read timeout after
    the create)."""

    def reply(self, request):
        response = super().reply(request)
        if request.method == "POST" and request.url.path.endswith("/pulls"):
            raise httpx.ReadTimeout("the forge's answer was lost", request=request)
        return response


_UNUSABLE_REPOSITORY = {"no-id": {"full_name": "tenants/blue"}, "list": [], "str-id": {"id": "11"},
                        "null-id": {"id": None}, "float-id": {"id": 11.0}, "bool-id": {"id": True}}


def _forge():
    return importlib.import_module("defender.learning.author.version_control.forgejo")


