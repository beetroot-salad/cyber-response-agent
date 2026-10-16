"""Shared machinery for #1108 P3's contract: real tenant repos, the forge's HTTP boundary, a
real smart-HTTP git remote, and out-of-process probes of the per-tenant lock.

Nothing here implements target policy: fixtures plant trees and record what crosses a
boundary; every judgement is the code under test's."""
from __future__ import annotations

import base64
import contextlib
import importlib
import json
import os
import shlex
import stat
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from defender.tests import _tenants1106 as tenants

ORIGIN = "http://forge.invalid:3000/tenants/blue.git"
TOKEN = "p3-blue-secret-credential"
DEFENDER = Path(__file__).resolve().parents[2]
#: The import root a probe subprocess needs, so it imports THIS tree's `defender`.
IMPORT_ROOT = DEFENDER.parent
#: The lanes every batch here declares writable.
LANES = ("lessons",)

_IDENTITY = {"GIT_AUTHOR_NAME": "P3", "GIT_AUTHOR_EMAIL": "p3@test.invalid",
             "GIT_COMMITTER_NAME": "P3", "GIT_COMMITTER_EMAIL": "p3@test.invalid"}


def target():
    # Lazy import: the contract must collect before its implementation exists.
    return importlib.import_module("defender.learning.author.tenant_delivery")


#: Git's automatic upkeep, off for every git the fixtures run. Git >= 2.47 starts
#: `maintenance run --auto` detached after a fetch, commit or merge: still taking
#: `maintenance.lock` once the fixture's git has returned, it races a test that deletes the clone
#: (CI: `FileNotFoundError` mid-`rmtree`). Never in the code under test's environment
#: (`os.environ`, `GitConfigHome`, `fresh_process_env`): whether ITS git leaves upkeep behind is
#: a case of its own (`test_no_git_upkeep_runs_over_the_clone_from_a_delivery_call`).
_NO_UPKEEP = (("maintenance.auto", "false"), ("maintenance.autoDetach", "false"),
              ("gc.auto", "0"), ("gc.autoDetach", "false"))
#: The same, as `git clone -c` writes it into a bare remote's own config: receive-pack runs with
#: that config alone (local transport drops the pusher's `GIT_CONFIG_*`), after every push the
#: fixtures or the code under test make.
BARE_NO_UPKEEP = tuple(arg for key, value in (("receive.autogc", "false"), *_NO_UPKEEP)
                       for arg in ("-c", f"{key}={value}"))


def no_upkeep(env):
    """`env` with `_NO_UPKEEP` as `GIT_CONFIG_KEY_n`/`VALUE_n`, after any entries it carries."""
    env = dict(env)
    base = int(env.get("GIT_CONFIG_COUNT") or "0")
    for i, (key, value) in enumerate(_NO_UPKEEP, start=base):
        env[f"GIT_CONFIG_KEY_{i}"] = key
        env[f"GIT_CONFIG_VALUE_{i}"] = value
    env["GIT_CONFIG_COUNT"] = str(base + len(_NO_UPKEEP))
    return env


#: Variables that would point the fixtures' git at another repository: a case that sets them
#: for the code under test (the ambient-repository case) must not move the harness too.
_REPOSITORY_VARIABLES = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR",
                         "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES")


def _git_env(extra=None):
    inherited = {k: v for k, v in os.environ.items() if k not in _REPOSITORY_VARIABLES}
    return no_upkeep({**inherited, "GIT_CONFIG_NOSYSTEM": "1", **_IDENTITY, **(extra or {})})


def git(cwd, *args, env=None):
    # lint-raw-git: test-only real repository fixture and observation boundary.
    proc = subprocess.run(["git", *map(str, args)], cwd=cwd, text=True,
                          capture_output=True, check=True, env=_git_env(env))
    return proc.stdout.strip()


def git_bytes(cwd, *args, data=None, env=None):
    """`git` with byte input and output, untrimmed: blob bytes are compared exactly."""
    # lint-raw-git: test-only real repository fixture and observation boundary.
    return subprocess.run(["git", *map(str, args)], cwd=cwd, input=data, capture_output=True,
                          check=True, env=_git_env(env)).stdout


# ---------------------------------------------------------------------------------------
# The forge's HTTP API boundary
# ---------------------------------------------------------------------------------------

#: Forgejo's repository objects as a PR row carries them: ours, and a fork of it.
OURS = {"id": 11, "name": "blue", "full_name": "tenants/blue", "owner": {"login": "tenants"}}
FORK = {"id": 99, "name": "blue", "full_name": "mallory/blue", "owner": {"login": "mallory"}}
#: A fork under the same owner: only the repository name differs from ours.
SIBLING_FORK = {"id": 98, "name": "blue-fork", "full_name": "tenants/blue-fork",
                "owner": {"login": "tenants"}}
#: Ours after a rename: identity is the repository id, which a rename or transfer keeps.
RENAMED = {"id": 11, "name": "renamed", "full_name": "tenants/renamed", "owner": {"login": "tenants"}}
#: Not ours, though it carries our full name (another repository took the name).
NAMESAKE = {"id": 97, "name": "blue", "full_name": "tenants/blue", "owner": {"login": "tenants"}}

#: The root Forgejo builds `Link` headers from (its `ROOT_URL`): an internal name, not the
#: address the host was given (review finding #6), so a Link followed leaves our address.
LINK_ROOT = "http://forgejo.internal:3000"
#: The PR store a remote-backed `ForgeHTTP` keeps inside the bare remote (git ignores it), so
#: a later process's forge double, and the harness's merges, see the same PRs.
_PULLS = "p3-forge-pulls.json"


def pr_row(number, head, *, repo=OURS, state="open", sha=None, merged=False):
    """A PR row in Forgejo's schema: the head's branch, commit and repository (id and
    object), the base's repository id. `repo=None` drops the head's repository entirely, as
    Forgejo does for a deleted fork (D-fork)."""
    head_side = {"ref": head, "sha": sha, "label": f"{(repo or {}).get('owner', {}).get('login', '')}:{head}"}
    if repo is not None:
        head_side.update(repo_id=repo["id"], repo=repo)
    return {"number": number, "state": "closed" if merged else state, "merged": merged,
            "merged_at": "2026-10-16T00:00:00Z" if merged else None, "head": head_side,
            "base": {"ref": "main", "label": "tenants:main", "repo_id": OURS["id"], "repo": OURS},
            "html_url": f"http://forge.invalid:3000/tenants/blue/pulls/{number}"}


def forge_pulls(remote):
    """The PRs a remote-backed `ForgeHTTP` holds for `remote`, in the order they were added."""
    path = Path(remote) / _PULLS
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []


def _save_pulls(remote, rows):
    path = Path(remote) / _PULLS
    path.with_suffix(".tmp").write_text(json.dumps(rows), encoding="utf-8")
    os.replace(path.with_suffix(".tmp"), path)


def _remote_tip(remote, branch):
    listed = git(remote, "for-each-ref", "--format=%(objectname)", f"refs/heads/{branch}")
    return listed or None


def _sync_open_pulls(remote):
    """As Forgejo does: an open PR's head follows its branch, and `refs/pull/N/head` with it."""
    rows = forge_pulls(remote)
    for row in rows:
        if row["state"] == "open" and row["head"].get("repo_id") == OURS["id"]:
            tip = _remote_tip(remote, row["head"]["ref"])
            if tip is not None and tip != row["head"]["sha"]:
                row["head"]["sha"] = tip
                git(remote, "update-ref", f"refs/pull/{row['number']}/head", tip)
    _save_pulls(remote, rows)
    return rows


def set_pull_state(remote, branch, *, merged, delete_branch=False):
    """A human closing, or merging, the open PR of our repository whose head is `branch`
    (raising when there is none, so no case passes on a PR that never existed). Deleting the
    branch leaves the row as Forgejo 15 lists it: `head.ref` `refs/pull/N/head`, no label,
    `head.sha` kept."""
    rows = _sync_open_pulls(remote)
    mine = [row for row in rows if row["state"] == "open" and row["head"]["ref"] == branch
            and row["head"].get("repo_id") == OURS["id"]]
    assert mine, f"no open PR of ours has the head {branch!r}: {rows}"
    for row in mine:
        row.update(state="closed", merged=merged,
                   merged_at="2026-10-16T00:00:00Z" if merged else None)
        if delete_branch:
            row["head"].update(ref=f"refs/pull/{row['number']}/head", label="")
    _save_pulls(remote, rows)
    if delete_branch:
        git(remote, "update-ref", "-d", f"refs/heads/{branch}")
    return mine


def close_on_remote(repo, branch):
    """A human closing the batch's PR without merging it: a rejection (D-closed)."""
    return set_pull_state(repo[1], branch, merged=False)


def _address(origin):
    parts = urlsplit(origin)
    scheme = parts.scheme.lower()
    return scheme, (parts.hostname or "").lower(), parts.port or {"http": 80, "https": 443}[scheme]


def _api(origin):
    """The repository API path the forge serves for `origin` (owner and repository, no case)."""
    owner, repo = urlsplit(origin).path.strip("/").lower().split("/")
    return f"/api/v1/repos/{owner}/{repo.removesuffix('.git')}"


def configured_origin(clone):
    """The origin URL `clone` is configured with (as written, before any `insteadOf`), or
    `None` when it has none a forge could serve."""
    try:
        origin = git(clone, "config", "--get", "remote.origin.url")
        _address(origin), _api(origin)
    except (OSError, KeyError, ValueError, subprocess.CalledProcessError):
        return None
    return origin


class ForgeHTTP:
    """Boundary fake: replies from the observed Forgejo schema, records actual requests.

    It answers our repository (`GET /repos/{o}/{r}`), branch protection, one PR
    (`GET /pulls/N`), the PR listing (`state`, `page`, `limit`) and PR creation, on the
    origin's scheme, host and port only; a request anywhere else is recorded in `foreign`
    and answered 404. The listing clamps `limit` to `page_size` (Forgejo's
    `max_response_items`), counts every row of the state asked for in `X-Total-Count`
    (`total_count`: `True`, `False` to omit it, or a number to lie), and links the next page
    from `LINK_ROOT`, never our address (`link`, when set, is sent as the next page's URL
    instead, whatever the page). Rows come in the order they were added.

    With `remote` (a bare repository; `delivery()` sets it), the PRs live in that remote,
    creating one writes `refs/pull/N/head` there, and an open PR's head follows its branch,
    as on Forgejo; without it they live here. `pages` (`{n: rows}`), when set, replaces the
    listing for shape cases (a short page before the end); `every_page` answers every page
    number with the same rows (a server that ignores `page`).

    `on_request(request)` runs before each reply (a probe of the host's state while the
    request is in flight); `fault(request)`, when set, may return a transport exception
    (`httpx.ConnectError`, say) to raise instead of replying."""

    def __init__(self, on_request=None, *, remote=None, origin=None):
        self.requests = []
        self.foreign = []
        self.protection = {"name": "main", "protected": True, "user_can_push": False}
        self.repository = dict(OURS)
        self.fail_create = False
        self.fault = None
        self.on_request = on_request
        self.remote = remote
        self.address = self.api = None
        if origin is not None:
            self.serve(origin)
        self.page_size = 50
        self.total_count = True
        self.pages = None
        self.every_page = None
        self.link = None
        self._rows = []
        self.client = httpx.Client(transport=httpx.MockTransport(self.reply))

    @property
    def prs(self):
        return forge_pulls(self.remote) if self.remote is not None else self._rows

    def add_pr(self, row):
        """Add a PR row to the store (its `refs/pull/N/head` written in a remote-backed one)."""
        if self.remote is None:
            self._rows.append(row)
            return row
        _save_pulls(self.remote, [*forge_pulls(self.remote), row])
        if row["head"].get("sha"):
            git(self.remote, "update-ref", f"refs/pull/{row['number']}/head", row["head"]["sha"])
        return row

    def listed(self, method="GET"):
        """The listing requests made, in order, as `(state, page, limit)`."""
        return [(r.url.params.get("state"), r.url.params.get("page"), r.url.params.get("limit"))
                for r in self.requests if r.method == method and r.url.path.endswith("/pulls")]

    def serve(self, origin):
        """Answer as the forge of `origin`: its scheme, host and port, its repository's API."""
        self.address, self.api = _address(origin), _api(origin)

    def _ours(self, request):
        url = request.url
        address = self.address if self.address is not None else _address(ORIGIN)
        return (url.scheme, url.host, url.port or {"http": 80, "https": 443}[url.scheme]) == address

    def reply(self, request):
        self.requests.append(request)
        if self.on_request is not None:
            self.on_request(request)
        fault = self.fault(request) if self.fault is not None else None
        if fault is not None:
            raise fault
        api = self.api if self.api is not None else _api(ORIGIN)
        path = request.url.path.lower()  # Forgejo resolves owner and repository without case
        if not self._ours(request) or not (path == api or path.startswith(api + "/")):
            self.foreign.append(request)
            return httpx.Response(404, json={"message": "not this forge's repository"})
        if self.remote is not None:
            _sync_open_pulls(self.remote)
        rest = path[len(api):]
        if rest == "" and request.method == "GET":
            return httpx.Response(200, json=self.repository)
        if rest == "/branches/main":
            return httpx.Response(200, content=json.dumps(self.protection),
                                  headers={"Content-Type": "application/json"})
        if rest == "/pulls" and request.method == "GET":
            return self._listing(request)
        if rest.startswith("/pulls/") and request.method == "GET":
            found = [row for row in self.prs if str(row["number"]) == rest.split("/")[2]]
            return httpx.Response(200, json=found[0]) if found else httpx.Response(404, json={})
        if rest == "/pulls" and request.method == "POST":
            return self._create(json.loads(request.content))
        raise AssertionError(f"unexpected HTTP boundary: {request.method} {request.url}")

    def _listing(self, request):
        params = request.url.params
        page = int(params.get("page") or "1")
        if self.every_page is not None:
            rows, total = self.every_page, len(self.every_page)
        elif self.pages is not None:
            rows, total = self.pages.get(page, []), sum(len(r) for r in self.pages.values())
            more = any(n > page for n in self.pages)
        else:
            state = params.get("state") or "open"
            matching = [row for row in self.prs if state == "all" or row["state"] == state]
            size = min(int(params.get("limit") or self.page_size), self.page_size)
            rows, total = matching[(page - 1) * size:page * size], len(matching)
            more = page * size < total
        headers = {}
        if self.total_count is not False:
            headers["X-Total-Count"] = str(total if self.total_count is True else self.total_count)
        if self.link is not None:
            headers["Link"] = f'<{self.link}>; rel="next"'
        elif self.every_page is not None or more:
            headers["Link"] = f'<{LINK_ROOT}/api/v1/repos/tenants/blue/pulls?page={page + 1}>; rel="next"'
        return httpx.Response(200, json=rows, headers=headers)

    def _create(self, body):
        if self.fail_create:
            return httpx.Response(503, json={"message": "the forge failed"})
        sha = None
        if self.remote is not None:
            sha = _remote_tip(self.remote, body["head"])
            if sha is None:
                return httpx.Response(422, json={"message": f"no branch {body['head']}"})
        number = max([6, *(row["number"] for row in self.prs)]) + 1
        row = self.add_pr(pr_row(number, body["head"], sha=sha))
        return httpx.Response(201, json=row)

    @property
    def creates(self):
        return [json.loads(r.content) for r in self.requests if r.method == "POST"]


# ---------------------------------------------------------------------------------------
# Real tenant repositories
# ---------------------------------------------------------------------------------------

def build_tenant(tmp_path, tenant_id="blue", *, root=None):
    """An accepted tenant whose knowledge folder is a real clone of a real bare `origin`,
    reached over git's local transport behind a network-shaped origin URL; its credential
    entry agrees with that origin. Returns `(tenant, bare remote, credential file)`."""
    root = root if root is not None else tmp_path / "data"
    tenants.place_tenant(root, tenant_id)
    tenant = tenants.accept(root, tenant_id)
    clone = tenant.knowledge
    (tenant.agent / "lessons").mkdir()
    (tenant.agent / "lessons" / "seed.md").write_text("seed\n", encoding="utf-8")
    git(clone, "init", "-b", "main")
    git(clone, "config", "user.name", "P3")
    git(clone, "config", "user.email", "p3@test.invalid")
    git(clone, "add", ".")
    git(clone, "commit", "-m", "seed")
    remote = tmp_path / ("origin.git" if tenant_id == "blue" else f"{tenant_id}-origin.git")
    git(tmp_path, "clone", "--bare", *BARE_NO_UPKEEP, clone, remote)
    origin = f"http://forge.invalid:3000/tenants/{tenant_id}.git"
    git(clone, "remote", "add", "origin", origin)
    # Git performs real local transport; delivery still validates the actual network origin.
    git(clone, "config", f"url.{remote}.insteadOf", origin)
    git(clone, "fetch", "origin")
    credentials = tenant.dir / "forge" / "git-credentials"
    credentials.parent.mkdir()
    credentials.write_text(f"http://bot:{TOKEN}@forge.invalid:3000\n", encoding="utf-8")
    credentials.chmod(0o600)
    return tenant, remote, credentials


@pytest.fixture
def repo(tmp_path):
    return build_tenant(tmp_path)


def delivery(repo, http, **options):
    """`TenantDelivery.open` on `repo`'s tenant, its forge double backed by `repo`'s remote and
    answering at the address of the clone's configured origin (unless given one)."""
    if http.remote is None:
        http.remote = repo[1]
    origin = configured_origin(repo[0].knowledge)
    if http.address is None and origin is not None:
        http.serve(origin)
    return target().TenantDelivery.open(repo[0], defender_dir=DEFENDER, client=http.client, **options)


def push_to_remote(repo, tmp_path, edit, message="human merge", *, stage=True):
    """Land one commit on the remote's `main`, as a human-reviewed merge would: `edit(checkout)`
    changes a fresh checkout of it; `stage=False` when `edit` stages raw index entries itself
    (a link or gitlink with no file behind it). Returns the new commit."""
    writer = tmp_path / f"merger-{len(list(tmp_path.glob('merger-*')))}"
    git(tmp_path, "clone", repo[1], writer)
    edit(writer)
    if stage:
        git(writer, "add", "-A")
    git(writer, "commit", "-m", message)
    git(writer, "push", "origin", "main")
    return git(writer, "rev-parse", "HEAD")


def advance_remote(repo, tmp_path):
    def merged(writer):
        (writer / "agent" / "lessons" / "merged.md").write_text("human-reviewed merge\n",
                                                                encoding="utf-8")
    return push_to_remote(repo, tmp_path, merged)


#: How a human merges a PR on Forgejo. Each lands the branch's changes on `main`; only
#: `merge` keeps the commit-maker's commits (by sha) in `main`'s history.
MERGE_STYLES = ("merge", "squash", "rebase")
_FORGE_COMMITTER = {"GIT_COMMITTER_NAME": "Forgejo", "GIT_COMMITTER_EMAIL": "forgejo@test.invalid"}


def merge_on_remote(repo, tmp_path, branch, style="merge", *, delete_branch=False):
    """A human merging a PR into the remote's `main`: `merge` makes a merge commit (Forgejo's
    default), `squash` one new commit holding the branch's changes, `rebase` re-commits each
    of the branch's commits on `main` under the forge's committer (new shas). The forge marks
    the branch's open PR merged (there must be one), and `delete_branch` deletes the branch
    as Forgejo's merge option does. Returns the new `main`."""
    writer = tmp_path / f"merger-{len(list(tmp_path.glob('merger-*')))}"
    git(tmp_path, "clone", repo[1], writer)
    if style == "merge":
        git(writer, "merge", "--no-ff", "-m", f"Merge {branch}", f"origin/{branch}")
    elif style == "squash":
        git(writer, "merge", "--squash", f"origin/{branch}")
        git(writer, "commit", "-m", f"{branch} (squashed)", env=_FORGE_COMMITTER)
    else:
        git(writer, "cherry-pick", f"main..origin/{branch}", env=_FORGE_COMMITTER)
    git(writer, "push", "origin", "main")
    set_pull_state(repo[1], branch, merged=True, delete_branch=delete_branch)
    return git(writer, "rev-parse", "HEAD")


def merged_agent_lesson(repo, tmp_path, batch_id, path, content, style="merge"):
    """A lesson the commit-maker wrote and a human merged: one batch whose claim writes
    `content` at `path` (repo-relative; `None` deletes it), finished as a PR by its own
    delivery object, then merged on the remote in `style`. Returns the commit-maker's
    commit."""
    writer = delivery(repo, ForgeHTTP())
    batch = writer.start_batch(batch_id, lanes=LANES)
    draft_file = batch.draft_root / path
    if content is None:
        draft_file.unlink()
    else:
        draft_file.parent.mkdir(parents=True, exist_ok=True)
        draft_file.write_bytes(content)
    sha = batch.commit(batch.change_set(), f"learning {batch_id}")
    writer.finish(batch)
    merge_on_remote(repo, tmp_path, batch.branch, style)
    return sha


def branch_tip(clone, branch):
    """The commit `refs/heads/<branch>` names in `clone`, or `None` when there is no such branch
    (a batch's branch exists from its first commit on)."""
    return _remote_tip(clone, branch)


def agent_blobs(cwd, rev, prefix="agent"):
    """Every blob under `prefix` at `rev`, by path below `prefix`, with its exact bytes (git's
    bytes, never a checkout's)."""
    names = git(cwd, "ls-tree", "-r", "--name-only", rev, "--", prefix).splitlines()
    return {name.removeprefix(f"{prefix}/"): git_bytes(cwd, "cat-file", "blob", f"{rev}:{name}")
            for name in names}


def batch_base(clone, batch):
    """The commit a batch's draft is judged against: its branch's tip, or the export commit
    before its first commit."""
    return branch_tip(clone, batch.branch) or batch.export.commit


def opened(result, number=7):
    """`result` of finish, deliver or revert is `opened` (a PR this call created), with the URL
    of PR `number` (any number when `None`); returns the URL."""
    assert result.status == "opened", result
    if number is not None:
        assert result.url.endswith(f"/pulls/{number}"), result.url
    return result.url


def still_open(result, url):
    """`result` of finish, deliver or revert is `open` (an open PR it found, none created),
    with `url`; returns the URL."""
    assert result.status == "open", result
    assert result.url == url, (result.url, url)
    return result.url


def remote_refs(remote):
    """Every ref of the remote but the forge's own `refs/pull/*`, with what it names."""
    return [line for line in git(remote, "for-each-ref", "--format=%(refname) %(objectname)").splitlines()
            if not line.startswith("refs/pull/")]


def push_object(repo, sha, ref):
    """Put `sha` (a commit of the tenant clone) on the remote under `ref`, as the forge holds a
    PR's head under `refs/pull/N/head`, whatever pushed it there."""
    git(repo[0].knowledge, "push", "-q", repo[1], f"{sha}:{ref}")


def index_entry(checkout, mode, path, *, blob=None, data=None):
    """Stage a raw tree entry (a link, a gitlink, an executable) the way git stores it."""
    if blob is None:
        blob = git_bytes(checkout, "hash-object", "-w", "--stdin", data=data).decode().strip()
    git(checkout, "update-index", "--add", "--cacheinfo", f"{mode},{blob},{path}")


def odd_entries(root):
    """Every entry below `root` that is neither a real directory nor a regular file."""
    return sorted(p.relative_to(root).as_posix() for p in Path(root).rglob("*")
                  if p.is_symlink() or not (p.is_dir() or p.is_file()))


def files_under(root):
    """Every regular file below `root`, by POSIX relative path, with its bytes; links and
    directories are not files (a link shows as its own `('link', target)` entry)."""
    out = {}
    for p in sorted(Path(root).rglob("*")):
        rel = p.relative_to(root).as_posix()
        if p.is_symlink():
            out[rel] = ("link", os.readlink(p))
        elif p.is_file():
            out[rel] = p.read_bytes()
    return out


def plain_file(path, data):
    """`path` is itself a regular file (not a link to one, not a FIFO) holding exactly `data`;
    nothing is opened unless it is."""
    return stat.S_ISREG(os.lstat(path).st_mode) and Path(path).read_bytes() == data


def plant_raw_commit(clone, ref, path, content, *, amend=False, base=None):
    """A commit the commit-maker did not make, written with the clone's own plumbing straight
    onto `ref` (no hook, no worktree involved): the tip's tree plus `path`, under the tip's
    exact message, author and committer, so nothing in the commit itself tells it apart.
    `amend` replaces the tip (same parents) instead of building on it; `base` is the tip to
    build on when `ref` does not exist yet (it is then created)."""
    listed = dict(line.split(" ", 1) for line in git(
        clone, "for-each-ref", "--format=%(refname) %(objectname)", ref).splitlines())
    existing = listed.get(ref)
    tip = existing or git(clone, "rev-parse", base)
    index = Path(clone) / ".git" / f"p3-plant-{os.getpid()}.index"
    env = {"GIT_INDEX_FILE": str(index)}
    git(clone, "read-tree", tip, env=env)
    blob = git_bytes(clone, "hash-object", "-w", "--stdin", data=content).decode().strip()
    git(clone, "update-index", "--add", "--cacheinfo", f"100644,{blob},{path}", env=env)
    tree = git(clone, "write-tree", env=env)
    index.unlink()
    who = git(clone, "log", "-1", "--format=%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI", tip).split("\x00")
    message = git_bytes(clone, "log", "-1", "--format=%B", tip)
    parents = git(clone, "log", "-1", "--format=%P", tip).split() if amend else [tip]
    planted = git_bytes(clone, "commit-tree", tree, *(a for p in parents for a in ("-p", p)),
                        data=message, env={
        "GIT_AUTHOR_NAME": who[0], "GIT_AUTHOR_EMAIL": who[1], "GIT_AUTHOR_DATE": who[2],
        "GIT_COMMITTER_NAME": who[3], "GIT_COMMITTER_EMAIL": who[4], "GIT_COMMITTER_DATE": who[5],
    }).decode().strip()
    git(clone, "update-ref", ref, planted, existing or "")
    return planted


#: A `reference-transaction` hook (git >= 2.28) for the clone: the first time a branch other
#: than `main` is moved to a commit other than `base`, it lays a commit the commit-maker did not
#: make on top (same message and identities, one extra allowed lesson), writing `marker`.
_PLANTING_HOOK = '''#!{python}
import os, subprocess, sys
from pathlib import Path
MARK = Path({marker!r})
if sys.argv[1] != "committed" or MARK.exists():
    sys.stdin.read()
    sys.exit(0)
ENV = {{k: v for k, v in os.environ.items() if not k.startswith("GIT_")}}
ENV.update({upkeep!r}, GIT_CONFIG_NOSYSTEM="1")
def git(*args, extra=None, data=None):
    return subprocess.run(["git", "--git-dir", {gitdir!r}, *args], input=data, check=True,
                          capture_output=True, env={{**ENV, **(extra or {{}})}}).stdout.decode().strip()
for line in sys.stdin.read().splitlines():
    old, new, ref = line.split(" ", 2)
    if not ref.startswith("refs/heads/") or ref == "refs/heads/main" or set(new) == {{"0"}} or new == {base!r}:
        continue
    MARK.write_text(ref + " " + new, encoding="utf-8")
    index = {{"GIT_INDEX_FILE": {index!r}}}
    git("read-tree", new, extra=index)
    blob = git("hash-object", "-w", "--stdin", data={content!r})
    git("update-index", "--add", "--cacheinfo", "100644," + blob + ",{path}", extra=index)
    tree = git("write-tree", extra=index)
    who = git("log", "-1", "--format=%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI", new).split("\\x00")
    message = git("log", "-1", "--format=%B", new)
    planted = git("commit-tree", tree, "-p", new, "-m", message, extra={{
        "GIT_AUTHOR_NAME": who[0], "GIT_AUTHOR_EMAIL": who[1], "GIT_AUTHOR_DATE": who[2],
        "GIT_COMMITTER_NAME": who[3], "GIT_COMMITTER_EMAIL": who[4], "GIT_COMMITTER_DATE": who[5]}})
    git("update-ref", ref, planted, new)
    break
'''


def install_planting_hook(clone, base, marker, path, content):
    hook = Path(clone) / ".git" / "hooks" / "reference-transaction"
    hook.parent.mkdir(exist_ok=True)
    hook.write_text(_PLANTING_HOOK.format(
        python=sys.executable, marker=str(marker), gitdir=str(Path(clone) / ".git"), base=base,
        upkeep=no_upkeep({}),
        index=str(Path(clone) / ".git" / "p3-hook.index"), content=content, path=path),
        encoding="utf-8")
    hook.chmod(0o755)


# ---------------------------------------------------------------------------------------
# Processes left behind
# ---------------------------------------------------------------------------------------

def running_in(*roots, naming=()):
    """`(pid, command line)` of every other process at work under `roots`: its working folder,
    a file it holds open, or a path on its command line is there (a git run with `--git-dir`
    from elsewhere, say); or its command line holds one of `naming` (a URL, say)."""
    folders = [os.path.realpath(root) for root in roots]

    def under(path):
        return any(path == folder or path.startswith(folder + os.sep) for folder in folders)
    found = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit() or int(entry) == os.getpid():
            continue
        proc = f"/proc/{entry}"
        try:
            with open(f"{proc}/cmdline", "rb") as f:
                argv = f.read(4096).decode("utf-8", "replace")
            held = [os.readlink(f"{proc}/cwd")]
            fds = os.listdir(f"{proc}/fd")
        except OSError:
            continue
        for fd in fds:
            with contextlib.suppress(OSError):
                held.append(os.readlink(f"{proc}/fd/{fd}"))
        if any(under(path) for path in held) or any(text in argv for text in (*folders, *naming)):
            found.append((int(entry), argv.replace("\0", " ").strip()))
    return found


def quiet(*roots, naming=(), seconds=60.0):
    """Wait until no other process runs under `roots` (or names one of `naming`); returns any
    still running at the end."""
    deadline = time.monotonic() + seconds
    while (running := running_in(*roots, naming=naming)) and time.monotonic() < deadline:
        time.sleep(0.01)
    return running


# ---------------------------------------------------------------------------------------
# A real smart-HTTP remote, so git's credential path actually runs
# ---------------------------------------------------------------------------------------

class Trickle:
    """What `on_service` returns to have the server answer that request slowly for ever: a 200
    with no length, then `size` bytes every `every` seconds until `stop` is set (or `limit`
    seconds pass), then the connection closes. About 50 KB/s by default: a forge that is slow
    but never below a client's low-speed limit, so only a wall timeout ends the wait."""

    def __init__(self, stop: threading.Event, size=1024, every=0.02, limit=60.0):
        self.stop, self.size, self.every, self.limit = stop, size, every, limit

    def send(self, handler):
        handler.send_response(200)
        handler.send_header("Content-Type", "application/octet-stream")
        handler.end_headers()
        deadline = time.monotonic() + self.limit
        with contextlib.suppress(OSError):
            while not self.stop.wait(self.every) and time.monotonic() < deadline:
                handler.wfile.write(b"0" * self.size)


class GitHTTP:
    """`git http-backend` behind HTTP Basic auth on 127.0.0.1. Local transport never consults
    a credential helper; this remote does, exactly as Forgejo does: an unauthenticated request
    gets 401, and git asks its helpers.

    `token` is what the server accepts; `refuse` holds services (`git-upload-pack`,
    `git-receive-pack`) whose authentication it rejects whatever is sent. `on_service(name)`
    runs once per service, at its first authenticated request, while the client waits; if it
    returns a `Trickle`, that request is answered by it instead of by the backend."""

    def __init__(self, project_root: Path, user="bot", token=TOKEN):
        self.project_root = project_root
        self.user, self.token = user, token
        self.refuse: set[str] = set()
        self.on_service = None
        #: `(service, token sent, accepted)` per request.
        self.seen: list[tuple[str, bool, bool]] = []
        #: The raw `Authorization` header of every request (`None` when absent).
        self.authorizations: list[str | None] = []
        self._fired: set[str] = set()
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                outer._serve(self)

            def do_POST(self):
                outer._serve(self)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    @staticmethod
    def _body(handler):
        if handler.headers.get("Transfer-Encoding", "").lower() == "chunked":
            chunks = []
            while True:
                size = int(handler.rfile.readline().strip(), 16)
                if size == 0:
                    handler.rfile.readline()
                    return b"".join(chunks)
                chunks.append(handler.rfile.read(size))
                handler.rfile.readline()
        return handler.rfile.read(int(handler.headers.get("Content-Length") or 0))

    def _serve(self, handler):
        parts = urlsplit(handler.path)
        service = parse_qs(parts.query).get("service", [""])[0] or parts.path.rsplit("/", 1)[-1]
        body = self._body(handler)
        expected = "Basic " + base64.b64encode(f"{self.user}:{self.token}".encode()).decode()
        sent = handler.headers.get("Authorization") == expected
        authorized = sent and service not in self.refuse
        with self._lock:
            self.seen.append((service, sent, authorized))
            self.authorizations.append(handler.headers.get("Authorization"))
            fire = authorized and service not in self._fired and self.on_service is not None
            if fire:
                self._fired.add(service)
        if not authorized:
            handler.send_response(401)
            handler.send_header("WWW-Authenticate", 'Basic realm="p3"')
            handler.send_header("Content-Length", "0")
            handler.end_headers()
            return
        if fire and isinstance(answer := self.on_service(service), Trickle):
            answer.send(handler)
            return
        env = {"PATH": os.environ.get("PATH", ""), "GIT_PROJECT_ROOT": str(self.project_root),
               "GIT_HTTP_EXPORT_ALL": "1", "GIT_CONFIG_NOSYSTEM": "1",
               "HOME": str(self.project_root), "PATH_INFO": parts.path,
               "QUERY_STRING": parts.query, "REQUEST_METHOD": handler.command,
               "CONTENT_TYPE": handler.headers.get("Content-Type", ""),
               "CONTENT_LENGTH": str(len(body)), "REMOTE_USER": self.user,
               "REMOTE_ADDR": "127.0.0.1", "GIT_HTTP_MAX_REQUEST_BUFFER": "100M"}
        if handler.headers.get("Content-Encoding"):
            env["HTTP_CONTENT_ENCODING"] = handler.headers["Content-Encoding"]
        if handler.headers.get("Git-Protocol"):
            env["GIT_PROTOCOL"] = handler.headers["Git-Protocol"]
        env = no_upkeep(env)
        # lint-raw-git: test-only smart-HTTP server; the CGI is the remote, not the code under test.
        proc = subprocess.run(["git", "http-backend"], input=body, env=env, capture_output=True,
                              check=False)
        head, _, payload = proc.stdout.partition(b"\r\n\r\n")
        status, headers = 200, []
        for line in head.split(b"\r\n"):
            if b":" not in line:
                continue
            name, value = (part.strip().decode() for part in line.split(b":", 1))
            if name.lower() == "status":
                status = int(value.split()[0])
            else:
                headers.append((name, value))
        handler.send_response(status)
        for name, value in headers:
            handler.send_header(name, value)
        handler.send_header("Content-Length", str(len(payload)))
        handler.end_headers()
        handler.wfile.write(payload)

    def rearm(self):
        """Let `on_service` fire again, once per service, from the next request on."""
        with self._lock:
            self._fired.clear()

    def authorized(self, service):
        """Some request for `service` carried the bot's token and was served."""
        return any(s == service and ok for s, _sent, ok in self.seen)

    def offered_and_refused(self, service):
        """Some request for `service` carried the bot's token and was refused anyway."""
        return any(s == service and sent and not ok for s, sent, ok in self.seen)


class GitConfigHome:
    """Where a credentialed test points git's per-user and system configuration: a private
    `HOME` (its `.gitconfig`), `XDG_CONFIG_HOME` (its `git/config`), `GIT_CONFIG_GLOBAL` and
    `GIT_CONFIG_SYSTEM`, all under the test's own folder and empty unless a test installs
    spies there. So no git the code under test runs can reach a developer's real helpers."""

    def __init__(self, base: Path):
        self.home = base / "home"
        self.xdg = self.home / "xdg"
        self.global_config = base / "global.gitconfig"
        self.system_config = base / "system.gitconfig"

    def files(self):
        return (self.home / ".gitconfig", self.xdg / "git" / "config", self.global_config,
                self.system_config)

    def create(self):
        for path in self.files():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("", encoding="utf-8")
        return self

    def env(self):
        return {"HOME": str(self.home), "XDG_CONFIG_HOME": str(self.xdg),
                "GIT_CONFIG_GLOBAL": str(self.global_config),
                "GIT_CONFIG_SYSTEM": str(self.system_config)}


def git_config_home(tmp_path) -> GitConfigHome:
    """The isolated configuration `http_repo` installs for `tmp_path`'s test."""
    return GitConfigHome(tmp_path / "git-config")


@pytest.fixture
def http_repo(tmp_path, monkeypatch):
    """Like `repo`, but `origin` is a real smart-HTTP remote demanding the bot's credential;
    the credential entry names that remote. Git's per-user and system configuration point at
    empty files under the test's folder (`git_config_home`), so a wrong implementation can
    reach only what a test installs there, never a developer's own credential helper.
    Yields `(tenant, bare remote, credentials, server)`."""
    for name, value in git_config_home(tmp_path).create().env().items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("GIT_CONFIG_NOSYSTEM", raising=False)
    root = tmp_path / "data"
    tenants.place_tenant(root, "blue")
    tenant = tenants.accept(root, "blue")
    clone = tenant.knowledge
    (tenant.agent / "lessons").mkdir()
    (tenant.agent / "lessons" / "seed.md").write_text("seed\n", encoding="utf-8")
    git(clone, "init", "-b", "main")
    git(clone, "config", "user.name", "P3")
    git(clone, "config", "user.email", "p3@test.invalid")
    git(clone, "add", ".")
    git(clone, "commit", "-m", "seed")
    served = tmp_path / "served"
    remote = served / "tenants" / "blue.git"
    remote.parent.mkdir(parents=True)
    git(tmp_path, "clone", "--bare", *BARE_NO_UPKEEP, clone, remote)
    server = GitHTTP(served)
    try:
        git(clone, "remote", "add", "origin", f"{server.url}/tenants/blue.git")
        git(clone, "fetch", remote, "+refs/heads/*:refs/remotes/origin/*")
        credentials = tenant.dir / "forge" / "git-credentials"
        credentials.parent.mkdir()
        credentials.write_text(f"http://bot:{TOKEN}@127.0.0.1:{server.server.server_address[1]}\n",
                               encoding="utf-8")
        credentials.chmod(0o600)
        yield tenant, remote, credentials, server
    finally:
        server.close()


# ---------------------------------------------------------------------------------------
# A later drain: a delivery opened in a fresh process
# ---------------------------------------------------------------------------------------

_LATER_SCRIPT = """
import json, sys
from pathlib import Path
from defender.tests import _tenants1106 as tenants
from defender.tests.tenant_1108_delivery._support import DEFENDER, ForgeHTTP, configured_origin, target
root, tenant_id, remote, verb, args = Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:]
mod = target()
tenant = tenants.accept(root, tenant_id)
http = ForgeHTTP(remote=remote, origin=configured_origin(tenant.knowledge))
out = {}
try:
    later = mod.TenantDelivery.open(tenant, defender_dir=DEFENDER, client=http.client)
    result = getattr(later, verb)(*args)
    status = result.status
    out["status"] = status if isinstance(status, str) else repr(status)
    out["url"] = getattr(result, "url", None)
except mod.DeliveryRefused as refused:
    out["refused"] = str(refused)
out["creates"] = http.creates
print(json.dumps(out))
"""


#: What a freshly started process (cron, systemd) inherits: the program search path and the
#: locale, nothing this process set or stored in its environment.
_FRESH_ENV_KEYS = ("PATH", "LANG", "LC_ALL", "LC_CTYPE")


def fresh_process_env(tenant, scratch: Path):
    """The environment of a process started afresh for `tenant`: an allowlist of this
    process's variables (never `os.environ` wholesale), the data root, this tree's imports,
    and git configuration isolated under `scratch`."""
    env = {key: os.environ[key] for key in _FRESH_ENV_KEYS if key in os.environ}
    env.update(GitConfigHome(scratch).create().env())
    env.update(PYTHONPATH=str(IMPORT_ROOT), PYTHONDONTWRITEBYTECODE="1",
               DEFENDER_DATA_ROOT=str(tenant.data_root))
    return env


def in_a_later_process(repo, verb, *args):
    """`verb(*args)` (`deliver` or `revert`) on a `TenantDelivery` opened for `repo`'s tenant in
    ANOTHER, freshly started process with its own forge double (backed by the same remote,
    as the real forge is) and a fresh environment, as a later drain would: nothing of this
    process's objects, memory or environment reaches it. Returns `{"status": ..., "url": ...}`
    (`url` `None` when the result has none) or `{"refused": ...}`, with `"creates"`, the PR
    requests it sent."""
    tenant, remote = repo[0], repo[1]
    scratch = Path(tenant.data_root).parent / f"later-{len(list(Path(tenant.data_root).parent.glob('later-*')))}"
    proc = subprocess.run([sys.executable, "-c", _LATER_SCRIPT, str(tenant.data_root), str(tenant.id),
                           str(remote), verb, *map(str, args)], capture_output=True, text=True,
                          env=fresh_process_env(tenant, scratch), timeout=300, check=False)
    assert proc.returncode == 0, f"the later process crashed: {proc.stderr}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


# ---------------------------------------------------------------------------------------
# The per-tenant lock, observed from another process
# ---------------------------------------------------------------------------------------

_LOCK_SCRIPT = """
import json, sys, time
from pathlib import Path
from defender.tests import _tenants1106 as tenants
from defender.tests.tenant_1108_delivery._support import target
root, tenant_id, mode = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
mod = target()
tenant = tenants.accept(root, tenant_id)
started = time.monotonic()
try:
    with mod.tenant_lock(tenant):
        if mode == "hold":
            Path(sys.argv[4]).write_text("held", encoding="utf-8")
            release = Path(sys.argv[5])
            while not release.exists() and time.monotonic() - started < 120:
                time.sleep(0.02)
except mod.LockBusy as busy:
    print(json.dumps({"busy": str(busy), "seconds": time.monotonic() - started}))
else:
    print(json.dumps({"free": True, "seconds": time.monotonic() - started}))
"""


def _lock_argv(tenant, mode, *extra):
    return [sys.executable, "-c", _LOCK_SCRIPT, str(tenant.data_root), str(tenant.id), mode,
            *map(str, extra)]


def _probe_env():
    return {**os.environ, "PYTHONPATH": str(IMPORT_ROOT)}


def lock_probe(tenant):
    """Try the tenant's lock from ANOTHER process (a lock's same-process semantics differ by
    primitive) and give it straight back: `{"free": True}` or `{"busy": <refusal>}`."""
    proc = subprocess.run(_lock_argv(tenant, "try"), capture_output=True, text=True,
                          env=_probe_env(), timeout=120, check=False)
    assert proc.returncode == 0, f"lock probe crashed: {proc.stderr}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


_GIT_OPTION_VALUES = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env"}


def git_subcommand(argv):
    """`(subcommand, argv)` of a spawned `git`, or `(None, argv)` for any other program."""
    args = shlex.split(argv) if isinstance(argv, str) else [os.fsdecode(a) for a in argv]
    if not args or os.path.basename(args[0]) != "git":
        return None, args
    rest = iter(args[1:])
    for arg in rest:
        if arg in _GIT_OPTION_VALUES:
            next(rest, None)
        elif not arg.startswith("-"):
            return arg, args
    return None, args


class LockAudit:
    """Probes the tenant lock from another process at chosen moments of THIS process: an
    audit hook passes every event to `pick(event, args)`, and whenever it names a label the
    lock is probed before the audited operation goes ahead (a spawn, an open, a rename).
    `probes` collects `(label, verdict)`; a probe that crashes is recorded, never raised into
    the code under test. Active only inside `with`; audit hooks cannot be removed."""

    def __init__(self, tenant, pick):
        self.tenant, self.pick = tenant, pick
        self.probes: list[tuple[str, dict]] = []
        self._active = False
        self._inside = threading.local()
        sys.addaudithook(self._audit)

    def _audit(self, event, args):
        if not self._active or getattr(self._inside, "on", False):
            return
        self._inside.on = True
        try:
            try:
                label = self.pick(event, args)
            except Exception as crash:  # noqa: BLE001 — recorded, judged by the caller
                self.probes.append(("pick", {"crashed": f"{event}: {crash!r}"}))
                return
            if label is not None:
                try:
                    verdict = lock_probe(self.tenant)
                except Exception as crash:  # noqa: BLE001 — recorded, judged by the caller
                    verdict = {"crashed": repr(crash)}
                self.probes.append((label, verdict))
        finally:
            self._inside.on = False

    def __enter__(self):
        self._active = True
        return self

    def __exit__(self, *exc):
        self._active = False


class LockHolder:
    """Holds the tenant's lock in another process, through the production lock, until exit."""

    def __init__(self, tenant, scratch: Path):
        self.tenant = tenant
        scratch.mkdir(parents=True, exist_ok=True)
        self.ready, self.release = scratch / "held", scratch / "release"
        self.proc = None

    def __enter__(self):
        self.proc = subprocess.Popen(_lock_argv(self.tenant, "hold", self.ready, self.release),
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                     env=_probe_env())
        deadline = time.monotonic() + 60
        while not self.ready.exists():
            if self.proc.poll() is not None or time.monotonic() > deadline:
                out, err = self.proc.communicate(timeout=10)
                raise AssertionError(f"the lock holder never held the lock: {out} {err}")
            time.sleep(0.02)
        return self

    @property
    def pid(self):
        return self.proc.pid

    def __exit__(self, *exc):
        self.release.write_text("go", encoding="utf-8")
        out, err = self.proc.communicate(timeout=60)
        assert self.proc.returncode == 0, err
        assert json.loads(out.strip().splitlines()[-1]).get("free") is True, out


def bounded(fn, *, seconds=30.0, fifos=()):
    """Run `fn` in a thread, failing instead of hanging: past `seconds`, anything blocked on
    one of `fifos` is released before the verdict (a reader opens and closes it, releasing a
    blocked writer; a writer does the same for a blocked reader). Returns
    `(result, exception, hung)`."""
    box = {}

    def run():
        try:
            box["result"] = fn()
        except BaseException as e:  # noqa: BLE001 — judged by the caller
            box["error"] = e
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(seconds)
    hung = thread.is_alive()
    if hung:
        for fifo in fifos:
            for flags in (os.O_RDONLY, os.O_WRONLY):
                with contextlib.suppress(OSError):
                    os.close(os.open(fifo, flags | os.O_NONBLOCK))
        thread.join(10)
    return box.get("result"), box.get("error"), hung
