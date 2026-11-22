"""#1618 contract machinery: tenant knowledge lives only in Forgejo (design r5, `.contract-first/1618-design-r5.md`).

The scene is built on what survives r5, with no production function r5 deletes: a bare remote served over smart HTTP
(`GitHTTP`), the forge fake (`ForgeHTTP`), the issuer fake (`VaultHTTP`), and a tenant directory (twin records plus the
forge wiring, `bind_forge`). Seeding is by hand (git plumbing against the bare remote), because today's way in is
`publish_placed` -> `TenantDelivery.publish`, which r5 deletes. Expected values come from the bare remote only
(`t.remote`, `t.origin_main()`, `half_at`), never from a clone, `exports/` or `current`.

Two scenes (`scene(..., decoy=)`):
- default: the upgrade step done (design "Upgrade"): `<T>` has no `knowledge/`, `exports/`, `current` or `knowledge.lock`;
  `main` is at the seed commit `t.commit`.
- `decoy=True`: today's clone (working tree holding `CLONE_ONLY_MARK`), `exports/<seed>/` and `current` are left in
  place, all at the seed commit, while the remote's `main` has moved on (`MERGED_MARK`): a reader still reading any of
  them shows it. `local_state(t)` lists them.

`t` is a `tenant_1108_p4._support.PublishedTenant` over a stand-in `tenant` (`id`, `tenant_root`): its `.remote`,
`.origin`, `.server` (`GitHTTP`), `.forge` (`ForgeHTTP`), `.vault`, `.directory`, `.data_root`, `.scratch`, `.commit`
(the seed), `.merge(files)`, `.origin_main()`, `.tenant_id` apply. Do not call `t.open_delivery`/`t.publish`/`t.admitted`:
they need a real accepted `Tenant`, which the scene does not make (r5's `Tenant` has no knowledge folder).
"""
from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx

from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.tenancy.tenant_1108_delivery._identity import VaultHTTP
from defender.tests.tenancy.tenant_1108_delivery._identity import token as issuer_token
from defender.tests.tenancy.tenant_1108_delivery._support import (
    BARE_NO_UPKEEP,
    DEFENDER,
    IMPORT_ROOT,
    ForgeHTTP,
    GitHTTP,
    git,
    merge_on_remote,
    push_to_remote,
)
from defender.tests.tenancy.tenant_1108_p4._support import (
    FIXTURE_TENANT_ID,
    PublishedTenant,
    bind_forge,
    committed_blobs,
    place_fixture,
)

# --- fixture content ----------------------------------------------------------------------------------------------

#: A lesson whose bytes differ between the seed and a later merge, and a settings mark likewise: which commit a reader
#: read is answerable from content alone.
LESSON = "agent/lessons/fixture-owner-before-close.md"
MARK_FILE = "settings/s-b-revision-mark.txt"
SEEDED_MARK = "K1618-SEEDED-REVISION-MARK"
MERGED_MARK = "K1618-MERGED-REVISION-MARK"
CLONE_ONLY_MARK = "K1618-CLONE-WORKTREE-ONLY-MARK"
#: A full commit id Forgejo does not serve.
ABSENT_COMMIT = "fedcba9876543210" * 2 + "fedcba98"


def lesson_text(mark: str) -> str:
    return ("---\nname: fixture-owner-before-close\ndescription: Made-up fixture lesson "
            f"{mark} - look up the host's inventory owner before closing.\n"
            "telemetry_source: [cmdb]\nattack_phase: [discovery]\n"
            "source_signature: [fixture-unclaimed-host]\nsource_finding_ids:\n"
            "  - fixture-run-1/1\ncreated_at: 2026-10-01T00:00:00Z\n---\n\n"
            f"Fixture content for tests (#1618). {mark}\n")


def mark_text(mark: str) -> str:
    return f'K1618_REVISION_MARK="{mark}"\n'


def marks(mark: str) -> dict[str, str]:
    """The two files that carry `mark` (a lesson in `agent/`, a plain file in `settings/`)."""
    return {LESSON: lesson_text(mark), MARK_FILE: mark_text(mark)}


# --- the scene -----------------------------------------------------------------------------------------------------

def tenant_root(t: Any) -> Path:
    """`<T>`."""
    return Path(location_path(t.data_root)) / t.tenant_id


def _plant_decoy(t: Any) -> None:
    """Today's `exports/<seed>/` and `current` (seeded by hand: the way in today is `publish_locked`) and a clone-only
    working-tree mark (never committed)."""
    root = tenant_root(t)
    export = root / "exports" / t.commit
    for half in ("agent", "settings"):
        shutil.copytree(Path(t.clone) / half, export / half, symlinks=True)
    (root / "exports" / "current").write_text(f"{t.commit}\n", encoding="utf-8")
    (Path(t.clone) / LESSON).write_text(lesson_text(CLONE_ONLY_MARK), encoding="utf-8")
    (Path(t.clone) / MARK_FILE).write_text(mark_text(CLONE_ONLY_MARK), encoding="utf-8")


def _retire_local_state(t: Any) -> None:
    """The design's upgrade step: delete `<T>/knowledge`, `<T>/exports/` and `<T>/knowledge.lock`."""
    root = tenant_root(t)
    for name in ("knowledge", "exports"):
        shutil.rmtree(root / name, ignore_errors=True)
    (root / "knowledge.lock").unlink(missing_ok=True)


@contextlib.contextmanager
def scene(tmp_path: Path, data_root: Path, *, decoy: bool = False) -> Iterator[PublishedTenant]:
    """A tenant r5's code can serve with no clone, `exports/` or `current`; `decoy=True` leaves a stale copy of them."""
    tenant_id = FIXTURE_TENANT_ID
    clone = Path(place_fixture(data_root, tenant_id, files=marks(SEEDED_MARK)))
    git(clone, "init", "-b", "main")
    git(clone, "config", "user.name", "K1618 fixture")
    git(clone, "config", "user.email", "k1618@test.invalid")
    git(clone, "add", "-A")
    git(clone, "commit", "-m", "tenant content")
    seed = git(clone, "rev-parse", "HEAD")
    scratch = tmp_path / "forge"
    remote = scratch / "tenants" / "fixture.git"
    remote.parent.mkdir(parents=True)
    git(scratch, "clone", "--bare", *BARE_NO_UPKEEP, clone, remote)
    server = GitHTTP(scratch, token=issuer_token(tenant_id))
    try:
        origin = f"{server.url}/tenants/fixture.git"
        git(clone, "remote", "add", "origin", origin)
        git(clone, "fetch", remote, "+refs/heads/*:refs/remotes/origin/*")
        vault = VaultHTTP(tenant_id)
        stand_in = SimpleNamespace(id=tenant_id, tenant_root=Path(location_path(data_root)) / tenant_id, knowledge=clone)
        t = PublishedTenant(
            tenant=stand_in, data_root=data_root, clone=clone, remote=remote, origin=origin,
            forge=ForgeHTTP(remote=remote, origin=origin), vault=vault, identity=vault.identity(), server=server,
            scratch=scratch, export=SimpleNamespace(commit=seed), p3=(stand_in, remote, None))
        bind_forge(t)
        t.directory  # noqa: B018 — the twin's records are seeded from the folder while it is still there
        if decoy:
            _plant_decoy(t)
            advance_main(t, MERGED_MARK)
        else:
            _retire_local_state(t)
        yield t
    finally:
        server.close()


# --- the bare remote: write and read -----------------------------------------------------------------------------

def advance_main(t: Any, mark: str | None = None, *, files: dict[str, Any] | None = None, message: str = "human merge") -> str:
    """Land one commit on the remote's `main` holding `mark`'s lesson and settings files, plus `files`; return it."""
    wanted = {**(marks(mark) if mark is not None else {}), **(files or {})}

    def edit(checkout: Path) -> None:
        for rel, content in wanted.items():
            path = Path(checkout) / rel
            if content is None:
                path.unlink()
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)

    return push_to_remote(t.p3, t.scratch, edit, message)


def half_at(t: Any, commit: str, half: str) -> dict[str, bytes]:
    """`half/`'s regular blobs at `commit`, read from the bare remote, keyed relative to `half/`."""
    return {path.removeprefix(f"{half}/"): data for path, data in committed_blobs(t.remote, commit, half).items()}


def tree_bytes(root: Path) -> dict[str, bytes]:
    """Every regular file under `root` (links skipped), keyed by its path relative to `root`."""
    root = Path(root)
    return {p.relative_to(root).as_posix(): p.read_bytes()
            for p in sorted(root.rglob("*")) if p.is_file() and not p.is_symlink()}


def push_branch(t: Any, branch: str, files: dict[str, Any], *, base: str = "main") -> str:
    """Make `branch` on the remote: one commit on `base` writing `files` (`None` deletes); return the commit."""
    work = t.scratch / f"branch-{branch.replace('/', '-')}"
    git(t.scratch, "clone", t.remote, work)
    git(work, "checkout", "-b", branch, f"origin/{base}")
    for rel, content in files.items():
        path = work / rel
        if content is None:
            path.unlink()
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)
    git(work, "add", "-A")
    git(work, "commit", "-m", f"batch {branch}")
    git(work, "push", "origin", f"{branch}:refs/heads/{branch}")
    return git(work, "rev-parse", "HEAD")


def open_pr(t: Any, branch: str) -> int:
    """Open a PR for `branch` on the forge fake (as the delivery does); the remote then holds `refs/pull/<n>/head`."""
    base = t.origin.split("/tenants/")[0]
    answer = t.forge.client.post(f"{base}{t.forge.api}/pulls", json={"head": branch, "base": "main", "title": branch})
    assert answer.status_code == 201, answer.text
    return int(answer.json()["number"])


def merge_pr(t: Any, branch: str, *, style: str = "merge", delete_branch: bool = True) -> str:
    """A human merging `branch`'s PR; the head branch is deleted as Forgejo's merge option does, its `refs/pull/<n>/head` stays."""
    return merge_on_remote(t.p3, t.scratch, branch, style, delete_branch=delete_branch)


def remote_ref(t: Any, ref: str) -> str | None:
    """What `ref` names on the bare remote, or None."""
    return git(t.remote, "for-each-ref", "--format=%(objectname)", ref) or None


# --- git over HTTP as a client (the fake's fidelity; not the code under test) -------------------------------------

def http_git(t: Any, cwd: Path, *args: str, protocol: int | None = None) -> str:
    """`git <args>` in `cwd` with the scene's bearer token and a private home; raises CalledProcessError on failure."""
    home = Path(cwd) / ".." / ".k1618-home"
    home.mkdir(exist_ok=True)
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(home.resolve()), "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0", "GIT_AUTHOR_NAME": "k", "GIT_AUTHOR_EMAIL": "k@x.invalid",
           "GIT_COMMITTER_NAME": "k", "GIT_COMMITTER_EMAIL": "k@x.invalid"}
    config = ["-c", f"http.extraHeader=Authorization: Bearer {t.server.token}", "-c", "credential.helper="]
    if protocol is not None:
        config += ["-c", f"protocol.version={protocol}"]
    # lint-raw-git: test-only client of the fake smart-HTTP remote; the remote is the fixture, not the code under test.
    done = subprocess.run(["git", *config, *args], cwd=cwd, env=env, capture_output=True, text=True, check=True, timeout=60)
    return done.stdout.strip()


def fetch_by_id(t: Any, into: Path, commit: str) -> str:
    """`git -c protocol.version=2 fetch --depth 1 <origin> <commit>` into the bare repository `into` (made if absent)."""
    if not (Path(into) / "HEAD").exists():
        Path(into).mkdir(parents=True, exist_ok=True)
        git(into, "init", "--bare", "--template=")
    http_git(t, into, "fetch", "--depth", "1", "--no-tags", t.origin, commit, protocol=2)
    return git(into, "cat-file", "-t", commit)


# --- failures ------------------------------------------------------------------------------------------------------

def forge_down(t: Any) -> None:
    """Forgejo unreachable: every forge API request raises a connect error and the git listener is closed (refused)."""

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("forge unreachable", request=request)

    t.forge.fault = down
    t.server.close()


# --- what exists on the host ---------------------------------------------------------------------------------------

def tenant_entries(t: Any) -> list[str]:
    """The names directly under `<T>`."""
    root = tenant_root(t)
    return sorted(p.name for p in root.iterdir()) if root.is_dir() else []


def local_state(t: Any) -> list[str]:
    """Which of today's tenant-wide entries (`knowledge`, `exports`, `knowledge.lock`) exist under `<T>`."""
    root = tenant_root(t)
    return sorted(n for n in ("knowledge", "exports", "knowledge.lock") if (root / n).exists() or (root / n).is_symlink())


def repo_scratch(t: Any) -> list[str]:
    """The names directly under `<data root>/.repo-scratch/` (none when it does not exist)."""
    root = Path(location_path(t.data_root)) / ".repo-scratch"
    return sorted(p.name for p in root.iterdir()) if root.is_dir() else []


# =====================================================================================================================
# Seams for production names that do not exist yet. Each imports lazily (so collection never fails) and calls.
# =====================================================================================================================

# FORCED seam list, ALL in this one place (production spellings are the implementer's; one name per seam, binding):
#   every reader of a knowledge copy takes ONE seam shape, `fetch(tenant_id, dest, *, data_root, commit=None) -> report line`
#   (`ok <commit>` | `refused <transient|lasting> <reason>`), default = the real fetch child (`Fetch` below, `K.child_report`):
#   - `run.main(..., fetch=)`         (replaces slice A's forced `publish=`; `_slice_a.Publish` is the same shape over the launcher);
#   - `job_host.main(..., fetch=)`    the learning helper, readiness and the other helper kinds; also the `ProcessHelper` driver;
#   - `HostActor(..., fetch=)`        onboarding's `prepare` (replaces `publish=`);
#   - `<operator tool>.main(argv, *, directory=None, fetch=None)` for the lessons page, tracer, policy CLI, workspace map, and
#     the branch launcher `cli.learning.branch.main(..., fetch=)`; `fetch=None` is production (the tool runs the child). The
#     tool/launcher process mints no credential itself (O8): there is no `identity=` seam any more.
#   - the judge: no seam of its own; in a job container its default copy path is the helper's `copy.make(commit=)` over the
#     socket `job_socket.SOCKET_ENV` names, and a refusal surfaces as `job_socket.Refused` (code and reason from the helper).
#   Other FORCED names: `fetch_copy` / `fetch_child_main` / `sweep_dead_owners` (below), `<T>/run-knowledge/<run_id>` owner record
#   written before the rename, `.repo-scratch/<tenant id>.owner-...` (owned_temporary's grammar), the launcher
#   `investigation.publish_launch.launch_publish(..., dest=, commit=, command=)`.

#: FORCED: the in-process entry lives beside today's `publish_for_run` (`version_control/publish.py`), as a new module.
FETCH_MODULE = "defender.learning.author.version_control.fetch"
#: FORCED: the child's `python -m` module, beside today's `publish_child` (`version_control/publish_child.py`).
CHILD_MODULE = "defender.learning.author.version_control.fetch_child"
#: FORCED: the sweep sits with the owner helpers (`tenancy/_owner.py`, home of `owned_temporary`/`owner_alive`).
SWEEP_MODULE = "defender.tenancy._owner"


def _attr(module: str, name: str) -> Callable[..., Any]:
    import importlib

    return getattr(importlib.import_module(module), name)


def fetch_copy(t: Any, dest: Path, commit: str | None = None, **seams: Any) -> str:
    """Design flow 1, in-process: fill the empty `dest` with `agent/` and `settings/` at `main` (or `commit`); return the commit.

    FORCED: `fetch_copy(tenant_id, dest, commit=None, *, data_root, directory, identity)` (the design names `tenant`; the
    id plus today's `publish_for_run` seams `data_root=`/`directory=`/`identity=`). A refusal raises: its type is
    unnamed, so observe refusals through `child_report`."""
    named = {"data_root": t.data_root, "directory": t.directory, "identity": t.vault.identity(), **seams}
    return _attr(FETCH_MODULE, "fetch_copy")(t.tenant_id, dest, commit, **named)


@dataclass(frozen=True)
class Report:
    """A real fetch child's outcome: exit status, its one report line, stderr."""

    rc: int
    line: str
    stderr: str

    @property
    def word(self) -> str:
        """`ok` or `refused`."""
        return self.line.partition(" ")[0]

    @property
    def commit(self) -> str:
        """The commit an `ok` line names."""
        assert self.word == "ok", self
        return self.line.split()[1]

    @property
    def klass(self) -> str:
        """`transient` or `lasting` for a `refused` line."""
        assert self.word == "refused", self
        return self.line.split()[1]

    @property
    def reason(self) -> str:
        """The reason words after the class of a `refused` line."""
        assert self.word == "refused", self
        return self.line.partition(" ")[2].partition(" ")[2].strip()


#: The child process a test spawns: the production child's `main` with the fakes rebuilt inside the subprocess (the issuer
#: fake's fixed clock mints the token the test's `GitHTTP` accepts), forwarding the argv the caller appended. FORCED: the
#: main is `fetch_child_main(argv, *, directory, identity)` in `CHILD_MODULE`, and argv `<tenant id> --data-root <root>
#: --dest <folder> [--commit <id>]`.
_CHILD_WRAPPER = '''
import json, sys
from pathlib import Path

spec = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
from defender.tests.support.tenancy._active1214 import active_directory
from defender.tests.tenancy.tenant_1108_delivery._identity import VaultHTTP
import importlib

main = importlib.import_module(spec["module"]).fetch_child_main
directory = active_directory(Path(spec["data_root"]), spec["tenant_id"], origin=spec["origin"])
sys.exit(main(sys.argv[2:], directory=directory, identity=VaultHTTP(spec["tenant_id"]).identity()))
'''


def child_report(t: Any, tmp_path: Path, dest: Path, commit: str | None = None, *, timeout: float = 120.0) -> Report:
    """Run the fetch child as a real subprocess for `dest` (made by the caller) and return its report line (`ok <commit>` /
    `refused <transient|lasting> <reason>`). FORCED: see `_CHILD_WRAPPER`."""
    wrapper = tmp_path / "fetch_child_wrapper.py"
    wrapper.write_text(_CHILD_WRAPPER, encoding="utf-8")
    spec = tmp_path / f"fetch_child_spec-{abs(hash(str(dest)))}.json"
    spec.write_text(json.dumps({"module": CHILD_MODULE, "tenant_id": t.tenant_id, "origin": t.origin,
                                "data_root": str(location_path(t.data_root))}), encoding="utf-8")
    argv = [t.tenant_id, "--data-root", str(location_path(t.data_root)), "--dest", str(dest)]
    if commit is not None:
        argv += ["--commit", commit]
    env = {**os.environ, "PYTHONPATH": str(IMPORT_ROOT)}
    done = subprocess.run([sys.executable, str(wrapper), str(spec), *argv], cwd=IMPORT_ROOT, env=env,  # noqa: S603
                          capture_output=True, text=True, check=False, timeout=timeout)
    lines = [line for line in done.stdout.splitlines() if line.strip()]
    return Report(done.returncode, lines[-1] if lines else "", done.stderr)


class Fetch:
    """THE fetch seam, one shape for every reader (design flows 1-4): `fetch(tenant_id, dest, *, data_root, commit=None) -> line`,
    the line being the child's one report (`ok <commit>` | `refused <transient|lasting> <reason>`).

    It runs the REAL fetch child (`child_report`) against the scene's bare remote over its real listener; it is a recorder, not a
    fake. Faults are made only by remote state (`forge_down`, `advance_main`, an absent commit, `server.refuse`): nothing here
    answers a line of its own. `calls` records each ask (tenant, dest, data_root, commit, whether `dest` was an empty folder, the
    line answered). `once(arm, heal)` queues a remote-state fault for the next call only: `arm()` runs before the child is
    spawned and `heal()` after it reported."""

    def __init__(self, t: Any, work: Path | None = None, *, origin_of: Callable[[str], str] | None = None,
                 before: Callable[[str], None] | None = None) -> None:
        import tempfile

        self.t = t
        self.work = Path(work) if work is not None else Path(tempfile.mkdtemp(prefix="fetch-seam-1618-"))
        self.origin_of = origin_of or (lambda _tenant: t.origin)
        self.before = before
        self.calls: list[dict[str, Any]] = []
        self.faults: list[tuple[Callable[[], Any], Callable[[], Any]]] = []

    def once(self, arm: Callable[[], Any], heal: Callable[[], Any] = lambda: None) -> None:
        self.faults.append((arm, heal))

    def __call__(self, tenant_id: Any, dest: Path, *, data_root: Any, commit: str | None = None, **_kw: Any) -> str:
        dest = Path(dest)
        call = {"tenant": str(tenant_id), "dest": dest, "data_root": Path(location_path(data_root)), "commit": commit,
                "was_empty_dir": dest.is_dir() and not dest.is_symlink() and not any(dest.iterdir()), "line": None}
        self.calls.append(call)
        arm, heal = self.faults.pop(0) if self.faults else (lambda: None, lambda: None)
        if self.before is not None:
            self.before(str(tenant_id))
        arm()
        self.work.mkdir(parents=True, exist_ok=True)
        folder = self.work / f"call-{len(self.calls)}"
        folder.mkdir()
        scene = SimpleNamespace(tenant_id=str(tenant_id), origin=self.origin_of(str(tenant_id)), data_root=data_root)
        try:
            call["line"] = child_report(scene, folder, dest, commit).line
        finally:
            heal()
            shutil.rmtree(folder, ignore_errors=True)
        return call["line"]


def fetch_seam(t: Any, work: Path | None = None, **kw: Any) -> Fetch:
    """The scene's fetch seam (see `Fetch`)."""
    return Fetch(t, work, **kw)


def sweep(t: Any) -> None:
    """Flow 8, host-side: remove dead owners' entries under `<T>/run-knowledge/`, `<T>/drafts/`, `<data root>/.repo-scratch/`.

    FORCED: `sweep_dead_owners(data_root, tenant_id)` in `SWEEP_MODULE` (today's of that name takes a `Tenant` and walks
    two roots)."""
    _attr(SWEEP_MODULE, "sweep_dead_owners")(t.data_root, t.tenant_id)


def owned_dest(parent: Path, prefix: str = "k1618") -> Path:
    """Make the empty folder `parent/<owned_temporary(prefix)>` (parent made if absent) and return it: a destination
    owned by this process, as design flow 1's caller makes it. `owned_temporary` exists today (`tenancy/_owner.py`)."""
    from defender.tenancy._owner import owned_temporary

    parent = Path(parent)
    parent.mkdir(parents=True, exist_ok=True)
    dest = parent / owned_temporary(prefix)
    dest.mkdir()
    return dest


__all__ = ["DEFENDER"]
