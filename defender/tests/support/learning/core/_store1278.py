"""#1278 sketch: the learning store as tests drive and observe it, and the tick's test seams.

The store under test is `defender.learning.store.LearningStore(dsn, **knobs)`: SQLAlchemy async over
PostgreSQL schema `learning`, tenant id the first positional argument of every verb (as `JobStore`).
Nothing here implements store policy: helpers open the store, call one verb, read one view, lapse a
lease by the database's clock, and record what a curator step saw. The target is imported inside each
helper, so a missing module is a per-test red, never a collection error.
"""
from __future__ import annotations

import importlib
import json
import os
import shutil
import signal
import subprocess
import time
from collections.abc import AsyncIterator, Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import anyio
import pytest

from defender.tests.support.shared._postgres1339 import execute, migrated_database  # noqa: F401 — re-exported for `world`

#: The lane the findings kinds feed (design r8: lane follows from kind).
AUTHOR_LANE = "author"
#: The lead lane (DrainLabel `lead_author`).
LEAD_LANE = "lead_author"
#: The tick reads its store from the same variable the worker's children read their tenant records from.
DSN_ENV = "DEFENDER_DATABASE_DSN"
#: Store knobs reach the tick as env vars read once at tick start (seam: interface.md, Tick wiring).
LEASE_ENV = "DEFENDER_LEARNING_LEASE_SECONDS"
GRACE_ENV = "DEFENDER_LEARNING_GRACE_SECONDS"
RENEW_ENV = "DEFENDER_LEARNING_RENEW_SECONDS"
#: Item kinds of the author lane (design r8: lane follows from kind).
FINDING = "finding"
QUESTIONER = "questioner_finding"
#: Every kind due at one waiting item: the thresholds a test passes when it is not about thresholds.
ONE = {"finding": 1, "questioner_finding": 1, "pitfall": 1, "curation_request": 1}


def store_mod() -> Any:
    return importlib.import_module("defender.learning.store")


@asynccontextmanager
async def learning_store(dsn: str, **knobs: Any) -> AsyncIterator[Any]:
    """The store under test on `dsn`, closed after. `knobs` (sketch): `lease`, seconds a claim or
    renewal holds a batch, counted by the database's clock."""
    store = store_mod().LearningStore(dsn, **knobs)
    try:
        yield store
    finally:
        await store.close()


def call(dsn: str, verb: str, *args: Any, **kw: Any) -> Any:
    """One store verb from sync code (a drain-level test), on a store of its own, in a thread of its
    own: a curator step's observation must not depend on whether the drain runs an event loop."""
    async def go() -> Any:
        async with learning_store(dsn) as store:
            return await getattr(store, verb)(*args, **kw)
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(anyio.run, go).result()


def work(dsn: str, tenant_id: str) -> dict[str, Any]:
    """O2's view of `tenant_id`'s items, by item key."""
    return {item.key: item for item in call(dsn, "work", tenant_id)}


def batches(dsn: str, tenant_id: str) -> list[Any]:
    return list(call(dsn, "batches", tenant_id))


def lapse_lease(dsn: str, batch_id: str, *, past_grace: bool = True) -> None:
    """The batch's lease ran out by the database's clock: an hour ago (`past_grace`, beyond any
    grace a test sets), or one second ago, within any grace of ten seconds or more.
    Columns `learning.batches.id` and `lease_expiry` (interface.md)."""
    ago = "interval '1 hour'" if past_grace else "interval '1 second'"
    execute(dsn, f"UPDATE learning.batches SET lease_expiry = now() - {ago} WHERE id = %s", (batch_id,))


def lease_seconds_left(dsn: str, batch_id: str) -> float:
    """Seconds until the batch's lease ends by the database's clock (negative: it ended)."""
    [(left,)] = execute(dsn, "SELECT EXTRACT(EPOCH FROM (lease_expiry - now())) FROM learning.batches WHERE id = %s",
                        (batch_id,))
    return float(left)


def finding(fid: str, *, run_id: str | None = None) -> dict[str, Any]:
    """A defender finding row the lessons gate admits (`_drain719.finding_row`)."""
    from defender.tests.support.learning.curation._drain719 import finding_row

    return finding_row(fid, run_id=run_id or f"run-{fid}")


def world_finding(fid: str) -> dict[str, Any]:
    """A questioner-channel row (a design world finding) the store admits as kind `questioner_finding`."""
    from defender.tests.support.learning.curation._spec773 import world_row

    return world_row(fid)


def oid(n: int) -> str:
    """A well-formed (fabricated) object id, for a store-level test that records a commit with no git behind it."""
    return f"{n:040x}"


def changes_of(*paths: str) -> list[tuple[str, str | None, str | None]]:
    """A commit's changes as the commit-maker records them: `(path, blob at base, blob left)`, created here
    (absent at base). Shape follows today's record row (`record._Made.changes`)."""
    return [(path, None, oid(900 + i)) for i, path in enumerate(paths)]


async def publish(store: Any, tenant: str, *ids: str, kind: str = FINDING, run: str = "run-1") -> Any:
    """Publish one row per id as `kind`, in one call."""
    make = world_finding if kind == QUESTIONER else finding
    return await store.publish_findings(tenant, run, [make(i) for i in ids], kind=kind)


async def claim(store: Any, tenant: str, *, owner: str = "host-a", thresholds: Mapping[str, int] = ONE) -> Any:
    return await store.claim(tenant, AUTHOR_LANE, owner=owner, thresholds=thresholds)


def lesson_citing(*finding_ids: str) -> str:
    from defender.tests.support.learning.curation._spec773 import lesson

    return lesson(*finding_ids)


class LessonWriter:
    """The drain's `trigger_author` seam as a curator that writes `lessons` (name -> text) into its
    batch's draft lane and commits them once per batch through the batch's own commit-maker.
    `before_commit(batch)` runs between the write and the commit, `after_commit(batch)` after it (an
    observation or a fault).
    Records the batches it served and each commit refusal; a refusal is re-raised, as a curator's
    would be. It ignores what else the drain hands it (the sketch pins only `batch=`)."""

    def __init__(self, lessons: dict[str, str], *, before_commit: Callable[[Any], None] | None = None,
                 after_commit: Callable[[Any], None] | None = None) -> None:
        self.lessons = lessons
        self.before_commit = before_commit
        self.after_commit = after_commit
        self.served: list[str] = []
        self.commits: list[str] = []
        self.refused: list[BaseException] = []

    def __call__(self, *_args: Any, batch: Any, **_kw: Any) -> None:
        if batch.id in self.served:
            return
        self.served.append(batch.id)
        for name, text in self.lessons.items():
            target = Path(batch.draft_root) / "agent" / "lessons" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        if self.before_commit is not None:
            self.before_commit(batch)
        try:
            self.commits.append(batch.commit(batch.change_set(), f"learning: batch {batch.id}"))
        except BaseException as refused:
            self.refused.append(refused)
            raise
        if self.after_commit is not None:
            self.after_commit(batch)


def files_under(root: Path) -> dict[str, bytes]:
    """Every regular file below `root` (relative path -> bytes); `{}` when `root` is absent."""
    if not root.is_dir():
        return {}
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


# --- the tick in a child process: a stop is delivered to a process that is not the pytest worker ----------------


def blocked_in_subprocess(marker: Path, seconds: int = 300) -> Callable[[Any], None]:
    """A curator-step hook that blocks in a child process (not a Python sleep): it starts `sleep`, writes the
    sleeper's pid to `marker`, and waits for it. Only a signal, not the clock, ends it within a test's bound."""
    def block(_batch: Any) -> None:
        sleeper = subprocess.Popen(["sleep", str(seconds)])  # noqa: S603, S607 — a test's own blocking child
        marker.write_text(str(sleeper.pid), encoding="utf-8")
        sleeper.wait()
    return block


def await_file(path: Path, *, seconds: float = 120.0) -> str:
    """The text of `path` once it exists (a child's marker), else a test failure naming the wait."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.is_file() and path.stat().st_size:
            return path.read_text(encoding="utf-8")
        time.sleep(0.05)
    raise AssertionError(f"{path} was never written within {seconds} s")


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").rsplit(")", 1)[1].split()[0] != "Z"


class TickChild:
    """`body()` run in a forked child of the test process, so the world's in-process fakes (the forge, the issuer)
    are the child's too and a signal sent to `pid` reaches the child, never the pytest worker. The child writes
    `{"rc": n}` or `{"raised": "<ExceptionType>"}` to `result` and leaves through `os._exit`; `wait()` returns it.
    A child still running at `wait`'s bound is killed and the test fails."""

    def __init__(self, body: Callable[[], Any], result: Path) -> None:
        self.result = result
        self.pid = os.fork()
        if self.pid == 0:  # pragma: no cover — runs in the forked child
            code = 1
            try:
                try:
                    out: dict[str, Any] = {"rc": body()}
                except BaseException as stopped:  # noqa: BLE001 — the child reports how it ended
                    out = {"raised": type(stopped).__name__}
                result.write_text(json.dumps(out), encoding="utf-8")
                code = 0
            finally:
                os._exit(code)

    def signal(self, signum: int) -> None:
        os.kill(self.pid, signum)

    def terminate(self) -> None:
        self.signal(signal.SIGTERM)

    def wait(self, *, seconds: float = 60.0) -> dict[str, Any]:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            done, _status = os.waitpid(self.pid, os.WNOHANG)
            if done:
                return json.loads(self.result.read_text(encoding="utf-8")) if self.result.is_file() else {"raised": "no-result"}
            time.sleep(0.05)
        os.kill(self.pid, signal.SIGKILL)
        os.waitpid(self.pid, 0)
        raise AssertionError(f"the child tick did not end within {seconds} s of its stop")


def kill_if_alive(*pids: int) -> None:
    for pid in pids:
        if alive(pid):
            os.kill(pid, signal.SIGKILL)


def forget_local_branch(clone: Path, branch: str, *, drafts: Path | None = None) -> None:
    """The clone as a replacement host's fresh one: no local `branch`, no remote-tracking ref, no worktree on it, and
    (`drafts`: the tenant's drafts folder) no draft. The branch stays on the origin."""
    from defender.tests.tenancy.tenant_1108_p4._support import git

    for line in git(clone, "worktree", "list", "--porcelain").splitlines():
        if line.startswith("worktree ") and Path(line.split(" ", 1)[1]).resolve() != clone.resolve():
            git(clone, "worktree", "remove", "--force", line.split(" ", 1)[1])
    git(clone, "worktree", "prune")
    if drafts is not None and drafts.is_dir():
        for draft in drafts.iterdir():
            shutil.rmtree(draft, ignore_errors=True)
    if git(clone, "for-each-ref", f"refs/heads/{branch}"):
        git(clone, "branch", "-D", branch)
    if git(clone, "for-each-ref", f"refs/remotes/origin/{branch}"):
        git(clone, "update-ref", "-d", f"refs/remotes/origin/{branch}")


def foreign_commit_on(remote: Path, branch: str, scratch: Path) -> str:
    """A commit nobody of ours made, pushed onto `branch` of the bare `remote` from a scratch clone; its id."""
    from defender.tests.tenancy.tenant_1108_p4._support import git

    work = scratch / "foreign-clone"
    git(scratch, "clone", "--quiet", str(remote), str(work))
    git(work, "config", "user.name", "someone else")
    git(work, "config", "user.email", "else@test.invalid")
    git(work, "checkout", "--quiet", branch)
    (work / "agent").mkdir(exist_ok=True)
    (work / "agent" / "foreign.md").write_text("pushed by hand\n", encoding="utf-8")
    git(work, "add", "-A")
    git(work, "commit", "--quiet", "-m", "by hand")
    git(work, "push", "--quiet", "origin", f"HEAD:refs/heads/{branch}")
    return git(work, "rev-parse", "HEAD")


# --- the tick's world, shared by the tick and revert files ---------------------------------------------------------


@pytest.fixture
def world(p4_tenant, migrated_database, monkeypatch, tmp_path):  # noqa: F811 — fixtures imported by the test module
    """The p4 tenant bound to its forge, active in the database the tick's (and the revert CLI's) store reads, both
    curators waking at one item. A lease of ten minutes with five of grace and a renewer that never fires, so only a
    case that lapses a lease, or sets a short renewal itself, sees one end."""
    from types import SimpleNamespace

    from defender.tests.support.jobs._jobs1342 import register_tenant
    from defender.tests.tenancy.tenant_1108_p4._drain_support import drain_paths, product_repo
    from defender.tests.tenancy.tenant_1108_p4._support import bind_forge

    t = p4_tenant
    bind_forge(t)
    register_tenant(migrated_database, t.tenant_id)
    monkeypatch.setenv(DSN_ENV, migrated_database)
    monkeypatch.setenv(LEASE_ENV, "600")
    monkeypatch.setenv(GRACE_ENV, "300")
    monkeypatch.setenv(RENEW_ENV, "600")
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    monkeypatch.setenv("LEARNING_QUESTIONER_THRESHOLD", "1")
    return SimpleNamespace(t=t, dsn=migrated_database, paths=drain_paths(t, product_repo(tmp_path)),
                           scratch=tmp_path, monkeypatch=monkeypatch)


def authored_and_merged(w: Any, fid: str = "f1") -> tuple[str, str]:
    """A lesson as the author tick makes one (real commit-maker, record in the database) and a person merges it on the
    forge, its batch left in review (nothing reconciled it): `(batch id, branch)`."""
    from defender.tests.tenancy.tenant_1108_delivery._support import merge_on_remote
    from defender.tests.tenancy.tenant_1108_p4._drain_support import (
        LESSON_NAME,
        BoxSpy,
        author_drain,
        remote_branches,
    )

    call(w.dsn, "publish_findings", w.t.tenant_id, "run-1", [finding(fid)], kind="finding")
    writer = LessonWriter({LESSON_NAME: lesson_citing(fid)})
    author_drain(w.t, w.paths, trigger=writer, box=BoxSpy())
    assert writer.served, "the seeding tick served no batch"
    [(branch, _tip)] = remote_branches(w.t.remote).items()
    merge_on_remote(w.t.p3, w.scratch, branch)
    return writer.served[-1], branch
