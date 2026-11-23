"""#1618: the in-process fetch stand-in for a caller of `run.main` / `job_host.main` / an operator tool that takes the one
fetch seam (`fetch(tenant_id, dest, *, data_root, commit=None) -> report line`, `run_knowledge.FetchSeam`).

Knowledge lives only in Forgejo (design r5, D2): there is no clone, `exports/` or `current` for a reader to fall back to.
What a test placed for the tenant (`place_fixture` / `place_tenant` at `<T>/knowledge`, the operator's working copy as the
retired layout spelt it) stands for the tenant's `main` on its forge: at CALL time it is committed into a seed checkout
beside the data root (`<root>-p4-forge/seeds/<T>`) and pushed to the served bare remote `<root>-p4-forge/tenants/<T>.git`,
so "an edit made before the launch is what the run reads" stays true. The placed folder is left as it is (the product
never reads it, K8), so a test may edit it again before its next launch.

The copy itself is made by the PRODUCT's fetch (`version_control.fetch.fetch_copy`), in-process, over a real smart-HTTP
listener (`GitHTTP`) for that served remote, with the issuer fake's identity: the content is validated as the child
validates it (K6), `dest` is filled no-follow and required empty, and the private repository is the product's own under
`.repo-scratch/`. The answer is the child's vocabulary: `ok <commit>`, or `refused <transient|lasting> <reason>`.

`halves_at` copies one commit's `agent/` and `settings/` out of a bare remote by git plumbing, for a harness that drives
the investigation driver directly (it reads a folder, not a fetch): a test-side copy, never a product path.
"""
from __future__ import annotations

import shutil
import subprocess
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from defender.tests.support.shared._locations_1210 import location_path

#: One seeding at a time per served remote (concurrent launches of one tenant push one main).
_SEEDING: dict[str, threading.Lock] = {}
_SEEDING_GUARD = threading.Lock()


def forge_scratch(data_root: Path | str) -> Path:
    """Where a data root's served remotes live: beside it (`<root>-p4-forge`), never under it."""
    root = Path(str(location_path(data_root)))
    return root.with_name(f"{root.name}-p4-forge")


def _git(cwd: Path, *args: str) -> str:
    from defender.tests.tenancy.tenant_1108_delivery._support import git

    return git(cwd, *args)


def served_remote(data_root: Path | str, tenant_id: str) -> Path:
    """`<root>-p4-forge/tenants/<T>.git`: the bare remote the stand-in serves for `tenant_id`."""
    return forge_scratch(data_root) / "tenants" / f"{tenant_id}.git"


def _lock_for(remote: Path) -> threading.Lock:
    with _SEEDING_GUARD:
        return _SEEDING.setdefault(str(remote), threading.Lock())


def seed_placed(data_root: Path | str, tenant_id: str) -> str | None:
    """Commit what is placed at `<T>/knowledge` (its `agent/` and `settings/`) into the seed checkout and push it to the
    served remote's `main` (a fast-forward; nothing new when unchanged). Returns `main`'s commit, or None when nothing is
    placed and no remote was ever seeded. The placed folder is read, never moved or changed."""
    from defender.tests.tenancy.tenant_1108_delivery._support import BARE_NO_UPKEEP

    root = Path(str(location_path(data_root)))
    tenant_id = str(tenant_id)
    served = forge_scratch(root)
    remote = served_remote(root, tenant_id)
    placed = root / tenant_id / "knowledge"
    with _lock_for(remote):
        if remote.is_symlink():
            # A published tenant's own remote (`publish_placed` links it here): its `main` is the test's, moved by its
            # merges; what is at `<T>/knowledge` then is a decoy (`plant_old_clone`), never seeded.
            return _git(remote, "rev-parse", "refs/heads/main")
        if not placed.is_dir():
            return _git(remote, "rev-parse", "refs/heads/main") if (remote / "HEAD").exists() else None
        work = served / "seeds" / tenant_id
        if not (work / ".git").exists():
            work.mkdir(parents=True, exist_ok=True)
            _git(work, "init", "-q", "-b", "main")
            _git(work, "config", "user.name", "P4 fixture")
            _git(work, "config", "user.email", "p4@test.invalid")
        for entry in list(work.iterdir()):
            if entry.name != ".git":
                shutil.rmtree(entry) if entry.is_dir() and not entry.is_symlink() else entry.unlink()
        for entry in placed.iterdir():
            if entry.name == ".git":
                continue
            if entry.is_dir() and not entry.is_symlink():
                shutil.copytree(entry, work / entry.name, symlinks=True)
            else:
                shutil.copy2(entry, work / entry.name, follow_symlinks=False)
        _git(work, "add", "-A")
        if _git(work, "status", "--porcelain") or not _has_head(work):
            _git(work, "commit", "-q", "--allow-empty", "-m", "tenant content")
        head = _git(work, "rev-parse", "HEAD")
        if (remote / "HEAD").exists():
            _git(work, "push", "-q", "-f", str(remote), "main:main")
        else:
            remote.parent.mkdir(parents=True, exist_ok=True)
            _git(served, "clone", "-q", "--bare", *BARE_NO_UPKEEP, str(work), str(remote))
        return head


def _has_head(work: Path) -> bool:
    done = subprocess.run(["git", "rev-parse", "--verify", "-q", "HEAD"], cwd=work,  # noqa: S603, S607
                          capture_output=True, check=False)
    return done.returncode == 0


def halves_at(remote: Path, commit: str, into: Path) -> Path:
    """`agent/` and `settings/` of `commit` in the bare `remote`, written under `into` (made; must not hold them yet) as
    regular files by git plumbing; returns `into`. A test-side copy for a harness that reads a folder."""
    into = Path(into)
    into.mkdir(parents=True, exist_ok=True)
    listing = subprocess.run(["git", "ls-tree", "-r", "-z", commit, "--", "agent", "settings"],  # noqa: S603, S607
                             cwd=remote, capture_output=True, check=True).stdout
    for half in ("agent", "settings"):
        (into / half).mkdir(exist_ok=True)
    for row in filter(None, listing.split(b"\0")):
        meta, path = row.split(b"\t", 1)
        mode, _kind, oid = meta.split()
        target = into / path.decode()
        target.parent.mkdir(parents=True, exist_ok=True)
        data = subprocess.run(["git", "cat-file", "blob", oid.decode()],  # noqa: S603, S607
                              cwd=remote, capture_output=True, check=True).stdout
        if mode == b"120000":
            target.symlink_to(data.decode())
        else:
            target.write_bytes(data)
    return into


def link_published(data_root: Path | str, tenant_id: str, remote: Path) -> None:
    """Name a published tenant's bare `remote` (`publish_placed`'s, outside the data root) as the data root's served
    remote for `tenant_id`, so whatever finds a tenant's Forgejo repository from the data root alone (the default
    `in_process_fetch()`, `copy_at_main`) finds that one. A later publish of the tenant re-links it."""
    served = served_remote(data_root, tenant_id)
    remote = Path(remote).resolve()
    if served.is_symlink():
        served.unlink()
    elif served.exists():
        if served.resolve() == remote:
            return
        shutil.rmtree(served)
    served.parent.mkdir(parents=True, exist_ok=True)
    served.symlink_to(remote, target_is_directory=True)


def _main_of(remote: Path) -> str:
    """`main`'s commit in the bare `remote`, read from its ref files (loose, else `packed-refs`) so a reader asking for a
    copy it already has starts no process (a proxy-side records read in the middle of a verb must not: #1391 O1's
    no-process check); git answers only for a layout it does not read."""
    remote = Path(remote)
    try:
        loose = (remote / "refs" / "heads" / "main").read_text(encoding="ascii").strip()
        if len(loose) in (40, 64):
            return loose
    except OSError:
        pass
    try:
        for line in (remote / "packed-refs").read_text(encoding="ascii").splitlines():
            oid, _sep, name = line.partition(" ")
            if name == "refs/heads/main" and len(oid) in (40, 64):
                return oid
    except OSError:
        pass
    return _git(remote, "rev-parse", "refs/heads/main")


def copy_at_main(data_root: Path | str, tenant_id: str) -> Path | None:
    """A test-side copy (`halves_at`) of `main`'s `agent/` and `settings/` on the tenant's served remote, beside the data
    root and one per commit (`<root>-p4-forge/copies/<T>/<commit>/`); None when the tenant has no served remote."""
    import os

    root = Path(str(location_path(data_root)))
    remote = served_remote(root, str(tenant_id))
    if not (remote / "HEAD").exists():
        return None
    commit = _main_of(remote)
    copy = forge_scratch(root) / "copies" / str(tenant_id) / commit
    if not copy.is_dir():
        building = copy.with_name(f".{commit}.{os.getpid()}.{threading.get_ident()}")
        shutil.rmtree(building, ignore_errors=True)
        halves_at(remote, commit, building)
        try:
            building.rename(copy)
        except OSError:  # made meanwhile: the same commit's bytes
            shutil.rmtree(building, ignore_errors=True)
    return copy


def commit_on_main(data_root: Path | str, tenant_id: str, files: dict[str, str | bytes | None], message: str) -> str:
    """Commit `files` (`{"agent/..." | "settings/...": text, bytes or None to delete}`) on `main` of the tenant's served
    remote, as a tenant admin's merge would land there (#1618 D2: knowledge changes only on Forgejo), through a scratch
    checkout beside the data root. Returns the new `main`."""
    import tempfile

    root = Path(str(location_path(data_root)))
    remote = served_remote(root, str(tenant_id))
    with _lock_for(remote), tempfile.TemporaryDirectory(dir=forge_scratch(root)) as scratch:
        work = Path(scratch) / "work"
        subprocess.run(["git", "clone", "-q", "-b", "main", str(remote), str(work)],  # noqa: S603, S607
                       check=True, capture_output=True)
        _git(work, "config", "user.name", "P4 fixture")
        _git(work, "config", "user.email", "p4@test.invalid")
        for rel, data in files.items():
            target = work / rel
            if data is None:
                target.unlink(missing_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
        _git(work, "add", "-A")
        _git(work, "commit", "-q", "--allow-empty", "-m", message)
        _git(work, "push", "-q", str(remote), "HEAD:main")
        return _git(work, "rev-parse", "HEAD")


def fetch_line(tenant_id: str, dest: Path, *, data_root: Any, commit: str | None = None,
               directory: Any = None, remote: Path | None = None) -> str:
    """The product's in-process fetch (`fetch_copy`) of `tenant_id`'s served remote into the empty `dest`, as one report
    line. The remote is `remote` (a bare repository, served as it stands) or, when None, the data root's served remote
    seeded from what is placed (`seed_placed`). `directory` defaults to the tenant active with its forge wiring naming
    the listener."""
    from defender.learning.author.version_control.fetch import REFUSED, fetch_copy, report
    from defender.learning.author.version_control.status import classify
    from defender.tests.support.tenancy._active1214 import active_directory
    from defender.tests.tenancy.tenant_1108_delivery._identity import VaultHTTP
    from defender.tests.tenancy.tenant_1108_delivery._identity import token as issuer_token
    from defender.tests.tenancy.tenant_1108_delivery._support import GitHTTP

    root = Path(str(location_path(data_root)))
    tenant_id = str(tenant_id)
    if remote is None:
        seed_placed(root, tenant_id)
        remote = served_remote(root, tenant_id)
    remote = Path(remote)
    server = GitHTTP(remote.parent.parent, token=issuer_token(tenant_id))
    try:
        origin = f"{server.url}/{remote.parent.name}/{remote.name}"
        if directory is None:
            directory = active_directory(root, tenant_id, origin=origin, records=None)
        try:
            got = fetch_copy(tenant_id, Path(dest), commit, data_root=root, directory=directory,
                             identity=VaultHTTP(tenant_id).identity())
        except Exception as refused:  # noqa: BLE001 — the child's own refusal, as its report line says it
            return report(REFUSED, f"{classify(refused)[0]} {refused}")
        return f"ok {got}"
    finally:
        server.close()


def fetched_copy(tenant_id: str, data_root: Path | str | None = None) -> Callable[[str], Any]:
    """A judge pass's `copy=` seam (`grade_episode(copy=)`, #1618 K5), shaped as the launcher's own (`branch/cli.py`
    `_judge_copy`): the product's fetch (`fetch_line`) of one commit by id into a fresh folder beside the data root,
    removed when the pass releases it; a refusal is the judge's `KnowledgeRefused`, naming the report."""
    import contextlib
    import os
    import tempfile

    @contextlib.contextmanager
    def copy(commit: str) -> Any:
        from defender.learning.judge import KnowledgeRefused

        root = Path(str(location_path(data_root if data_root is not None else os.environ["DEFENDER_DATA_ROOT"])))
        scratch = forge_scratch(root) / "judge-copies"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as held:
            dest = Path(held) / "copy"
            dest.mkdir()
            line = fetch_line(str(tenant_id), dest, data_root=root, commit=commit)
            if not line.startswith("ok "):
                raise KnowledgeRefused(f"knowledge commit {commit} could not be copied: {line}")
            yield dest

    return copy


def in_process_fetch(remote: Path | str | None = None) -> Callable[..., str]:
    """A `fetch=` for `run.main` / `job_host.main` / an operator tool (module doc): over `remote` (a bare repository
    path, e.g. a `PublishedTenant`'s `.remote`) when given, else the data root's served remote seeded from what is placed.
    Every ask is in `.calls` (`tenant`, `dest`, `commit`, `line`)."""
    calls: list[dict[str, Any]] = []
    bare = None if remote is None else Path(str(remote))

    def fetch(tenant_id: Any, dest: Path, *, data_root: Any, commit: str | None = None, **_kw: Any) -> str:
        line = fetch_line(str(tenant_id), Path(dest), data_root=data_root, commit=commit, remote=bare)
        calls.append({"tenant": str(tenant_id), "dest": Path(dest), "commit": commit, "line": line})
        return line

    fetch.calls = calls  # type: ignore[attr-defined]
    return fetch
