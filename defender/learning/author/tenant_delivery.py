"""Dormant tenant delivery composition root; P4 connects it to production drains.

The host owns credentials and Git; boxes receive code and agent lanes only.
"""
from __future__ import annotations

import contextlib
import shlex
import stat
from collections.abc import Iterator, Sequence
from dataclasses import field
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx

from defender import _git
from defender._io import read_text_utf8
from defender._model import model
from defender._tenant import Tenant
from defender.learning.author.branch import AuthorBranch, BranchError
from defender.learning.author.forge import ForgeError, ForgejoForge
from defender.runtime import box
from defender.runtime.box._docker import DockerFn, _docker
from defender.runtime.box._lifecycle import _start_boxed_request


class DeliveryRefused(Exception):
    """The tenant cannot safely author or deliver this batch."""


@contextlib.contextmanager
def _delivery_errors() -> Iterator[None]:
    try:
        yield
    except (_git.GitError, _git.GitTimeout, BranchError, ForgeError, OSError, ValueError) as e:
        raise DeliveryRefused(str(e)) from e


def _path(relative: str) -> PurePosixPath:
    """Commit operands are literal descendants of agent, excluding its identity marker."""
    path = PurePosixPath(relative)
    if (not relative or path.is_absolute() or relative != path.as_posix()
            or ".." in path.parts or len(path.parts) < 2 or path.parts[0] != "agent"
            or path.parts[1] == ".tenant-id" or "\x00" in relative):
        raise DeliveryRefused(f"forbidden agent commit path: {relative!r}")
    return path


def _check_commits(repo: Path, base: str, head: str) -> None:
    env = _git.env_for_cwd()
    commits = _git.git(["rev-list", f"{base}..{head}"], cwd=repo, env=env).splitlines()
    for commit in commits:
        for path in _git.git_commit_changed_paths(repo, commit, env=env):
            _path(path)


@model
class _TenantBranch(AuthorBranch):
    """Keep the push gate on the branch owner, including retained-branch delivery."""

    def finish_batch(self, batch_id: str, wt: Path) -> str | None:
        _check_commits(wt, self.branch_base, "HEAD")
        return super().finish_batch(batch_id, wt)

    def deliver(self, batch_id: str) -> str | None:
        branch = self.branch_name(batch_id)
        if _git.git_ok(["show-ref", "--verify", f"refs/heads/{branch}"],
                       cwd=self.repo_root, env=_git.env_for_cwd()):
            _check_commits(self.repo_root, self.branch_base, f"refs/heads/{branch}")
        return super().deliver(batch_id)


@model(frozen=True)
class TenantDelivery:
    """One accepted tenant's host-side delivery; no credential material in its repr."""

    tenant: Tenant
    defender_dir: Path
    branch: AuthorBranch = field(repr=False)
    _origin: str = field(repr=False)

    @classmethod
    def open(cls, accepted_tenant: Tenant, *, defender_dir: Path,
             client: httpx.Client) -> TenantDelivery:
        with _delivery_errors():
            repo = accepted_tenant.knowledge
            env = _git.env_for_cwd()
            if Path(_git.git(["rev-parse", "--show-toplevel"], cwd=repo, env=env)).resolve() != repo.resolve():
                raise DeliveryRefused(f"tenant knowledge is not its own versioned git repository: {repo}")
            origin = _git.git(["config", "--get", "remote.origin.url"], cwd=repo, env=env)
            parsed = urlsplit(origin)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None:
                raise DeliveryRefused("tenant origin must be a network repository without credentials")
            for ref in ("refs/heads/main", "refs/remotes/origin/main"):
                if not _git.git_ok(["show-ref", "--verify", ref], cwd=repo, env=env):
                    raise DeliveryRefused(f"tenant repository is missing required main ref: {ref}")
            credentials = accepted_tenant.forge_credentials
            if not stat.S_ISREG(credentials.lstat().st_mode) or stat.S_IMODE(credentials.stat().st_mode) != 0o600:
                raise DeliveryRefused("tenant credential file must be a regular 0600 file")
            # Sole credential read for this delivery process. Git gets only the file location.
            entry = read_text_utf8(credentials, limit=65536).strip()
            credential = urlsplit(entry)
            if ("\n" in entry or "\r" in entry or credential.scheme != parsed.scheme
                    or credential.hostname != parsed.hostname or credential.port != parsed.port
                    or not credential.username or not credential.password
                    or credential.path not in {"", "/"} or credential.query or credential.fragment):
                raise DeliveryRefused("tenant credential and origin scheme, host and port must agree")
            forge = ForgejoForge(origin=origin, token=unquote(credential.password), client=client)
            forge.verify_main_protection()
            branch = _TenantBranch(
                forge=forge, repo_root=repo, worktree_base=accepted_tenant.worktrees,
                network_config=("-c", "credential.helper=", "-c",
                                f"credential.helper=store --file={shlex.quote(str(credentials))}"),
                pr_body=lambda head, base: f"Tenant agent knowledge batch `{head}`, based on `{base}`. Changes `agent/` only.",
            )
            return cls(tenant=accepted_tenant, defender_dir=defender_dir, branch=branch, _origin=origin)

    def _check_origin(self) -> None:
        current = _git.git(["config", "--get", "remote.origin.url"],
                           cwd=self.tenant.knowledge, env=_git.env_for_cwd())
        if current != self._origin:
            raise DeliveryRefused("tenant origin changed after credential acceptance")

    def start_batch(self, batch_id: str) -> Path:
        with _delivery_errors():
            self._check_origin()
            repo = self.tenant.knowledge
            env = _git.env_for_cwd()
            if _git.git(["status", "--porcelain", "--untracked-files=all"], cwd=repo, env=env):
                raise DeliveryRefused("tenant clone is dirty or has untracked files")
            if _git.git(["symbolic-ref", "--short", "HEAD"], cwd=repo, env=env) != "main":
                raise DeliveryRefused("tenant clone must be on main for fast-forward refresh")
            _git.git_fetch(repo, config=self.branch.network_config)
            # ff-only also accepts a locally-ahead branch; explicitly refuse that state.
            if not _git.git_ok(["merge-base", "--is-ancestor", "HEAD", "origin/main"], cwd=repo, env=env):
                raise DeliveryRefused("tenant clone has diverged; cannot fast-forward to origin/main")
            _git.git(["merge", "--ff-only", "origin/main"], cwd=repo, env=env)
            return self.branch.start_batch(batch_id, fetch=False)

    def _worktree(self, wt: Path) -> Path:
        if not wt.is_relative_to(self.tenant.worktrees) or wt.resolve() != wt:
            raise DeliveryRefused(f"batch worktree is outside tenant worktrees: {wt}")
        if Path(_git.git(["rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=wt,
                         env=_git.env_for_cwd())).resolve() != (self.tenant.knowledge / ".git").resolve():
            raise DeliveryRefused("batch worktree is not owned by the tenant repository")
        return wt / "agent"

    def commit(self, wt: Path, relative_paths: Sequence[str], message: str) -> str | None:
        with _delivery_errors():
            agent = self._worktree(wt)
            paths = [_path(p).as_posix() for p in relative_paths]
            for path in paths:
                candidate = wt / path
                if candidate.resolve() != candidate or not candidate.resolve().is_relative_to(agent):
                    raise DeliveryRefused(f"commit path must stay inside agent without links: {path}")
            present = [p for p in paths if (wt / p).exists()]
            absent = [p for p in paths if p not in present]
            return _git.git_commit_paths(wt, present, absent, message,
                                        env={**_git.env_for_cwd(), "GIT_LITERAL_PATHSPECS": "1"})

    def finish_batch(self, batch_id: str, wt: Path) -> str | None:
        with _delivery_errors():
            self._check_origin()
            self._worktree(wt)
            return self.branch.finish_batch(batch_id, wt)

    def deliver(self, batch_id: str) -> str | None:
        with _delivery_errors():
            self._check_origin()
            return self.branch.deliver(batch_id)

    def box_request(self, wt: Path, batch_id: str, *, writable_dirs: Sequence[str]) -> box.BoxRequest:
        with _delivery_errors():
            agent = self._worktree(wt)
            mounts = [box.Mount(source=self.defender_dir, target=self.defender_dir, kind="code"),
                      box.Mount(source=agent, target=agent, kind="agent")]
            for relative in writable_dirs:
                path = _path(f"agent/{relative}")
                lane = wt / path
                if lane.resolve() != lane or not lane.is_dir():
                    raise DeliveryRefused(f"agent write lane is not a real directory: {relative}")
                mounts.append(box.Mount(source=lane, target=lane, writable=True))
            return box.BoxRequest(
                name=f"defender-tenant-{self.tenant.id}-{batch_id}", mounts=tuple(mounts),
                workdir=agent, defender_dir=self.defender_dir, require_sandbox=True,
                env={"DEFENDER_AGENT_DIR": str(agent)},
            )

    def start_box(self, request: box.BoxRequest, *, docker: DockerFn = _docker) -> box.BoxExecutor:
        # Use the shared startup path, with no opt-out branch for tenant knowledge writes.
        return _start_boxed_request(request, docker)
