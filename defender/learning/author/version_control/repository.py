"""Git operations for a tenant knowledge repository; hosting is explicitly Forgejo."""

from __future__ import annotations

import contextlib
import math
import secrets
import tempfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx
from defender import _git

from .auth import CLOCK_SKEW, TOKEN_TTL, ForgeCredential
from .forgejo import ForgejoForge, OpenedPullRequest, PullRequest
from .model import _REGULAR_MODES, ChangeSet, DeliveryRefused
from .transport import _NO_BACKGROUND_GIT, GitTransport, clone, init_for_commit


def _local_env() -> dict[str, str]:
    """Every git call's environment: nothing that relocates the repository (`GIT_DIR`,
    `GIT_WORK_TREE`, ...), no replace objects, pathspecs taken literally, no prompt (an empty
    `GIT_ASKPASS` stops `core.askPass` and `SSH_ASKPASS`, and the terminal prompt is off), and
    `_NO_BACKGROUND_GIT`, given as environment configuration (after any already there, so it
    wins) so the git processes git itself starts carry it too. A `GIT_CONFIG_COUNT` that is
    not a count is a `ValueError`, as git would refuse it."""
    env = _git.env_for_cwd()
    env.update(
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_LITERAL_PATHSPECS="1",
        GIT_TERMINAL_PROMPT="0",
        GIT_ASKPASS="",
    )
    count = int(env.get("GIT_CONFIG_COUNT") or 0)
    if count < 0:
        raise ValueError(f"GIT_CONFIG_COUNT is not a count: {count}")
    for key, value in _NO_BACKGROUND_GIT:
        env[f"GIT_CONFIG_KEY_{count}"], env[f"GIT_CONFIG_VALUE_{count}"] = key, value
        count += 1
    env["GIT_CONFIG_COUNT"] = str(count)
    return env


def _cat_blobs(
    repo: Path, oids: Iterable[str], env: dict[str, str]
) -> dict[str, bytes]:
    """Each blob's exact stored bytes, by id, in one `cat-file --batch` read by `_git`'s
    parser."""
    wanted = list(dict.fromkeys(oids))
    if not wanted:
        return {}
    args = ["cat-file", "--batch"]
    out = _git.git_bytes(
        args,
        cwd=repo,
        env=env,
        input="".join(f"{oid}\n" for oid in wanted).encode("ascii"),
    )
    return dict(zip(wanted, _git.blob_batch(args, out, wanted), strict=True))


def _tree_entries(
    repo: Path, rev: str, paths: Sequence[str], env: dict[str, str], *, recursive: bool
) -> list[tuple[str, str, str, str]]:
    """`(mode, kind, oid, path)` of each entry `rev` holds at `paths` (below them too, when
    `recursive`), NUL-framed (`_git`'s listing parser) so no path is quoted or trimmed; a path
    that is not UTF-8 refuses."""
    args = [
        "ls-tree",
        "-z",
        "--full-tree",
        *(["-r"] if recursive else []),
        rev,
        "--",
        *paths,
    ]
    return _git.tree_records(_git.git_bytes(args, cwd=repo, env=env), errors="strict")


NETWORK_TIMEOUT = 120.0


@dataclass(frozen=True, repr=False)
class LocalRepository:
    """Git's local semantics for one private bare repository: its objects and refs, with no forge, no identity and no
    network."""

    path: Path

    def _git(
        self,
        args: Sequence[str],
        *,
        input: str | None = None,
        env: dict[str, str] | None = None,
    ) -> str:
        return _git.git(
            args,
            cwd=self.path,
            input=input,
            env=env if env is not None else _local_env(),
        )

    def revision(self, rev: str) -> str:
        return self._git(["rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}"])

    def holds_commit(self, commit: str) -> bool:
        """Whether the repository holds `commit` as a commit (no fetch is made)."""
        return _git.git_ok(
            ["cat-file", "-e", f"{commit}^{{commit}}"], cwd=self.path, env=_local_env()
        )

    def holds_ref(self, ref: str) -> bool:
        """Whether the repository has the full ref `ref` (no fetch is made)."""
        return _git.git_ok(
            ["show-ref", "--verify", "--quiet", ref], cwd=self.path, env=_local_env()
        )

    def branch_tip(self, branch: str) -> str | None:
        """The commit `refs/heads/<branch>` names, or `None` when the repository has no such
        branch."""
        tip = _git.git(
            ["rev-parse", "--verify", "--quiet", f"refs/heads/{branch}^{{commit}}"],
            cwd=self.path,
            env=_local_env(),
            check=False,
        )
        return tip or None

    def entries(self, rev: str, paths: Sequence[str], *, recursive: bool):
        return _tree_entries(self.path, rev, paths, _local_env(), recursive=recursive)

    def blobs(self, oids: Iterable[str]) -> dict[str, bytes]:
        return _cat_blobs(self.path, oids, _local_env())

    def commits_since(self, base: str, tip: str) -> list[str]:
        return self._git(["rev-list", f"{base}..{tip}"]).split()

    def regular_blobs(self, rev: str, paths: Sequence[str]) -> dict[str, str]:
        """The blob id `rev` holds at each of `paths` that is a regular file there."""
        return {
            path: oid
            for mode, kind, oid, path in _tree_entries(
                self.path, rev, paths, _local_env(), recursive=False
            )
            if kind == "blob" and mode in _REGULAR_MODES
        }

    def regular_blob_on(self, rev: str, path: str) -> str | None:
        """The blob `rev` holds at `path`, or `None` when it holds none; refused when the
        entry there is not a regular file."""
        found = _tree_entries(self.path, rev, [path], _local_env(), recursive=False)
        if found and (found[0][1] != "blob" or found[0][0] not in _REGULAR_MODES):
            raise DeliveryRefused(f"{path} on main is not a regular file")
        return found[0][2] if found else None

    def commit_message(self, commit: str) -> str:
        """The full message of `commit` (#1414 A2: a registry PR's body is built from its batch's commit)."""
        return self._git(["show", "-s", "--format=%B", commit]).strip()

    def make_commit(
        self, parent: str, changes: ChangeSet, message: str
    ) -> tuple[str, dict[str, str | None]]:
        tree, after = self._stage(parent, changes, _local_env())
        if tree == self._git(["rev-parse", f"{parent}^{{tree}}"]):
            raise DeliveryRefused("the change set changes nothing")
        return self._git(
            ["commit-tree", tree, "-p", parent, "-F", "-"], input=message,
            env={**_local_env(), **_git.PRODUCT_IDENTITY},
        ), after

    def move_branch(self, branch: str, commit: str, old: str | None) -> None:
        self._git(
            [
                "update-ref",
                "-m",
                "tenant commit-maker",
                f"refs/heads/{branch}",
                commit,
                old or "0" * len(commit),
            ]
        )

    def _stage(
        self, parent: str, change_set: ChangeSet, env: dict[str, str]
    ) -> tuple[str, dict[str, str | None]]:
        """Write each change's blob (no filter: the bytes as given) and the tree `parent` plus
        the changes makes, in a private index; every file 100644. Answers the tree, and each
        path's new blob (`None`: deleted)."""
        index = Path(
            self._git(
                [
                    "rev-parse",
                    "--path-format=absolute",
                    "--git-path",
                    f"commit-maker-{secrets.token_hex(8)}.index",
                ]
            )
        )
        staged = {**env, "GIT_INDEX_FILE": str(index)}
        try:
            self._git(["read-tree", parent], env=staged)
            zero = "0" * len(parent)
            after: dict[str, str | None] = {}
            rows = []
            for change in sorted(change_set, key=lambda c: c.content is not None):
                if change.content is None:
                    after[change.path] = None
                    rows.append(f"0 {zero}\t{change.path}\0")
                    continue
                oid = (
                    _git.git_bytes(
                        ["hash-object", "-w", "--no-filters", "--stdin"],
                        cwd=self.path,
                        env=env,
                        input=change.content,
                    )
                    .decode("ascii")
                    .strip()
                )
                after[change.path] = oid
                rows.append(f"100644 {oid}\t{change.path}\0")
            _git.git_bytes(
                ["update-index", "-z", "--index-info"],
                cwd=self.path,
                env=staged,
                input="".join(rows).encode("utf-8"),
            )
            return self._git(["write-tree"], env=staged), after
        finally:
            index.unlink(missing_ok=True)


@dataclass(frozen=True, repr=False)
class GitRepository(LocalRepository):
    """Git semantics for one private bare repository, with an explicit Forgejo client and identity.
    Raw git syntax and remote authentication stay here; delivery coordinates domain steps.
    """

    origin: str
    forge: ForgejoForge
    identity: ForgeCredential
    network_timeout: float = NETWORK_TIMEOUT

    @classmethod
    def open(
        cls,
        *,
        tenant_id: str,
        origin: str,
        identity: ForgeCredential,
        client: httpx.Client,
        network_timeout: float = NETWORK_TIMEOUT,
        data_root: Path | None = None,
    ) -> GitRepository:
        """One operation's private bare repository (a drain tick's, revert's, adoption's or feedback's), never under
        `<T>`: on the host (`data_root`) an owned 0700 folder under `<data root>/.repo-scratch/`; in a job container
        (`None`) its temporary folder, which dies with it. Opened by one clone of every branch with history, each as the
        same local head, so its tip of a branch is the remote's. `close()` removes it."""
        if (
            isinstance(network_timeout, bool)
            or not isinstance(network_timeout, (int, float))
            or not math.isfinite(network_timeout)
            or network_timeout <= 0
            or network_timeout + CLOCK_SKEW >= TOKEN_TTL
        ):
            raise DeliveryRefused(
                "Network timeout must fit within the short-lived token budget"
            )
        if identity.tenant_id != tenant_id:
            raise DeliveryRefused("The Forgejo identity belongs to a different tenant")
        forge = ForgejoForge(origin=origin, identity=identity, client=client)
        forge.repository_id()
        forge.verify_main_protection()  # D9: delivery checks main's protection
        from defender.tenancy import private_folder

        scratch = contextlib.ExitStack()
        try:
            folder = (scratch.enter_context(private_folder(data_root, tenant_id)) if data_root is not None
                      else Path(scratch.enter_context(tempfile.TemporaryDirectory(prefix="defender-repo-"))))
            path = folder / "repo.git"
            clone(path, origin=origin, identity=identity, timeout=float(network_timeout), main_only=False)
        except BaseException:
            scratch.close()
            raise
        repository = cls(path, origin, forge, identity, float(network_timeout))
        object.__setattr__(repository, "_scratch", scratch)
        return repository

    def close(self) -> None:
        """Remove the repository `open` made (a fetch child's has no scratch of its own: its caller owns the folder)."""
        scratch = getattr(self, "_scratch", None)
        if scratch is not None:
            scratch.close()

    @classmethod
    def open_private(
        cls,
        path: Path,
        *,
        tenant_id: str,
        origin: str,
        identity: ForgeCredential,
        client: httpx.Client,
        network_timeout: float = NETWORK_TIMEOUT,
        commit: str | None = None,
    ) -> tuple[GitRepository, str]:
        """The fetch child's repository: a fresh bare repository at `path` holding one depth-1 fetch of `main`, or of
        `commit` by id; answers it and the commit the fetch brought. No forge API call is made (D9)."""
        if identity.tenant_id != tenant_id:
            raise DeliveryRefused("The Forgejo identity belongs to a different tenant")
        forge = ForgejoForge(origin=origin, identity=identity, client=client)
        timeout = float(network_timeout)
        repository = cls(path, origin, forge, identity, timeout)
        try:
            if commit is None:
                clone(path, origin=origin, identity=identity, timeout=timeout, main_only=True)
                return repository, repository.revision("refs/heads/main")
            init_for_commit(path, commit, timeout=timeout)
            repository._transport().fetch_commit(commit, depth=1)
            return repository, repository.revision(f"refs/fetched/{commit}")
        except _git.GitError as refused:
            what = f"commit {commit}" if commit else "main"
            raise DeliveryRefused(f"Forgejo did not serve {what}: {refused}") from None

    def _transport(self) -> GitTransport:
        return GitTransport(self.path, self.origin, self.identity, self.network_timeout)

    def fetch(self, *refs: str) -> None:
        """A later fetch into this repository, by name (`main` when none is named; `GitTransport.fetch`)."""
        self._transport().fetch(*refs)

    def pull_head(self, number: int) -> str | None:
        """The tip of PR `number` (`refs/pull/<n>/head`, which Forgejo keeps after the branch is deleted: C-F5),
        fetched now by name; `None` when it cannot be fetched (a caller that needs a tip then fetches one by id, which
        refuses when the forge is unreachable)."""
        ref = f"refs/pull/{number}/head"
        try:
            self.fetch(ref)
        except _git.GitError:
            return None
        return self.revision(ref)

    def require_commit(self, commit: str) -> None:
        """`commit` held: fetched by id (protocol v2) when this repository lacks it; refused when Forgejo does not serve it."""
        if not self.holds_commit(commit):
            try:
                self._transport().fetch_commit(commit)
            except _git.GitError as refused:
                raise DeliveryRefused(f"Forgejo did not serve commit {commit}: {refused}") from None

    def push(self, commit: str, branch: str) -> None:
        self._transport().push(commit, branch)

    def pull_requests(self, commits: Iterable[str]) -> list[PullRequest]:
        wanted = frozenset(commits)
        return [pr for pr in self.forge.pull_requests() if pr.head_sha in wanted]

    def open_pr(self, *, branch: str, title: str, body: str) -> OpenedPullRequest:
        return self.forge.open_pr(base="main", head=branch, title=title, body=body)
