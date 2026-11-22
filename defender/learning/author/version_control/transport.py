"""Host-owned git transfer context: every transfer is into its owner's private repository, with no operator git policy."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from defender import _git

from .auth import ForgeCredential
from .credentials import network_git
from .forgejo import ForgeAddress

#: Settings every git process on a tenant repository runs with, so none outlives the call
#: that started it: no automatic maintenance or gc (a fetch, merge or commit otherwise spawns
#: `git maintenance run --auto --detach`, which keeps working on the repository after the
#: call returns), and no file-system monitor daemon.
_NO_BACKGROUND_GIT = (
    ("maintenance.auto", "false"),
    ("maintenance.autoDetach", "false"),
    ("gc.auto", "0"),
    ("gc.autoDetach", "false"),
    ("core.fsmonitor", "false"),
)


def _environment(home: Path) -> dict[str, str]:
    """Allow only process lookup and locale from the caller; all git policy is owned here.

    A private home also excludes curl's implicit netrc files. TLS uses the host trust store;
    proxies, git config injection, alternate executable paths and trace settings are not
    inherited from the operator's shell.
    """
    env = {
        key: os.environ[key]
        for key in ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ")
        if key in os.environ
    }
    env.update(
        HOME=str(home),
        XDG_CONFIG_HOME=str(home / "xdg"),
        CURL_HOME=str(home),
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_SYSTEM=os.devnull,
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_COUNT="0",
        GIT_TERMINAL_PROMPT="0",
        GIT_ASKPASS="",
        SSH_ASKPASS="",
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_LITERAL_PATHSPECS="1",
        GIT_ALLOW_PROTOCOL="http:https",
    )
    for index, (key, value) in enumerate(_NO_BACKGROUND_GIT):
        env[f"GIT_CONFIG_KEY_{index}"] = key
        env[f"GIT_CONFIG_VALUE_{index}"] = value
    env["GIT_CONFIG_COUNT"] = str(len(_NO_BACKGROUND_GIT))
    return env


@dataclass(frozen=True, repr=False)
class GitTransport:
    repository: Path
    origin: str
    identity: ForgeCredential
    timeout: float

    def __post_init__(self) -> None:
        ForgeAddress.parse(self.origin)

    def fetch(self, *refs: str) -> None:
        """Each of `refs` (`refs/heads/main` when none is named) as the same local ref, into the owner's private
        repository: a later fetch names what it reads, never every branch, and prunes nothing, so it cannot move or delete
        the holder's own unpushed batch branch (the opening `clone` is the only fetch of every branch)."""
        with tempfile.TemporaryDirectory(prefix="defender-git-") as temporary:
            network_git(
                ["fetch", "--no-tags", "--no-recurse-submodules", "--no-write-fetch-head", self.origin,
                 *(f"+{ref}:{ref}" for ref in refs or ("refs/heads/main",))],
                repo=self.repository, origin=self.origin, identity=self.identity, env=_environment(Path(temporary)),
                timeout=self.timeout)

    def fetch_commit(self, commit: str, *, depth: int | None = None) -> None:
        """One commit by id (protocol v2), kept under `refs/fetched/`."""
        with tempfile.TemporaryDirectory(prefix="defender-git-") as temporary:
            network_git(
                ["-c", "protocol.version=2", "fetch", "--no-tags", "--no-recurse-submodules", "--no-write-fetch-head",
                 *(["--depth", str(depth)] if depth is not None else []), self.origin, f"+{commit}:refs/fetched/{commit}"],
                repo=self.repository, origin=self.origin, identity=self.identity, env=_environment(Path(temporary)),
                timeout=self.timeout)

    def push(self, commit: str, branch: str) -> None:
        with tempfile.TemporaryDirectory(prefix="defender-git-") as temporary:
            env = _environment(Path(temporary))
            network_git(
                ["push", "--quiet", "--no-follow-tags", "--no-recurse-submodules", self.origin,
                 f"{commit}:refs/heads/{branch}"],
                repo=self.repository, origin=self.origin, identity=self.identity, env=env, timeout=self.timeout)


def init_for_commit(path: Path, commit: str, *, timeout: float) -> None:
    """A fresh bare repository for a fetch by id: the object format is the id's length (40 sha1, 64 sha256), so no
    network request is needed to learn it."""
    object_format = {40: "sha1", 64: "sha256"}.get(len(commit))
    if object_format is None:
        raise ValueError(f"{commit!r} is not a commit id")
    with tempfile.TemporaryDirectory(prefix="defender-git-") as temporary:
        _git.git(["init", "--bare", "--template=", f"--object-format={object_format}", str(path)],
                 cwd=Path(temporary), env=_environment(Path(temporary)), timeout=timeout)


def clone(path: Path, *, origin: str, identity: ForgeCredential, timeout: float, main_only: bool) -> None:
    """A new bare repository at `path` from `origin` (git learns the object format in the same connection). `main_only`:
    `main` at depth 1 (a copy's fetch); otherwise every branch with history, each as the same local head
    (`+refs/heads/*:refs/heads/*`, what a bare clone maps), so a branch's local tip is the remote's. No tags.
    `network_git` only needs a working directory, so the clone runs from the temp root."""
    with tempfile.TemporaryDirectory(prefix="defender-git-") as temporary:
        root = Path(temporary)
        network_git(["clone", "--bare", "--no-tags", "--template=",
                     *(["--depth", "1", "--single-branch", "--branch", "main"] if main_only else []), origin, str(path)],
                    repo=root, origin=origin, identity=identity, env=_environment(root), timeout=timeout)
