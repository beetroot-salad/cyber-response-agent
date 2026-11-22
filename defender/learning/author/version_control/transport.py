"""Host-owned git transfer context; tenant objects are shared, configuration and refs are not."""

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
#: `git maintenance run --auto --detach`, which keeps working on the clone after the call
#: returns and the tenant's lock is released), and no file-system monitor daemon.
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
        """Every branch of `origin` as the same local head (`+refs/heads/*:refs/heads/*`) and each of `refs`
        (`refs/pull/<n>/head`) as the same local ref, into the owner's private repository. No other process touches
        its refs, so there is nothing to collide with (C-F1)."""
        with tempfile.TemporaryDirectory(prefix="defender-git-") as temporary:
            env = _environment(Path(temporary))
            network_git(
                ["fetch", "--no-tags", "--no-recurse-submodules", "--no-write-fetch-head", self.origin,
                 "+refs/heads/*:refs/heads/*", *(f"+{ref}:{ref}" for ref in refs)],
                repo=self.repository, origin=self.origin, identity=self.identity, env=env, timeout=self.timeout)

    def fetch_commit(self, commit: str) -> None:
        """One commit by id (protocol v2), kept under `refs/fetched/`."""
        with tempfile.TemporaryDirectory(prefix="defender-git-") as temporary:
            env = _environment(Path(temporary))
            network_git(
                ["-c", "protocol.version=2", "fetch", "--no-tags", "--no-recurse-submodules", "--no-write-fetch-head",
                 self.origin, f"+{commit}:refs/fetched/{commit}"],
                repo=self.repository, origin=self.origin, identity=self.identity, env=env, timeout=self.timeout)

    def push(self, commit: str, branch: str) -> None:
        with tempfile.TemporaryDirectory(prefix="defender-git-") as temporary:
            env = _environment(Path(temporary))
            network_git(
                ["push", "--quiet", "--no-follow-tags", "--no-recurse-submodules", self.origin,
                 f"{commit}:refs/heads/{branch}"],
                repo=self.repository, origin=self.origin, identity=self.identity, env=env, timeout=self.timeout)


def init_private(path: Path, *, origin: str, identity: ForgeCredential, timeout: float) -> None:
    """SPIKE (#1618): a fresh bare repository at `path`, in the object format `origin` serves (the clone used to
    fix it; a fresh repository must learn it, so one `ls-remote` round trip)."""
    ForgeAddress.parse(origin)
    with tempfile.TemporaryDirectory(prefix="defender-git-") as temporary:
        root = Path(temporary)
        env = _environment(root)
        probe = root / "probe.git"
        _git.git(["init", "--bare", "--template=", str(probe)], cwd=root, env=env, timeout=timeout)
        out = network_git(["ls-remote", origin, "HEAD", "refs/heads/main"], repo=probe, origin=origin,
                          identity=identity, env=env, timeout=timeout)
        first = out.split()[0] if out.split() else ""
        object_format = "sha256" if len(first) == 64 else "sha1"
        _git.git(["init", "--bare", "--template=", f"--object-format={object_format}", str(path)],
                 cwd=root, env=env, timeout=timeout)


def init_for_commit(path: Path, commit: str, *, timeout: float) -> None:
    """A fresh bare repository for a fetch by id: the object format is the id's length (40 sha1, 64 sha256), so no
    network request is needed to learn it."""
    object_format = {40: "sha1", 64: "sha256"}.get(len(commit))
    if object_format is None:
        raise ValueError(f"{commit!r} is not a commit id")
    with tempfile.TemporaryDirectory(prefix="defender-git-") as temporary:
        _git.git(["init", "--bare", "--template=", f"--object-format={object_format}", str(path)],
                 cwd=Path(temporary), env=_environment(Path(temporary)), timeout=timeout)


def clone_main(path: Path, *, origin: str, identity: ForgeCredential, timeout: float) -> str:
    """`main` at depth 1 into a new bare repository at `path` (git learns the object format in the one connection);
    answers the commit. `network_git` only needs a working directory, so the clone runs from the temp root."""
    with tempfile.TemporaryDirectory(prefix="defender-git-") as temporary:
        root = Path(temporary)
        env = _environment(root)
        network_git(["clone", "--bare", "--depth", "1", "--no-tags", "--single-branch", "--branch", "main",
                     "--template=", origin, str(path)],
                    repo=root, origin=origin, identity=identity, env=env, timeout=timeout)
        return _git.git(["rev-parse", "--verify", "refs/heads/main^{commit}"], cwd=path, env=env, timeout=timeout)


def fetch_private(path: Path, *, origin: str, identity: ForgeCredential, timeout: float,
                  commit: str | None = None) -> str:
    """SPIKE (#1618): fetch `refs/heads/main` (or, with `commit`, that commit by id, protocol v2, depth 1) into the
    private bare repository `path` and answer the commit it now holds: the fetcher's own, never a shared ref."""
    with tempfile.TemporaryDirectory(prefix="defender-git-") as temporary:
        env = _environment(Path(temporary))
        if commit is None:
            args = ["fetch", "--no-tags", "--no-recurse-submodules", "--no-write-fetch-head", origin,
                    "+refs/heads/main:refs/remotes/origin/main"]
            ref = "refs/remotes/origin/main"
        else:
            args = ["-c", "protocol.version=2", "fetch", "--no-tags", "--no-recurse-submodules", "--depth", "1",
                    "--no-write-fetch-head", origin, f"+{commit}:refs/fetched/{commit}"]
            ref = f"refs/fetched/{commit}"
        network_git(args, repo=path, origin=origin, identity=identity, env=env, timeout=timeout)
        return _git.git(["rev-parse", "--verify", f"{ref}^{{commit}}"], cwd=path, env=env, timeout=timeout)
