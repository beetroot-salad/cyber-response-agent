"""Host-owned git transfer context; tenant objects are shared, configuration and refs are not."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
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

    @contextmanager
    def _context(self) -> Iterator[tuple[Path, dict[str, str]]]:
        with tempfile.TemporaryDirectory(prefix="defender-git-") as temporary:
            root = Path(temporary)
            env = _environment(root)
            objects = _git.git(
                ["rev-parse", "--path-format=absolute", "--git-path", "objects"],
                cwd=self.repository,
                env=env,
                timeout=self.timeout,
            )
            object_format = _git.git(
                ["rev-parse", "--show-object-format"],
                cwd=self.repository,
                env=env,
                timeout=self.timeout,
            )
            path = root / "transfer.git"
            _git.git(
                [
                    "init",
                    "--bare",
                    "--template=",
                    f"--object-format={object_format}",
                    str(path),
                ],
                cwd=root,
                env=env,
                timeout=self.timeout,
            )
            # The temporary repository owns its config, refs, hooks and shallow state.
            # Only objects cross the boundary; fetched objects land in the tenant database.
            yield path, {**env, "GIT_OBJECT_DIRECTORY": objects}

    def fetch(self) -> None:
        with self._context() as (path, env):
            network_git(
                [
                    "fetch",
                    "--no-tags",
                    "--no-recurse-submodules",
                    "--no-write-fetch-head",
                    self.origin,
                    "+refs/heads/*:refs/remotes/origin/*",
                ],
                repo=path,
                origin=self.origin,
                identity=self.identity,
                env=env,
                timeout=self.timeout,
            )
            refs = _git.git(
                [
                    "for-each-ref",
                    "--format=%(objectname) %(refname)",
                    "refs/remotes/origin/",
                ],
                cwd=path,
                env=env,
                timeout=self.timeout,
            )
            updates = [
                f"update {ref} {oid}"
                for oid, ref in (line.split() for line in refs.splitlines())
            ]
            if updates:
                # Credential descriptor and network process group are gone before local
                # ref updates, including any reference-transaction hook of the tenant clone.
                local = {
                    key: value
                    for key, value in env.items()
                    if key != "GIT_OBJECT_DIRECTORY"
                }
                _git.git(
                    ["update-ref", "--stdin"],
                    cwd=self.repository,
                    env=local,
                    input="start\n" + "\n".join(updates) + "\nprepare\ncommit\n",
                    timeout=self.timeout,
                )

    def push(self, commit: str, branch: str) -> None:
        with self._context() as (path, env):
            network_git(
                [
                    "push",
                    "--quiet",
                    "--no-follow-tags",
                    "--no-recurse-submodules",
                    self.origin,
                    f"{commit}:refs/heads/{branch}",
                ],
                repo=path,
                origin=self.origin,
                identity=self.identity,
                env=env,
                timeout=self.timeout,
            )
