"""Driving the lifecycle (#1214 DC-14) and its production adapters: `serve`'s loop, the git runner
over the sealed transport (DC-10), the fixed integration command, and the HTTP clients a process
builds from its `LifecycleConfig`."""
from __future__ import annotations

import asyncio
import os
import ssl
import subprocess
import tempfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import httpx

from defender import _git
from defender.lifecycle.config import LifecycleConfig

#: Each external call's own bound (seconds): a hung call ends, so a lock is never held forever.
CALL_TIMEOUT = 60.0
#: The integration command after `docker exec <container>` (dev; hosted: an SSH forced command).
INTEGRATION = ("forgejo", "admin", "user", "create-authorized-integration")


async def serve(service: Any, host: Any, *, config: LifecycleConfig, stop: Callable[[], bool]) -> None:
    """One pass of each actor, then `config.poll_interval`, until `stop()` (asked once per round) is
    true. `python -m defender.lifecycle serve` runs both actors this way (dev); hosted runs one each."""
    while True:
        await service.work()
        await host.work()
        if stop():
            return
        await asyncio.sleep(config.poll_interval)


def _isolated_env(home: Path) -> dict[str, str]:
    """Git's environment for the lifecycle: process lookup and locale from the caller, everything
    else (home, config, prompts, protocols) owned here."""
    env = {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ") if k in os.environ}
    env.update(HOME=str(home), XDG_CONFIG_HOME=str(home / "xdg"), CURL_HOME=str(home), GIT_CONFIG_NOSYSTEM="1",
               GIT_CONFIG_SYSTEM=os.devnull, GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0",
               GIT_ASKPASS="", SSH_ASKPASS="", GIT_ALLOW_PROTOCOL="http:https")
    return env


def git_runner(args: Sequence[str], *, cwd: Path | None = None, env: Mapping[str, str] | None = None,
               origin: str | None = None, identity: Any = None) -> subprocess.CompletedProcess[str]:
    """The lifecycle's git (`git <args>`): with `identity` (a `ForgeCredential`) the call talks to
    `origin` and the JWT travels only in a sealed descriptor (`network_git`, DC-10), never in argv,
    the environment or a file. A failure is the returned exit status and message, never raised."""
    argv = [str(a) for a in args]
    with tempfile.TemporaryDirectory(prefix="defender-lifecycle-git-") as scratch:
        home = Path(scratch)
        full_env = {**_isolated_env(home), **(env or {})}
        where = Path(cwd) if cwd is not None else home
        try:
            if identity is None:
                out = _git.git(argv, cwd=where, env=full_env, timeout=CALL_TIMEOUT)
            else:
                from defender.learning.author.version_control.credentials import network_git

                if origin is None:
                    raise ValueError("an authenticated git call names its origin")
                out = network_git(argv, repo=where, origin=origin, identity=identity, env=full_env,
                                  timeout=CALL_TIMEOUT)
        except _git.GitError as failed:
            return subprocess.CompletedProcess(argv, failed.returncode, "", failed.stderr)
        except _git.GitTimeout:
            return subprocess.CompletedProcess(argv, 124, "", f"git timed out after {CALL_TIMEOUT:g}s")
    return subprocess.CompletedProcess(argv, 0, out, "")


def integration_runner(container: str) -> Callable[[Sequence[str]], subprocess.CompletedProcess[str]]:
    """The fixed integration command in the dev Forgejo container (`docker exec`), run with the
    recorded arguments only."""
    def run(arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["docker", "exec", "-u", "git", container, *INTEGRATION, *map(str, arguments)],  # noqa: S603, S607 — fixed argv
                              capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=CALL_TIMEOUT, check=False)
    return run


def _openbao_verify(config: LifecycleConfig) -> ssl.SSLContext | bool:
    return ssl.create_default_context(cafile=str(config.openbao_ca)) if config.openbao_ca else True


def forge_admin(config: LifecycleConfig) -> httpx.AsyncClient:
    """The management service's forge client: the admin token on every call."""
    return httpx.AsyncClient(base_url=config.forge_url, timeout=CALL_TIMEOUT,
                             headers={"Authorization": f"token {config.forge_admin_token}"})


def forge_anonymous(config: LifecycleConfig) -> httpx.AsyncClient:
    """The host actor's forge client: no credential (each call presents the bot's JWT, F-1)."""
    return httpx.AsyncClient(base_url=config.forge_url, timeout=CALL_TIMEOUT)


def openbao_management(config: LifecycleConfig) -> httpx.AsyncClient:
    """The management service's OpenBao client: the management login on every call."""
    return httpx.AsyncClient(base_url=config.openbao_url, timeout=CALL_TIMEOUT, verify=_openbao_verify(config),
                             headers={"X-Vault-Token": config.openbao_login})


def openbao_login(config: LifecycleConfig) -> httpx.AsyncClient:
    """The host actor's OpenBao client: no token (unwrap, AppRole login, token reads; DC-12)."""
    return httpx.AsyncClient(base_url=config.openbao_url, timeout=CALL_TIMEOUT, verify=_openbao_verify(config))
