"""Learning's processes inside a job container (#1170): the learning job entry, its pre-flight and siblings, the
post-step and the family-less check.

Inside the container a learning process takes no host lock, runs no admission and opens no database: the per-job host
helper (`defender.job_host`) did those before the container started, holds the tenant's lock for the whole job, and
answers the rest over the job socket (`job_socket`). This module is that side's one door onto the socket:

- `JobContainer.of(environ, ...)`: the job's client and its `launch` facts; `NotInContainer` outside a job container
  (a host shell: the entry then does nothing, A6);
- `JobContainer.access(id)`: a read pass for an id the helper minted, held by `job_socket.PassHolder` and asked
  afresh whenever the one held is within the reuse margin (O5, O6: no single long pass);
- `JobContainer.box(kind, id)`: a box the helper starts (O9: the request names a kind and an id, never a path);
- `JobContainer.materialised_export(commit)`: the export of a commit, materialised by the helper (the container
  writes no export and takes no knowledge lock, P-A);
- `JobContainer.records()` / `.forge_credential()`: the post-step's drain's tenant records (its publish outcomes
  written by the helper, `record.*`) and forge credential (tokens minted by the helper, `forge.token`), so the drain
  runs unchanged with no database login and no forge login (O3, O4);
- `sigterm_on_stdin_eof()`: the container's death tie (A5): the helper holds the container's stdin, so its end is
  this process's SIGTERM."""
from __future__ import annotations

import logging
import os
import signal
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from defender import job_socket
from defender.credential_proxy import PASS_REUSE_MARGIN_SEC
from defender.kit.access import RequestAccess

_logger = logging.getLogger(__name__)

__all__ = ["JobContainer", "NotInContainer", "sigterm_on_stdin_eof"]


class NotInContainer(RuntimeError):
    """A container-only entry run with no job socket in its environment (a host shell): it does nothing."""


@dataclass(frozen=True)
class JobContainer:
    """The job socket's client (`ask(request, **fields)`) and the `launch` facts the helper answered."""

    ask: Callable[..., dict[str, Any]] = field(repr=False)
    launch: Mapping[str, Any]

    @staticmethod
    def client(environ: Mapping[str, str] | None) -> Callable[..., dict[str, Any]]:
        """The job socket's client `environ` names (default: this process's), or `NotInContainer` when it names none
        (a host shell)."""
        ask = job_socket.from_environ(os.environ if environ is None else environ)
        if ask is None:
            raise NotInContainer(f"no job socket ({job_socket.SOCKET_ENV}) in the environment: this entry runs only "
                                 "inside its job container, which the per-job host helper starts")
        return ask

    @classmethod
    def connect(cls, ask: Callable[..., dict[str, Any]], *, tenant: str) -> JobContainer:
        """The job container over `ask`: its `launch` facts asked and checked to name `tenant`. A socket that cannot
        be asked raises its `OSError` or `job_socket.Refused`; facts naming another tenant are a `ValueError`."""
        launch = ask("launch")
        if not isinstance(launch, Mapping) or str(launch.get("tenant")) != str(tenant):
            raise ValueError("the job socket's launch facts name another tenant than the command line")
        return cls(ask=ask, launch=dict(launch))

    @classmethod
    def of(cls, environ: Mapping[str, str] | None, *, tenant: str) -> JobContainer:
        """`connect` over the client `environ` names (`client`)."""
        return cls.connect(cls.client(environ), tenant=tenant)

    @classmethod
    def in_environ(cls, environ: Mapping[str, str] | None = None) -> JobContainer | None:
        """The job container this process runs in (its `launch` facts asked), or None outside one (no job socket in
        `environ`, default this process's): how a step the container's entry calls finds the helper (the post-step's
        drain, `drains.author_drain`)."""
        ask = job_socket.from_environ(os.environ if environ is None else environ)
        if ask is None:
            return None
        launch = ask("launch")
        if not isinstance(launch, Mapping):
            raise ValueError("the job socket's launch facts are not a mapping")
        return cls(ask=ask, launch=dict(launch))

    @property
    def proxy_url(self) -> str | None:
        url = self.launch.get("proxy_url")
        return str(url) if url else None

    def access(self, ident: str) -> RequestAccess | None:
        """Where the job's callers get a read pass for `ident` (asked of the helper when a call first needs it, and
        again within the margin); None when the helper's launch facts name no proxy (an empty grant)."""
        if self.proxy_url is None:
            return None
        held = job_socket.PassHolder(self.ask, str(ident), margin=PASS_REUSE_MARGIN_SEC)
        return RequestAccess(self.proxy_url, held.token)

    def box(self, kind: str, ident: str) -> Any:
        """A box of `kind` for `ident`, started by the helper (`box.relay_start`); a refusal is the box's `BoxFault`."""
        from defender import box

        return box.relay_start(self.ask, kind, str(ident))

    def materialised_export(self, commit: str) -> Mapping[str, Any]:
        """`<T>/exports/<commit>/` made by the helper if absent (`export.materialise`, P-A: the container writes no
        export and takes no knowledge lock): the helper's answer, `{commit, path}`. A refusal is the helper's
        `job_socket.Refused`; a helper that cannot be reached, its `OSError`."""
        answer = self.ask("export.materialise", commit=commit)
        if not isinstance(answer, Mapping):
            raise ValueError("the helper's answer to export.materialise is not a mapping")
        return answer

    def box_factory(self, kind: str, ident: str) -> Callable[[], Any]:
        return lambda: self.box(kind, ident)

    def records(self) -> Any:
        """The tenant records as the drain reads and writes them, answered over the socket (`_SocketRecords`)."""
        from defender.tenancy import TenantDirectory

        return TenantDirectory(lambda: _SocketRecords(self))

    def forge_credential(self) -> _SocketForgeCredential:
        return _SocketForgeCredential(self.ask, str(self.launch.get("tenant")))


#: The longest validity the helper mints a forge token for (C25).
FORGE_TOKEN_CAP = 150.0


@dataclass(frozen=True)
class _SocketForgeCredential:
    """The tenant's forge credential inside the container (O4): each token asked of the helper (`forge.token`),
    for at most `FORGE_TOKEN_CAP` seconds; the helper holds the forge login."""

    ask: Callable[..., dict[str, Any]] = field(repr=False)
    tenant_id: str

    def token(self, *, min_validity: float = 0.0) -> str:
        return str(self.ask("forge.token", min_validity=min(float(min_validity), FORGE_TOKEN_CAP))["token"])

    def close(self) -> None:
        return None


@dataclass(frozen=True)
class _Wiring:
    repo: str | None
    origin: str


@dataclass(frozen=True)
class _Tenant:
    state: str


class _SocketRecords:
    """The few tenant-record calls the drain makes, answered from the `launch` facts or over the socket (the
    `TenantDirectory` repository's shape): the forge wiring and state the helper admitted, and the publish outcome
    written by the helper (`record.published`, `record.refusal`)."""

    def __init__(self, container: JobContainer) -> None:
        self._container = container

    async def forge_wiring(self, tenant_id: Any) -> _Wiring | None:
        del tenant_id
        origin = self._container.launch.get("forge_origin")
        return None if not origin else _Wiring(self._container.launch.get("forge_repo"), str(origin))

    async def tenant(self, tenant_id: Any) -> _Tenant | None:
        del tenant_id
        state = self._container.launch.get("tenant_state")
        return None if state is None else _Tenant(str(state))

    async def record_publish_status(self, tenant_id: Any, line: str, *, by: str) -> None:
        del tenant_id, by
        from defender.tenancy import FRESH, OPERATOR, STALE_TRANSIENT, TRANSIENT

        word, _, rest = str(line).partition(" ")
        if word == FRESH:
            self._container.ask("record.published", commit=rest.strip())
        else:
            # `stale:transient` may pass by itself; `stale:operator` and `misconfigured` need a human.
            kind = TRANSIENT if word == STALE_TRANSIENT else OPERATOR
            self._container.ask("record.refusal", kind=kind, reason=rest or word)

    async def close(self) -> None:
        return None


def sigterm_on_stdin_eof() -> threading.Thread:
    """Watch this process's stdin, the per-job host helper's end of the container (A5): at its end (EOF, or a stdin
    that cannot be read) send this process SIGTERM, so the entry unwinds exactly as on the helper's stop. Only a
    process's own entry point calls this (never an in-process caller, whose stdin is not the helper's)."""

    def watch() -> None:
        try:
            while os.read(0, 65536):
                pass
        except OSError as unreadable:
            _logger.warning(f"the job container's stdin cannot be read ({unreadable!r}); ending as on SIGTERM")
        os.kill(os.getpid(), signal.SIGTERM)

    thread = threading.Thread(target=watch, name="stdin-eof", daemon=True)
    thread.start()
    return thread
