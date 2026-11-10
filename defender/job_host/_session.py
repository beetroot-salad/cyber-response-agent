"""The helper's state for its one job, and the registry its requests and job kinds are answered from (#1170).

`Session` is what every request handler and kind hook is handed: the job's identity (kind, id, tenant, claim), the
helper's seams (docker, signer, publish, forge, command), the signal state, the ids this helper minted for the claim,
and the boxes it started. `Prepared` is what a kind's `prepare` hands back: the `launch` answer, the container's
command, the pass mint and the kind's own state, and what to undo at the end.

`Registry` maps a request name and a job kind to its handler, and a job kind and a box kind to the box starter, so a
kind module (`_investigation`, `_learning`) adds what its kind is answered, and nothing is answered to a kind that
did not register it (requests are answered by job kind, r3)."""
from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from defender.job_socket import Refused
from defender.records.formats import TenantId

#: The job kinds the helper is started for (the worker's three).
KINDS = ("investigation", "learning", "post-step")
#: Seconds a pass lives from when it is signed (#1163 r7 A20; `run.py`'s `TOKEN_SEC`).
PASS_LIFETIME = 600


class SetupRefused(Exception):
    """A setup step refused the job before its container (A3 `setup: refused`); the message names the cause."""


class StartFailed(Exception):
    """The job cannot be started confined (A3 `box: start_failed`): no socket, no image, a refusing runtime, or the
    helper signalled before the container started."""


class HandBack(Exception):  # noqa: N818 — named for what it asks of the worker
    """The tenant's lock stayed busy past the kind's wait (a learning job's 30 s): the kind's `stopped` ending."""


@dataclass
class PassMint:
    """Signs a job's passes (O5): the tenant, the investigation (or pre-flight's learning job) id, the read grant
    (`reads`, each `r`), an expiry of one pass lifetime. Each call signs anew; the signer touches no database, so a
    database outage stops no pass (O6)."""

    signer: Any
    proxy_url: str
    tenant_id: str
    reads: tuple[str, ...]
    _signing: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def mint(self, investigation: str) -> dict[str, Any]:
        from defender.credential_proxy import mint_request_token

        expires_at = time.time() + PASS_LIFETIME
        with self._signing:
            token = mint_request_token(self.signer, tenant_id=self.tenant_id, investigation=investigation,
                                       grant={(s, "r") for s in self.reads},
                                       expires_at=datetime.fromtimestamp(expires_at, UTC))
        return {"token": token, "expires_at": expires_at, "proxy_url": self.proxy_url}


@dataclass
class Prepared:
    """What a kind's `prepare` settled before the container: the `launch` answer, the container's command line, the
    pass mint (None: an empty grant, or a kind that gets no pass), the kind's own state, and `cleanup`, closed at the
    helper's end (step 8) before the lock is released (what the helper made: copies, drafts, oracle folders)."""

    launch: dict[str, Any]
    command: list[str]
    passes: PassMint | None = None
    state: Any = None
    cleanup: contextlib.ExitStack = field(default_factory=contextlib.ExitStack)
    #: Called once the container has exited, with its exit status, before `cleanup` (the run page's copy, A10; a
    #: start failure only the exit status shows, A3).
    exited: Callable[[Session, int], None] | None = None


@dataclass
class Box:
    """A box this helper started for the job: its executor (docker-backed), the box kind and id it was asked for,
    and its proven stop once the helper has one."""

    executor: Any
    kind: str
    ident: str
    stopped: dict[str, Any] | None = None
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)


@dataclass
class Session:
    """The helper's one job (module doc)."""

    kind: str
    job_id: str | None
    tenant_id: TenantId
    source: str | None
    #: The data root as `tenancy.resolve_data_root` resolved it (a `DataRoot`), and as a plain path.
    root: Any
    data_root: Path
    claim: str
    docker: Any
    defender_dir: Path
    signer: Any = None
    publish: Any = None
    forge: Any = None
    command: list[str] | None = None
    signalled: threading.Event = field(default_factory=threading.Event)
    #: Every id this helper minted for the claim (the job's own, a sibling's run, a draft): `pass` and `box.start`
    #: name only these (A6).
    minted: set[str] = field(default_factory=set)
    prepared: Prepared | None = None
    boxes: dict[str, Box] = field(default_factory=dict)
    container: str = ""
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def tenant_root(self) -> Path:
        return self.data_root / self.tenant_id

    def require_minted(self, ident: object) -> str:
        if not isinstance(ident, str) or ident not in self.minted:
            raise Refused(f"{ident!r} is no id this helper minted for its claim", "unknown-id")
        return ident

    def launch(self) -> dict[str, Any]:
        if self.prepared is None:
            raise Refused("the job is not set up", "internal")
        return dict(self.prepared.launch)


Handler = Callable[[Session, dict[str, Any]], dict[str, Any]]
BoxStarter = Callable[[Session, str], Any]


@dataclass(frozen=True)
class Answering:
    """One request's handler for one job kind: the fields it requires and those it allows, and whether it is still
    answered once the helper is signalled (A1)."""

    handler: Handler
    required: frozenset[str]
    optional: frozenset[str]
    after_signal: bool


@dataclass(frozen=True)
class KindSpec:
    """A job kind's hooks: `prepare(session, hold) -> Prepared` (the host half: lock and admission entered on
    `hold`, which is closed last, so the lock goes when the helper exits), and `end(session, cause)` for an ending
    decided before the container starts (`refused`, `start-failed`, `crashed`, `busy`), written in the kind's own
    vocabulary (A3)."""

    prepare: Callable[[Session, contextlib.ExitStack], Prepared]
    end: Callable[[Session, str], None]


@dataclass
class Registry:
    """Requests by (name, job kind), box starters by (job kind, box kind), and the job kinds' hooks."""

    handlers: dict[tuple[str, str], Answering] = field(default_factory=dict)
    box_kinds: dict[tuple[str, str], BoxStarter] = field(default_factory=dict)
    kinds: dict[str, KindSpec] = field(default_factory=dict)

    def add(self, name: str, *, kinds: Iterable[str], handler: Handler, required: Iterable[str] = (),
            optional: Iterable[str] = (), after_signal: bool = False) -> None:
        for kind in kinds:
            self.handlers[(name, kind)] = Answering(handler, frozenset(required), frozenset(optional), after_signal)

    def box_kind(self, box_kind: str, *, kinds: Iterable[str], start: BoxStarter) -> None:
        for kind in kinds:
            self.box_kinds[(kind, box_kind)] = start

    def kind(self, name: str, spec: KindSpec) -> None:
        self.kinds[name] = spec

    def answer(self, session: Session, name: object, fields: object) -> dict[str, Any]:
        """The answer to one request, or `Refused` (unknown, not for this kind, bad fields, refused once signalled)."""
        if not isinstance(name, str) or not isinstance(fields, dict):
            raise Refused("a request is a name and its fields", "bad-fields")
        answering = self.handlers.get((name, session.kind))
        if answering is None:
            known = any(n == name for n, _k in self.handlers)
            raise Refused(f"{name!r} is not answered to a {session.kind} job" if known else
                          f"{name!r} is no request the helper knows", "not-for-kind" if known else "unknown-request")
        missing = answering.required - set(fields)
        extra = set(fields) - answering.required - answering.optional
        if missing or extra:
            raise Refused(f"{name!r} takes {sorted(answering.required)} (and optionally "
                          f"{sorted(answering.optional)}); got {sorted(fields)}", "bad-fields")
        if session.signalled.is_set() and not answering.after_signal:
            raise Refused(f"the helper has been told to stop; {name!r} is no longer answered", "signalled")
        return answering.handler(session, fields)
