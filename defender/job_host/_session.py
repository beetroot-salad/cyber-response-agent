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

from defender.credential_proxy import PASS_LIFETIME_SEC
from defender.job_socket import Refused
from defender.records.formats import TenantId

#: The job kinds the helper is started for (the worker's three).
KINDS = ("investigation", "learning", "post-step")
#: The exit statuses of a `docker run` that never ran the job: docker's own failure (an image missing, a runtime
#: refused, 125), a command it could not invoke (126) or find (127). Every kind's after-the-container hook reads them.
DOCKER_DID_NOT_RUN = frozenset({125, 126, 127})


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

        expires_at = time.time() + PASS_LIFETIME_SEC
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
    #: The helper's own window handle on the box (`box.BoxRuns`), made at the job's first `box.window` or `box.halt`:
    #: it holds an open window's attached start between the job's requests.
    windows: Any = field(default=None, repr=False)

    def window_handle(self) -> Any:
        """The box's window handle, made once (call under `lock`)."""
        if self.windows is None:
            from defender.box import BoxRuns

            self.windows = BoxRuns(self.executor)
        return self.windows


@dataclass
class Session:
    """The helper's one job (module doc)."""

    kind: str
    job_id: str | None
    tenant_id: TenantId
    source: str | None
    #: The data root as `tenancy.resolve_data_root` resolved it (a `DataRoot`), and as the plain folder its owner
    #: exports to a child (`tenancy.data_root_for_child`): where the claim's socket and scratch folders are made
    #: (H9, C21), outside every tenant's folder, and the container's `DEFENDER_DATA_ROOT`.
    root: Any
    root_folder: Path
    claim: str
    docker: Any
    defender_dir: Path
    signer: Any = None
    publish: Any = None
    forge: Any = None
    client: Any = None
    command: list[str] | None = None
    signalled: threading.Event = field(default_factory=threading.Event)
    #: Every id this helper minted for the claim (the job's own, a sibling's run, a draft): `pass` and `box.start`
    #: name only these (A6).
    minted: set[str] = field(default_factory=set)
    prepared: Prepared | None = None
    boxes: dict[str, Box] = field(default_factory=dict)
    #: The (box kind, id) pairs whose start is under way: reserved under `lock` before the start, so two concurrent
    #: starts of one run's box cannot both pass the one-box-per-id check.
    starting: set[tuple[str, str]] = field(default_factory=set)
    container: str = ""
    #: The tenant's folder, from the tenant the kind's `prepare` accepted (`tenancy.job_tenant_folder`): the job
    #: container's tenant bind (O1) and the folder every path the helper derives is confined to (H10). None until
    #: the tenant is accepted.
    tenant_folder: Path | None = None
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def tenant_accepted(self, tenant: Any) -> None:
        """The tenant `prepare` admitted: its folder is the one this job's container and boxes are confined to."""
        from defender import tenancy

        self.tenant_folder = tenancy.job_tenant_folder(tenant)

    def inside_tenant(self, path: Path, *, must_exist: bool = True) -> Path:
        """`path`, judged inside the accepted tenant's folder with no link followed (`_paths.confined`)."""
        from ._paths import confined

        if self.tenant_folder is None:
            raise Refused("the job's tenant is not accepted yet", "internal")
        return confined(self.tenant_folder, path, must_exist=must_exist)

    def judge_binds(self, sources: Iterable[Path | str], *, must_exist: bool = True) -> None:
        """Every bind source of a box under the accepted tenant's folder, judged from `<T>/` down with no link
        followed at any component (`inside_tenant`, H10), so a job that swaps any folder on the way for a link is
        refused (`confinement`) before the box is started over it; with `must_exist` false a source not there yet
        passes (the start makes it, or refuses it). A source outside `<T>/` (the code tree, the claim's scratch
        folder) is none the job can swap."""
        for source in sources:
            path = Path(source)
            if self.tenant_folder is None or path.is_relative_to(self.tenant_folder):
                self.inside_tenant(path, must_exist=must_exist)

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
