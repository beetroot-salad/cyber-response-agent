"""The launch-time publish (#1108 P4 U7): a short-lived child process, started by a run's launcher
before the run begins, publishes the tenant's merged `main` and reports ONE line on stdout:

    fresh <commit>               `current` names <commit>, the fetched `origin/main`
    stale:transient <reason>     an outage (issuer or forge unreachable, a timeout, lock busy)
    stale:operator <reason>      needs a human (a refused login or token, `main` unprotected,
                                 a dirty or diverged clone, a merged commit refused on content)
    misconfigured <reason>       decided locally, before any network call: no issuer client
                                 config file, or no forge binding in the tenant row

The child exits 0 for every outcome it reports (OD20); anything else is the parent's to read
as a failed child. The run process never imports this package (P-3): it only spawns
`python -m defender.learning.author.version_control.publish_child <tenant id> --data-root
<root>`
and reads the line. The child accepts the tenant itself, reads the issuer client config
(its own path, never handed over the environment) and the row's forge binding itself, and
logs in itself (A-ID); none of that material reaches its report (O8).
"""

from __future__ import annotations

import argparse
import signal
from collections.abc import Callable, Sequence
from pathlib import Path
from types import FrameType
from typing import TYPE_CHECKING

from defender.tenancy._tenant import (
    Tenant,
    TenantRefused,
    data_root_from_path,
    read_forge_binding,
    requested_tenant,
)

from .auth import ForgejoIdentity
from .exports import _pointed_at, publish_locked, tenant_lock
from .issuer import DEV_ISSUER_CONFIG, issuer_login, read_issuer_config
from .model import DeliveryRefused, LockBusy, _refusals
from .repository import GitRepository
from .status import OPERATOR, classify, one_line, record_published, record_refused

if TYPE_CHECKING:
    import httpx

FRESH = "fresh"
STALE_TRANSIENT = "stale:transient"
STALE_OPERATOR = "stale:operator"
MISCONFIGURED = "misconfigured"
#: Every report line's first word.
REPORT_CLASSES = (FRESH, STALE_TRANSIENT, STALE_OPERATOR, MISCONFIGURED)
#: Each network call's own bound in the child (issuer, forge, fetch), well inside the
#: launcher's budget, so a stalled call ends in the child before the parent gives up.
CHILD_NETWORK_TIMEOUT = 30.0
#: Who records a launch-time publish's outcome (`tenant.py check` names the trigger).
_TRIGGER = "launch-time publish"


def report(kind: str, detail: str) -> str:
    """One report line: `kind` and its one-line detail."""
    return f"{kind} {one_line(detail)}"


def publish_for_run(
    tenant_id: str,
    *,
    data_root: Path,
    issuer_config: Path,
    client: httpx.Client | None = None,
    issuer_transport: httpx.BaseTransport | None = None,
    identity: ForgejoIdentity | None = None,
    network_timeout: float | None = None,
    locked_hook: Callable[[], None] | None = None,
) -> str:
    """The child's work, in-process: accept the tenant from its id and the data root; decide
    misconfiguration (issuer client config file, forge binding) before anything is sent; log in
    (or use the injected `identity`); open the tenant's delivery against the binding's origin
    with the forge `client`; fetch; then, under the tenant lock (`locked_hook` first, the
    locked phase's one injectable slow point), publish. Returns the report line; records the
    outcome for `tenant.py check` (O-SEE). With the lock busy the outcome is `fresh` when
    `current` already names the fetched `origin/main`, else `stale:transient`."""
    try:
        tenant = requested_tenant(data_root_from_path(Path(data_root)), tenant_id)
    except TenantRefused as refused:
        return report(STALE_OPERATOR, f"the tenant was not accepted: {refused}")
    try:
        read_issuer_config(issuer_config)
        binding = read_forge_binding(tenant)
    except (DeliveryRefused, TenantRefused) as misconfigured:
        record_refused(tenant, misconfigured, by=_TRIGGER)
        return report(MISCONFIGURED, str(misconfigured))
    timeout = CHILD_NETWORK_TIMEOUT if network_timeout is None else network_timeout
    repository: GitRepository | None = None
    try:
        with _refusals():
            if identity is None:
                identity = issuer_login(
                    tenant, issuer_config=issuer_config, transport=issuer_transport
                )
            if client is None:
                import httpx

                client = httpx.Client()
            repository = GitRepository.open(
                tenant.knowledge,
                tenant_id=str(tenant.id),
                identity=identity,
                origin=binding.origin,
                client=client,
                network_timeout=timeout,
            )
            repository.fetch()
            with tenant_lock(tenant):
                _LOCKED.enter()
                try:
                    if locked_hook is not None:
                        locked_hook()
                    export = publish_locked(tenant, repository)
                finally:
                    _LOCKED.leave()
    except LockBusy as busy:
        return _lock_busy(tenant, repository, busy)
    except DeliveryRefused as refused:
        record_refused(tenant, refused, by=_TRIGGER)
        kind, reason = classify(refused)
        return report(STALE_OPERATOR if kind == OPERATOR else STALE_TRANSIENT, reason)
    record_published(tenant, export.commit, by=_TRIGGER)
    return report(FRESH, export.commit)


def _lock_busy(tenant: Tenant, repository: GitRepository | None, busy: LockBusy) -> str:
    """O7b: a drain holds the lock. Fresh only when `current` already names the fetched
    `origin/main` (the run reads the merge anyway); otherwise stale for the lock."""
    current = _pointed_at(tenant)
    upstream = None
    if repository is not None:
        try:
            with _refusals():
                upstream = repository.revision("refs/remotes/origin/main")
        except DeliveryRefused:
            upstream = None
    if current is not None and current == upstream:
        return report(FRESH, current)
    return report(STALE_TRANSIENT, f"the tenant knowledge lock is busy: {busy}")


class _Locked:
    """Whether this process is in its locked phase. A child holding the tenant lock is never
    stopped part way (a SIGTERM then is ignored): its local work finishes, so no `index.lock`
    or half-swapped `current` is left (O-BUDGET), and no network call follows it."""

    def __init__(self) -> None:
        self.held = False

    def enter(self) -> None:
        self.held = True

    def leave(self) -> None:
        self.held = False


_LOCKED = _Locked()


class _Stopped(BaseException):
    """The launcher stopped waiting and asked the child to end (SIGTERM): unwinds every
    `finally` on the way out (a network git call kills its own process group there)."""


def _on_terminate(_signum: int, _frame: FrameType | None) -> None:
    if not _LOCKED.held:
        raise _Stopped()


def publish_child_main(
    argv: Sequence[str],
    *,
    issuer_config: Path | None = None,
    client: httpx.Client | None = None,
    identity: ForgejoIdentity | None = None,
    network_timeout: float | None = None,
    locked_hook: Callable[[], None] | None = None,
) -> int:
    """The child process's entry: `<tenant id> --data-root <root> [--issuer-config <path>]`
    (identifiers and one path, never a secret). Prints the report line and returns 0 for every
    outcome it reports. The keywords are in-process stand-ins (as `publish_for_run`'s);
    `issuer_config` defaults to `--issuer-config`, else the dev config path."""
    parser = argparse.ArgumentParser(prog="publish-child", add_help=False)
    parser.add_argument("tenant_id")
    parser.add_argument("--data-root", required=True, type=Path)
    parser.add_argument("--issuer-config", type=Path, default=None)
    ns = parser.parse_args(list(argv))
    config = issuer_config or ns.issuer_config or DEV_ISSUER_CONFIG
    previous = signal.signal(signal.SIGTERM, _on_terminate)
    try:
        line = publish_for_run(
            ns.tenant_id,
            data_root=ns.data_root,
            issuer_config=config,
            client=client,
            identity=identity,
            network_timeout=network_timeout,
            locked_hook=locked_hook,
        )
    except _Stopped:
        return 128 + signal.SIGTERM
    finally:
        signal.signal(signal.SIGTERM, previous)
    print(one_line(line), flush=True)
    return 0
