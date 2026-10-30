"""The launch-time publish (#1108 P4 U7): a short-lived child process, started by a run's launcher
before the run begins, publishes the tenant's merged `main` and reports ONE line on stdout:

    fresh <commit>               `current` names <commit>, the fetched `origin/main`
    stale:transient <reason>     an outage (issuer or forge unreachable, a timeout, lock busy)
    stale:operator <reason>      needs a human (a refused login or token, `main` unprotected,
                                 a dirty or diverged clone, a merged commit refused on content)
    misconfigured <reason>       decided locally, before any network call: no tenant records
                                 to read, no forge wiring recorded, or no issuer configured

The child exits 0 for every outcome it reports (OD20); anything else is the parent's to read
as a failed child. The run process never imports this package (P-3): it only spawns
`python -m defender.learning.author.version_control.publish_child <tenant id> --data-root
<root> --budget <seconds>`
and reads the line. The child accepts the tenant itself, reads its forge wiring from the tenant
records (`DEFENDER_DATABASE_DSN`, the one variable its launcher adds back to the scrubbed
environment, #1214 DC-9), mints its credential through the tenant's live generation
(`forge_credential`), and records its outcome there (P2); none of that material reaches its
report (O8). It holds ONE deadline over its
whole network phase (`--budget`, inside the launcher's own wait), so an outage ends as its own
recorded `stale:transient` report rather than as the launcher stopping it.
"""

from __future__ import annotations

import argparse
import contextlib
import signal
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from types import FrameType
from typing import TYPE_CHECKING, Any

from defender._text import one_line
from defender.tenancy import Tenant, data_root_from_path, requested_tenant
from defender.records.formats import TenantRefused

from .auth import ForgeCredential
from .credential import forge_credential
from .exports import _pointed_at, publish_locked, tenant_lock
from .model import DeliveryRefused, LockBusy, _refusals
from .repository import GitRepository
from .status import (
    FRESH,
    MISCONFIGURED,
    OPERATOR,
    STALE_OPERATOR,
    STALE_TRANSIENT,
    classify,
    is_misconfigured,
    record_report,
)

if TYPE_CHECKING:
    import httpx

    from defender.tenancy import TenantDirectory

#: Every report line's first word.
REPORT_CLASSES = (FRESH, STALE_TRANSIENT, STALE_OPERATOR, MISCONFIGURED)
#: Each network call's own bound in the child (issuer, forge, fetch). The calls together are
#: bounded by the child's one deadline (`--budget`), which this never outlasts.
CHILD_NETWORK_TIMEOUT = 30.0
#: Who records a launch-time publish's outcome (`tenant.py check` names the trigger).
_TRIGGER = "launch-time publish"


def report(kind: str, detail: str) -> str:
    """One report line: `kind` (one of `REPORT_CLASSES`) and its one-line detail."""
    if kind not in REPORT_CLASSES:
        raise ValueError(f"{kind!r} is not a publish outcome")
    return f"{kind} {one_line(detail)}"


def publish_for_run(  # noqa: PLR0913 — the child's work and its in-process stand-ins
    tenant_id: str,
    *,
    data_root: Path,
    directory: TenantDirectory | None = None,
    credential_config: Any = None,
    client: httpx.Client | None = None,
    issuer_transport: httpx.BaseTransport | None = None,
    identity: ForgeCredential | None = None,
    network_timeout: float | None = None,
    locked_hook: Callable[[], None] | None = None,
    budget: float | None = None,
) -> str:
    """The child's work, in-process: accept the tenant from its id and the data root; read its
    forge wiring from the tenant records (`directory`, else the one `DEFENDER_DATABASE_DSN` names)
    and decide misconfiguration before anything is sent; mint the tenant's credential through its
    live generation (or use the injected `identity`; `credential_config` is the host's issuer
    configuration, `issuer_transport` a stand-in transport to it); open the tenant's delivery
    against the recorded origin with the forge `client`; fetch; then, under the tenant lock
    (`locked_hook` first, the locked phase's one injectable slow point), publish. Returns the
    report line; records the outcome in the tenant records for `tenant.py check` (O-SEE). With
    the lock busy the outcome is `fresh` when `current` already names the fetched `origin/main`,
    else `stale:transient`. `budget` is the one deadline over the network phase (login, open,
    fetch; none when `None`): past it, `stale:transient`. Clients made here are closed before it
    returns. Every outcome reported for an accepted tenant is recorded, once, from the report line
    itself."""
    from defender.systems.run_tenant import RecordsUnreachable, entry_directory

    try:
        tenant = requested_tenant(data_root_from_path(Path(data_root)), tenant_id)
    except TenantRefused as refused:
        return report(STALE_OPERATOR, f"the tenant was not accepted: {refused}")
    try:
        directory = entry_directory(directory)
    except RecordsUnreachable as down:
        return report(STALE_TRANSIENT, str(down))
    except TenantRefused as unconfigured:
        return report(MISCONFIGURED, str(unconfigured))
    line = _publish_unrecorded(
        tenant, directory=directory, credential_config=credential_config, client=client,
        issuer_transport=issuer_transport, identity=identity, network_timeout=network_timeout,
        locked_hook=locked_hook, budget=budget)
    record_report(directory, tenant.id, line, by=_TRIGGER)
    return line


def _publish_unrecorded(  # noqa: PLR0913 — `publish_for_run`'s work, its outcome unrecorded
    tenant: Tenant,
    *,
    directory: TenantDirectory,
    credential_config: Any,
    client: httpx.Client | None,
    issuer_transport: httpx.BaseTransport | None,
    identity: ForgeCredential | None,
    network_timeout: float | None,
    locked_hook: Callable[[], None] | None,
    budget: float | None,
) -> str:
    wiring = directory.forge_wiring(str(tenant.id))
    if wiring is None:
        return report(MISCONFIGURED, f"tenant {tenant.id} has no forge wiring recorded: its repository is "
                                     "not bound to a forge")
    try:
        credential = identity if identity is not None else forge_credential(
            str(tenant.id), "publish", directory=directory, config=credential_config,
            transport=issuer_transport)
    except DeliveryRefused as misconfigured:
        return report(MISCONFIGURED, str(misconfigured))
    timeout = CHILD_NETWORK_TIMEOUT if network_timeout is None else network_timeout
    repository: GitRepository | None = None
    try:
        with contextlib.ExitStack() as owned, _refusals():
            with _deadline(budget):
                if identity is None:
                    # made here (not the caller's): its OpenBao client closes with the publish
                    owned.callback(credential.close)  # type: ignore[attr-defined]
                if client is None:
                    import httpx

                    client = owned.enter_context(httpx.Client())
                repository = GitRepository.open(
                    tenant.knowledge,
                    tenant_id=str(tenant.id),
                    identity=credential,
                    origin=wiring.origin,
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
    except _OutOfTime as late:
        return report(STALE_TRANSIENT, f"the launch-time publish did not finish its network "
                                       f"phase within its {late.budget:g}s budget")
    except LockBusy as busy:
        return _lock_busy(tenant, repository, busy)
    except DeliveryRefused as refused:
        if is_misconfigured(refused):
            return report(MISCONFIGURED, str(refused))
        kind, reason = classify(refused)
        return report(STALE_OPERATOR if kind == OPERATOR else STALE_TRANSIENT, reason)
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


class _OutOfTime(BaseException):
    """The deadline over the network phase passed (SIGALRM): unwinds as `_Stopped` does, and
    `publish_for_run` reports and records it as `stale:transient`."""

    def __init__(self, budget: float) -> None:
        super().__init__(budget)
        self.budget = budget


def _on_terminate(_signum: int, _frame: FrameType | None) -> None:
    if not _LOCKED.held:
        raise _Stopped()


@contextlib.contextmanager
def _deadline(budget: float | None) -> Iterator[None]:
    """`_OutOfTime` once `budget` seconds pass inside the block (nothing when `None`; at once,
    on entry, when it is not positive: an interval timer of 0 is no timer). Scoped to the
    network phase, so the locked phase and the report after it are never cut off."""
    if budget is None:
        yield
        return
    if budget <= 0:
        raise _OutOfTime(budget)

    def expired(_signum: int, _frame: FrameType | None) -> None:
        raise _OutOfTime(budget)

    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, budget)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def publish_child_main(
    argv: Sequence[str],
    *,
    directory: TenantDirectory | None = None,
    credential_config: Any = None,
    client: httpx.Client | None = None,
    identity: ForgeCredential | None = None,
    network_timeout: float | None = None,
    locked_hook: Callable[[], None] | None = None,
) -> int:
    """The child process's entry: `<tenant id> --data-root <root> [--budget <seconds>]`
    (identifiers and a number, never a secret or a path to one). Prints the report line and
    returns 0 for every outcome it reports. The keywords are in-process stand-ins (as
    `publish_for_run`'s); with no `--budget` the child holds no deadline of its own."""
    parser = argparse.ArgumentParser(prog="publish-child", add_help=False)
    parser.add_argument("tenant_id")
    parser.add_argument("--data-root", dest="root", required=True, type=Path)
    parser.add_argument("--budget", type=float, default=None)
    ns = parser.parse_args(list(argv))
    previous = signal.signal(signal.SIGTERM, _on_terminate)
    try:
        line = publish_for_run(
            ns.tenant_id,
            data_root=ns.root,
            directory=directory,
            credential_config=credential_config,
            client=client,
            identity=identity,
            network_timeout=network_timeout,
            locked_hook=locked_hook,
            budget=ns.budget,
        )
    except _Stopped:
        return 128 + signal.SIGTERM
    finally:
        signal.signal(signal.SIGTERM, previous)
    print(one_line(line), flush=True)
    return 0
