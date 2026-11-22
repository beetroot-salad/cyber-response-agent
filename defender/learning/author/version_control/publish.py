"""The launch-time publish (#1108 P4 U7): a short-lived child process, started by a run's launcher
before the run begins, publishes the tenant's merged `main` and reports ONE line on stdout:

    fresh <commit>               `current` names <commit>, the fetched `origin/main`
    stale:transient <reason>     an outage (issuer or forge unreachable, a timeout, lock busy)
    stale:operator <reason>      needs a human (a refused login or token, `main` unprotected,
                                 a dirty or diverged clone, a merged commit refused on content)
    misconfigured <reason>       needs a setting or a host file, not a retry: no tenant
                                 records to read, no forge wiring recorded, or a host secret
                                 file missing, unreadable or malformed

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
import os
import shutil
import tempfile
import signal
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from types import FrameType
from typing import TYPE_CHECKING, Any

from defender import _io
from defender._text import one_line
from defender.tenancy import Tenant, data_root_from_path, requested_tenant
from defender.records.formats import TenantRefused

from .auth import ForgeCredential
from .credential import forge_credential
from .exports import knowledge_at, sweep_dead_owners
from .model import DeliveryRefused, _OID, _refusals
from .repository import GitRepository
from .status import classify, record_report
from defender.tenancy._publish_status import MISCONFIGURED, OK, REFUSED
from defender.tenancy import run_knowledge

if TYPE_CHECKING:
    import httpx

    from defender.tenancy import TenantDirectory

#: Every report line's first word.
REPORT_CLASSES = (OK, REFUSED)
#: Each network call's own bound in the child (issuer, forge, fetch). The calls together are
#: bounded by the child's one deadline (`--budget`), which this never outlasts.
CHILD_NETWORK_TIMEOUT = 30.0
#: Who records a launch-time publish's outcome when its launcher names no trigger (`--trigger`; a readiness check's
#: publish is recorded `readiness`, #1471): an investigation's launch.
_TRIGGER = "launch-time publish"
#: Who asks for main's protection to be checked as well (D9): onboarding and readiness, not a run.
_PROTECTED_TRIGGERS = ("readiness", "onboarding")


def report(kind: str, detail: str) -> str:
    """One report line: `kind` (one of `REPORT_CLASSES`) and its one-line detail."""
    if kind not in REPORT_CLASSES:
        raise ValueError(f"{kind!r} is not a publish outcome")
    if kind == REFUSED and detail.split(" ", 1)[0] not in ("transient", "lasting"):
        detail = f"lasting {detail}"  # D5: every refusal carries its class
    return f"{kind} {one_line(detail)}"


def publish_for_run(  # noqa: PLR0913 — the child's work and its in-process stand-ins
    tenant_id: str,
    *,
    data_root: Path,
    dest: Path,
    commit: str | None = None,
    directory: TenantDirectory | None = None,
    credential_config: Any = None,
    client: httpx.Client | None = None,
    issuer_transport: httpx.BaseTransport | None = None,
    identity: ForgeCredential | None = None,
    network_timeout: float | None = None,
    budget: float | None = None,
    trigger: str = _TRIGGER,
) -> str:
    """SPIKE #1618. The fetch child's work: accept the tenant, mint its credential, fetch `main` (or `commit` by
    id) into a private repository, validate it and write `<T>/run-knowledge/<run_id>/` owned by `owner_pid`
    (default this process). Returns `ok <commit>` or `refused <reason>`, recorded as `trigger`'s."""
    from defender.systems.run_tenant import RecordsUnreachable, entry_directory

    try:
        tenant = requested_tenant(data_root_from_path(Path(data_root)), tenant_id)
    except TenantRefused as refused:
        return report(REFUSED, f"the tenant was not accepted: {refused}")
    try:
        directory = entry_directory(directory)
    except RecordsUnreachable as down:
        return report(REFUSED, str(down))
    except TenantRefused as unconfigured:
        return report(REFUSED, str(unconfigured))
    line = _publish_unrecorded(
        tenant, directory=directory, credential_config=credential_config, client=client,
        issuer_transport=issuer_transport, identity=identity, network_timeout=network_timeout,
        budget=budget, dest=Path(dest), commit=commit, trigger=trigger)
    record_report(directory, tenant.id, line, by=trigger)
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
    budget: float | None,
    dest: Path,
    commit: str | None,
    trigger: str,
) -> str:
    if commit is not None and not _OID.fullmatch(commit):
        return report(REFUSED, f"{commit!r} is not a full commit id")
    credential = identity if identity is not None else forge_credential(
        tenant.id, "publish", directory=directory, config=credential_config,
        transport=issuer_transport)
    timeout = CHILD_NETWORK_TIMEOUT if network_timeout is None else network_timeout
    try:
        with contextlib.ExitStack() as owned, _refusals():
            wiring = directory.forge_wiring(tenant.id)
            if wiring is None:
                return report(MISCONFIGURED, f"tenant {tenant.id} has no forge wiring recorded: its repository "
                                             "is not bound to a forge")
            # Flow 8: every start sweeps dead owners' scratch; no lock (K7)
            sweep_dead_owners(tenant)
            with _deadline(budget):
                if identity is None:
                    owned.callback(credential.close)  # type: ignore[attr-defined]
                if client is None:
                    import httpx

                    client = owned.enter_context(httpx.Client())
                private = Path(tempfile.mkdtemp(prefix="defender-fetch-"))  # 0700, the child's own, outside <T>
                try:
                    repository, got = GitRepository.open_private(
                        private / "fetch.git", tenant_id=str(tenant.id), identity=credential,
                        origin=wiring.origin, client=client, network_timeout=timeout, commit=commit)
                    if trigger in _PROTECTED_TRIGGERS:  # D9: onboarding and readiness also check main's protection
                        repository.forge.verify_main_protection()
                    files = knowledge_at(tenant, repository, got)
                    _fill(dest, files)
                finally:
                    shutil.rmtree(private, ignore_errors=True)
    except _OutOfTime as late:
        return report(REFUSED, f"the fetch did not finish within its {late.budget:g}s budget")
    except (DeliveryRefused, run_knowledge.KnowledgeRefused, OSError) as refused:
        klass = "transient" if classify(refused)[0] == "transient" else "lasting"
        return report(REFUSED, f"{klass} {refused}")
    return report(OK, got)


def _fill(dest: Path, files: dict[str, bytes]) -> None:
    """`files` (`agent/...`, `settings/...`) written below `dest`, held open no-follow and required empty, every write
    relative to that handle: `agent/` under `stage/` (the run copy's layout), `settings/` beside it."""
    with _io.hold(dest, follow=False) as held:
        with held._dup() as fd:  # noqa: SLF001 — `Held` has no listing verb, and its root is a path-only handle
            listing = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=fd)
            try:
                present = os.listdir(listing)
            finally:
                os.close(listing)
            if present:
                raise run_knowledge.KnowledgeRefused(f"the destination {dest} is not empty")
        for half, under in (("agent", "stage/agent"), ("settings", "settings")):
            held.mkdir(under)  # lint-unguarded-tree-write: ok — `Held.mkdir`, no link followed
        for path, data in files.items():
            head, _sep, rel = path.partition("/")
            if head in ("agent", "settings"):
                held.write(f"{'stage/agent' if head == 'agent' else 'settings'}/{rel}", data, mode="create")


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
) -> int:
    """The child process's entry: `<tenant id> --data-root <root> [--budget <seconds>] [--trigger <who asked>]`
    (identifiers, a number and a fixed word, never a secret or a path to one). Prints the report line and
    returns 0 for every outcome it reports. The keywords are in-process stand-ins (as
    `publish_for_run`'s); with no `--budget` the child holds no deadline of its own."""
    parser = argparse.ArgumentParser(prog="publish-child", add_help=False)
    parser.add_argument("tenant_id")
    parser.add_argument("--data-root", dest="root", required=True, type=Path)
    parser.add_argument("--budget", type=float, default=None)
    parser.add_argument("--trigger", default=_TRIGGER)
    parser.add_argument("--dest", required=True, type=Path)
    parser.add_argument("--commit", default=None)
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
            budget=ns.budget,
            trigger=ns.trigger,
            dest=ns.dest,
            commit=ns.commit,
        )
    except _Stopped:
        return 128 + signal.SIGTERM
    finally:
        signal.signal(signal.SIGTERM, previous)
    print(one_line(line), flush=True)
    return 0
