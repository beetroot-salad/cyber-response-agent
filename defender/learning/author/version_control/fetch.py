"""The fetch child (#1618 flow 1): the one way knowledge leaves Forgejo for the host. A short-lived child process,
started by a reader (a run's launcher, the learning helper, an operator tool), fetches the tenant's `main` (or one
commit by id) into a private repository, validates it, fills the empty folder its caller made, and reports ONE line
on stdout:

    ok <commit>                       `dest` holds `agent/` and `settings/` at <commit>
    refused <transient|lasting> <reason>
                                      transient: an outage (issuer or forge unreachable, a timeout);
                                      lasting: a retry changes nothing (a refused login, an unserved commit, content
                                      that does not validate, a tenant not accepted)

The child exits 0 for every outcome it reports; anything else is the parent's to read as a failed child. The run
process never imports this package (P-3). The child accepts the tenant itself, reads its forge wiring from the tenant
records, and mints its credential through the tenant's live generation (none of that reaches its report, O8). It
records nothing: the caller owns `dest`, keeps it on `ok` and discards it otherwise.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import signal
from collections.abc import Iterator, Sequence
from pathlib import Path
from types import FrameType
from typing import TYPE_CHECKING, Any

from defender import _io
from defender._text import one_line
from defender.records.formats import TenantRefused
from defender.tenancy import (
    data_root_from_path,
    data_root_for_child,
    private_folder,
    requested_tenant,
    run_knowledge,
    sweep_dead_owners,
)

from .auth import ForgeCredential
from .credential import forge_credential
from .exports import knowledge_at
from .model import _OID, DeliveryRefused, _refusals
from .repository import GitRepository
from .status import classify

if TYPE_CHECKING:
    import httpx

    from defender.tenancy import TenantDirectory

OK, REFUSED = "ok", "refused"
#: Each network call's own bound in the child (issuer, forge, fetch). The calls together are bounded by the child's
#: one deadline (`--budget`), which this never outlasts.
CHILD_NETWORK_TIMEOUT = 30.0
#: Who asks for main's protection to be checked as well (D9): onboarding and readiness, not a run.
_PROTECTED_TRIGGERS = ("readiness", "onboarding")


def report(kind: str, detail: str) -> str:
    """One report line: `ok <commit>`, or `refused <transient|lasting> <reason>` (a refusal without its class is
    `lasting`)."""
    if kind == REFUSED and detail.split(" ", 1)[0] not in ("transient", "lasting"):
        detail = f"lasting {detail}"
    return f"{kind} {one_line(detail)}"


def fetch_copy(  # noqa: PLR0913 — the child's work and its in-process stand-ins
    tenant_id: str,
    dest: Path,
    commit: str | None = None,
    *,
    data_root: Path,
    directory: TenantDirectory | None = None,
    credential_config: Any = None,
    client: httpx.Client | None = None,
    issuer_transport: httpx.BaseTransport | None = None,
    identity: ForgeCredential | None = None,
    network_timeout: float | None = None,
    budget: float | None = None,
    trigger: str = "",
) -> str:
    """Fetch `main` (or `commit`, by id) of the tenant's Forgejo repository into a private repository, validate it, and
    fill the empty folder `dest` with its `agent/` and `settings/`. Answers the commit; any refusal raises (the child
    turns it into its report line)."""
    line = _fetch_line(
        tenant_id, Path(dest), commit, data_root=data_root, directory=directory, credential_config=credential_config,
        client=client, issuer_transport=issuer_transport, identity=identity, network_timeout=network_timeout,
        budget=budget, trigger=trigger)
    word, _sep, rest = line.partition(" ")
    if word != OK:
        raise DeliveryRefused(rest.partition(" ")[2] or rest)
    return rest


def _fetch_line(  # noqa: C901, PLR0913 — `fetch_copy`'s inputs: one accept, one fetch, one report
    tenant_id: str, dest: Path, commit: str | None, *, data_root: Path, directory: TenantDirectory | None,
    credential_config: Any, client: httpx.Client | None, issuer_transport: httpx.BaseTransport | None,
    identity: ForgeCredential | None, network_timeout: float | None, budget: float | None, trigger: str,
) -> str:
    from defender.systems.run_tenant import RecordsUnreachable, entry_directory

    try:
        tenant = requested_tenant(data_root_from_path(Path(data_root)), tenant_id)
    except TenantRefused as refused:
        return report(REFUSED, f"the tenant was not accepted: {refused}")
    try:
        directory = entry_directory(directory)
    except RecordsUnreachable as down:
        return report(REFUSED, f"transient {down}")
    except TenantRefused as unconfigured:
        return report(REFUSED, str(unconfigured))
    if commit is not None and not _OID.fullmatch(commit):
        return report(REFUSED, f"{commit!r} is not a full commit id")
    credential = identity if identity is not None else forge_credential(
        tenant.id, "fetch", directory=directory, config=credential_config, transport=issuer_transport)
    timeout = CHILD_NETWORK_TIMEOUT if network_timeout is None else network_timeout
    root = data_root_for_child(data_root_from_path(Path(data_root)))
    try:
        with contextlib.ExitStack() as owned, _refusals():
            wiring = directory.forge_wiring(tenant.id)
            if wiring is None:
                return report(REFUSED, f"lasting tenant {tenant.id} has no forge wiring recorded: its repository "
                                       "is not bound to a forge")
            sweep_dead_owners(root, tenant.id)  # flow 8: every fetch starts by sweeping dead owners
            with _deadline(budget):
                if identity is None:
                    owned.callback(credential.close)  # type: ignore[attr-defined]
                if client is None:
                    import httpx

                    client = owned.enter_context(httpx.Client())
                with private_folder(root, tenant.id) as private:
                    repository, got = GitRepository.open_private(
                        private / "fetch.git", tenant_id=str(tenant.id), identity=credential, origin=wiring.origin,
                        client=client, network_timeout=timeout, commit=commit)
                    if trigger in _PROTECTED_TRIGGERS:  # D9: only onboarding and readiness check main's protection
                        repository.forge.verify_main_protection()
                    _write_into(dest, knowledge_at(tenant, repository, got))
    except _OutOfTime as late:
        return report(REFUSED, f"transient the fetch did not finish within its {late.budget:g}s budget")
    except (DeliveryRefused, run_knowledge.KnowledgeRefused, OSError) as refused:
        return report(REFUSED, f"{classify(refused)[0]} {refused}")
    return report(OK, got)


def _write_into(dest: Path, files: dict[str, bytes]) -> None:
    """`files` (`agent/...`, `settings/...`) written below `dest`, held open no-follow and required empty, every write
    relative to that handle: `agent/` and `settings/` as the commit holds them."""
    with _io.hold(dest, follow=False) as held:
        with held._dup() as fd:  # noqa: SLF001 — `Held` has no listing verb, and its root is a path-only handle
            listing = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=fd)
            try:
                present = os.listdir(listing)
            finally:
                os.close(listing)
            if present:
                raise run_knowledge.KnowledgeRefused(f"the destination {dest} is not empty")
        for under in ("agent", "settings"):
            held.mkdir(under)  # lint-unguarded-tree-write: ok — `Held.mkdir`, no link followed
        for path, data in files.items():
            head, _sep, rel = path.partition("/")
            held.write(f"{head}/{rel}", data, mode="create")


class _Stopped(BaseException):
    """The launcher stopped waiting and asked the child to end (SIGTERM): unwinds every `finally` on the way out (a
    network git call kills its own process group there)."""


class _OutOfTime(BaseException):
    """The deadline over the network phase passed (SIGALRM): unwinds as `_Stopped` does, and the child reports it."""

    def __init__(self, budget: float) -> None:
        super().__init__(budget)
        self.budget = budget


def _on_terminate(_signum: int, _frame: FrameType | None) -> None:
    raise _Stopped()


@contextlib.contextmanager
def _deadline(budget: float | None) -> Iterator[None]:
    """`_OutOfTime` once `budget` seconds pass inside the block (nothing when `None`; at once, on entry, when it is not
    positive: an interval timer of 0 is no timer)."""
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


def fetch_child_main(
    argv: Sequence[str],
    *,
    directory: TenantDirectory | None = None,
    credential_config: Any = None,
    client: httpx.Client | None = None,
    identity: ForgeCredential | None = None,
    network_timeout: float | None = None,
) -> int:
    """The child process's entry: `<tenant id> --data-root <root> --dest <folder> [--commit <id>] [--budget <seconds>]
    [--trigger <who asked>]` (identifiers, a number and a fixed word, never a secret). Prints the report line and
    returns 0 for every outcome it reports. The keywords are in-process stand-ins; with no `--budget` the child holds
    no deadline of its own."""
    parser = argparse.ArgumentParser(prog="fetch-child", add_help=False)
    parser.add_argument("tenant_id")
    parser.add_argument("--data-root", dest="root", required=True, type=Path)
    parser.add_argument("--dest", required=True, type=Path)
    parser.add_argument("--commit", default=None)
    parser.add_argument("--budget", type=float, default=None)
    parser.add_argument("--trigger", default="")
    ns = parser.parse_args(list(argv))
    previous = signal.signal(signal.SIGTERM, _on_terminate)
    try:
        line = _fetch_line(
            ns.tenant_id, ns.dest, ns.commit, data_root=ns.root, directory=directory,
            credential_config=credential_config, client=client, issuer_transport=None, identity=identity,
            network_timeout=network_timeout, budget=ns.budget, trigger=ns.trigger)
    except _Stopped:
        return 128 + signal.SIGTERM
    finally:
        signal.signal(signal.SIGTERM, previous)
    print(one_line(line), flush=True)
    return 0
