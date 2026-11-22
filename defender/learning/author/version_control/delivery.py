"""Tenant knowledge delivery: publish, batch and deliver.

GitRepository owns git and Forgejo operations. The orchestrator supplies a tenant-bound
Vault identity; boxes receive only host-made copies. Production drain/run wiring is P4.
"""

from __future__ import annotations

import contextlib
import os
import secrets
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import httpx

    from defender.tenancy import TenantDirectory
from defender import _io
from defender.tenancy import Tenant, data_root_for_child, sweep_dead_owners
from defender.records.formats import TenantRefused
from defender import box
from defender.box import DockerFn, run_docker

from .auth import ForgeCredential
from .batch import Batch
from .commits import CommitMaker, Recorder, _Line
from .exports import (
    DRAFT_STAGE,
    draft_path,
    TenantExport,
    build_draft,
)
from .credential import forge_credential
from .model import (
    DeliveryRefused,
    _lanes,
    _one_word,
    _refusals,
)
from .record import _BatchKey
from .repository import NETWORK_TIMEOUT, GitRepository

#: The lessons lane's branch prefix on the tenant repository (a lane passes its own).
LESSONS_BRANCH_PREFIX = "lessons/"


@contextlib.contextmanager
def opened_delivery(  # noqa: PLR0913 — the tenant, its records, and the in-process stand-ins
    tenant: Tenant,
    *,
    defender_dir: Path,
    directory: TenantDirectory,
    purpose: str,
    client: httpx.Client | None = None,
    identity: ForgeCredential | None = None,
    credential_config: Any = None,
    issuer_transport: httpx.BaseTransport | None = None,
    relay: Callable[..., dict[str, Any]] | None = None,
) -> Iterator[TenantDelivery]:
    """The tenant's delivery, opened against its forge wiring in the tenant records (#1214
    Flow 4): the recorded origin; `identity`, else the tenant's forge credential for `purpose`
    (`forge_credential`, minting through its live generation; `credential_config` and
    `issuer_transport` are the host's issuer configuration and an in-process stand-in transport);
    `client`, else a new forge client; `relay`, inside a job container, the job socket's client (#1170: the batch's
    publish, draft and box are the per-job host helper's, `TenantDelivery.relay`). A client or credential made here is closed on exit; a
    given one stays its caller's. No wiring recorded is `TenantRefused`; a refused open,
    `DeliveryRefused` or `ForgejoAuthError`. Publish outcomes are recorded through `directory`."""
    wiring = directory.forge_wiring(tenant.id)
    if wiring is None:
        raise TenantRefused(f"tenant {tenant.id} has no forge wiring recorded: its repository is not bound to "
                            "a forge")
    with contextlib.ExitStack() as owned:
        if identity is None:
            credential = forge_credential(tenant.id, purpose, directory=directory,
                                          config=credential_config, transport=issuer_transport)
            owned.callback(credential.close)
            identity = credential
        if client is None:
            import httpx

            client = owned.enter_context(httpx.Client())
        delivery = TenantDelivery.open(tenant, defender_dir=defender_dir, client=client,
                                       identity=identity, origin=wiring.origin, directory=directory, relay=relay)
        owned.callback(delivery.close)
        yield delivery


@dataclass(frozen=True, eq=False)
class TenantDelivery:
    """Host-side delivery for one tenant, opened with its explicit Vault identity."""

    tenant: Tenant
    defender_dir: Path
    repository: GitRepository = field(repr=False)
    branch_prefix: str = LESSONS_BRANCH_PREFIX
    #: Where this delivery's publish outcomes are recorded (`None`: an in-process caller with no
    #: tenant records records none).
    directory: TenantDirectory | None = field(default=None, repr=False)
    #: Inside a job container (#1170 C23, A6): the job socket's client. The batch's publish and draft are then the
    #: per-job host helper's (`batch.start`: it publishes, builds the draft and owns it), and so is its box
    #: (`box.start` of the `batch` kind at the draft's id); this process makes no draft or owner record.
    relay: Callable[..., dict[str, Any]] | None = field(default=None, repr=False)

    @property
    def network_timeout(self) -> float:
        return self.repository.network_timeout

    @classmethod
    def open(
        cls,
        accepted_tenant: Tenant,
        *,
        defender_dir: Path,
        client: httpx.Client,
        identity: ForgeCredential,
        origin: str,
        network_timeout: float = NETWORK_TIMEOUT,
        directory: TenantDirectory | None = None,
        relay: Callable[..., dict[str, Any]] | None = None,
    ) -> TenantDelivery:
        with _refusals():
            # One private repository for this delivery's life: history and every branch fetched once, here (D4/K12).
            repository = GitRepository.open(
                tenant_id=str(accepted_tenant.id),
                identity=identity,
                origin=origin,
                client=client,
                network_timeout=network_timeout,
            )
            return cls(
                tenant=accepted_tenant, defender_dir=defender_dir, repository=repository,
                directory=directory, relay=relay,
            )

    def close(self) -> None:
        """The delivery's private repository is its tick's: removed when the tick ends."""
        self.repository.close()

    def start_batch(self, batch_id: str, *, lanes: Sequence[str], branch: str | None = None,
                    recorder: Recorder | None = None) -> Batch:
        """Flow 3: refuse at once an id whose draft or branch exists (ids are never retried, so
        a reused one is caught before any box runs); publish; then, under the same lock hold,
        build the git-free draft of the export commit's `agent/` in a dot-named temporary
        under `<T>/drafts/` and rename it to `<T>/drafts/<batch_id>`. A build that fails leaves
        nothing. No checkout is made, and the branch exists from the first commit on. With a
        `relay` the helper does all of this at an id it mints (`batch_id` is not sent).

        `branch` is the learning store's (#1278 D5: set at claim, never re-derived; else the
        prefix and the id), and `recorder` where each commit is recorded before its branch
        moves (else the commit-maker keeps its commits in memory for `finish`); a relayed batch
        takes both too, its commits being made in this process."""
        if self.relay is not None:
            return self._relayed_batch(lanes, branch=branch, recorder=recorder)
        with _refusals():
            batch_id = _one_word(batch_id, "batch id")
            declared = _lanes(lanes)
            branch = branch if branch is not None else f"{self.branch_prefix}{batch_id}"
            self._refuse_taken(batch_id, branch)
            sweep_dead_owners(data_root_for_child(self.tenant.data_root), self.tenant.id)  # flow 8: a batch start sweeps
            # The draft is the tick's own fetch of `main` (D4): nothing is fetched or published here.
            commit = self.repository.revision("refs/heads/main")
            build_draft(self.tenant, self.repository, batch_id, commit, declared)
            export = TenantExport(commit=commit, path=draft_path(self.tenant, batch_id))
            line = _Line(
                batch=_BatchKey(
                    branch=branch, base=export.commit, start=secrets.token_hex(8)
                ),
                lanes=declared,
            )
            return Batch(
                id=batch_id,
                branch=branch,
                export=export,
                draft_root=draft_path(self.tenant, batch_id) / DRAFT_STAGE,
                lanes=declared,
                tenant=self.tenant,
                defender_dir=self.defender_dir,
                repository=self.repository,
                committer=CommitMaker(self.tenant, self.repository, recorder),
                _line=line,
            )

    def _relayed_batch(self, lanes: Sequence[str], *, branch: str | None,
                       recorder: Recorder | None) -> Batch:
        """Flow 3 done by the per-job host helper (`batch.start`): the batch over the draft it made and owns."""
        from defender.job_socket import Refused

        declared = _lanes(lanes)
        assert self.relay is not None
        try:
            answer = self.relay("batch.start", lanes=list(declared))
        except Refused as refused:
            raise DeliveryRefused(f"the helper did not start the batch: {refused}") from None
        except OSError as unreachable:
            raise DeliveryRefused(f"the helper could not be asked to start the batch: {unreachable}") from None
        batch_id = _one_word(str(answer["batch"]), "batch id")
        commit, folder = str(answer["base"]), Path(answer["path"])
        if folder != draft_path(self.tenant, batch_id):
            raise DeliveryRefused(f"the helper's draft {folder} is not batch {batch_id}'s")
        branch = branch if branch is not None else f"{self.branch_prefix}{batch_id}"
        with _refusals():
            self.repository.require_commit(commit)  # the helper's base, fetched by id when this tick's fetch lacks it
        line = _Line(batch=_BatchKey(branch=branch, base=commit, start=secrets.token_hex(8)), lanes=declared)
        return Batch(id=batch_id, branch=branch, export=TenantExport(commit=commit, path=Path(answer["export"])),
                     draft_root=folder / DRAFT_STAGE, lanes=declared, tenant=self.tenant,
                     defender_dir=self.defender_dir, repository=self.repository,
                     committer=CommitMaker(self.tenant, self.repository, recorder), _line=line)

    def start_batch_box(self, batch: Batch, *, docker: DockerFn = run_docker) -> box.BoxExecutor:
        """The batch's box: started by the per-job host helper for the batch's id when this delivery has a `relay`,
        else `start_box(batch.box_request())`."""
        if self.relay is not None:
            return box.relay_start(self.relay, "batch", batch.id)
        return self.start_box(batch.box_request(), docker=docker)

    def _refuse_taken(self, batch_id: str, branch: str) -> None:
        if os.path.lexists(draft_path(self.tenant, batch_id)):
            raise DeliveryRefused(
                f"the batch id {batch_id} has a draft already: batch ids are "
                "never used again while their draft remains"
            )
        if self.repository.branch_tip(branch) is not None:
            raise DeliveryRefused(
                f"the branch {branch} already exists in the tenant clone: "
                "its commits are deliver's to pick up, and its id is not used "
                "again"
            )

    def start_box(
        self, request: box.BoxRequest, *, docker: DockerFn = run_docker
    ) -> box.BoxExecutor:
        """The tenant drain's box, through `box.start_box`, the one entry: it requires a
        sandbox, so a start fault raises whatever the operator's opt-out says, never an
        unsandboxed executor, and leaves nothing under `<T>/drafts/` (no did-not-run marker).
        Never over a draft root holding `settings/` (a run copy's half, never a draft's)."""
        for mount in request.mounts:
            if mount.kind == "staged" and _io.entry_present(
                Path(mount.source) / "settings"
            ):
                raise box.BoxFault(
                    f"the draft root {mount.source} holds settings/: a draft "
                    "holds agent/ alone"
                )
        return box.start_box(replace(request, require_sandbox=True), docker=docker)
