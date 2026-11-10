"""Tenant knowledge delivery: publish, batch and deliver.

GitRepository owns git and Forgejo operations. The orchestrator supplies a tenant-bound
Vault identity; boxes receive only host-made copies. Production drain/run wiring is P4.
"""

from __future__ import annotations

import contextlib
import os
import secrets
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import httpx

    from defender.tenancy import TenantDirectory
from defender import _io
from defender.tenancy import Tenant
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
    publish_locked,
    tenant_lock,
)
from .credential import forge_credential
from .model import (
    _PRECEDENCE,
    Delivered,
    DeliveryRefused,
    DeliveryStatus,
    _answer,
    _lanes,
    _one_word,
    _refusals,
)
from .record import _BatchKey
from .repository import NETWORK_TIMEOUT, GitRepository
from .status import record_published, recording

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
) -> Iterator[TenantDelivery]:
    """The tenant's delivery, opened against its forge wiring in the tenant records (#1214
    Flow 4): the recorded origin; `identity`, else the tenant's forge credential for `purpose`
    (`forge_credential`, minting through its live generation; `credential_config` and
    `issuer_transport` are the host's issuer configuration and an in-process stand-in transport);
    `client`, else a new forge client. A client or credential made here is closed on exit; a
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
        yield TenantDelivery.open(tenant, defender_dir=defender_dir, client=client,
                                  identity=identity, origin=wiring.origin, directory=directory)


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
    ) -> TenantDelivery:
        with recording(directory, accepted_tenant.id, by="delivery"), _refusals():
            repository = GitRepository.open(
                accepted_tenant.knowledge,
                tenant_id=str(accepted_tenant.id),
                identity=identity,
                origin=origin,
                client=client,
                network_timeout=network_timeout,
            )
            return cls(
                tenant=accepted_tenant, defender_dir=defender_dir, repository=repository,
                directory=directory,
            )

    def publish(self) -> TenantExport:
        """Flow 1: fetch (no lock), then under the lock fast-forward the clone to `origin/main`
        and publish its export. Refuses, publishing nothing, a dirty, untracked or diverged
        clone, a tree entry under `agent/` or `settings/` that is not a regular blob, and an
        `agent/.tenant-id` not naming this tenant."""
        with recording(self.directory, self.tenant.id, by="delivery"), _refusals():
            self.repository.fetch()
            with tenant_lock(self.tenant):
                export = publish_locked(self.tenant, self.repository)
        record_published(self.directory, self.tenant.id, export.commit, by="delivery")
        return export

    def start_batch(self, batch_id: str, *, lanes: Sequence[str], branch: str | None = None,
                    recorder: Recorder | None = None) -> Batch:
        """Flow 3: refuse at once an id whose draft or branch exists (ids are never retried, so
        a reused one is caught before any box runs); publish; then, under the same lock hold,
        build the git-free draft of the export commit's `agent/` in a dot-named temporary
        under `<T>/drafts/` and rename it to `<T>/drafts/<batch_id>`. A build that fails leaves
        nothing. No checkout is made, and the branch exists from the first commit on.

        `branch` is the learning store's (#1278 D5: set at claim, never re-derived; else the
        prefix and the id), and `recorder` where each commit is recorded before its branch
        moves (else the commit-maker keeps its commits in memory for `finish`)."""
        with _refusals():
            batch_id = _one_word(batch_id, "batch id")
            declared = _lanes(lanes)
            branch = branch if branch is not None else f"{self.branch_prefix}{batch_id}"
            self._refuse_taken(batch_id, branch)
            with recording(self.directory, self.tenant.id, by="delivery"), _refusals():
                self.repository.fetch()
            with tenant_lock(self.tenant):
                with recording(self.directory, self.tenant.id, by="delivery"), _refusals():
                    export = publish_locked(
                        self.tenant, self.repository, temporaries_only=True
                    )
                record_published(self.directory, self.tenant.id, export.commit, by="delivery")
                self._refuse_taken(batch_id, branch)
                build_draft(
                    self.tenant, self.repository, batch_id, export.commit, declared
                )
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

    def _deliver(
        self, batch: _BatchKey, tip: str, *, mine: frozenset[str], title: str, body: str
    ) -> Delivered:
        """The push route. Each commit between the batch's base and `tip` must be one the
        commit-maker made for this batch (`mine`, checked before anything else, so a branch
        holding only a foreign commit refuses rather than having nothing to deliver). Then the
        batch's PR is looked up, before any push: one found (open, merged or closed) is
        answered and nothing is pushed or opened (D-closed). With none, a branch at its base
        has nothing to deliver; otherwise `tip` (by id, so a branch moved meanwhile sends
        nothing new) is pushed to the remote branch alone and a PR opened against `main`."""
        if tip != batch.base:
            sent = self.repository.commits_since(batch.base, tip)
            foreign = [commit for commit in sent if commit not in mine]
            if foreign or not sent:
                raise DeliveryRefused(
                    f"the branch {batch.branch} at {tip} holds {len(foreign) or 'no'} commit(s) "
                    f"past its base {batch.base} that the commit-maker did not make for it "
                    f"({', '.join(foreign) or 'it does not descend from its base'}): nothing "
                    "is pushed"
                )
        found = sorted(
            self.repository.pull_requests(mine) if mine else (),
            key=lambda pr: (_PRECEDENCE[pr.status], -pr.number),
        )
        if found:
            return _answer(found[0])
        if tip == batch.base:
            return Delivered(status=DeliveryStatus.NOTHING)
        self.repository.push(tip, batch.branch)
        url = self.repository.open_pr(branch=batch.branch, title=title, body=body)
        return Delivered(status=DeliveryStatus.OPENED, url=url)

    def finish(self, batch: Batch) -> Delivered:
        """Deliver the batch: `nothing to deliver` when it made no commit (it has no branch);
        otherwise its PR's status when the forge has one, or its branch pushed and a PR
        opened. A branch moved from the commit-maker's last commit, or holding any commit it
        did not make for this batch, is refused before any push."""
        with _refusals():
            line = batch._line
            tip = self.repository.branch_tip(line.batch.branch)
            if tip != line.tip:
                raise DeliveryRefused(
                    f"the branch {line.batch.branch} is at {tip or 'nothing'}, not the "
                    f"commit-maker's last commit {line.tip or '(none yet)'}: nothing is pushed"
                )
            if tip is None:
                return Delivered(status=DeliveryStatus.NOTHING)
            return self._deliver(
                line.batch,
                tip,
                mine=frozenset(m.commit for m in batch.committer.made if m.batch == line.batch),
                title=_batch_title(batch.id),
                body=_batch_body(line.batch.branch, line.batch.base),
            )


def _batch_title(batch_id: str) -> str:
    return f"learning: tenant knowledge batch {batch_id}"


def _batch_body(branch: str, base: str) -> str:
    return (
        f"Tenant agent knowledge batch `{branch}`, based on `{base[:12]}`. Changes `agent/` "
        "only, every commit made by the host's commit-maker."
    )
