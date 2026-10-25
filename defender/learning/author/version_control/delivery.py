"""Tenant knowledge delivery: publish, batch, deliver and revert.

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
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx
from defender import _io
from defender.tenancy._tenant import Tenant, read_forge_binding
from defender import box
from defender.box._docker import DockerFn, _docker

from .auth import ForgejoIdentity
from .batch import Batch
from .commits import CommitMaker, _Line
from .exports import (
    DRAFT_STAGE,
    draft_path,
    TenantExport,
    build_draft,
    publish_locked,
    tenant_lock,
)
from .forgejo import PullRequest
from .issuer import issuer_login
from .model import (
    _PRECEDENCE,
    AgentChange,
    ChangeSet,
    Delivered,
    DeliveryRefused,
    DeliveryStatus,
    _agent_path,
    _answer,
    _lanes,
    _one_word,
    _refusals,
)
from .record import _BatchKey, _NetChange, _Record
from .repository import NETWORK_TIMEOUT, GitRepository
from .status import record_published, recording

#: The lessons lane's branch prefix on the tenant repository (a lane passes its own).
LESSONS_BRANCH_PREFIX = "lessons/"


@contextlib.contextmanager
def opened_delivery(
    tenant: Tenant,
    *,
    defender_dir: Path,
    client: httpx.Client | None = None,
    identity: ForgejoIdentity | None = None,
    issuer_config: Path | None = None,
    issuer_transport: httpx.BaseTransport | None = None,
) -> Iterator[TenantDelivery]:
    """The tenant's delivery, opened against its row's forge binding: the binding's origin;
    `identity`, else an AppRole login with the issuer client config the binding names
    (`issuer_config` and `issuer_transport` are in-process stand-ins); `client`, else a new
    forge client. A client made here is closed on exit; a given one stays its caller's. An
    unbound row is `TenantRefused`; a refused open, `DeliveryRefused` or `ForgejoAuthError`."""
    binding = read_forge_binding(tenant)
    with contextlib.ExitStack() as owned:
        if identity is None:
            identity = issuer_login(tenant, issuer_config=issuer_config,
                                    transport=issuer_transport, binding=binding)
            owned.callback(identity.client.close)
        if client is None:
            import httpx

            client = owned.enter_context(httpx.Client())
        yield TenantDelivery.open(tenant, defender_dir=defender_dir, client=client,
                                  identity=identity, origin=binding.origin)


@dataclass(frozen=True, eq=False)
class TenantDelivery:
    """Host-side delivery for one tenant, opened with its explicit Vault identity."""

    tenant: Tenant
    defender_dir: Path
    repository: GitRepository = field(repr=False)
    branch_prefix: str = LESSONS_BRANCH_PREFIX

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
        identity: ForgejoIdentity,
        origin: str,
        network_timeout: float = NETWORK_TIMEOUT,
    ) -> TenantDelivery:
        with recording(accepted_tenant, by="delivery"), _refusals():
            repository = GitRepository.open(
                accepted_tenant.knowledge,
                tenant_id=str(accepted_tenant.id),
                identity=identity,
                origin=origin,
                client=client,
                network_timeout=network_timeout,
            )
            return cls(
                tenant=accepted_tenant, defender_dir=defender_dir, repository=repository
            )

    def publish(self) -> TenantExport:
        """Flow 1: fetch (no lock), then under the lock fast-forward the clone to `origin/main`
        and publish its export. Refuses, publishing nothing, a dirty, untracked or diverged
        clone, a tree entry under `agent/` or `settings/` that is not a regular blob, and an
        `agent/.tenant-id` not naming this tenant."""
        with recording(self.tenant, by="delivery"), _refusals():
            self.repository.fetch()
            with tenant_lock(self.tenant):
                export = publish_locked(self.tenant, self.repository)
        record_published(self.tenant, export.commit, by="delivery")
        return export

    def start_batch(self, batch_id: str, *, lanes: Sequence[str]) -> Batch:
        """Flow 3: refuse at once an id whose draft or branch exists (ids are never retried, so
        a reused one is caught before any box runs); publish; then, under the same lock hold,
        build the git-free draft of the export commit's `agent/` in a dot-named temporary
        under `<T>/drafts/` and rename it to `<T>/drafts/<batch_id>`. A build that fails leaves
        nothing. No checkout is made, and the branch exists from the first commit on."""
        with _refusals():
            batch_id = _one_word(batch_id, "batch id")
            declared = _lanes(lanes)
            branch = f"{self.branch_prefix}{batch_id}"
            self._refuse_taken(batch_id, branch)
            with recording(self.tenant, by="delivery"), _refusals():
                self.repository.fetch()
            with tenant_lock(self.tenant):
                with recording(self.tenant, by="delivery"), _refusals():
                    export = publish_locked(
                        self.tenant, self.repository, temporaries_only=True
                    )
                record_published(self.tenant, export.commit, by="delivery")
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
                committer=CommitMaker(self.tenant, self.repository),
                _line=line,
            )

    def open_pr_exists(self) -> bool:
        """The lane's writer lease (amendment 3 C1, OD8): whether the tenant repository has an
        open PR of its own whose branch starts with `branch_prefix`. A fork's PR, or a row
        with no head repository (D-fork), holds nothing."""
        with _refusals():
            return bool(self.repository.forge.list_open_prs(self.branch_prefix))

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
        self, request: box.BoxRequest, *, docker: DockerFn = _docker
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
        self, batch: _BatchKey, tip: str, *, title: str, body: str
    ) -> Delivered:
        """Every push route's one path. Each commit between the batch's base and `tip` must be
        one the commit-maker made for this batch (checked before anything else, so a branch
        holding only a foreign commit refuses rather than having nothing to deliver). Then the
        batch's PR is looked up, before any push: one found (open, merged or closed) is
        answered and nothing is pushed or opened (D-closed). With none, a branch at its base
        has nothing to deliver; otherwise `tip` (by id, so a branch moved meanwhile sends
        nothing new) is pushed to the remote branch alone and a PR opened against `main`."""
        mine = _Record.read(self.tenant).commits_of(batch)
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
                title=_batch_title(batch.id),
                body=_batch_body(line.batch.branch, line.batch.base),
            )

    def deliver(self, batch_id: str) -> Delivered:
        """Deliver a batch's branch from any later delivery (its draft discarded, its push or
        PR request failed before): the batch is the one the commit-maker's record says made
        the branch's tip. `nothing to deliver` when the clone holds no such branch; refused
        when the record knows no batch of it, or any commit on it past its base is not that
        batch's."""
        with _refusals():
            branch = f"{self.branch_prefix}{_one_word(batch_id, 'batch id')}"
            tip = self.repository.branch_tip(branch)
            if tip is None:
                return Delivered(status=DeliveryStatus.NOTHING)
            batch = _Record.read(self.tenant).batch_holding(branch, tip)
            if batch is None:
                raise DeliveryRefused(
                    f"the branch {branch} holds no commit the commit-maker "
                    "made: nothing is pushed"
                )
            return self._deliver(
                batch,
                tip,
                title=_batch_title(batch_id),
                body=_batch_body(branch, batch.base),
            )

    def revert(self, lesson_path: str, lesson_name: str) -> Delivered:
        """Flow 4, D-peel: undo the newest batch's net change to `lesson_path` whose result
        `origin/main` still holds exactly there (absence included) and which has no merged
        revert, restoring the bytes from before it (or deleting the lesson it created), as one
        commit-maker commit on `main` pushed to a branch of its own with its PR (`opened`).
        That change's last revert decides first: its PR open answers `open` with it; closed is
        a rejection, refused; never a PR (its push or PR request failed) makes the revert
        again. Refused when no change is eligible: a lesson the commit-maker never wrote, one
        a human changed since, one already peeled back to human-written content."""
        with _refusals():
            path = _agent_path(lesson_path)
            name = _one_word(lesson_name, "lesson name")
            self.repository.fetch()
            main = self.repository.revision("refs/remotes/origin/main")
            record = _Record.read(self.tenant)
            change, pending = self._peel(
                record, path, self.repository.regular_blob_on(main, path)
            )
            if pending is not None:
                if pending.status == "open":
                    return _answer(pending)
                raise DeliveryRefused(
                    f"the revert of {path} the commit-maker last made was closed unmerged "
                    f"({pending.url}): a rejection, so it is not made again"
                )
            content = (
                None
                if change.before is None
                else self.repository.blobs([change.before])[change.before]
            )
            line = _Line(
                batch=_BatchKey(
                    branch=f"{self.branch_prefix}revert-{name}-{secrets.token_hex(4)}",
                    base=main,
                    start=secrets.token_hex(8),
                ),
                lanes=record.lanes_of(change.batch),
            )
            commit = CommitMaker(self.tenant, self.repository).commit(
                line,
                ChangeSet((AgentChange(path, content),)),
                f"revert lesson: {name}",
                reverts=(change.batch, path),
            )
            tip = self.repository.branch_tip(line.batch.branch)
            if tip != commit:
                raise DeliveryRefused(
                    f"the revert branch {line.batch.branch} moved from the "
                    f"commit-maker's commit {commit} (now {tip}): nothing is "
                    "pushed"
                )
            return self._deliver(
                line.batch,
                tip,
                title=f"revert lesson: {name}",
                body=(
                    f"Reverts `{path}` to what it held before the commit-maker's change in batch "
                    f"`{change.batch.branch}`, which `main` still holds exactly."
                ),
            )

    def _peel(
        self, record: _Record, path: str, current: str | None
    ) -> tuple[_NetChange, PullRequest | None]:
        """D-peel: the newest batch's net change to `path` whose result is `current` and which
        has no merged revert (merged by the forge's word on the revert commit's PR, whatever
        the merge style), with its last revert's unmerged PR (`None`: it has no revert, or its
        last revert never had a PR). Refused when there is none."""
        prs: list[PullRequest] | None = None
        for change in record.net_changes(path):
            if change.after != current or change.before == change.after:
                continue
            reverts = record.reverts_of(change)
            if not reverts:
                return change, None
            if prs is None:
                prs = self.repository.pull_requests(
                    m.commit for m in record.made if m.reverts is not None
                )
            statuses = {
                m.commit: sorted(
                    (pr for pr in prs if pr.head_sha == m.commit),
                    key=lambda pr: (_PRECEDENCE[pr.status], -pr.number),
                )
                for m in reverts
            }
            if any(
                pr.status == "merged" for found in statuses.values() for pr in found
            ):
                continue
            last = statuses[reverts[-1].commit]
            return change, (last[0] if last else None)
        raise DeliveryRefused(
            f"no change the commit-maker made to {path} is what main holds "
            "there now, with no merged revert: nothing to revert"
        )


def _batch_title(batch_id: str) -> str:
    return f"learning: tenant knowledge batch {batch_id}"


def _batch_body(branch: str, base: str) -> str:
    return (
        f"Tenant agent knowledge batch `{branch}`, based on `{base[:12]}`. Changes `agent/` "
        "only, every commit made by the host's commit-maker."
    )
