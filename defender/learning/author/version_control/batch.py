"""A batch is a host-owned branch and a git-free draft for its box."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from defender.tenancy._exports import regular_files as _regular_files
from defender.tenancy._exports import remove_entry as _remove_entry
from defender.tenancy._tenant import Tenant
from defender import box
from defender.runtime.model_view import ModelView

from .commits import CommitMaker, _Line
from .exports import TenantExport, agent_blobs
from .files import _folders_of, _resync
from .model import AgentChange, ChangeSet, _refusals, _require_in_lanes
from .repository import GitRepository

_logger = logging.getLogger(__name__)


@dataclass(eq=False)
class Batch:
    """One drain batch: a branch of the tenant clone (`branch`, made by the batch's first
    commit, from `export`'s commit) and the git-free draft under `draft_root` its box writes
    into, through `lanes` only. No checkout is made for it."""

    id: str
    branch: str
    export: TenantExport
    draft_root: Path
    lanes: tuple[str, ...]
    tenant: Tenant = field(repr=False)
    defender_dir: Path
    repository: GitRepository = field(repr=False)
    committer: CommitMaker = field(repr=False)
    _line: _Line = field(repr=False)

    def box_request(self) -> box.BoxRequest:
        """The drain box: product code read-only (`code`), the draft's root read-only (`staged`),
        and each lane writable inside it. The model sees `/defender` and `/draft`;
        `/draft/agent` is its cwd and `DEFENDER_AGENT_DIR`. It requires a sandbox."""
        agent = self.draft_root / "agent"
        code = self.defender_dir
        view = ModelView.for_draft(code, self.draft_root)
        mounts = [
            box.Mount(source=code, target=Path(view.to_model(code)), kind="code"),
            box.Mount(source=self.draft_root, target=Path(view.to_model(self.draft_root)), kind="staged"),
            *(
                box.Mount(source=agent / lane, target=Path(view.to_model(agent / lane)), writable=True)
                for lane in self.lanes
            ),
        ]
        return box.BoxRequest(
            name=f"defender-tenant-{self.tenant.id}-{self.id}",
            mounts=tuple(mounts),
            workdir=agent,
            defender_dir=code,
            require_sandbox=True,
            env={"DEFENDER_AGENT_DIR": view.to_model(agent)},
            view=view,
        )

    def change_set(self) -> ChangeSet:
        """The claim: the draft's `agent/` against the blobs of the batch's base (its branch's
        last commit, or the export commit before the first), as changes. The base is read from
        git's objects, never a checkout, so attributes on `main` (`eol`, `ident`, a filter)
        never show a change the box did not make. Only regular files in the lanes may differ;
        any other entry anywhere in the draft, an oversized file, a change outside the lanes or
        one touching a forbidden name refuses the claim whole."""
        with _refusals():
            draft = _regular_files(self.draft_root / "agent")
            base = agent_blobs(self.repository, self._line.head)
            changes = []
            for rel in sorted(draft.keys() | base.keys()):
                if draft.get(rel) == base.get(rel):
                    continue
                change = AgentChange(f"agent/{rel}", draft.get(rel))
                _require_in_lanes(change.path, self.lanes)
                changes.append(change)
            return ChangeSet(tuple(changes))

    def base(self) -> dict[str, bytes]:
        """The batch's base (its branch's last commit, or the export commit before the first):
        `agent/` as `{repo-relative path: exact bytes}`, read from git's objects — what
        `change_set` derives against and `reset` restores."""
        with _refusals():
            return {f"agent/{rel}": data
                    for rel, data in agent_blobs(self.repository, self._line.head).items()}

    def commit(self, change_set: ChangeSet, message: str) -> str:
        """The commit-maker: commit `change_set` on the batch branch, returning the commit."""
        return self.committer.commit(self._line, change_set, message)

    def reset(self) -> None:
        """Re-sync the draft's `agent/` with the blobs of the batch's base, in place: the box's
        additions removed, its deletions and edits restored, links and FIFOs removed without
        being followed or opened. The lanes stay, so a running box keeps its binds."""
        with _refusals():
            files = agent_blobs(self.repository, self._line.head)
            _resync(self.draft_root / "agent", files, _folders_of(files, self.lanes))

    def discard(self) -> None:
        """Remove the draft (no link below it followed). The branch and its commits stay:
        a branch with commits is `deliver`'s to pick up. Cleanup, best effort: a draft that
        cannot be removed is logged, never raised, so it never replaces the outcome of the
        work it follows (a refusal, or a delivered PR); the owner sweep removes it later."""
        folder = self.draft_root.parent
        try:
            _remove_entry(folder.parent, folder.name)
        except OSError as e:
            _logger.error(f"batch {self.id}: its draft {folder} could not be removed: {e!r}")
