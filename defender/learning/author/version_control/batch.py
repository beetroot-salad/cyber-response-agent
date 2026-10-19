"""A batch is a host-owned branch and a git-free draft for its box."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from defender._tenant import Tenant
from defender import box

from .commits import CommitMaker, _Line
from .exports import TenantExport, agent_blobs
from .files import _folders_of, _regular_files, _remove_entry, _resync
from .model import AgentChange, ChangeSet, _refusals, _require_in_lanes
from .repository import GitRepository


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
        and each lane writable inside it. Never the clone, an export, `settings/`, `.git` or
        `forge/`. `agent/` is the workdir and `DEFENDER_AGENT_DIR`. It requires a sandbox."""
        agent = self.draft_root / "agent"
        code = self.defender_dir
        mounts = [
            box.Mount(source=code, target=code, kind="code"),
            box.Mount(source=self.draft_root, target=self.draft_root, kind="staged"),
            *(
                box.Mount(source=agent / lane, target=agent / lane, writable=True)
                for lane in self.lanes
            ),
        ]
        return box.BoxRequest(
            name=f"defender-tenant-{self.tenant.id}-{self.id}",
            mounts=tuple(mounts),
            workdir=agent,
            defender_dir=code,
            require_sandbox=True,
            env={"DEFENDER_AGENT_DIR": str(agent)},
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
        a branch with commits is `deliver`'s to pick up."""
        with _refusals():
            _remove_entry(self.draft_root.parent, self.id)
