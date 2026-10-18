"""The sole commit-maker: validate, create objects, record durably, then move the branch."""

from __future__ import annotations

from dataclasses import dataclass

from defender._tenant import Tenant

from .model import AgentChange, ChangeSet, DeliveryRefused, _refusals, _require_in_lanes
from .record import _BatchKey, _Made, _record_made
from .repository import GitRepository


@dataclass
class _Line:
    """Where the commit-maker commits for one batch: its branch and base (`batch`), its lanes,
    and `tip`, the last commit it put on the branch (`None` before the first, when the branch
    does not exist yet)."""

    batch: _BatchKey
    lanes: tuple[str, ...]
    tip: str | None = None

    @property
    def head(self) -> str:
        """What the batch's next commit builds on: its last, or the base."""
        return self.tip or self.batch.base


@dataclass
class CommitMaker:
    tenant: Tenant
    repository: GitRepository

    def commit(
        self,
        line: _Line,
        change_set: ChangeSet,
        message: str,
        *,
        reverts: tuple[_BatchKey, str] | None = None,
    ) -> str:
        """The one maker of tenant commits. It takes only a `ChangeSet` within `line`'s lanes,
        writes git objects only (each blob exactly the change's bytes, mode 100644, in a tree
        built in a private index), records the commit, and moves the branch by compare-and-swap
        from its own last commit, the first commit expecting no branch at all (so it creates
        it, and never takes one over). No lock: the compare-and-swap is enough, and it never
        touches `main`, the clone's index or its checkout."""
        if not isinstance(change_set, ChangeSet):
            raise TypeError(
                f"the commit-maker takes a ChangeSet, not {type(change_set).__name__}"
            )
        # Re-validated from scratch into a copy the commit-maker alone holds: a change set
        # altered after it was built (past its frozen attributes) is refused or not seen.
        change_set = ChangeSet(
            tuple(
                AgentChange(change.path, change.content)
                for change in tuple(change_set.changes)
            )
        )
        with _refusals():
            if not isinstance(message, str) or not message.strip():
                raise DeliveryRefused("a commit needs a message")
            if not len(change_set):
                raise DeliveryRefused(
                    "the change set is empty: there is nothing to commit"
                )
            for change in change_set:
                _require_in_lanes(change.path, line.lanes)
            branch = line.batch.branch
            tip = self.repository.branch_tip(branch)
            if tip != line.tip:
                raise DeliveryRefused(
                    f"the branch {branch} is at {tip or 'nothing'}, not the commit-maker's last "
                    f"commit {line.tip or '(none yet)'}: it builds on nothing it did not make"
                )
            parent = line.head
            paths = [change.path for change in change_set]
            before = self.repository.regular_blobs(parent, paths)
            for change in change_set:
                if change.content is None and change.path not in before:
                    raise DeliveryRefused(
                        f"{change.path} is not a file {parent} holds: it "
                        "cannot be deleted"
                    )
            at_base = (
                before
                if parent == line.batch.base
                else self.repository.regular_blobs(line.batch.base, paths)
            )
            commit, after = self.repository.make_commit(parent, change_set, message)
            _record_made(
                self.tenant,
                _Made(
                    commit=commit,
                    batch=line.batch,
                    lanes=line.lanes,
                    reverts=reverts,
                    changes=()
                    if reverts is not None
                    else tuple(
                        (path, at_base.get(path), after[path]) for path in paths
                    ),
                ),
            )
            self.repository.move_branch(branch, commit, tip)
            line.tip = commit
            return commit
