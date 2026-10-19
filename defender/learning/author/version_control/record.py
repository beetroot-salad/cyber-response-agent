"""Durable commit provenance and net changes per batch and lesson."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from defender import _io
from defender.tenancy._tenant import Tenant

from .model import _OID, DeliveryRefused

_logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _BatchKey:
    """Which batch a commit-maker commit belongs to: the branch it was made on, the commit the
    batch started from (the export commit for a drain's batch, `main` for a revert), and the
    start's own random word, so a batch id used again is never mistaken for its earlier use."""

    branch: str
    base: str
    start: str


@dataclass(frozen=True)
class _Made:
    """One commit the commit-maker made (one record row): its batch and lanes; per path it
    changed, the blob at the batch's base and the blob it left (`None`: absent); and, for a
    revert commit, the batch change it undoes (`(batch, path)`). A revert commit changes no
    batch's net change: it is provenance only."""

    commit: str
    batch: _BatchKey
    lanes: tuple[str, ...]
    changes: tuple[tuple[str, str | None, str | None], ...]
    reverts: tuple[_BatchKey, str] | None = None


@dataclass(frozen=True)
class _NetChange:
    """A batch's net change to one lesson: the blob at the batch's base (`before`) and the
    blob its last commit-maker commit left (`after`), `None` for absent. A lesson one claim
    created and a later claim changed is one change, absent to the last bytes. `order` is the
    record position of the commit that last touched it (larger is newer)."""

    batch: _BatchKey
    path: str
    before: str | None
    after: str | None
    order: int


def _batch_row(batch: _BatchKey) -> dict:
    return {"branch": batch.branch, "base": batch.base, "start": batch.start}


def _record_made(tenant: Tenant, made: _Made) -> None:
    """Append `made` to the tenant's commit-maker record, durably, before the commit is put on
    any branch: a crash in between leaves a recorded commit no branch holds, never a branch
    holding an unrecorded one."""
    row: dict = {
        "commit": made.commit,
        "batch": _batch_row(made.batch),
        "lanes": list(made.lanes),
        "changes": [{"path": p, "before": b, "after": a} for p, b, a in made.changes],
    }
    if made.reverts is not None:
        row["reverts"] = {"batch": _batch_row(made.reverts[0]), "path": made.reverts[1]}
    record = tenant.commit_record
    _io.rooted_mkdir(record.parent, ".")
    _io.rooted_write(
        record.parent,
        record.name,
        json.dumps(row, sort_keys=True)
        + "\n",  # lint-jsonl-io: ok — one durable, no-follow append of one JSON row to the host-only commit-maker record
        mode="append",
        durable=True,
    )


def _oid_or_none(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str) and _OID.fullmatch(value):
        return value
    raise ValueError(f"not an object id: {value!r}")


def _parse_batch(value: object) -> _BatchKey:
    if not isinstance(value, dict):
        raise ValueError("not a batch")
    branch, base, start = value.get("branch"), value.get("base"), value.get("start")
    if (
        not isinstance(branch, str)
        or not isinstance(start, str)
        or not isinstance(base, str)
        or not _OID.fullmatch(base)
    ):
        raise ValueError("not a batch")
    return _BatchKey(branch=branch, base=base, start=start)


def _parse_made(row: dict) -> _Made:
    """One record row as `_Made`; `ValueError` for a row of any other shape."""
    commit, lanes, changes = row.get("commit"), row.get("lanes"), row.get("changes")
    if (
        not isinstance(commit, str)
        or not _OID.fullmatch(commit)
        or not isinstance(lanes, list)
        or not all(isinstance(lane, str) for lane in lanes)
        or not isinstance(changes, list)
    ):
        raise ValueError("not a commit-maker record row")
    parsed: list[tuple[str, str | None, str | None]] = []
    for change in changes:
        if not isinstance(change, dict) or not isinstance(change.get("path"), str):
            raise ValueError("not a commit-maker change")
        parsed.append(
            (
                change["path"],
                _oid_or_none(change.get("before")),
                _oid_or_none(change.get("after")),
            )
        )
    reverts = None
    if "reverts" in row:
        target = row["reverts"]
        if not isinstance(target, dict) or not isinstance(target.get("path"), str):
            raise ValueError("not a revert's target")
        reverts = (_parse_batch(target.get("batch")), target["path"])
    return _Made(
        commit=commit,
        batch=_parse_batch(row.get("batch")),
        lanes=tuple(lanes),
        changes=tuple(parsed),
        reverts=reverts,
    )


@dataclass(frozen=True)
class _Record:
    """The commit-maker's record as read, oldest row first."""

    made: tuple[_Made, ...]

    @classmethod
    def read(cls, tenant: Tenant) -> _Record:
        """Every row the commit-maker recorded for this tenant. A row of another shape records
        nothing (a torn last line from a crash among them): its commit is then refused by every
        push route, failing closed. An unreadable record refuses."""
        record = tenant.commit_record
        with _io.bind(record.parent) as folder:
            rows, malformed, read = folder.read_jsonl(record.name)
        if read.reason is not None:
            raise DeliveryRefused(
                f"the commit-maker's record {record} could not be read: {read.refusal}"
            )
        made: list[_Made] = []
        for row in rows:
            try:
                made.append(_parse_made(row))
            except ValueError:
                malformed += 1
        if malformed:
            _logger.warning(
                "the commit-maker's record %s holds %d rows of another shape; their "
                "commits count as not made by it",
                record,
                malformed,
            )
        return cls(made=tuple(made))

    def commits_of(self, batch: _BatchKey) -> frozenset[str]:
        """Every commit the commit-maker made for `batch`."""
        return frozenset(m.commit for m in self.made if m.batch == batch)

    def batch_holding(self, branch: str, tip: str) -> _BatchKey | None:
        """The batch whose commits hold `tip` on `branch`; failing that (a tip the commit-maker
        did not make), the batch that last committed on `branch`; `None` when none did."""
        mine = [m for m in self.made if m.batch.branch == branch]
        for m in mine:
            if m.commit == tip:
                return m.batch
        return mine[-1].batch if mine else None

    def lanes_of(self, batch: _BatchKey) -> tuple[str, ...]:
        return next(m.lanes for m in self.made if m.batch == batch)

    def net_changes(self, path: str) -> list[_NetChange]:
        """Every batch's net change to `path`, newest first: per batch the blob at its base and
        the blob its last commit touching `path` left."""
        net: dict[_BatchKey, _NetChange] = {}
        for order, m in enumerate(self.made):
            for changed, before, after in m.changes:
                if changed == path:
                    net[m.batch] = _NetChange(
                        batch=m.batch,
                        path=path,
                        before=before,
                        after=after,
                        order=order,
                    )
        return sorted(net.values(), key=lambda change: change.order, reverse=True)

    def reverts_of(self, change: _NetChange) -> list[_Made]:
        """The revert commits made of `change`, oldest first."""
        return [m for m in self.made if m.reverts == (change.batch, change.path)]
