"""Which knowledge a run reads, and its own copy of it (#1108 P4, flow 3).

Run start never touches git, the network or the issuer (P-3): the launch-time publish runs in
a child process and hands back one report line. This module reads that line
(`read_publish_report`), picks the export the run reads (`current`, or the pinned commit), copies it into the run's own
folder `<T>/run-knowledge/<run_id>/{owner, settings/, stage/{agent/, token}}` (U9: the box mounts
`stage/` only) and writes the host-held record of what was read and why (U12).
"""
from __future__ import annotations

import contextlib
import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from defender import _io
from defender._text import one_line
from defender.records.formats import OID
from defender.tenancy._exports import remove_entry
from defender.tenancy._owner import owned_temporary, write_owner
from defender.tenancy._tenant import Tenant
from defender.tenancy._tenants import AGENT_HALF, SETTINGS_HALF

if TYPE_CHECKING:
    from defender.tenancy.record_values import TenantRecords

#: The fetch child's report vocabulary: `ok <commit>` or `refused <transient|lasting> <reason>`. A source is fresh (main's
#: tip, as fetched) or pinned (a commit asked for by id).
OK, REFUSED, TRANSIENT, LASTING = "ok", "refused", "transient", "lasting"
FRESH, PINNED = "fresh", "pinned"

#: How long a failed child's summary may run in the reason, so one line stays one line.
_SUMMARY_LIMIT = 300

#: The run copy's own names (U9). The box mounts `stage/`, which holds exactly `agent/` and the
#: startup token; `owner` (`tenancy._owner.OWNER_FILE`, written by `write_owner`) and `settings/`
#: sit beside it, outside every mount.
STAGE = "stage"
STAGE_TOKEN = "token"
#: A copy is built under a dot-name and renamed into place; the dot keeps it out of the run-id
#: grammar, so no run copy is ever named so.
_BUILDING_PREFIX = ".building-"


class KnowledgeRefused(Exception):
    """Run start cannot read knowledge for this run; the text says why and what to do."""


@dataclass(frozen=True)
class PublishReport:
    """What the fetch child reported: `ok` with the commit it fetched, or `refused` with its reason (and
    whether it may pass). `unreadable`: the line was not one of those."""

    kind: str
    commit: str | None = None
    reason: str | None = None
    unreadable: bool = False
    transient: bool = False


def child_failed(summary: object) -> PublishReport:
    """U11: a child with no valid report line (a crash, garbage, nothing, a spawn failure) is a refusal."""
    shown = one_line(str(summary))[:_SUMMARY_LIMIT] or "no report line"
    return PublishReport(REFUSED, reason=f"fetch child failed: {shown}", unreadable=True)


def failed_line(summary: object) -> str:
    """U11's report line for a child with no valid one of its own: what the launcher returns, and records."""
    return f"{REFUSED} {LASTING} {child_failed(summary).reason}"


def read_publish_report(line: object) -> PublishReport:
    """The child's report line: `ok <commit>` or `refused <reason>` (SPIKE #1618; FORCED vocabulary), or a refusal
    for anything else."""
    if not isinstance(line, str):
        return child_failed(f"not a report line: {line!r}")
    text = line.strip()
    if "\n" in text or "\r" in text:
        return child_failed(f"more than one line: {text!r}")
    head, _sep, rest = text.partition(" ")
    rest = rest.strip()
    if head == OK:
        if OID.fullmatch(rest):
            return PublishReport(OK, commit=rest)
        return child_failed(f"ok without a full commit id: {text!r}")
    if head == REFUSED and rest:
        klass, _sep2, why = rest.partition(" ")
        if klass in (TRANSIENT, LASTING) and why.strip():
            return PublishReport(REFUSED, reason=why.strip(), transient=klass == TRANSIENT)
        return child_failed(f"refused without a class: {text!r}")
    return child_failed(f"unrecognised report line: {text!r}")


@dataclass(frozen=True)
class KnowledgeSource:
    """What the run read and why (OD1): `kind` fresh or pinned; `commit`, the commit its fetch brought; `reason`
    (host only, U12). SPIKE #1618: no stale kind, no `reported` (the copy is the fetch's own)."""

    kind: str
    commit: str
    reason: str | None = None

    def host_record(self) -> dict[str, Any]:
        """The host-held record (U12), every field."""
        return {"kind": self.kind, "commit": self.commit, "reason": self.reason}

    def stamp_view(self) -> dict[str, Any]:
        """What the box-readable stamp may carry (OD17): never the reason."""
        return {"kind": self.kind, "commit": self.commit}


def pinned_commit(raw: str) -> str:
    """`--knowledge-commit`'s value, held to a full commit id before anything is read (O-PIN):
    `current`, a path and a short id are refused, never resolved."""
    if not OID.fullmatch(raw):
        raise KnowledgeRefused(
            f"--knowledge-commit {raw!r} is not a full commit id (40 or 64 lowercase hex): a "
            "pinned run names the export it reads by its whole commit")
    return raw


def resolve_source(tenant: Tenant, *, report: PublishReport | None,
                   pinned: str | None) -> KnowledgeSource:
    """The commit this run reads, from the fetch child's report, or `KnowledgeRefused` (a refused fetch refuses the
    run: no stale fallback, D3). A pinned run's report must name the commit it asked for."""
    assert report is not None
    if report.kind != OK:
        raise KnowledgeRefused(f"tenant {tenant.id}'s knowledge could not be fetched: {report.reason}")
    if pinned is not None:
        if report.commit != pinned:
            raise KnowledgeRefused(f"tenant {tenant.id}: asked for {pinned}, the fetch brought {report.commit}")
        return KnowledgeSource(PINNED, pinned)
    assert report.commit is not None
    return KnowledgeSource(FRESH, report.commit)


@dataclass(frozen=True)
class RunCopy:
    """One run's copy of one export (U9), at `<T>/run-knowledge/<run_id>/`."""

    root: Path

    @property
    def stage(self) -> Path:
        return self.root / STAGE

    @property
    def agent(self) -> Path:
        return self.stage / AGENT_HALF

    @property
    def settings(self) -> Path:
        return self.root / SETTINGS_HALF

    @property
    def token(self) -> Path:
        return self.stage / STAGE_TOKEN

    def remove(self) -> None:
        """Remove the copy; nothing when it is gone already. Never raises for the run."""
        _remove_copy(self.root.parent, self.root.name)


def _remove_copy(folder: Path, name: str) -> None:
    """`folder/name` removed as the entry it is, nothing below it followed; never raises."""
    with contextlib.suppress(OSError):
        remove_entry(folder, name)


def make_owned_empty(parent: Path, label: str) -> Path:
    """D5: the CALLER's owned empty folder (`owned_temporary`: this process's pid and start time in its name), a sibling
    of the final place under `parent`. The fetch child fills it; the caller then `place`s or `discard`s it."""
    name = owned_temporary(f"{_BUILDING_PREFIX}{label}")
    with _io.hold_new(parent, name, exclusive=True):
        pass
    return parent / name


def place(temporary: Path, final: Path) -> None:
    """The filled temporary made the run's copy: `agent/` moved under `stage/` with the box's start token, an `owner`
    record for this process, then renamed into place. Run ids are minted, never reused (C-K11), so anything already
    at `final` refuses: nothing there is replaced."""
    if os.path.lexists(final):
        raise KnowledgeRefused(f"{final} exists already: a run id is never reused")
    with _io.hold(temporary, follow=False) as held:
        held.mkdir(STAGE)  # lint-unguarded-tree-write: ok — `Held.mkdir`, no link followed
        held.write(f"{STAGE}/{STAGE_TOKEN}", secrets.token_hex(16), mode="create")
    os.rename(temporary / AGENT_HALF, temporary / STAGE / AGENT_HALF)
    write_owner(temporary)
    os.rename(temporary, final)


def adopt_copy(tenant: Tenant, run_id: str, into: Path | None = None) -> RunCopy:
    """SPIKE #1618: the run's side. The copy the fetch child made at `<run_id>`, judged present (never made here: the
    run has no git)."""
    final = (tenant.run_knowledge if into is None else into) / run_id
    try:
        with _io.bind(final.parent) as folder:
            found = _io.stat_entry(folder, final.name)
    except OSError as refused:
        raise KnowledgeRefused(f"the run copy {final} cannot be read: {refused}") from refused
    if found.st is None or not stat.S_ISDIR(found.st.st_mode):
        raise KnowledgeRefused(f"the fetch child made no run copy at {final}")
    return RunCopy(final)


def write_host_record(path: Path, source: KnowledgeSource) -> None:
    """The host-held knowledge-source record (U12), beside the run dir."""
    _io.write_guarded(path, json.dumps(source.host_record(), indent=2, sort_keys=True) + "\n")


def write_record_versions(path: Path, records: TenantRecords) -> None:
    """The host-held record of the system and case versions a run read at its start (#1366 O6,
    P3; audit only), beside the knowledge-source record: every current version, disabled ones
    too, and the case version (null when the tenant has none)."""
    used = {"systems": {system: record.version for system, record in sorted(records.systems.items())},
            "case": None if records.case is None else records.case.version}
    _io.write_guarded(path, json.dumps(used, indent=2, sort_keys=True) + "\n")


__all__ = [
    "FRESH", "LASTING", "OK", "PINNED", "REFUSED", "STAGE", "STAGE_TOKEN",
    "TRANSIENT", "KnowledgeRefused", "KnowledgeSource", "PublishReport", "RunCopy",
    "adopt_copy", "make_owned_empty", "place", "child_failed", "failed_line", "pinned_commit", "read_publish_report", "resolve_source",
    "write_host_record", "write_record_versions",
]
