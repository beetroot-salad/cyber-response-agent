"""Which knowledge a run reads, and its own copy of it (#1108 P4, flow 3).

Run start never touches git, the network or the issuer (P-3): the launch-time publish runs in
a child process and hands back one report line. This module reads that line
(`read_publish_report`), picks the export the run reads (`current`, or the pinned commit), copies it into the run's own
folder `<T>/run-knowledge/<run_id>/{owner, settings/, stage/{agent/, token}}` (U9: the box mounts
`stage/` only) and writes the host-held record of what was read and why (U12).
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender import _io
from defender.records._locations import _unwrap_exports_root, _unwrap_run_knowledge_root
from defender.tenancy._exports import DeliveryRefused, current_export, regular_files
from defender.tenancy._owner import owner_alive, write_owner
from defender.tenancy._tenant import Tenant
from defender.tenancy._tenants import AGENT_HALF, SETTINGS_HALF

#: A full commit id, as an export is named: SHA-1 (40) or SHA-256 (64) lowercase hex.
_COMMIT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")

#: The report line's classes (OD2). `stale:*` keeps a run with a snapshot going; `misconfigured`
#: refuses it (O9); anything else is a failed child (U11).
FRESH, STALE, PINNED = "fresh", "stale", "pinned"
TRANSIENT, OPERATOR = "transient", "operator"
MISCONFIGURED = "misconfigured"
_STALE_PREFIX = "stale:"

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
    """What the launch-time publish child reported: `fresh` with the commit it published,
    `stale` with its kind and reason, or `misconfigured` with its reason."""

    kind: str
    commit: str | None = None
    stale_kind: str | None = None
    reason: str | None = None


def _one_line(text: str) -> str:
    return " ".join(text.split())


def child_failed(summary: object) -> PublishReport:
    """U11: a child with no valid report line (a crash, garbage, nothing, a spawn failure) is
    `stale:operator`, never fresh."""
    shown = _one_line(str(summary))[:_SUMMARY_LIMIT] or "no report line"
    return PublishReport(STALE, stale_kind=OPERATOR, reason=f"publish child failed: {shown}")


def read_publish_report(line: object) -> PublishReport:
    """The child's report line (OD2: `fresh <commit>`, `stale:transient <reason>`,
    `stale:operator <reason>`, `misconfigured <reason>`), or U11's `stale:operator` for anything
    else."""
    if not isinstance(line, str):
        return child_failed(f"not a report line: {line!r}")
    text = line.strip()
    if "\n" in text or "\r" in text:
        return child_failed(f"more than one line: {text!r}")
    head, _sep, rest = text.partition(" ")
    rest = rest.strip()
    if head == FRESH:
        if _COMMIT.fullmatch(rest):
            return PublishReport(FRESH, commit=rest)
        return child_failed(f"fresh without a full commit id: {text!r}")
    if head in (f"{_STALE_PREFIX}{TRANSIENT}", f"{_STALE_PREFIX}{OPERATOR}") and rest:
        return PublishReport(STALE, stale_kind=head.removeprefix(_STALE_PREFIX), reason=rest)
    if head == MISCONFIGURED and rest:
        return PublishReport(MISCONFIGURED, reason=rest)
    return child_failed(f"unrecognised report line: {text!r}")


@dataclass(frozen=True)
class KnowledgeSource:
    """What the run read and why (OD1): `kind` fresh, stale or pinned; `commit`, the export
    actually copied; `stale_kind` (non-null iff stale); `reason`, the child's own words (host
    only, U12); `reported`, the commit the child reported when it differs from the one copied
    (A-MISMATCH: `current` moved on by fast-forward since)."""

    kind: str
    commit: str
    stale_kind: str | None = None
    reason: str | None = None
    reported: str | None = None

    def host_record(self) -> dict[str, Any]:
        """The host-held record (U12), every field."""
        record: dict[str, Any] = {"kind": self.kind, "commit": self.commit,
                                  "stale_kind": self.stale_kind, "reason": self.reason}
        if self.reported is not None:
            record["reported_commit"] = self.reported
        return record

    def stamp_view(self) -> dict[str, Any]:
        """What the box-readable stamp may carry (OD17): never the reason."""
        return {"kind": self.kind, "commit": self.commit, "stale_kind": self.stale_kind}


def pinned_commit(raw: str) -> str:
    """`--knowledge-commit`'s value, held to a full commit id before anything is read (O-PIN):
    `current`, a path and a short id are refused, never resolved."""
    if not _COMMIT.fullmatch(raw):
        raise KnowledgeRefused(
            f"--knowledge-commit {raw!r} is not a full commit id (40 or 64 lowercase hex): a "
            "pinned run names the export it reads by its whole commit")
    return raw


def _export_of(tenant: Tenant, commit: str) -> Path:
    """`<T>/exports/<commit>/`, judged without following it, or `KnowledgeRefused`."""
    exports = _unwrap_exports_root(tenant.exports)
    with _io.bind(exports) as folder:
        found = _io.stat_entry(folder, commit)
    if found.st is None or not stat.S_ISDIR(found.st.st_mode):
        why = "no export is published for it" if found.absent else (found.reason or "not a folder")
        raise KnowledgeRefused(
            f"tenant {tenant.id}'s knowledge at {commit} cannot be read: {why} "
            f"({exports / commit}) — a run never materialises one (it has no git); publish or "
            "materialise it first")
    return exports / commit


def _current_commit(tenant: Tenant) -> str | None:
    """The commit `<T>/exports/current` names, or `None` when there is no usable snapshot."""
    try:
        return current_export(tenant).commit
    except DeliveryRefused:
        return None


def resolve_source(tenant: Tenant, *, report: PublishReport | None,
                   pinned: str | None) -> KnowledgeSource:
    """The export this run reads and how it came to read it, or `KnowledgeRefused`:
    pinned → that export; misconfigured → refused (O9, a snapshot does not save it); otherwise
    `current` — fresh at the copied commit, keeping the reported one when they differ
    (A-MISMATCH), or stale with the child's kind and reason — and no `current` refuses (O-A)."""
    if pinned is not None:
        _export_of(tenant, pinned)
        return KnowledgeSource(PINNED, pinned)
    assert report is not None
    if report.kind == MISCONFIGURED:
        raise KnowledgeRefused(
            f"the launch-time publish is misconfigured for tenant {tenant.id}: {report.reason}")
    current = _current_commit(tenant)
    if current is None:
        said = (f"the launch-time publish reported {report.kind}"
                + (f":{report.stale_kind} ({report.reason})" if report.kind == STALE else ""))
        raise KnowledgeRefused(
            f"tenant {tenant.id} has no published knowledge snapshot (`exports/current`) and "
            f"{said}: there is nothing to start the run on")
    _export_of(tenant, current)
    if report.kind == FRESH:
        reported = report.commit if report.commit != current else None
        return KnowledgeSource(FRESH, current, reported=reported)
    return KnowledgeSource(STALE, current, stale_kind=report.stale_kind, reason=report.reason)


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
    """`folder/name` removed as the entry it is, nothing below it followed."""
    try:
        fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return
    try:
        try:
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if stat.S_ISDIR(st.st_mode):
            shutil.rmtree(name, dir_fd=fd)
        else:
            os.unlink(name, dir_fd=fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _files_of(root: Path) -> dict[str, bytes]:
    try:
        return regular_files(root)
    except DeliveryRefused as refused:
        raise KnowledgeRefused(f"the export cannot be copied for this run: {refused}") from refused


def copy_for_run(tenant: Tenant, source: KnowledgeSource, run_id: str) -> RunCopy:
    """Copy `source`'s export into `<T>/run-knowledge/<run_id>/`: built as a dot-named
    temporary holding its owner record (this process: pid + start time, so a publish sweeps it
    once this process is gone), then renamed into place. Every file is written anew (no inode
    is shared with the export) from a no-follow read that refuses anything but regular files.

    A copy already at `<run_id>` (a resumed run id whose earlier run was killed) is replaced
    when its owner is dead, and refused while it lives."""
    export = _export_of(tenant, source.commit)
    agent_files = _files_of(export / AGENT_HALF)
    settings_files = _files_of(export / SETTINGS_HALF)
    copies = _unwrap_run_knowledge_root(tenant.run_knowledge)
    final = copies / run_id
    if _io.entry_present(final):
        if owner_alive(final):
            raise KnowledgeRefused(
                f"run id {run_id} already has a live run copy at {final}: another process is "
                "running it")
        _remove_copy(copies, run_id)
    temporary = f"{_BUILDING_PREFIX}{run_id}-{secrets.token_hex(4)}"
    try:
        with _io.hold_new(copies, temporary, exclusive=True) as held:
            write_owner(copies / temporary)
            for files, under in ((agent_files, f"{STAGE}/{AGENT_HALF}"),
                                 (settings_files, SETTINGS_HALF)):
                held.mkdir(under)  # lint-unguarded-tree-write: ok — `Held.mkdir`, no link followed below the held temporary
                for rel, data in files.items():
                    held.write(f"{under}/{rel}", data, mode="create")
            held.write(f"{STAGE}/{STAGE_TOKEN}", secrets.token_hex(16), mode="create")
        os.rename(copies / temporary, final)
    except BaseException:
        _remove_copy(copies, temporary)
        raise
    return RunCopy(final)


def write_host_record(path: Path, source: KnowledgeSource) -> None:
    """The host-held knowledge-source record (U12), beside the run dir."""
    _io.write_guarded(path, json.dumps(source.host_record(), indent=2, sort_keys=True) + "\n")


__all__ = [
    "FRESH", "MISCONFIGURED", "OPERATOR", "PINNED", "STALE", "STAGE", "STAGE_TOKEN",
    "TRANSIENT", "KnowledgeRefused", "KnowledgeSource", "PublishReport", "RunCopy",
    "child_failed", "copy_for_run", "pinned_commit", "read_publish_report", "resolve_source",
    "write_host_record",
]
