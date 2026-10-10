"""The held runs folder (#1105 H1–H4): the one object every lookup and tenant-keyed record
function works through, and the argument checks they share.

`hold_runs(tenant, io)` opens `tenant.runs` — or the folder the repository's episode view
names, an episode's container — ONCE, no-follow, and yields a `HeldRuns` for the block,
closing the handle when it ends. The object is the call's whole view of the folder:

* `absent` — the folder's one expected state other than present (empty answers);
* `view` — the held folder, handed out only after `_tenant.json` has been judged through it
  (H3) and found to name the tenant, so a caller cannot list or read before the tenant check
  (NF-8: another tenant's folder is refused on its record, never on its entries);
* `listing()` — every entry judged from its directory entry, never followed (H4), once.

This module is the package's bottom layer: `_record` (the episode records) and `_lookup` (the
lookups) import it, and it imports neither. A fault of the folder or of its `_tenant.json` is
`TenantRefused` (P2), which escapes its own message to one line, as `RunRefused` does.
"""
from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender import _io
from defender._run_id import run_id_fault
from defender._shown import quoted, shown
from defender._tenant import (
    TENANT_RECORD_NAME, Tenant, TenantRecord, TenantRecordMismatch, TenantRefused, read_tenant,
    record_path,
)
from defender.run_repository._errors import RunRefused
from defender.run_repository._id import RunId
from defender.run_repository._layout import _SIDECAR_SUFFIXES, _STAGED_TAIL

#: The episode-record folder, directly in the tenant's runs folder. A leading `_` is never a
#: run id (`RunId.parse` refuses it), so no run folder can share its name.
EPISODES_DIRNAME = "_episodes"

# -- the arguments ----------------------------------------------------------------------------


def require_accepted_tenant(tenant: object) -> Tenant:
    """`tenant`, when it is an accepted `Tenant`; else `TypeError` (S2: the tenant is never a
    bare id, a path or a carrier the repository would have to trust or re-accept)."""
    if not isinstance(tenant, Tenant):
        raise TypeError(f"the runs repository takes an accepted Tenant, not "
                        f"{type(tenant).__name__}")
    return tenant


def require_run_id(run_id: object, *, what: str = "run id") -> RunId:
    """`run_id`, when it is a `RunId`; else `TypeError` (a `str` included: callers convert at
    their own edge with `RunId.parse`)."""
    if not isinstance(run_id, RunId):
        raise TypeError(f"the {what} must be a RunId, not {type(run_id).__name__}")
    return run_id


def sidecar_owner(name: str) -> str | None:
    """The run id a sidecar file named `name` belongs to — `<id>` of `<id><suffix>`, or of the
    staged `<id><suffix>.staged-<hex>` a sidecar write creates first — or `None` when `name` is
    not shaped like a sidecar. The one statement of the sidecar clause (#1105 D2.1, MF-21): run
    setup and `open_run` refuse an id it answers for, and the listings take a regular file it
    answers for as a known sidecar when `RunId.parse` admits the owner (any other such file is
    refused). It judges a name, not a path; outside the package it is asked through
    `run_name_fault`."""
    bare = name[: m.start()] if (m := _STAGED_TAIL.search(name)) else name
    for suffix in _SIDECAR_SUFFIXES:
        if bare.endswith(suffix) and len(bare) > len(suffix):
            return bare[: -len(suffix)]
    return None


def run_name_fault(text: str) -> str | None:
    """Why `text` cannot name a run folder, or `None`: the run-id rule (`run_id_fault`: grammar,
    case stability, the 206-byte bound) and the sidecar clause (D2.1, MF-21: a name shaped like
    a host-only sidecar file, or the staged file a sidecar write makes first, never names a
    run). Judged on the name alone, before anything is read. The one answer to "may this text
    name a run?": run setup admits a run id by it, the family model's gate judges each
    `<episode_id>-<label>` by it, and the record writer each arm."""
    if (why := run_id_fault(text)) is not None:
        return why
    if sidecar_owner(text) is not None:
        return (f"{quoted(text)} is shaped like a host-only sidecar file beside a run folder, "
                "not a run")
    return None


def refuse_sidecar_id(run_id: RunId) -> None:
    """`run_name_fault` on a `RunId` (whose run-id rule already holds), as `RunRefused`."""
    if (why := run_name_fault(str(run_id))) is not None:
        raise RunRefused(why)


def entry_path(folder: Path | str, name: str) -> str:
    """`<folder>/<name>` as a refusal shows it: a hostile name read off disk is quoted."""
    return f"{folder}/{shown(name)}"


# -- the folder's entries (H4) -------------------------------------------------------------------


@dataclass(frozen=True)
class Listing:
    """What a held runs folder holds, every entry judged: its runs (sorted by text), and the
    known sidecar files beside them, by name and by the run id each belongs to."""

    runs: tuple[RunId, ...]
    sidecars: frozenset[str]
    sidecar_ids: frozenset[RunId]

    def holds(self, run_id: RunId) -> bool:
        """Whether `run_id` is taken in this folder: a run stands there, a sidecar file owned by
        that id stands beside it (a new run there would meet that file), or a sidecar file is
        named exactly `run_id`. The one definition `run_exists` and the record writer share."""
        return (run_id in self.runs or run_id in self.sidecar_ids
                or str(run_id) in self.sidecars)


def _parses(text: str) -> RunId | None:
    try:
        return RunId.parse(text)
    except RunRefused:
        return None


def _list_entries(view: _io.Bound, folder: Path, *, io: Any) -> Listing:
    """Every entry of the held runs folder, judged from its directory entry and never followed
    (D2.4, H4). Accepted: a run (a real directory whose name `RunId.parse` admits and the
    sidecar clause passes), `_tenant.json` and `_episodes` (each judged where it is read), and a
    known sidecar file — a REGULAR file `<id><suffix>` whose `<id>` `RunId.parse` admits. Any
    other entry is `RunRefused` naming it, a legacy run folder off the id rules included; a
    folder that cannot be listed is `TenantRefused`."""
    answer = view.entries()
    if answer.entries is None:
        why = "it is gone" if answer.absent else answer.reason
        raise TenantRefused(f"the runs folder {folder} could not be listed: {why}")
    runs: list[RunId] = []
    sidecars: set[str] = set()
    sidecar_ids: set[RunId] = set()
    for name in sorted(answer.entries):
        kind = answer.entries[name]
        if name in (TENANT_RECORD_NAME, EPISODES_DIRNAME):
            continue
        owner = sidecar_owner(name)
        if kind == io.ENTRY_DIR:
            run_id = _parses(name) if owner is None else None
            if run_id is None:
                raise RunRefused(
                    f"{entry_path(folder, name)} is a directory that is not a run: its name is "
                    "off the run-id rules or shaped like a sidecar file — rename or move it")
            runs.append(run_id)
        elif kind == io.ENTRY_FILE and owner is not None and (owned := _parses(owner)):
            sidecars.add(name)
            sidecar_ids.add(owned)
        else:
            raise RunRefused(
                f"{entry_path(folder, name)} is not a run, a known sidecar file, "
                f"{TENANT_RECORD_NAME} or {EPISODES_DIRNAME} (a link, a stray file or another "
                "entry) — move it out of the runs folder")
    return Listing(tuple(runs), frozenset(sidecars), frozenset(sidecar_ids))


# -- the held folder (H1–H3) ---------------------------------------------------------------------


def _hold_fault(folder: Path, exc: OSError) -> str:
    """Why `folder` could not be held, judged from the folder's own entry (a no-follow `lstat`,
    description only) rather than from the errno, which an ancestor's fault shares: a link at
    the folder, something other than a directory there, else the hold's own reason — a folder
    above it that cannot be walked included."""
    try:
        st = os.lstat(folder)
    except OSError:
        st = None
    if st is not None and stat.S_ISLNK(st.st_mode):
        return "is a link, which is never followed"
    if st is not None and not stat.S_ISDIR(st.st_mode):
        return "is not a directory"
    return f"cannot be opened ({exc.strerror or exc})"


class _HeldRecordIO:
    """`read_tenant`'s `io=` seam served through the held view (H3): the record is read off
    the held handle, never by path, so its verdict is about the folder this call holds."""

    def __init__(self, view: _io.Bound) -> None:
        self._view = view

    def read_guarded(self, _path: Path, **_kwargs: Any) -> tuple[str | None, str | None]:
        answer = self._view.read(TENANT_RECORD_NAME)
        if answer.text is not None:
            return answer.text, None
        return None, "absent" if answer.absent else answer.reason


class HeldRuns:
    """One call's hold of a runs folder of the tenant's — `tenant.runs`, or an episode's
    container through the repository's episode view (see the module docstring). Built only by
    `hold_runs`; valid for its block."""

    def __init__(self, tenant: Tenant, held: _io.Held | None, io: Any, *,
                 folder: Path) -> None:
        self.tenant = tenant
        self.folder = Path(folder)
        self.absent = held is None
        self._held = held
        self.io = io
        self._checked: _io.Bound | None = None
        self._record: TenantRecord | None = None
        self._listing: Listing | None = None

    def require_present(self) -> HeldRuns:
        """This hold, when the folder exists; else `TenantRefused` (a function that needs the
        folder — `open_run`, the writer — never creates it: run setup does, with its record)."""
        if self.absent:
            raise TenantRefused(f"the runs folder {self.folder} is absent — run setup creates "
                                 "it, with its tenant record")
        return self

    @property
    def view(self) -> _io.Bound:
        """`judged()`: the held folder, its tenant record judged."""
        return self.judged()

    def judged(self) -> _io.Bound:
        """The held folder, once its `_tenant.json` is judged (once per hold): `read_tenant`'s
        verdict read through the held handle, then an exact compare with `tenant.id`. Every
        failure is `TenantRefused` naming the record — `TenantRecordMismatch` for another
        tenant's, as `Run.for_tenant` raises — never a raw error, never carrying a run id of the
        folder (NF-8)."""
        if self._checked is None:
            self.require_present()
            assert self._held is not None
            view = self._held.view()
            path = record_path(self.folder)
            try:
                record = read_tenant(self.folder, io=_HeldRecordIO(view))
            except (RecursionError, ValueError, TypeError, OSError) as exc:
                raise TenantRefused(f"{path} could not be judged: {exc}") from None
            if record.tenant_id != self.tenant.id:
                raise TenantRecordMismatch(f"{path} names the tenant {quoted(record.tenant_id)}, "
                                           f"not {quoted(self.tenant.id)}")
            self._checked, self._record = view, record
        return self._checked

    def record(self) -> TenantRecord:
        """The folder's tenant record, as `judged()` read and judged it through the held
        handle (the episode view's `base_world_id` reads it here, never by path)."""
        self.judged()
        assert self._record is not None
        return self._record

    def listing(self) -> Listing:
        """Every entry of the folder, judged once per hold (after the tenant record)."""
        if self._listing is None:
            self._listing = _list_entries(self.view, self.folder, io=self.io)
        return self._listing

    def write(self, name: str, text: str, *, mode: str) -> None:
        """`Held.write` on the checked folder (the record writer's create lane)."""
        self.judged()
        assert self._held is not None
        self._held.write(name, text, mode=mode)


def hold_runs_folder(folder: Path, *, create: bool = False, io: Any = _io) -> _io.Held:
    """`folder` — a runs folder — held open no-follow, the one way the package and run setup
    open one (#1105 H1, OP-2). An absent folder is `FileNotFoundError`, or with `create` is made
    first (`guarded_mkdir`: the runs folder is the host-controlled trust root, nothing above it
    is judged) and then held. Every other failure — a link (dangling or not) or a non-directory
    at the folder, a folder above it that cannot be walked, a create that fails — is
    `TenantRefused` naming the folder and the fault."""
    folder = Path(folder)
    try:
        return io.hold(folder, follow=False)
    except FileNotFoundError:
        if not create:
            raise
    except OSError as exc:
        raise TenantRefused(f"the runs folder {folder} {_hold_fault(folder, exc)}") from None
    try:
        io.guarded_mkdir(folder, base=folder)
        return io.hold(folder, follow=False)
    except OSError as exc:
        raise TenantRefused(f"the runs folder {folder} could not be created and held: "
                            f"{_hold_fault(folder, exc)}") from None


@contextmanager
def hold_runs(tenant: Tenant, io: Any, *, folder: Path | None = None) -> Iterator[HeldRuns]:
    """`folder` — `tenant.runs` when not given; an episode's container when the repository's
    episode view hands its own — held open no-follow for the block (`absent` when it does not
    exist, the one expected state of the folder itself) by `hold_runs_folder`; the handle is
    closed when the block ends, however it ends."""
    folder = Path(tenant.runs) if folder is None else Path(folder)
    try:
        held = hold_runs_folder(folder, io=io)
    except FileNotFoundError:
        held = None
    if held is None:
        yield HeldRuns(tenant, None, io, folder=folder)
        return
    try:
        yield HeldRuns(tenant, held, io, folder=folder)
    finally:
        held.close()
