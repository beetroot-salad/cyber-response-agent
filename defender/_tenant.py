"""#1078 pass (A) — tenant 1 on the request.

D2's runs-base record, `<runs_base>/_tenant.json`, keeps its name and fields
(`{tenant_id, base_world_id, created_at}`); what changes is who decides its tenant:
`ensure_runs_base_record(runs_base, tenant_id)` mints it with the REQUEST's id, or reads it
back and refuses on disagreement — never overwrites, never falls back to a default.

D1 adds the tenant itself: a `<data root>/<tenant>/` folder whose ROW (`tenant.json`) is the
only thing that makes it exist. `TenantPaths` is the one place the tenant's layout is spelled;
`create_tenant`/`require_tenant` are the row's writer and reader; `resolve_data_root` is the
one path from `DEFENDER_DATA_ROOT` (no default) to an absolute, symlink-resolved root, and
carries the widened learning-state-overlap refusal (O13/J24); `runs_base_for` composes the two.

Demand #0 (F0/J29, human): every owner function here refuses a caller-supplied value (a bad
tenant id, a foreign data root, an unset `DEFENDER_DATA_ROOT`, a disagreeing record) through
ONE `ValueError` subclass (`TenantRefused`), whose message names the refused value; every entry
point passes that message through verbatim. `TenantRecordCorrupt` is a deliberate second
subclass, scoped narrowly to the runs-base record's own content (`read_tenant`/
`_parse_record`): decision 4's sole exception to read-as-`None` for a record that fails to
parse or is missing/mistyped fields — a distinct failure mode from F0/J29's refusal, not a
second spelling of it.

§7 J16/J63 (human, COMPLETE-OR-ABSENT WRITES): a concurrent reader of a create-lane artifact
(the runs-base record, the tenant row) sees the name absent or the file complete, never empty
or partial; one name throughout; mode 0644; a crash leaves no stray entry. `_create_once`
below is the mechanism — `O_TMPFILE` + `linkat` on Linux, where the file is written complete
before it is ever given a name, so there is no window in which a reader can see it partial.
This is a local primitive, not a `_io.write_guarded` mode: `write_guarded`'s `create` lane also
backs every run's `alert.json`/`provenance.json`, and widening ITS guarantee is a larger blast
radius than these two artifacts asked for (a declared deviation — see the PR body).
"""
from __future__ import annotations

import ctypes
import dataclasses
import errno
import json
import os
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from defender import _io as _real_io
from defender import _paths

#: D2's file-backend location, unchanged from #1077: under the runs base, beside the sidecars.
TENANT_RECORD_NAME = "_tenant.json"

#: D1's row, inside the tenant's own folder.
ROW_NAME = "tenant.json"

TENANT_FIELDS = ("tenant_id", "base_world_id", "created_at")
_ROW_FIELDS = ("tenant_id", "created_at")

#: The data-root knob (D2). Private: the design exports no public string constant from this
#: module (J05 — a public `str` here is an import-refused "record name" under
#: `lint_run_records`'s import arm).
_DATA_ROOT_ENV = "DEFENDER_DATA_ROOT"

#: The learning-state knob O13's widened refusal compares the data root against.
_LEARNING_STATE_ENV = "DEFENDER_LEARNING_STATE_DIR"

#: O3's grammar, matched with `re.fullmatch` (a `$`-anchored `re.match` would accept a trailing
#: newline — settled by the user).
_GRAMMAR = re.compile(r"^[a-z][a-z0-9-]{0,62}$")


class TenantRefused(ValueError):
    """The one refusal shape (#0, F0/J29) for every owner function in this module: the
    message names the value that was refused, and every entry surfaces it verbatim."""


@dataclasses.dataclass(frozen=True)
class TenantRecord:
    tenant_id: str
    base_world_id: str
    created_at: str


class TenantRecordCorrupt(ValueError):
    """The runs-base record fails to parse, or parses but is missing a required field, carries
    the wrong type, or names an off-grammar tenant id. Decision 4's sole exception to
    read-as-`None`: this record refuses the whole run rather than degrading."""


@dataclasses.dataclass(frozen=True)
class TenantRow:
    tenant_id: str
    created_at: str


# ==========================================================================================
# The grammar (O3)
# ==========================================================================================

def is_valid_tenant_id(tenant_id: str) -> bool:
    return isinstance(tenant_id, str) and bool(_GRAMMAR.fullmatch(tenant_id))


def refuse_bad_tenant_id(tenant_id: str) -> None:
    if not is_valid_tenant_id(tenant_id):
        raise TenantRefused(
            f"{tenant_id!r} is not a valid tenant id (must match {_GRAMMAR.pattern!r})")


# ==========================================================================================
# The runs-base record (D2), kept from #1077, with the request deciding its tenant.
# ==========================================================================================

def record_path(runs_base: Path) -> Path:
    return Path(runs_base) / TENANT_RECORD_NAME


def _parse_record(text: str, *, source: Path) -> TenantRecord:
    try:
        obj = json.loads(text)
    except ValueError as bad:
        raise TenantRecordCorrupt(f"{source} is not valid JSON: {bad}") from bad
    if not isinstance(obj, dict):
        raise TenantRecordCorrupt(f"{source} is not a JSON object")
    missing = [f for f in TENANT_FIELDS if f not in obj]
    if missing:
        raise TenantRecordCorrupt(f"{source} is missing required field(s) {missing}")
    for field_name in TENANT_FIELDS:
        if not isinstance(obj[field_name], str):
            raise TenantRecordCorrupt(
                f"{source}: {field_name!r} must be a string, got "
                f"{type(obj[field_name]).__name__}")
    if not is_valid_tenant_id(obj["tenant_id"]):
        raise TenantRecordCorrupt(
            f"{source}: tenant_id {obj['tenant_id']!r} is not a valid tenant id")
    return TenantRecord(
        tenant_id=obj["tenant_id"], base_world_id=obj["base_world_id"],
        created_at=obj["created_at"])


def _record_doc(record: TenantRecord) -> dict[str, Any]:
    return {
        "tenant_id": record.tenant_id, "base_world_id": record.base_world_id,
        "created_at": record.created_at,
    }


def read_tenant(runs_base: Path, *, io: Any = _real_io) -> TenantRecord:
    """The tenant record at `runs_base`, or the refusal — never `None`: an absent or corrupt
    tenant record refuses the caller rather than degrading (decision 4's sole exception)."""
    path = record_path(runs_base)
    text, reason = io.read_guarded(path)
    if text is None:
        raise TenantRecordCorrupt(f"{path} could not be read: {reason}")
    return _parse_record(text, source=path)


def refuse_colliding_run_id(run_id: str) -> Exception | None:
    """An explicit collision guard for run creation (#1077 decision 13) — replacing the three
    coincidences that keep a run dir and the tenant record apart today (the leading
    underscore outside the run-id character space, the stale-sidecar clear's exact keying,
    both runs-base walkers' `is_dir()` filter), none of which is a constraint anything
    enforces. Returns the refusal rather than raising it — the caller (`materialize_run_dir`)
    decides how to surface it."""
    if run_id == TENANT_RECORD_NAME:
        return ValueError(
            f"run id {run_id!r} collides with the tenant record's own filename "
            f"({TENANT_RECORD_NAME}) — refused before anything is created")
    return None


def ensure_runs_base_record(runs_base: Path, tenant_id: str) -> TenantRecord:
    """Mint the runs-base record naming `tenant_id` when absent; read it back and hand it over
    when present and naming `tenant_id`; refuse when present and naming another tenant —
    never overwrite (D1, O6; §7 J16/J63's complete-or-absent creator)."""
    refuse_bad_tenant_id(tenant_id)
    runs_base = Path(runs_base)
    path = record_path(runs_base)
    record = TenantRecord(
        tenant_id=tenant_id, base_world_id=uuid.uuid4().hex, created_at=_now())
    body = json.dumps(_record_doc(record), indent=2, sort_keys=True) + "\n"
    if _create_once(path, body):
        return record
    # Lost the race (or the name was already occupied): the value on disk is the identity —
    # read it back rather than trusting or overwriting ours.
    winner = read_tenant(runs_base)
    if winner.tenant_id != tenant_id:
        raise TenantRefused(
            f"{path} names {winner.tenant_id!r}, not {tenant_id!r} — ensure_runs_base_record "
            "never overwrites a disagreeing record")
    return winner


# ==========================================================================================
# The tenant's own folder and layout (D1, O11a).
# ==========================================================================================

class TenantPaths:
    """The tenant's layout under a data root — the ONE place it is spelled (D1). A path owner:
    constructing it creates nothing."""

    def __init__(self, root: Path | str, tenant_id: str) -> None:
        refuse_bad_tenant_id(tenant_id)
        root = Path(root)
        if not root.is_absolute():
            raise TenantRefused(f"data root {str(root)!r} must be an absolute path")
        _refuse_inside_defender_tree(root, tenant_id)
        self.dir = root / tenant_id

    #: Computed as properties, not `__init__`-set attributes, so `dir(TenantPaths)` lists them
    #: for the #1077 owner-derived-join lint (`_astlib._OWNER_CLASS_ORIGINS`,
    #: `lint_run_records._accessor_names`) exactly as `RunPaths`/`EpisodePaths` do.
    @property
    def row(self) -> Path:
        return self.dir / ROW_NAME

    @property
    def runs(self) -> Path:
        return self.dir / "runs"

    @property
    def episodes(self) -> Path:
        return self.dir / "episodes"

    @property
    def learning(self) -> Path:
        return self.dir / "learning"


def _refuse_inside_defender_tree(root: Path, tenant_id: str) -> None:
    """O11a: a tenant folder may not land inside THIS checkout's box-mounted `defender/` tree
    (comparison against `PATHS.defender_dir` specifically — not any directory named
    'defender', so another checkout's own `defender/` tree is untouched, N13)."""
    defender_dir = _paths.PATHS.defender_dir.resolve()
    candidate = (root / tenant_id).resolve()
    if candidate == defender_dir or defender_dir in candidate.parents:
        raise TenantRefused(
            f"{root / tenant_id} is inside the checkout's defender/ tree ({defender_dir}) — "
            "a tenant folder must live outside the box-mounted checkout")


# ==========================================================================================
# The row: create_tenant / require_tenant (D1, O2, O10).
# ==========================================================================================

def _now() -> str:
    return datetime.now(UTC).isoformat()


def create_tenant(root: Path, tenant_id: str) -> TenantRow:
    """Mint tenant_id's row exactly once, into a FRESH data root (O10: tenant 1 only). The
    folder is made through `guarded_mkdir` (F12: no raw mkdir here), which re-judges every
    component below `root` at mkdir time, closing an O11a-vs-write-time symlink swap; the row
    itself is created through the complete-or-absent lane (J16/J63), never overwritten (O2,
    D1)."""
    paths = TenantPaths(root, tenant_id)
    root = Path(root)
    refuse_foreign_data_root(root, tenant_id)
    try:
        _real_io.guarded_mkdir(paths.dir, base=root)
    except OSError as blocked:
        raise TenantRefused(f"{paths.dir}: {blocked}") from blocked
    row = TenantRow(tenant_id=tenant_id, created_at=_now())
    body = json.dumps(
        {"tenant_id": row.tenant_id, "created_at": row.created_at}, indent=2, sort_keys=True,
    ) + "\n"
    if not _create_once(paths.row, body):
        raise TenantRefused(f"{paths.row} already exists — a tenant is created once")
    return row


def refuse_foreign_data_root(root: Path, tenant_id: str) -> None:
    """O10: a tenant is created only into a FRESH data root — one whose only entry, if any, is
    this tenant's own folder, containing nothing that is not its own row or (once the row
    exists) whatever setup made since. §7 J08/J09 (human, RECORD MEANS THE TENANT): a
    `<root>/<tenant_id>/` folder with NO record is an unfinished setup, completed by a re-run —
    so while the row is absent, anything else inside the own folder is foreign too; once the
    row exists, the folder's other contents (runs/, sessions/) are the tenant's own business and
    never re-checked. Any OTHER entry at `root`, or any other id's folder however it is shaped,
    is always foreign. The row's OWN name is exempt from the inner scan either way (J60: an
    alias planted there is the guarded write's refusal to make, never this one's). Refuses,
    naming what it found; called both by `create_tenant` and, directly, by setup — so a
    caller that skips `create_tenant` on an idempotent re-run still meets this check."""
    if not root.is_dir():
        return
    entries = sorted(p.name for p in root.iterdir())
    foreign = [e for e in entries if e != tenant_id]
    if foreign:
        raise TenantRefused(
            f"the data root is not empty: {root} holds {foreign} — a tenant is created only "
            "into a fresh data root")
    own = root / tenant_id
    if own.is_dir() and not (own / ROW_NAME).exists():
        inside = [f"{tenant_id}/{name}" for name in sorted(p.name for p in own.iterdir())
                 if name != ROW_NAME]
        if inside:
            raise TenantRefused(
                f"the data root is not empty: {root} holds {inside} — a tenant is created only "
                "into a fresh data root")


def require_tenant(root: Path, tenant_id: str) -> TenantRow:
    """`tenant_id`'s row, or the refusal: absent, corrupt (bad JSON, a non-object top level, an
    undecodable byte, a missing or non-string field), a directory or dangling link at the row's
    name (folded as corrupt/absent, §7 J22), or a row naming another tenant. Every refusal
    names the row's path."""
    paths = TenantPaths(root, tenant_id)
    text, reason = _real_io.read_guarded(paths.row)
    if text is None:
        raise TenantRefused(f"{paths.row}: {reason}")
    try:
        doc = json.loads(text)
    except ValueError as bad:
        raise TenantRefused(f"{paths.row} is not valid JSON: {bad}") from bad
    if not isinstance(doc, dict):
        raise TenantRefused(f"{paths.row} is not a JSON object")
    missing = [f for f in _ROW_FIELDS if f not in doc]
    if missing:
        raise TenantRefused(f"{paths.row} is missing required field(s) {missing}")
    for field_name in _ROW_FIELDS:
        if not isinstance(doc[field_name], str):
            raise TenantRefused(
                f"{paths.row}: {field_name!r} must be a string, got "
                f"{type(doc[field_name]).__name__}")
    if doc["tenant_id"] != tenant_id:
        raise TenantRefused(f"{paths.row} names {doc['tenant_id']!r}, not {tenant_id!r}")
    return TenantRow(tenant_id=doc["tenant_id"], created_at=doc["created_at"])


# ==========================================================================================
# The data root (D2) and runs_base_for.
# ==========================================================================================

def resolve_data_root() -> Path:
    """The one path from `DEFENDER_DATA_ROOT` to an absolute, symlink-resolved root. No
    default: an unset or empty value is refused, naming the variable (settled by the user).
    Carries O13's widened learning-state-overlap refusal (moved here by fork J24: it must run
    wherever the data root resolves, siblings included)."""
    raw = os.environ.get(_DATA_ROOT_ENV, "")
    if not raw:
        raise TenantRefused(f"{_DATA_ROOT_ENV} is not set — there is no default data root")
    root = Path(raw)
    if not root.is_absolute():
        raise TenantRefused(f"{_DATA_ROOT_ENV}={raw!r} must be an absolute path")
    resolved = root.resolve()
    _refuse_widened_learning_state_overlap(resolved)
    return resolved


def _refuse_widened_learning_state_overlap(data_root: Path) -> None:
    raw = os.environ.get(_LEARNING_STATE_ENV)
    if not raw:
        return
    learning = Path(raw).resolve()
    if learning == data_root or data_root in learning.parents or learning in data_root.parents:
        raise TenantRefused(
            f"{_LEARNING_STATE_ENV}={learning} overlaps the data root {data_root} — learning "
            "state and tenant data must not share a tree")


def runs_base_for(tenant_id: str) -> Path:
    """`TenantPaths(resolve_data_root(), tenant_id).runs` — `<root>/<tenant>/runs`."""
    return TenantPaths(resolve_data_root(), tenant_id).runs


def tenant_of_run_dir(run_dir: Path) -> str:
    """The tenant a run dir belongs to, learned from its source's HOST-ONLY runs-base record
    (never a stamp a box can write): the record at `run_dir.parent`, refused unless
    `run_dir.parent` is exactly the CURRENT `runs_base_for(record.tenant_id)` — a run dir left
    over from before its tenant's current data root, or under an unrelated tree, is refused
    rather than silently trusted."""
    run_dir = Path(run_dir)
    runs_base = run_dir.parent
    record = read_tenant(runs_base)
    data_root = resolve_data_root()
    expected = TenantPaths(data_root, record.tenant_id).runs
    if runs_base.resolve() != expected.resolve():
        raise TenantRefused(
            f"{runs_base} does not match the current runs base for tenant "
            f"{record.tenant_id!r} ({expected}) — refusing a run directory outside its "
            "tenant's own tree")
    require_tenant(data_root, record.tenant_id)
    return record.tenant_id


# ==========================================================================================
# §7 J16/J63 — the complete-or-absent create lane.
# ==========================================================================================

def _create_once(path: Path, body: str) -> bool:
    """True if THIS call created `path`; False if it already existed (any shape — a plain
    file, a symlink, a hard link, a directory), never touching what is there.

    Linux: `O_TMPFILE` opens an anonymous, unnamed inode in `path`'s own directory; the body is
    written to it in full BEFORE it is given any name, then `linkat` (via the `/proc/self/fd`
    trick, `os.link(..., follow_symlinks=True)`) gives it `path`'s name atomically. There is no
    instant at which the name exists and the body is incomplete, and no instant with two names
    (the anonymous inode has zero links until the one `linkat` succeeds). A losing `linkat`
    (`FileExistsError`) leaves the tmpfile inode to be reclaimed on close — no stray entry —
    and never touches whatever already occupies `path`.

    Elsewhere: falls back to `_io.write_guarded(mode='create')` (today's one-`open` lane) — a
    documented, weaker guarantee off Linux; CI runs Linux. Only a lost race (`FileExistsError`)
    or `write_guarded`'s own alias refusal (a symlink/hard link already at the name) reads as
    "already existed"; any OTHER `OSError` (ENOSPC, EACCES, …) is a real failure of THIS call's
    own write and must propagate rather than being told to the caller as "someone else won" —
    which would send it off to read a record that was never written."""
    path = Path(path)
    if hasattr(os, "O_TMPFILE"):
        fd = os.open(path.parent, os.O_TMPFILE | os.O_WRONLY, 0o644)
        try:
            os.fchmod(fd, 0o644)
            _write_all(fd, body.encode("utf-8"))
            os.fsync(fd)
            try:
                return _link_tmpfile(fd, path)
            except FileExistsError:
                return False
        finally:
            os.close(fd)
    try:
        _real_io.write_guarded(path, body, mode="create")
    except FileExistsError:
        return False
    except OSError as failed:
        if failed.strerror == _real_io.ALIAS_READ_REFUSAL:
            return False
        raise
    return True


def _write_all(fd: int, data: bytes) -> None:
    """`os.write` may write fewer bytes than asked (a short write — POSIX allows it on any fd,
    not only pipes/sockets); a single unchecked call could link a SHORT body into `path` under
    a name the complete-or-absent contract promises is never partial. Loop until every byte has
    landed."""
    sent = 0
    while sent < len(data):
        sent += os.write(fd, data[sent:])


_libc: Any = None


def _link_tmpfile(fd: int, path: Path) -> bool:
    """Give the anonymous `O_TMPFILE` descriptor `fd` the name `path`, exactly once.

    The portable, unprivileged route is `linkat` through the `/proc/self/fd` magic symlink
    (`os.link(..., follow_symlinks=True)`) — no capability needed on ordinary Linux, which is
    what CI runs. Some sandboxed containers (observed in this project's dev container) refuse
    that specific route with `EXDEV` even though the target names the same device — a runtime
    artifact of how they virtualize `/proc`, not a real cross-filesystem link. There, fall back
    to the raw `linkat(AT_EMPTY_PATH)` syscall, which needs `CAP_DAC_READ_SEARCH` (root has it,
    which the affected sandbox runs as)."""
    try:
        os.link(f"/proc/self/fd/{fd}", path, follow_symlinks=True)
        return True
    except OSError as first:
        if first.errno != errno.EXDEV:
            raise
    _linkat_at_empty_path(fd, path)
    return True


def _linkat_at_empty_path(fd: int, path: Path) -> None:
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL("libc.so.6", use_errno=True)
    at_fdcwd = -100
    at_empty_path = 0x1000
    target = os.fsencode(str(path))
    ret = _libc.linkat(fd, b"", at_fdcwd, target, at_empty_path)
    if ret != 0:
        err = ctypes.get_errno()
        if err == errno.EEXIST:
            raise FileExistsError(err, os.strerror(err), str(path))
        raise OSError(err, os.strerror(err), str(path))
