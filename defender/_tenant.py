"""The tenant record: `<runs_base>/_tenant.json`, the sole authority for the tenant a run
stamps.

Created once, when absent, through the exclusive alias-refusing `write_guarded(mode="create")`
lane so the loser of a create race cannot overwrite the winner's identity. Unlike other records,
a corrupt tenant record refuses the run rather than reading as `None`: a run with a forged
tenant is worse than no run. `refuse_colliding_run_id` keeps run ids off the record's filename.
"""
from __future__ import annotations

import dataclasses
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeGuard

from defender import _io as _real_io

#: Lives under the runs base beside the run sidecars, at their trust level — not beside the
#: runs base, which under the default base would be `/tmp`.
TENANT_RECORD_NAME = "_tenant.json"

#: The tenant a newly created record gets — a bootstrap value, not an enforced constant; the
#: record is the authority. It names the lab's folder under the tenants root.
DEFAULT_TENANT_ID = "playground"  # lint-shippable: ok — bootstrap tenant, the lab's folder name until the tenant comes from the request

#: A retired bootstrap value that names no tenant folder. Never remapped: a record or stamp
#: carrying it is refused, naming the file to fix.
LEGACY_DEFAULT_TENANT_ID = "default"


def is_usable_tenant_id(tenant_id: object) -> TypeGuard[str]:
    """Can a run be started for `tenant_id`? Not when it is absent, not a string, or the
    retired `default` — there is no fallback."""
    return isinstance(tenant_id, str) and bool(tenant_id) and tenant_id != LEGACY_DEFAULT_TENANT_ID

TENANT_FIELDS = ("tenant_id", "base_world_id", "created_at")


@dataclasses.dataclass(frozen=True)
class TenantRecord:
    tenant_id: str
    base_world_id: str
    created_at: str


class TenantRecordCorrupt(ValueError):
    """The tenant record fails to parse, lacks a required field, or has one of the wrong type.
    Refuses the whole run rather than degrading."""


class TenantRecordMismatch(ValueError):
    """A runs base's record is not the one a run was resolved from (another tenant, or changed
    since). The run refuses rather than stamp a record its settings did not come from."""


def record_path(runs_base: Path) -> Path:
    return Path(runs_base) / TENANT_RECORD_NAME


def peek_tenant(runs_base: Path, *, io: Any = _real_io) -> TenantRecord | None:
    """The record at `runs_base`, never created (`None` when absent). A corrupt or aliased
    record still raises `TenantRecordCorrupt`."""
    if not io.entry_present(record_path(runs_base)):
        return None
    return read_tenant(runs_base, io=io)


def tenant_of_run(run_dir: Path, *, io: Any = _real_io) -> TenantRecord:
    """The tenant a finished run ran as: its runs base's record, or `TenantRecordCorrupt`.

    Never the run's `provenance.json` stamp: the run dir is the box's writable bind, so the
    model can write anything there. The record is never mounted into a box."""
    return read_tenant(Path(run_dir).parent, io=io)


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
                f"{source}: {field_name!r} must be a string, got {type(obj[field_name]).__name__}"
            )
    return TenantRecord(
        tenant_id=obj["tenant_id"], base_world_id=obj["base_world_id"],
        created_at=obj["created_at"])


def _doc(record: TenantRecord) -> dict[str, Any]:
    return {
        "tenant_id": record.tenant_id, "base_world_id": record.base_world_id,
        "created_at": record.created_at,
    }


def read_tenant(runs_base: Path, *, io: Any = _real_io) -> TenantRecord:
    """The tenant record at `runs_base`; absent or corrupt raises `TenantRecordCorrupt`."""
    path = record_path(runs_base)
    text, reason = io.read_guarded(path)
    if text is None:
        raise TenantRecordCorrupt(f"{path} could not be read: {reason}")
    return _parse_record(text, source=path)


def ensure_tenant(
    runs_base: Path, *, io: Any = _real_io, tenant_id: str = DEFAULT_TENANT_ID,
) -> TenantRecord:
    """Create the tenant record when absent and return it; an existing record is returned as
    is (the caller compares `tenant_id`).

    The create is exclusive, so the loser of a create race re-reads the winner's record, and a
    record this process cannot read is never clobbered as if absent. Any other write failure
    (a planted alias, a directory at the name) raises; there is exactly one attempt.
    """
    path = record_path(runs_base)
    existing_text, _reason = io.read_guarded(path)
    if existing_text is not None:
        return _parse_record(existing_text, source=path)
    # The runs base is the trust root; `guarded_mkdir` on its own anchor judges nothing above it.
    io.guarded_mkdir(Path(runs_base), base=Path(runs_base))
    record = TenantRecord(
        tenant_id=tenant_id, base_world_id=uuid.uuid4().hex,
        created_at=datetime.now(UTC).isoformat())
    try:
        io.write_guarded(
            path, json.dumps(_doc(record), indent=2, sort_keys=True) + "\n", mode="create")
    except FileExistsError as taken:
        # Lost the create race (or the name holds something unreadable): the winner's record wins.
        winner_text, reason = io.read_guarded(path)
        if winner_text is None:
            raise FileExistsError(
                f"{path} is occupied but could not be read back ({reason}) — refusing the run "
                "rather than minting a second identity over it") from taken
        return _parse_record(winner_text, source=path)
    return record


def refuse_colliding_run_id(run_id: str) -> Exception | None:
    """Explicit guard against a run id equal to the tenant record's filename. Without it only
    coincidences keep them apart (the leading underscore, the sidecar clear's keying, the
    runs-base walkers' `is_dir()` filter). Returns the refusal rather than raising; the caller
    decides how to surface it."""
    if run_id == TENANT_RECORD_NAME:
        return ValueError(
            f"run id {run_id!r} collides with the tenant record's own filename "
            f"({TENANT_RECORD_NAME}) — refused before anything is created")
    return None
