"""D2 — the tenant record: `<runs_base>/_tenant.json`, the sole authority for the tenant a run
stamps.

Created ONCE, when absent, through `_io.write_guarded` — the same alias-refusing staged create
every other shared-tree writer routes through, never a raw `os.open`. A record that fails to
parse REFUSES THE RUN rather than degrading: decision 4 makes every other record's field read
`None` on corruption, and the tenant record is the sole, deliberate exception — a run with a
forged tenant is worse than no run.

The leading underscore in the filename keeps it out of the run-id space (`_run_id.is_valid_run_id`
requires a leading alphanumeric, claim C18) — but that alone is a coincidence, not a constraint
anything enforces, so `refuse_colliding_run_id` is the EXPLICIT collision guard run creation
calls (decision 13).
"""
from __future__ import annotations

import dataclasses
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from defender import _io as _real_io

#: D2's file-backend location — under the runs base, beside the sidecars (`<runs_base>/<run>.
#: run-end.json` and friends), at the same trust level as those (N9), NOT `<runs_base>/../`
#: (the first draft's location — that resolves to `/tmp/tenant.json` under the default runs
#: base and is rejected explicitly by `test_nothing_is_written_beside_the_runs_base`).
TENANT_RECORD_NAME = "_tenant.json"

#: D2's creation-time bootstrap value — NOT an enforced constant (settled premise s29/s31): the
#: record is the sole authority for the stamped tenant, and a sibling runs base mints its OWN
#: record with the same default, which is a new base-world record for the same tenant.
DEFAULT_TENANT_ID = "default"

TENANT_FIELDS = ("tenant_id", "base_world_id", "created_at")


@dataclasses.dataclass(frozen=True)
class TenantRecord:
    tenant_id: str
    base_world_id: str
    created_at: str


class TenantRecordCorrupt(ValueError):
    """The tenant record at `<runs_base>/_tenant.json` fails to parse, or parses but is
    missing a required field or carries one of the wrong type. Decision 4's sole exception to
    read-as-`None`: this record refuses the whole run rather than degrading."""


def record_path(runs_base: Path) -> Path:
    return Path(runs_base) / TENANT_RECORD_NAME


def _parse(text: str, *, source: Path) -> TenantRecord:
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


def read_tenant(runs_base: Path, *, io: Any = None) -> TenantRecord:
    """The tenant record at `runs_base`, or the refusal — never `None`: an absent or corrupt
    tenant record refuses the caller rather than degrading (decision 4's sole exception)."""
    io = io if io is not None else _real_io
    path = record_path(runs_base)
    text, reason = io.read_guarded(path)
    if text is None:
        raise TenantRecordCorrupt(f"{path} could not be read: {reason}")
    return _parse(text, source=path)


def ensure_tenant(runs_base: Path, *, io: Any = None) -> TenantRecord:
    """Create the tenant record once, when absent, and hand it back — reading it back when it
    is already there.

    On a CREATE RACE (another process wins between the absence check and this call's own
    create), the loser discards the value it was about to write and RE-READS the winner's
    record — no retry, no error surfaced (decision 13). An identity-bearing write that fails
    for any other reason (an alias planted at the name, a directory squatting it) FAILS LOUDLY
    and is NEVER silently retried (decision 7) — exactly one `write_guarded` attempt.
    """
    io = io if io is not None else _real_io
    path = record_path(runs_base)
    existing_text, _reason = io.read_guarded(path)
    if existing_text is not None:
        return _parse(existing_text, source=path)
    record = TenantRecord(
        tenant_id=DEFAULT_TENANT_ID, base_world_id=uuid.uuid4().hex,
        created_at=datetime.now(UTC).isoformat())
    # ONE attempt, never retried (decision 7 — an identity-bearing write fails loudly). A
    # `FileExistsError` here is the staged-create collision `_io.write_guarded` itself raises
    # (claim C19); it is not swallowed, it propagates.
    io.write_guarded(path, json.dumps(_doc(record), indent=2, sort_keys=True) + "\n")
    # RE-READ rather than trust the value just staged — the loser of a create race that opens
    # between this call's own absence check and its own write discards what it was about to
    # write and reads back whatever is actually there now (decision 13).
    winner_text, _reason = io.read_guarded(path)
    if winner_text is None:
        raise TenantRecordCorrupt(f"{path} could not be read back after being written")
    return _parse(winner_text, source=path)


def refuse_colliding_run_id(run_id: str) -> Exception | None:
    """An explicit collision guard for run creation (decision 13) — replacing the three
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
