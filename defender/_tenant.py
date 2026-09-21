"""D2 — the tenant record: `<runs_base>/_tenant.json`, the sole authority for the tenant a run
stamps.

Created ONCE, when absent, through `_io.write_guarded(mode="create")` — the alias-refusing
EXCLUSIVE lane, never a raw `os.open` and never the `replace` lane (which would let the loser of
a create race overwrite the winner's identity with its own). A record that fails to
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
    """The tenant record at `runs_base`, or the refusal — never `None`: an absent or corrupt
    tenant record refuses the caller rather than degrading (decision 4's sole exception)."""
    path = record_path(runs_base)
    text, reason = io.read_guarded(path)
    if text is None:
        raise TenantRecordCorrupt(f"{path} could not be read: {reason}")
    return _parse_record(text, source=path)


def ensure_tenant(runs_base: Path, *, io: Any = _real_io) -> TenantRecord:
    """Create the tenant record once, when absent, and hand it back — reading it back when it
    is already there.

    The create is EXCLUSIVE (`write_guarded(mode="create")`): an occupied name raises
    `FileExistsError` and is never overwritten. That is what makes the CREATE RACE resolve the
    only way O4 can hold for both racers — the loser discards the value it was about to write
    and RE-READS the winner's record; no retry, no error surfaced (decision 13). It is also
    what keeps a record this process could not READ (permissions, an undecodable byte) from
    being treated as absent and clobbered: the create collides on it, and the re-read then
    names why it cannot be read. An identity-bearing write that fails for any other reason (an
    alias planted at the name, a directory squatting it) FAILS LOUDLY and is NEVER silently
    retried (decision 7) — exactly one `write_guarded` attempt.
    """
    path = record_path(runs_base)
    existing_text, _reason = io.read_guarded(path)
    if existing_text is not None:
        return _parse_record(existing_text, source=path)
    record = TenantRecord(
        tenant_id=DEFAULT_TENANT_ID, base_world_id=uuid.uuid4().hex,
        created_at=datetime.now(UTC).isoformat())
    try:
        io.write_guarded(
            path, json.dumps(_doc(record), indent=2, sort_keys=True) + "\n", mode="create")
    except FileExistsError as taken:
        # Lost the create race (or the name was occupied by something this process could not
        # read): the winner's record is the tenant's identity, ours is discarded unwritten.
        winner_text, reason = io.read_guarded(path)
        if winner_text is None:
            raise FileExistsError(
                f"{path} is occupied but could not be read back ({reason}) — refusing the run "
                "rather than minting a second identity over it") from taken
        return _parse_record(winner_text, source=path)
    return record


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
