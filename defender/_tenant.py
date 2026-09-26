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
from typing import Any, TypeGuard

from defender import _io as _real_io

#: D2's file-backend location — under the runs base, beside the sidecars (`<runs_base>/<run>.
#: run-end.json` and friends), at the same trust level as those (N9), NOT `<runs_base>/../`
#: (the first draft's location — that resolves to `/tmp/tenant.json` under the default runs
#: base and is rejected explicitly by `test_nothing_is_written_beside_the_runs_base`).
TENANT_RECORD_NAME = "_tenant.json"

#: D2's creation-time bootstrap value — NOT an enforced constant (settled premise s29/s31): the
#: record is the sole authority for the stamped tenant, and a sibling runs base mints its OWN
#: record with the same default, which is a new base-world record for the same tenant.
#: The lab's tenant id since #1106 (D4, the bridge until #1078 puts the tenant on the request):
#: the id names a folder under the tenants root, and the lab's folder is named for it. An
#: existing record that says `default` is read back as written and refused at run start.
DEFAULT_TENANT_ID = "playground"  # lint-shippable: ok — the bridge's bootstrap tenant (#1106 D4), the lab's folder name until #1078 removes the default

#: The bootstrap value records were minted with before #1106. It names no tenant folder, and it
#: is never remapped: a runs base or a source stamp still carrying it is refused, naming the
#: file to fix (D4, N10).
LEGACY_DEFAULT_TENANT_ID = "default"


def is_usable_tenant_id(tenant_id: object) -> TypeGuard[str]:
    """Can a run be started for `tenant_id` as a record or a stamp carries it? Not when it is
    absent, not a string, or the retired bootstrap `default` (N10) — there is no fallback."""
    return isinstance(tenant_id, str) and bool(tenant_id) and tenant_id != LEGACY_DEFAULT_TENANT_ID

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


def tenant_of_run(run_dir: Path, *, io: Any = _real_io) -> TenantRecord:
    """The tenant a finished run ran as: the record of the runs base it sits in (a run dir is
    `<runs_base>/<run_id>`), or `TenantRecordCorrupt`.

    THE RECORD, NEVER THE RUN'S STAMP. `provenance.json` lives in the run dir, which is the
    box's writable bind, so its `tenant_id` is whatever the model last wrote there. The record
    sits beside the run dir, is never mounted into any box, and is the sole authority for which
    tenant a runs base serves. A stamp is evidence to compare against this, not a source of it."""
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
    """The tenant record at `runs_base`, or the refusal — never `None`: an absent or corrupt
    tenant record refuses the caller rather than degrading (decision 4's sole exception)."""
    path = record_path(runs_base)
    text, reason = io.read_guarded(path)
    if text is None:
        raise TenantRecordCorrupt(f"{path} could not be read: {reason}")
    return _parse_record(text, source=path)


def ensure_tenant(
    runs_base: Path, *, io: Any = _real_io, tenant_id: str = DEFAULT_TENANT_ID,
) -> TenantRecord:
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

    `tenant_id` is what a record created HERE says (#1106): the bootstrap default for an
    ordinary runs base, the episode's own tenant when the branching launcher seeds a sibling's.
    An existing record is returned as it is — the caller compares.
    """
    path = record_path(runs_base)
    existing_text, _reason = io.read_guarded(path)
    if existing_text is not None:
        return _parse_record(existing_text, source=path)
    # The runs base is the trust root, created plainly when absent (`guarded_mkdir` on its own
    # anchor judges nothing above it) — the record is the first thing a fresh base holds.
    io.guarded_mkdir(Path(runs_base), base=Path(runs_base))
    record = TenantRecord(
        tenant_id=tenant_id, base_world_id=uuid.uuid4().hex,
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
