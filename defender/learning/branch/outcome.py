"""An episode's two outcome records (#1224): pre-flight's write-once outcome, and each world's own.

`outcome.yaml` is written once, by the launcher's pre-flight, before any sibling starts, and is
never rewritten (S6): `accepted`, `unusable` (two or more worlds failed calibration) or
`refused` (nothing to calibrate, for a reason that belongs to no world), with the reason, the
worlds pre-flight found unservable, the calls it could not replay and the calls whose live
answer drifted from the recording.

Anything learned after launch is a world's own record, `world_records/<label>.yaml`, holding
one reason (S7, S8): `oracle unservable` or `budget` (written by the sibling as it aborts),
`did not finish` (written by the launcher when a sibling's process exited without a record),
or `not archived` (written by the launcher when the archive refused that world's tree). Every
record has one writer; the exclusive create refuses a second.

Readers treat every word other than exactly `accepted` as not gradable, and an absent or torn
outcome record as the distinct "no record" state, never as `accepted` (M05=A).
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

import yaml

from defender import _yaml
from defender._episode_handle import Episode
from defender._episode_paths import LAYOUT
from defender._io import Bound

ACCEPTED, UNUSABLE, REFUSED = "accepted", "unusable", "refused"
#: Every word the outcome record may hold; there is no fourth (`incomplete` is retired).
OUTCOMES: tuple[str, ...] = (ACCEPTED, UNUSABLE, REFUSED)

#: A world's own record: one of these reasons.
ORACLE_UNSERVABLE = "oracle unservable"
BUDGET = "budget"
DID_NOT_FINISH = "did not finish"
#: The archive refused the world's finished tree, so no reader of the archive can see it
#: (S10: it counts toward O5 like any world the judge cannot see).
NOT_ARCHIVED = "not archived"
WORLD_REASONS: tuple[str, ...] = (ORACLE_UNSERVABLE, BUDGET, DID_NOT_FINISH, NOT_ARCHIVED)

#: How many failed worlds make a family unusable (O5).
UNUSABLE_AT = 2

#: The word a reader states for an absent, empty or torn outcome record: the distinct "no record"
#: state (M05=A), never one of `OUTCOMES` and never the retired `incomplete`.
NO_RECORD = "no record"


class OutcomeUnreadable(ValueError):
    """The outcome record is absent, torn or not a record: the "no record" state."""


def write_outcome(episode: Episode, outcome: str, *, reason: str,
                  unservable_worlds: Iterable[Mapping[str, Any]] = (),
                  not_replayable: Iterable[Mapping[str, Any]] = (),
                  drift: Iterable[Mapping[str, Any]] = ()) -> None:
    """Create the episode's outcome record, once.

    @owns outcome — the shipped `outcome.yaml` (`outcome`, `reason`, `unservable_worlds`,
    `not_replayable`, `drift`) is produced here and nowhere else. The exclusive create refuses a
    second write (`FileExistsError`), so the record pre-flight wrote is the one every sibling
    started under."""
    if outcome not in OUTCOMES:
        raise ValueError(f"{outcome!r} is not an episode outcome ({', '.join(OUTCOMES)})")
    episode.outcome.create(_yaml.safe_dump({
        "outcome": outcome, "reason": reason,
        "unservable_worlds": [dict(u) for u in unservable_worlds],
        "not_replayable": [dict(n) for n in not_replayable],
        "drift": [dict(d) for d in drift],
    }, sort_keys=False))


def write_world_record(episode: Episode, label: str, reason: str, *,
                       call: Mapping[str, Any] | None = None, detail: str = "") -> bool:
    """Create world `label`'s own record with one reason; `False` when it already has one.

    @owns world_records — the shipped `world_records/<label>.yaml` (`world`, `reason`, `call`,
    `detail`) is produced here and nowhere else, for the sibling's writer and the launcher's
    alike. An existing record is never rewritten: whoever wrote first holds the reason."""
    if reason not in WORLD_REASONS:
        raise ValueError(f"{reason!r} is not a world record's reason ({', '.join(WORLD_REASONS)})")
    try:
        episode.world_record(label).create(_yaml.safe_dump({
            "world": label, "reason": reason,
            "call": dict(call) if call is not None else None, "detail": detail,
        }, sort_keys=False))
    except FileExistsError:
        return False
    return True


def read_outcome(bound: Bound) -> dict[str, Any]:
    """The episode's outcome record, or `OutcomeUnreadable` naming why there is none.

    A refused read (a link, a non-plain entry, undecodable bytes) is not "none recorded" either:
    it may be hiding one, so it is the same refusal."""
    rec = bound.read(LAYOUT.outcome)
    if rec.text is None:
        why = "absent" if rec.absent else f"refused ({rec.reason})"
        raise OutcomeUnreadable(f"no record: {LAYOUT.outcome} is {why}")
    try:
        record = _yaml.safe_load(rec.text)
    except (yaml.YAMLError, _yaml.AliasRefused) as torn:
        raise OutcomeUnreadable(
            f"no record: {LAYOUT.outcome} does not parse (torn mid-write?): {torn}") from None
    if not isinstance(record, dict) or record.get("outcome") not in OUTCOMES:
        raise OutcomeUnreadable(
            f"no record: {LAYOUT.outcome} holds no outcome word ({', '.join(OUTCOMES)})")
    if not isinstance(record.get("reason"), str):
        # `write_outcome` always writes one; a record without it is not one pre-flight wrote.
        raise OutcomeUnreadable(f"no record: {LAYOUT.outcome} carries no reason")
    return record


def failed_worlds(bound: Bound, record: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Every world O5 counts as failed, by label: pre-flight's `unservable_worlds` plus every
    world whose own record (`world_records/<label>.yaml`) exists (S9, M04=A). Each value is
    `{world, reason, call, detail}`; a world named by both keeps its own record's entry.

    A world record that cannot be read still counts — its presence is the fact — with the
    refusal as its detail. Labels come off the records as written; nothing here checks them
    against the manifest."""
    failed: dict[str, dict[str, Any]] = {}
    listed = record.get("unservable_worlds")
    for entry in listed if isinstance(listed, (list, tuple)) else ():
        if isinstance(entry, Mapping) and isinstance(entry.get("world"), str):
            failed[entry["world"]] = {"world": entry["world"], "reason": entry.get("reason"),
                                      "call": entry.get("call"), "detail": entry.get("detail", "")}
    records = bound.under(LAYOUT.world_records)
    for name in records.entries().files():
        if not name.endswith(".yaml") or len(name) <= len(".yaml"):
            continue
        label = name[:-len(".yaml")]
        rec = records.read(name)
        try:
            doc = _yaml.safe_load(rec.text) if rec.text is not None else None
        except (yaml.YAMLError, _yaml.AliasRefused):
            doc = None
        if isinstance(doc, dict):
            failed[label] = {"world": label, "reason": doc.get("reason"), "call": doc.get("call"),
                             "detail": doc.get("detail", "")}
        else:
            failed[label] = {"world": label, "reason": None, "call": None,
                             "detail": f"its record ({name}) could not be read"}
    return failed


def unusable_reason(failed: Mapping[str, Mapping[str, Any]]) -> str | None:
    """O5's verdict on `failed_worlds`: the reason the family is unusable, or `None` while
    fewer than `UNUSABLE_AT` worlds failed."""
    if len(failed) < UNUSABLE_AT:
        return None
    named = ", ".join(f"{label} ({entry.get('reason')})" for label, entry in sorted(failed.items()))
    return (f"{len(failed)} worlds could not be judged ({named}) — O5 calls a family with two or "
            "more unusable")


__all__ = [
    "ACCEPTED", "BUDGET", "DID_NOT_FINISH", "NOT_ARCHIVED", "NO_RECORD", "ORACLE_UNSERVABLE",
    "OUTCOMES", "REFUSED", "UNUSABLE", "UNUSABLE_AT", "WORLD_REASONS", "OutcomeUnreadable",
    "failed_worlds", "read_outcome", "unusable_reason", "write_outcome", "write_world_record",
]
