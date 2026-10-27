"""Sibling provenance verification and family archive publication."""
from __future__ import annotations





import json






from collections.abc import Mapping, Sequence





from defender.records._episode_handle import Episode


from defender._io import (
    read_text_utf8,
)


from defender.records import (
    Run,
    RunAbsent,
    RunRefused,
    artifact_file,
)


from defender.learning.branch import outcome as outcome_mod
from defender.runtime.branch._family import load_family














from defender.learning.branch.preflight import _HELD as _HELD, _family_refusal as _family_refusal, _stamp_of as _stamp_of




# ---------------------------------------------------------------------------------------
# `Step.VERIFY` — verification, the family stamp, and the archive
# ---------------------------------------------------------------------------------------


def _scrub_ran(run: Run) -> bool:
    """Did the reap scan walk this sibling's tree and say so?

    Read at the sidecar beside the run dir: the verdict lives outside the tree it judges, where
    the box that is root on that mount cannot forge it.
    """
    verdict = run.facts.scrub_verdict.path
    if not artifact_file(verdict):
        return False
    try:
        record = json.loads(read_text_utf8(verdict))
    except (OSError, ValueError):
        return False
    return isinstance(record, dict) and record.get("ran") is True




def verify_family(
    episode: Episode, arms: Mapping[str, Run | RunRefused], *, source: dict,
    allow_dirty: bool = False,
) -> dict:
    """Check every sibling, archive each verified one, and write the family stamp unless a
    comparability fault forbids it."""
    family = load_family(episode.view(), expected_episode_id=episode.dir.name)
    labels = {world_id: family.world_by_id(world_id).label for world_id in arms}
    runs = {world_id: arm for world_id, arm in arms.items() if isinstance(arm, Run)}
    absent = [world_id for world_id, arm in arms.items() if isinstance(arm, RunAbsent)]
    refused = {world_id: arm for world_id, arm in arms.items()
               if isinstance(arm, RunRefused) and not isinstance(arm, RunAbsent)}
    scrub_verified = [world_id for world_id in runs if _scrub_ran(runs[world_id])]
    # An absent arm has no tree, so no scrub verdict records a walk of one.
    unverified = sorted((set(runs) - set(scrub_verified)) | set(absent))
    stamps = {world_id: _stamp_of(run) for world_id, run in runs.items()}

    # `blocking`: the comparability faults, which withhold the stamp. `per_world`: faults that
    # are one world's own record and leave the stamp to the rest.
    blocking: list[str] = []
    per_world: list[str] = []
    if not arms:
        blocking.append("the family has no sibling — a comparison over no arm is not one, so "
                        "there is nothing to hold to the source's commit or to archive")
    if unverified:
        per_world.append(
            f"sibling(s) {[labels[world_id] for world_id in unverified]} have no scrub verdict "
            "recording a completed walk — an "
            "unwalked tree is one nothing has certified as free of what the box left behind")
    judged = _family_refusal(
        source, {f"sibling {labels[world_id]!r}": stamps[world_id] for world_id in scrub_verified},
        source_who="the source run", allow_dirty=allow_dirty)
    if judged.refusal is not None:
        blocking.append(judged.refusal)
    cross_tenant = _cross_tenant_fault(stamps, scrub_verified)
    if cross_tenant is not None:
        blocking.append(cross_tenant)

    archived = _archive_worlds(episode, runs, refused=refused, unverified=unverified,
                               per_world=per_world)
    if arms and not archived:
        blocking.append(
            f"no sibling of {sorted(arms)} was verified and archived — there is no arm left to "
            "compare")
    not_comparable = "; ".join(blocking)
    if not blocking:
        # The agreement among the verified, archived siblings: a world with only its own
        # `not archived` record is not a member of what the stamp certifies.
        _write_family_stamp(
            episode, {world_id: stamps[world_id] for world_id in archived}, source=source,
            allow_dirty=allow_dirty, waived=judged.waived)
    else:
        # The judge names this reason when it stamps the family `not comparable`.
        outcome_mod.write_not_comparable(episode, not_comparable)
    return {"comparable": not blocking, "reason": "; ".join(blocking + per_world),
            "not_comparable": not_comparable, "scrub_verified": scrub_verified,
            "archived": archived, "worlds": sorted(arms)}




def _archive_worlds(
    episode: Episode, runs: Mapping[str, Run], *, refused: Mapping[str, RunRefused],
    unverified: Sequence[str], per_world: list[str],
) -> list[str]:
    """`verify_family`'s per-world pass: archive every scrub-verified run, and give every other
    finished world its own `not archived` record, appending each such fault to `per_world`.
    Returns the world UUIDs archived.

    `worlds/` exists whatever happens below; a world's own record says why one is missing.
    Every finished world ends archived or with its own `not archived` record — never neither,
    since the judge counts a world it cannot see only through that record (S10, O5). An absent
    arm is among `unverified`."""
    from defender.learning.branch import archive as archive_mod

    family = load_family(episode.view(), expected_episode_id=episode.dir.name)
    labels = {world_id: family.world_by_id(world_id).label
              for world_id in {*runs, *refused, *unverified}}
    episode.worlds.ensure()
    archived: list[str] = []
    for world_id in sorted(refused):
        per_world.append(f"world {labels[world_id]}'s run folder was refused ({refused[world_id]})")
        outcome_mod.write_world_record(
            episode, world_id, outcome_mod.NOT_ARCHIVED,
            detail=f"its run folder was refused, so nothing was read from it: {refused[world_id]}")
    for world_id in sorted({*runs, *unverified}):
        if world_id in unverified:
            outcome_mod.write_world_record(
                episode, world_id, outcome_mod.NOT_ARCHIVED,
                detail="no scrub verdict records a completed walk of its tree, so it was not "
                       "archived")
            continue
        try:
            archive_mod.archive_episode(episode, {world_id: runs[world_id].run_dir})
        except Exception as refusal:  # noqa: BLE001 — one world's archive, recorded; the rest go on
            per_world.append(f"world {labels[world_id]}'s tree could not be archived ({refusal})")
            outcome_mod.write_world_record(
                episode, world_id, outcome_mod.NOT_ARCHIVED,
                detail=f"the archive refused its finished tree: {refusal}")
            continue
        archived.append(world_id)
    return archived




def _cross_tenant_fault(stamps: dict[str, dict | None], labels: Sequence[str]) -> str | None:
    """Siblings disagreeing on `tenant_id`, or a mix of stamps with and without the field.

    A missing field is its own fault, never treated as agreeing. Siblings with no readable
    stamp are skipped (`_member_faults` reports them) and the skip count is recorded."""
    readable: dict[str, dict] = {
        label: stamp for label in labels
        if isinstance(stamp := stamps.get(label), dict)}
    skipped = len(labels) - len(readable)
    no_field = sorted(label for label, s in readable.items() if s.get("tenant_id") is None)
    # All siblings silent on tenant (older stamps) is fine; only a mix is a fault.
    if no_field and len(no_field) == len(readable):
        no_field = []
    parts: list[str] = []
    if no_field:
        parts.append(
            f"sibling(s) {no_field} carry no tenant field at all — treated as its own named "
            "fault, never as agreeing with the rest")
    else:
        values = {label: s.get("tenant_id") for label, s in readable.items()}
        if len(set(values.values())) > 1:
            parts.append(f"siblings disagree on tenant: {values}")
    if skipped:
        # Recorded so an unstamped sibling cannot silently shrink the comparison. Always
        # accompanies `_member_faults`'s own fault for that sibling, so this note alone never
        # makes a family incomplete.
        parts.append(
            f"the cross-tenant comparison ran over the {len(readable)} sibling(s) already "
            f"stamped and skipped {skipped} unstamped one(s)")
    return "; ".join(parts) if parts else None




def _write_family_stamp(
    episode: Episode, stamps: dict[str, dict | None], *, source: dict, allow_dirty: bool,
    waived: list[str] | None = None,
) -> None:
    """The family's one stamp: what every sibling agreed on, what it was anchored to, and
    whether it was waved through."""
    present = [stamp for stamp in stamps.values() if stamp is not None]
    # Every held field is the agreed record's, since `_family_refusal` passed: the first
    # sibling's value, except where an unknown is its own waived fault — there the agreed value
    # is one a sibling actually named, or `None` when none did. Dirt fields may differ under
    # `--allow-dirty` and here are the first sibling's; each sibling's own is archived in
    # `worlds/<world-uuid>/provenance.json`. `verify_family` guarantees at least one sibling.
    agreed = {k: v for k, v in present[0].items() if k != "world_id"}
    for field, rule in _HELD.items():
        if rule.unknown_kind is not None:
            agreed[field] = next(
                (stamp.get(field) for stamp in present if rule.compared(stamp) is not None), None)
    doc: dict[str, object] = {
        "agreed": agreed, "allow_dirty": bool(allow_dirty), "source": dict(source),
        "waived": list(waived or [])}
    episode.family_stamp.write(
        json.dumps(doc, indent=2, sort_keys=True) + "\n")
