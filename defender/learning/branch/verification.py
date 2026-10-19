"""Sibling provenance verification and family archive publication."""
from __future__ import annotations





import json






from collections.abc import Mapping, Sequence





from defender._episode_handle import Episode


from defender._io import (
    read_text_utf8,
)


from defender.run_repository import (
    Run,
    RunAbsent,
    RunRefused,
    artifact_file,
)


from defender.learning.branch import outcome as outcome_mod














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
    allow_dirty: bool = False, base_world_id: str | None = None,
) -> dict:
    """Check every sibling, archive each verified one, and write the family stamp unless a
    comparability fault forbids it.

    `arms` is every finished arm, keyed by its label (#1105 PR 2: nothing decodes a label from a
    folder's name): the `Run` its episode view opened, or the refusal the open raised. A
    `RunAbsent` is a missing arm folder, read as before: a world with no scrub verdict, so its
    own `not archived` record. Any other refusal (an entry that is not a real directory,
    declared change 5, or a container that cannot be reached, `RunUnreachable`) is likewise that
    world's own `not archived` record, and nothing is read through it. `base_world_id` is the episode container's record's
    (`EpisodeRuns.base_world_id`), carried into the family stamp when one is written.

    `source` is the source run's stamp as judged by `preflight_episode`. Required with no
    default, so siblings are always held to the source's commit rather than only to each other.

    Runs only after an `accepted` pre-flight (no sibling starts otherwise), and never touches
    the outcome record pre-flight wrote (S6). Only scrub-verified worlds are archived, each on
    its own: a world whose tree the archive refuses, or that has no scrub verdict, is one the
    judge cannot see, and gets its own `not archived` record (S10, counted by O5) while the
    others are still archived.

    Two kinds of fault (FORK-1 as amended 2026-10-10, PR #1232 round 7). A PER-WORLD fault (no
    scrub verdict, an archive refusal, a refused arm entry) is that world's own record and does
    not withhold the stamp, which records the agreement among the verified, archived siblings.
    A COMPARABILITY fault — `_family_refusal`'s (commit/knowledge mismatch, dirt unless waived),
    `_cross_tenant_fault`'s, or no sibling verified and archived at all — withholds the stamp,
    and its reason is recorded (`outcome.write_not_comparable`) for the judge, which stamps such
    a family `not comparable`.

    Returns `comparable` (the stamp was written: no comparability fault), `reason` (every
    fault of both kinds, `""` when none) and `not_comparable` (the comparability faults alone,
    the recorded reason; `""` when the stamp was written).
    """
    runs = {label: arm for label, arm in arms.items() if isinstance(arm, Run)}
    absent = [label for label, arm in arms.items() if isinstance(arm, RunAbsent)]
    refused = {label: arm for label, arm in arms.items()
               if isinstance(arm, RunRefused) and not isinstance(arm, RunAbsent)}
    scrub_verified = [label for label in runs if _scrub_ran(runs[label])]
    # An absent arm has no tree, so no scrub verdict records a walk of one.
    unverified = sorted((set(runs) - set(scrub_verified)) | set(absent))
    stamps = {label: _stamp_of(run) for label, run in runs.items()}

    # `blocking`: the comparability faults, which withhold the stamp. `per_world`: faults that
    # are one world's own record and leave the stamp to the rest.
    blocking: list[str] = []
    per_world: list[str] = []
    if not arms:
        blocking.append("the family has no sibling — a comparison over no arm is not one, so "
                        "there is nothing to hold to the source's commit or to archive")
    if unverified:
        per_world.append(
            f"sibling(s) {unverified} have no scrub verdict recording a completed walk — an "
            "unwalked tree is one nothing has certified as free of what the box left behind")
    judged = _family_refusal(
        source, {f"sibling {label!r}": stamps[label] for label in scrub_verified},
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
            episode, {label: stamps[label] for label in archived}, source=source,
            allow_dirty=allow_dirty, waived=judged.waived, base_world_id=base_world_id)
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
    Returns the labels archived.

    `worlds/` exists whatever happens below; a world's own record says why one is missing.
    Every finished world ends archived or with its own `not archived` record — never neither,
    since the judge counts a world it cannot see only through that record (S10, O5). An absent
    arm is among `unverified`."""
    from defender.learning.branch import archive as archive_mod

    episode.worlds.ensure()
    archived: list[str] = []
    for label in sorted(refused):
        per_world.append(f"world {label}'s run folder was refused ({refused[label]})")
        outcome_mod.write_world_record(
            episode, label, outcome_mod.NOT_ARCHIVED,
            detail=f"its run folder was refused, so nothing was read from it: {refused[label]}")
    for label in sorted({*runs, *unverified}):
        if label in unverified:
            outcome_mod.write_world_record(
                episode, label, outcome_mod.NOT_ARCHIVED,
                detail="no scrub verdict records a completed walk of its tree, so it was not "
                       "archived")
            continue
        try:
            archive_mod.archive_episode(episode, {label: runs[label].run_dir})
        except Exception as refusal:  # noqa: BLE001 — one world's archive, recorded; the rest go on
            per_world.append(f"world {label}'s tree could not be archived ({refusal})")
            outcome_mod.write_world_record(
                episode, label, outcome_mod.NOT_ARCHIVED,
                detail=f"the archive refused its finished tree: {refusal}")
            continue
        archived.append(label)
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
    waived: list[str] | None = None, base_world_id: str | None = None,
) -> None:
    """The family's one stamp: what every sibling agreed on, what it was anchored to, and
    whether it was waved through.

    @owns source — the family stamp's `source` key, the source run's whole provenance record as
    `_stamp_of` read it at preflight. Copied verbatim so a waived dirty source shows
    `source.dirty` beside `allow_dirty`, and the archive never reads as anchored to a clean sha.

    @owns waived — the family stamp's `waived` key: the kinds of fault (`DIRT`,
    `UNPROVEN_KNOWLEDGE`) `--allow-dirty` actually waived for this family, from
    `_family_refusal`'s judgement; `[]` when nothing was. `allow_dirty` alone cannot tell a
    dirty-code family from one whose source merely predates the knowledge stamp.

    The agreed record (about the siblings), the source (what they were held to) and the
    override (the operator's flag, and what it waived) are kept separate so a clean family and
    a waived one read differently.
    """
    present = [stamp for stamp in stamps.values() if stamp is not None]
    # Every held field is the agreed record's, since `_family_refusal` passed: the first
    # sibling's value, except where an unknown is its own waived fault — there the agreed value
    # is one a sibling actually named, or `None` when none did. Dirt fields may differ under
    # `--allow-dirty` and here are the first sibling's; each sibling's own is archived in
    # `worlds/<label>/provenance.json`. `verify_family` guarantees at least one sibling.
    agreed = {k: v for k, v in present[0].items() if k != "world_id"}
    for field, rule in _HELD.items():
        if rule.unknown_kind is not None:
            agreed[field] = next(
                (stamp.get(field) for stamp in present if rule.compared(stamp) is not None), None)
    # The family's base world, from the tenant record at the siblings' container (handed in by
    # the launcher from its episode view): no member stamps it, and lessons attribution keys on
    # it.
    doc: dict[str, object] = {
        "agreed": agreed, "allow_dirty": bool(allow_dirty), "source": dict(source),
        "waived": list(waived or [])}
    if base_world_id is not None:
        doc["base_world_id"] = base_world_id
    episode.family_stamp.write(
        json.dumps(doc, indent=2, sort_keys=True) + "\n")
