"""The family's runs as one pass reads them: which are usable, which are excluded and why, and
the reference set each judged world is compared against (M1, A3).

Every run — the control and each planted world — goes through the one usability read,
`family.read_world`. A planted world that is O5-failed, cut short, missing an input or malformed
is excluded from every reference set under the reason its own row carries; the control is
required (a control that is not usable stamps the family not graded, which is the pass's call).
The reference set of a planted world is the control and every other usable planted world; the
family call's scope is every usable run.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import field
from pathlib import Path
from typing import Annotated, Any

from pydantic import SkipValidation

from defender._io import Bound
from defender._model import model
from defender._vocab import normalized_disposition
from defender.learning.judge import family as family_mod
from defender.learning.judge.calls import inherited_denials, readable_tables, table_refusals
from defender.learning.judge.family import WorldFacts
from defender.learning.judge.pointers import PointerScope


def failed_row(world: dict[str, Any], entry: dict[str, Any]) -> dict[str, Any]:
    """The row of a world O5 counts as failed (N22): an explicit entry built from its own
    record or pre-flight's result — never judged, no bucket, no findings. The reason quotes the
    record's `detail` whole, as data (the user's record of why); it can quote the forged rows,
    so no prompt reads a failed world's reason — the noise context names failed worlds from
    pre-flight's record without it (`render.render_family_text`, `render.excluded_text`)."""
    detail = entry.get("detail")
    reason = f"world {world['label']!r}: {entry.get('reason')}"
    if isinstance(detail, str) and detail:
        reason += f" — {detail}"
    return {"world": world["label"],
            "declared": normalized_disposition(world.get("disposition_declared")),
            "ungradable": True, "failed_world": entry, "ungradable_reason": reason}


@model(frozen=True)
class RunSet:
    """The pass's runs. `usable` holds every run the usability read admitted, the control first
    and then the planted worlds in manifest order; `rows` every world's row as the read left it
    (the control's included); `excluded` the reason each unusable run carries."""

    control: str
    usable: Annotated[dict[str, WorldFacts], SkipValidation]
    rows: Annotated[dict[str, dict[str, Any]], SkipValidation]
    excluded: dict[str, str] = field(default_factory=dict)
    #: J3's rows: the request keys of the inherited `∅.denied` rows every readable run's table
    #: carries (A12, A14; `calls.readable_tables`).
    j3: frozenset[str] = frozenset()

    @property
    def planted(self) -> list[str]:
        """The usable planted worlds, in manifest order: the worlds a pass judges."""
        return [label for label in self.usable if label != self.control]

    def references(self, focus: str) -> list[str]:
        """`focus`'s reference runs (M1): the control, then every other usable planted world."""
        return [label for label in self.usable if label != focus]

    def scope(self, bound: Bound, *, manifest: dict[str, Any], outcome: dict[str, Any] | None,
              samples: dict[str, Any] | None, focus: str | None = None,
              served_systems: Sequence[str] = ()) -> PointerScope:
        """The pointer scope of one call: the focus and its references (world scope, with the
        samples record), or every usable run (`focus=None`: the family call, shown no samples,
        A22)."""
        labels = list(self.usable) if focus is None else [focus, *self.references(focus)]
        return PointerScope(
            bound=bound,
            run_facts={label: self.usable[label] for label in labels}, manifest=manifest,
            outcome=dict(outcome or {}), samples=None if focus is None else dict(samples or {}),
            j3=self.j3, served_systems=frozenset(served_systems))


def read_run_set(bound: Bound, manifest: dict[str, Any], *, episode_dir: Path,
                 failed: dict[str, dict[str, Any]]) -> RunSet:
    """Every world of `manifest` through the one usability read (`family.read_world`), the
    control included; an O5-failed world gets its failed row and no read. A world whose query
    table's inherited rows differ from the family's (`calls.table_refusals`, A21) is malformed
    whatever its own read says."""
    control = family_mod.control_world(manifest)
    worlds = [control, *family_mod.non_control_worlds(manifest)]
    usable: dict[str, WorldFacts] = {}
    rows: dict[str, dict[str, Any]] = {}
    excluded: dict[str, str] = {}
    edited = table_refusals(bound, manifest)
    for world in worlds:
        label = world["label"]
        if label in failed:
            rows[label] = failed_row(world, failed[label])
        else:
            rows[label], facts = family_mod.read_world(bound, world, episode_dir=episode_dir)
            if facts is not None and label in edited:
                # A table that reads whole but whose inherited rows differ from the family's
                # is a failed read too (A21): only the family's tables together can show it.
                rows[label].update(ungradable=True, malformed=True,
                                   ungradable_reason=edited[label])
                facts = None
            if facts is not None:
                usable[label] = facts
                continue
        excluded[label] = str(rows[label].get("ungradable_reason"))
    # J3's rows are identified over every readable table (A12), not only the usable runs':
    # the found gaps read the same tables, so a row is J3's in every view or in none.
    j3 = inherited_denials(readable_tables(bound, manifest)[0])
    return RunSet(control=control["label"], usable=usable, rows=rows,
                  excluded=excluded, j3=j3)


__all__ = ["RunSet", "failed_row", "read_run_set"]
