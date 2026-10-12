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

from dataclasses import field
from pathlib import Path
from typing import Annotated, Any

from pydantic import SkipValidation

from defender._io import Bound
from defender._model import model
from defender._vocab import normalized_disposition
from defender.learning.judge import family as family_mod
from defender.learning.judge.calls import inherited_denials
from defender.learning.judge.family import WorldFacts
from defender.learning.judge.pointers import PointerScope


def failed_row(world: dict[str, Any], entry: dict[str, Any]) -> dict[str, Any]:
    """The row of a world O5 counts as failed (N22): an explicit entry built from its own
    record or pre-flight's result — never judged, no bucket, no findings. The record's
    `detail` stays on `failed_world` and out of the reason: it can quote the forged rows."""
    return {"world": world["world_id"],
            "declared": normalized_disposition(world.get("disposition_declared")),
            "ungradable": True, "failed_world": entry,
            "ungradable_reason": f"world {world['world_id']!r}: {entry.get('reason')}"}


@model(frozen=True)
class RunSet:
    """The pass's runs. `usable` holds every run the usability read admitted, the control first
    and then the planted worlds in manifest order; `rows` every world's row as the read left it
    (the control's included); `excluded` the reason each unusable run carries."""

    control: str
    episode_token: str
    usable: Annotated[dict[str, WorldFacts], SkipValidation]
    rows: Annotated[dict[str, dict[str, Any]], SkipValidation]
    excluded: dict[str, str] = field(default_factory=dict)
    #: J3's rows: the request keys of the inherited `∅.denied` rows every usable run's table
    #: carries (A12, A14).
    j3: frozenset[str] = frozenset()

    @property
    def planted(self) -> list[str]:
        """The usable planted worlds, in manifest order: the worlds a pass judges."""
        return [label for label in self.usable if label != self.control]

    def references(self, focus: str) -> list[str]:
        """`focus`'s reference runs (M1): the control, then every other usable planted world."""
        return [label for label in self.usable if label != focus]

    def scope(self, bound: Bound, *, manifest: dict[str, Any], outcome: dict[str, Any] | None,
              samples: dict[str, Any] | None, focus: str | None = None) -> PointerScope:
        """The pointer scope of one call: the focus and its references (world scope, with the
        samples record), or every usable run (`focus=None`: the family call, shown no samples,
        A22)."""
        labels = list(self.usable) if focus is None else [focus, *self.references(focus)]
        return PointerScope(
            bound=bound, episode_token=self.episode_token,
            runs={label: self.usable[label] for label in labels}, manifest=manifest,
            outcome=dict(outcome or {}), samples=None if focus is None else dict(samples or {}),
            j3=self.j3)


def read_run_set(bound: Bound, manifest: dict[str, Any], *, episode_dir: Path,
                 failed: dict[str, dict[str, Any]]) -> RunSet:
    """Every world of `manifest` through the one usability read (`family.read_world`), the
    control included; an O5-failed world gets its failed row and no read."""
    from defender.runtime.branch._family import episode_token_for

    token = episode_token_for(family_mod.episode_id_of(manifest))
    control = family_mod.control_world(manifest)
    worlds = [control, *family_mod.non_control_worlds(manifest)]
    usable: dict[str, WorldFacts] = {}
    rows: dict[str, dict[str, Any]] = {}
    excluded: dict[str, str] = {}
    for world in worlds:
        label = world["world_id"]
        if label in failed:
            rows[label] = failed_row(world, failed[label])
        else:
            rows[label], facts = family_mod.read_world(bound, world, episode_dir=episode_dir,
                                                        episode_token=token)
            if facts is not None:
                usable[label] = facts
                continue
        excluded[label] = str(rows[label].get("ungradable_reason"))
    j3 = inherited_denials((facts.token, facts.table_rows) for facts in usable.values())
    return RunSet(control=control["world_id"], episode_token=token, usable=usable, rows=rows,
                  excluded=excluded, j3=j3)


__all__ = ["RunSet", "failed_row", "read_run_set"]
