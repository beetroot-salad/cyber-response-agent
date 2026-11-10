"""The judge suites' door onto the corpus-author claim (#1278): what the lessons / questioner gate does with the rows
the judge queued, observed as the claim's fates.

Under the file queue a test seeded rows into `_pending/*.jsonl`, ran a tick and read the queue back (pending = held,
consumed = authored). The store's claim hands `drain.run_batch` its items and an `outcomes` map; the gate and the curator
write each item's fate there (`drain._decide_fates` / `_gate_outcome`). This module builds the real lessons / questioner
config over a git-free draft lane (no file-state handle: `LoopPaths` carries no state root) and runs one claim.

Nothing here decides a fate: the real `_gate_findings`, the real config, only the curator's model spawn
(`invoke_agent`) is the caller's double.
"""
from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

from defender.learning.core.config import LoopPaths
from defender.tests.support.learning.curation import _curator1134 as C

#: The store kind of each corpus-author channel's items.
KIND = {"findings": "finding", "questioner_findings": "questioner_finding"}


def gate_lane(tmp_path: Path, *, lanes: tuple[str, ...] = C.AUTHOR_LANES) -> Any:
    """One started batch of the fixture tenant with its git-free draft (`_curator1134.draft_lane` without any state)."""
    from defender.tests.tenancy.tenant_1108_p4._support import published_tenant

    scene = tmp_path / "gate-lane"
    source = C.draft_agent(scene / "agent-source")
    with published_tenant(scene / "forge", root=scene / "data", agent=source) as t:
        batch = t.open_delivery().start_batch("b1", lanes=lanes)
        clone = t.clone
    product = scene / "product"
    product.mkdir(exist_ok=True)
    return C.DraftLane(tmp=scene, clone=clone, batch=batch, paths=LoopPaths(repo_root=product), lanes=tuple(lanes))


def lessons_cfg(lane: Any, **replaced: Any) -> Any:
    """The real lessons config over `lane`'s draft, `replaced` swapped in."""
    from defender.learning.author.lessons import run as lessons_run

    cfg = lessons_run.build_author_config(lane.paths, trees=C.draft_trees(lane), batch=lane.batch)
    return dataclasses.replace(cfg, **replaced) if replaced else cfg


def questioner_cfg(lane: Any, **replaced: Any) -> Any:
    """The real questioner config over `lane`'s draft, `replaced` swapped in."""
    from defender.learning.author.questioner import run as questioner_run

    cfg = questioner_run.build_questioner_config(lane.paths, trees=C.draft_trees(lane), batch=lane.batch)
    return dataclasses.replace(cfg, **replaced) if replaced else cfg


def claim(cfg: Any, rows: list[dict], *, kind: str = "finding") -> tuple[int, dict[tuple[str, str], Any]]:
    """One claim of `rows` (queued as `kind`, keyed by the channel's id): `(rc, outcomes)` of `drain.run_batch`."""
    from defender.learning.author import drain

    items = [(kind, str(r.get(cfg.channel.id_key)), r) for r in rows]
    outcomes: dict[tuple[str, str], Any] = {}
    return drain.run_batch(cfg=cfg, items=items, outcomes=outcomes), outcomes


def fates(outcomes: dict[tuple[str, str], Any]) -> dict[str, tuple[str, str | None]]:
    """`{item key: (fate name, reason)}` for the items the claim named; an item not named stays in its batch (cited)
    or returns to waiting (the tick's citation rule)."""
    return {key: (o.name, o.reason) for (_kind, key), o in outcomes.items()}
