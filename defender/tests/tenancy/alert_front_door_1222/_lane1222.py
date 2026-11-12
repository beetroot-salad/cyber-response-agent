"""A started draft lane for the front door's lessons-author scenarios, over the learning store's claim shape (#1278).

`_curator1134.draft_lane` builds its lane's `LoopPaths` from a state folder the learning state handle's deletion
removed; this is its lane without one: the fixture tenant published for real, a started batch, `paths` over the
product checkout. The drain is `drain.run_batch(cfg=, items=, outcomes=)` over the claim's items."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from defender.learning.core.config import LoopPaths
from defender.tests.support.learning.curation import _curator1134 as C


def draft_lane(tmp_path: Path, *, files: dict[str, str | bytes] | None = None) -> C.DraftLane:
    """The fixture tenant published over its own data root (agent content `C.draft_agent(files)`), then the real
    `start_batch("b1", lanes=C.AUTHOR_LANES)`."""
    from defender.tests.tenancy.tenant_1108_p4._support import published_tenant

    scene = tmp_path / f"draft-lane-{next(C._DRAFT_SEQ)}"  # noqa: SLF001 — the sequence the other lanes draw from
    source = C.draft_agent(scene / "agent-source", files)
    with published_tenant(scene / "forge", root=scene / "data", agent=source) as t:
        batch = t.open_delivery().start_batch("b1", lanes=C.AUTHOR_LANES)
        clone = t.clone
    product = scene / "product"
    product.mkdir(parents=True, exist_ok=True)
    return C.DraftLane(tmp=scene, clone=clone, batch=batch, paths=LoopPaths(repo_root=product), lanes=tuple(C.AUTHOR_LANES))


def author_cfg(lane: C.DraftLane, **replaced: Any) -> Any:
    """The real lessons config over `lane` (`batch=lane.batch`), `replaced` swapped in."""
    import dataclasses

    from defender.learning.author.lessons import run as lessons_run

    cfg = lessons_run.build_author_config(lane.paths, trees=C.draft_trees(lane), batch=lane.batch)
    return dataclasses.replace(cfg, **replaced) if replaced else cfg
