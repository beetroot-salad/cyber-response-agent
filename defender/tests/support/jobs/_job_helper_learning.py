"""#1170 (r4): machinery for the helper's learning kinds (learning job, post-step, family-less check): the job's argv, one
driven run of the helper for a kind, the learning end record and the publish-status row, both read at the host."""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from collections.abc import Callable

from defender.tests.support.jobs._job_helper import (
    ContainerStandIn,
    ForgeCredentialRecorder,
    HelperScene,
    drive_helper,
)
from defender.tests.support.shared._postgres1339 import execute

KINDS = ("investigation", "learning", "post-step")


def job_argv(scene: HelperScene, kind: str, job_id: str | None, source: str | None = None) -> list[str]:
    """The helper's argv for `kind`: an investigation is planted as the worker plants it; a learning job names a source
    run; a post-step with no job id is the family-less check."""
    if kind == "investigation":
        assert job_id is not None
        scene.plant(job_id)
    return scene.argv(kind, job_id, source=(source or str(uuid.uuid4())) if kind == "learning" else None)


@dataclass
class KindRan:
    job_id: str | None
    docker: ContainerStandIn
    signer: Any
    forge: ForgeCredentialRecorder
    rc: int | None


def run_kind(  # noqa: PLR0913 — one keyword per thing a case may replace
             scene: HelperScene, kind: str, job: Callable[[Any], int] | None, *, job_id: str | None = None,
             forge: ForgeCredentialRecorder | None = None, signer: Any = None,
             docker: ContainerStandIn | None = None, family_less: bool = False,
             source: str | None = None, **seams: Any) -> KindRan:
    """One helper run for `kind` (`family_less`: a post-step with no job, the tenant's own check). The helper raised
    nothing and the job no error."""
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A

    jid = None if family_less else (job_id or str(uuid.uuid4()))
    assert not family_less or kind == "post-step"
    forge = forge or ForgeCredentialRecorder()
    signer = signer or A.MarkedSigner()
    docker = docker or ContainerStandIn(job)
    ran = drive_helper(scene, job_argv(scene, kind, jid, source), docker=docker, signer=signer, forge=forge, **seams)
    assert ran.raised is None, ran.raised
    assert docker.job_error is None, docker.job_error
    return KindRan(jid, docker, signer, forge, ran.rc)


@dataclass
class PlantedEpisode:
    """A learning job's episode as its pre-flight leaves it: `dir` under `<T>/episodes/`, the `source` run it was made from,
    the learning job's id (`job_id`: the episode's id, `job_entry.py:83`), each manifest label's world id (`worlds`) and the canonical arm run id the roster minted for it (`roster`, by world id)."""

    dir: Path
    source: str
    job_id: str
    worlds: dict[str, str]
    roster: dict[str, str]

    def run_id(self, label: str) -> str:
        return self.roster[self.worlds[label]]


def plant_siblings(scene: HelperScene, source: str | None = None) -> PlantedEpisode:
    """A real episode (`plant_episode`) at the learning job's own id (job id = episode id), whose `--source` is `source`,
    with its arm roster. Run the job with `job_id=planted.job_id`."""
    from defender.tests.storage.ids_1187 import _spec1187 as S
    from defender.tests.support.jobs._learning_container1170 import plant_episode
    from defender.tests.support.learning.branch import _triplet_947 as T

    source = source or str(uuid.uuid4())
    job_id = str(uuid.uuid4())
    ep, _ = plant_episode(scene, job_id, source)
    worlds = {w: T.world_id(ep, w) for w in T.WORLDS}
    roster = dict(S.read_roster(ep))
    return PlantedEpisode(ep, source, job_id, worlds, roster)


def plant_decoy(scene: HelperScene, planted: PlantedEpisode) -> PlantedEpisode:
    """Another episode of the tenant, at an id that is not the job's, made from the job's own `--source`: the one a helper
    that finds the episode by `--source` would pick."""
    return plant_siblings(scene, planted.source)


def learning_end(scene: HelperScene, job_id: str) -> Any:
    """The learning job's end record `<runs>/<job>.learning-end.json` as `LearningEnd`, or None when there is none."""
    from defender.records.job_lane import LearningEnd

    path = scene.runs / f"{job_id}.learning-end.json"
    if not path.exists():
        return None
    parsed = LearningEnd.parse(path.read_text(encoding="utf-8"))
    assert parsed is not None, f"not a learning end record: {path.read_text(encoding='utf-8')!r}"
    return parsed


def publish_status(scene: HelperScene) -> tuple[Any, ...] | None:
    """The tenant's `(published, refused, kind)` row in `tenancy.publish_status`, or None when it has none."""
    rows = execute(scene.dsn, "SELECT published, refused, kind FROM tenancy.publish_status WHERE tenant_id = %s",
                   (scene.tenant,))
    return tuple(rows[0]) if rows else None


def clear_publish_status(scene: HelperScene) -> None:
    execute(scene.dsn, "DELETE FROM tenancy.publish_status WHERE tenant_id = %s", (scene.tenant,))


def listing(folder: Path) -> list[str]:
    return sorted(p.name for p in folder.iterdir()) if folder.is_dir() else []
