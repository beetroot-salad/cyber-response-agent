"""#1546 sketch (r6), "Readiness / adoption" (D5; A-O2, A-O9, PR4): the worker finishes a host request from the
`result` (and readiness `knowledge`) facts the helper staged under the request's claim, never from a file; the
readiness container gets only the allowlisted binds and writes no result file.

Worker cases: `_host_requests1471.host_worker` with a `HostChild` that leaves contradicting files, wrapped so that,
after the claim, the facts are staged by SQL under the claim row naming the request.
Helper case: `_readiness1471.readiness` (the real helper, the real `readiness_main` as the container's process).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests.evidence_1546._support import facts, insert_claim, job_inputs, job_root, stage_fact
from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.jobs import _worker1342 as _shared
from defender.tests.support.jobs._host_requests1471 import (
    ADOPTION,
    COMMIT,
    FRESH_SERVED,
    KNOWLEDGE,
    READINESS,
    STALE_OPERATOR,
    adopted,
    failed,
    host_child,
    host_row,
    host_worker,
    plant,
)
from defender.tests.support.jobs._jobs1342 import T1, job_store
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]
world = _shared.world
_no_database_address_in_the_workers_environment = _shared._no_database_address_in_the_workers_environment
process_state = J.process_state


class Staging:
    """`readiness_argv`/`adoption_argv`: after the claim, stage `staged` facts under the request's claim token (read
    off `jobs.claims`), then run `child` (which leaves its contradicting files)."""

    def __init__(self, child, staged: dict) -> None:
        self.child, self.staged, self.token, self.dsn = child, staged, None, ""

    def __call__(self, launch) -> list[str]:
        dsn = self.dsn
        [(self.token,)] = execute(dsn, "SELECT token FROM jobs.claims WHERE host_request_id = %s", (launch.request_id,))
        for name, body in self.staged.items():
            stage_fact(dsn, self.token, name, body)
        return self.child(launch)


async def _run(world, kind: str, files: dict, staged: dict):
    child = host_child(world, files=files)
    staging = Staging(child, staged)
    staging.dsn = world["dsn"]
    async with job_store(world["dsn"]) as store:
        rec, _ = await (store.create_readiness(T1, actor="u-1") if kind == "readiness"
                        else store.create_adoption(T1, "ticket", actor="u-1"))
        await host_worker(world, store, staging).drain()
    return host_row(world["dsn"], rec.request_id)


async def test_a_readiness_request_finishes_from_its_staged_result_and_knowledge_not_its_files(world):
    """Staged: result `ready` with no warnings, knowledge `current` at COMMIT. The child leaves a `failed` readiness
    record and a stale knowledge record in the runs folder. The row completes from the rows. (D5, A-O2, PR4)
    FORCED CHOICE: the `result` fact's shape: today's `ReadinessRecord` as parsed (`outcome`, `warnings`, a refusal's
    `step`/`sentence`) vs the row's `result` (which also folds in the knowledge status). Picked: the record's shape."""
    stored = await _run(world, "readiness",
                        {READINESS: failed("handover"), KNOWLEDGE: STALE_OPERATOR},
                        {"result": {"outcome": "ready", "warnings": []},
                         "knowledge": {"kind": "fresh", "commit": COMMIT, "stale_kind": None, "reason": None}})
    assert (stored["stage"], stored["failure_reason"]) == ("completed", None), stored
    assert stored["result"] == {"outcome": "ready", "knowledge": FRESH_SERVED, "warnings": []}


async def test_an_adoption_request_finishes_from_its_staged_result_not_its_file(world):
    """Staged: `opened` PR 7; the child's file says `nothing_to_adopt`. The row completes `opened`, 7. (D5, A-O2)"""
    import json

    stored = await _run(world, "adoption", {ADOPTION: adopted("nothing_to_adopt")},
                        {"result": json.loads(adopted("opened", 7))})
    assert (stored["stage"], stored["result"]) == ("completed", {"outcome": "opened", "pr_number": 7}), stored


def test_a_readiness_container_gets_only_allowlisted_binds_and_stages_its_result(tmp_path, monkeypatch,
                                                                                 migrated_database):
    """The real helper and container entry for a readiness check: its binds are its own root (rw, at its own path),
    its inputs folder (ro, holding the knowledge copy), the code tree (ro) and its socket folder; none names the
    tenant folder or another claim. Its result arrives as the staged `result` fact; no `<rid>.readiness.json` is
    written anywhere under the tenant folder. (A-O9, D5)
    FORCED CHOICE: the claim row the helper stages under must exist first (FK); r6 says the worker's claim
    transaction inserts it, so a helper run outside a worker (this harness, the operator) needs one planted. The
    case plants it; write-tests needs a harness that claims through the store."""
    from defender.tests.support.jobs._readiness1471 import readiness, readiness_scene

    with readiness_scene(tmp_path, monkeypatch, migrated_database) as scene:
        rid = plant(scene.dsn, scene.tenant, "readiness", stage="running")
        insert_claim(scene.dsn, token=scene.claim, tenant=scene.tenant, kind="readiness", ref=rid)
        ran = readiness(scene, rid=rid)
        assert ran.docker.boxes, ran.said()
        box = ran.docker.boxes[0]
        seen = {"mounts": box.mounts, "env": box.env}
        tenant_dir = scene.runs.parent
        mounts = seen["mounts"]
        root, inputs = job_root(scene.root, scene.claim), job_inputs(scene.root, scene.claim)
        by_source = {m["source"]: m for m in mounts}
        assert by_source[str(root)]["target"] == str(root) and not by_source[str(root)]["readonly"]
        assert by_source[str(inputs)]["readonly"]
        for m in mounts:
            source = m["source"]
            assert not Path(source).is_relative_to(tenant_dir), f"a bind names the tenant folder: {m}"
        assert seen["env"].get("DEFENDER_DATA_ROOT") == str(root)
        staged = facts(scene.dsn, scene.claim)
        assert staged.get("result", {}).get("outcome") == "ready", staged
        assert list(tenant_dir.rglob(f"{rid}.readiness.json")) == []
