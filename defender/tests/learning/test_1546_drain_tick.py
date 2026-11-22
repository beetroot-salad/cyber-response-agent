"""#1546 (design r8, D7) the drain tick over its input set, three items in ONE tick: the run in the set (pulled by the helper
into the drain root's `<T>/runs/<run id>`, seen through the `runs=` seam) is served; a run that is expired or not `clean` ends `dead("artifact-missing")`; a
`clean` run outside the set (its request filed after the claim fixed the set) WAITS though it is absent from the root, as the
dead ones are. Today every absent run is dead, so only the third separates design from today. Nothing is written into a
source run. Obligations: D7, PR6, A-O6."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.support.jobs._ending1546 import plant_claim, plant_complete_source, plant_uploads  # noqa: E402
from defender.tests.support.evidence._facts1546 import BUNDLE, DRAIN_EXIT_STATUS, UP, up  # noqa: E402
from defender.tests.support.jobs._jobs1342 import job_store  # noqa: E402
from defender.tests.support.learning.core._store1278 import call, migrated_database, world  # noqa: E402, F401 — fixtures
from defender.tests.support.sandbox._spec791 import make_run_dir  # noqa: E402
from defender.tests.support.shared._locations_1210 import location_path  # noqa: E402
from defender.tests.support.shared._postgres1339 import execute  # noqa: E402
from defender.tests.tenancy.tenant_1108_p4._drain_support import BoxSpy, lead_author_drain  # noqa: E402
from defender.tests.tenancy.tenant_1108_p4.conftest import p4_tenant  # noqa: E402, F401 — fixture `world` is built on

pytestmark = pytest.mark.postgres


async def _owner(w, store, *, state: str, scrub: str = "clean") -> str:
    """A finished investigation (a jobs row) of the world's tenant, its accepted bundle, and its curation request."""
    _alert, inv = await plant_complete_source(w.dsn, store, w.t.tenant_id)
    execute(w.dsn, "UPDATE jobs.investigations SET evidence_state = %s, scrub = %s WHERE id = %s", (state, scrub, inv))
    if state != "expired":  # an expired run's objects are gone
        token = plant_claim(w.dsn, tenant=w.t.tenant_id, kind="investigation", ref=inv)
        plant_uploads(w.dsn, token, {BUNDLE: up(UP, scrub)})
        execute(w.dsn, "UPDATE jobs.uploads SET accepted_at = now() WHERE token = %s", (token,))
    return inv


def _request(w, run_id: str) -> None:
    call(w.dsn, "enqueue_request", w.t.tenant_id, run_id, f"case-{run_id}",
         {"case_id": f"case-{run_id}", "tenant_id": w.t.tenant_id, "run_id": run_id})


def _items(w) -> dict:
    return {(i.kind, i.key): i for i in call(w.dsn, "work", w.t.tenant_id)}


def _inputs(w, rid: str) -> list[tuple[str, str]]:
    [(found,)] = execute(w.dsn, "SELECT inputs FROM jobs.claims WHERE kind = 'drain' AND host_request_id = %s", (rid,))
    return sorted((i["owner"], i["object"]) if isinstance(i, dict) else tuple(i) for i in found)


def test_a_drain_tick_serves_the_run_in_its_set_kills_the_expired_and_tainted_and_leaves_the_outside_one_waiting(
        world, monkeypatch):  # noqa: F811 — the imported fixture
    """In one tick: the in-set run (resolved from the drain root, absent from the host folder) is served (handed to the lead step); an expired and a
    tainted run are dead `artifact-missing`; a clean run outside the set waits; the tick's status is the drain's result and
    no marker file is written into the source run. (D7, PR6, A-O6)"""
    from defender.tenancy import JobTenant  # PINNED (jobs design "JobTenant", `inputs` a Path): the run source over the drain root

    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1000")
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1000")
    tenant = world.t.tenant_id
    ids: dict[str, str] = {}

    async def claimed() -> str:
        async with job_store(world.dsn) as store:
            ids["in"] = await _owner(world, store, state="complete")
            ids["expired"] = await _owner(world, store, state="expired")
            ids["tainted"] = await _owner(world, store, state="partial", scrub="tainted")
            for run in ids.values():
                _request(world, run)
            drain = (await store.create_drain(tenant, actor="u-1"))[0]  # SEAM (missing): the operator command (D7)
            assert (await store.claim_host_request()).record.request_id == drain.request_id
            return drain.request_id

    async def filed_after() -> str:
        async with job_store(world.dsn) as store:  # clean, but its request is filed after the claim fixed the set
            outside = await _owner(world, store, state="complete")
        _request(world, outside)
        return outside

    rid = asyncio.run(claimed())
    in_set, expired, tainted = ids["in"], ids["expired"], ids["tainted"]
    assert _inputs(world, rid) == [(in_set, BUNDLE)], "the set is the clean, unexpired runs the open items name"
    outside = asyncio.run(filed_after())

    host_runs = Path(location_path(world.t.tenant.tenant_root)) / "runs"
    root = world.scratch / "drain-root"
    pulled = make_run_dir(root / tenant / "runs", name=in_set, disposition="benign")  # as the helper unpacks the pulled bundle
    assert not (host_runs / in_set).exists(), "premise: the host tenant folder does not hold the run; only the drain root does"
    inputs_dir = world.scratch / "drain-inputs"  # the claim's inputs folder (not the set); the set is what the root holds
    inputs_dir.mkdir()
    runs = JobTenant(id=tenant, data_root=root, inputs=inputs_dir).runs_repository()
    seen: list[str] = []

    def lead(_paths, _state, run, *, on_done, **_kw):
        seen.append(Path(run.run_dir).name)
        on_done(None)

    # SEAM (missing): `lead_author_drain(runs=)`, the only place `_run_of` resolves a run from; the host `world.paths` serves the rest.
    # A run absent from `runs` is dead when its owner is expired or not clean, else it waits (owner state through the #1487 port).
    rc = lead_author_drain(world.t, world.paths, runs=runs, box=BoxSpy(), run_lead_author=lead, run_pitfalls=lambda *_a, **_k: 0)

    assert rc == DRAIN_EXIT_STATUS
    assert seen == [in_set], "only the run in the set is served"
    items = _items(world)
    for gone in (expired, tainted):
        assert (items[("curation_request", gone)].status, items[("curation_request", gone)].reason) == (
            "dead", "artifact-missing"), gone
    assert items[("curation_request", outside)].status == "waiting", "a clean run outside the set was killed, not left for the next drain"
    assert not (pulled / "lead_author").exists(), "a marker was written into the source run"
    assert not list(root.rglob("pitfalls_collected")), "a pitfalls marker file was written"
