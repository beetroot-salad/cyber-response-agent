"""#1366 R16, O1 (learning): a tenant's lanes are drawn over ITS systems through every production entry, never over a roster
the lane made up for itself.

Two tenants, identical but for one record: A's records lack cmdb, B's hold it, and the product checkout carries a cmdb
adapter and an elastic adapter for both. Each entry below is driven from where production starts it (`lead_author_drain`
with its DEFAULT work steps, the by-hand `lead_author.main`), with the tenant's directory handed in the one way an entry
takes it, and what is observed is the scope the author agent is SPAWNED with (`ctx.systems` of the stage, the lanes its
write and `rm` shapes are drawn over). One test, so a hop that stops handing the tenant's records down (the drain to its
step, the step to the lane module, `run` to its deps, the pitfalls curator to its spawn) leaves A and B with the same scope
and fails it; the hops are not named here, so the test holds whichever way R16 passes the tenant's systems down.
"""
from __future__ import annotations

import contextlib
from pathlib import Path
from typing import Any

import pytest

from defender.learning.core import persist
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._locations_1210 import location_path
from defender.learning.leads import lead_author, lead_author_engine
from defender.tests.support.learning.core._state1135 import curation_run_dir, state_for_paths
from defender.tests.support.runtime.engine._declared869 import pitfall_row, seed_executed_query, seed_tree
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.tenancy.tenant_1108_p4._drain_support import BoxSpy, drain_paths, lead_author_drain
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, published_tenant

#: The platform-served system every tenant's roster holds with no adapter file.
PLATFORM_SERVED = "tacit-knowledge"
#: What differs between the two tenants.
OMITTED = "cmdb"


def _product(tmp_path: Path) -> Path:
    """A product checkout whose adapters are cmdb and elastic (a catalog both tenants share) and whose committed markers
    declare neither: the tenant's records are the only thing that can say a tenant has cmdb."""
    return seed_tree(tmp_path, adapters=(OMITTED, "elastic"), markers=(), skills=("elastic",), catalog=("elastic",), name="product")


class _Spawns:
    """Every author-agent spawn of a drive: the stage the spawn reaches is replaced by a recorder (no model is called), which
    answers 0 so the claim goes on as a spawn that changed nothing."""

    def __init__(self) -> None:
        self.scopes: list[tuple[str, ...] | None] = []

    def stage(self, **kw: Any) -> int:
        ctx = kw["ctx"]
        self.scopes.append(None if ctx.systems is None else tuple(sorted(ctx.systems)))
        return 0

    @property
    def scope(self) -> tuple[str, ...] | None:
        assert len(self.scopes) == 1, f"expected the author agent spawned once, got {self.scopes}"
        assert self.scopes[0] is not None, "the agent was spawned with no tenant scope at all (the lanes fell back to the checkout)"
        return self.scopes[0]


def _drain(tmp_path: Path, data_root: Path, tenant_id: str, records: R.RecordsSpec, *, queue: str, monkeypatch: pytest.MonkeyPatch) -> _Spawns:
    """One real `lead_author_drain` tick with its default work steps over a published tenant whose records are `records`; the
    tick's queue holds `queue` ("lead": one run that executed an elastic query; "pitfalls": two elastic pitfalls)."""
    spawns = _Spawns()
    monkeypatch.setattr(lead_author_engine, "run_author_stage", spawns.stage)  # lint-monkeypatch: ok — the spawn reaches the stage through `_spawn_author_agent`, which offers no seam; the recorder stands where a model would be called
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    with published_tenant(tmp_path / "forge", root=data_root, tenant_id=tenant_id) as t:
        bind_forge(t)
        directory = t.directory_with(records=records)
        paths = drain_paths(t, _product(tmp_path))
        location_path(paths.state_root).mkdir(parents=True, exist_ok=True)
        state = state_for_paths(paths)
        if queue == "lead":
            run_dir = curation_run_dir("run-1", tenant_id=t.tenant_id)
            seed_executed_query(run_dir, query_id="elastic.newthing", system="elastic", verb="esql")
            from defender.tests.support.learning.core._state1135 import curation_row

            state.enqueue_curation("case-1", curation_row("case-1", run_dir))
        else:
            persist.append_pitfalls([pitfall_row(f"r:l-00{i}:0", "elastic") for i in range(2)], state=state)
        rc = lead_author_drain(t, paths, box=BoxSpy(), directory=directory)
    assert rc == 0, f"the tick ended {rc}"
    return spawns


def _by_hand(tmp_path: Path, data_root: Path, tenant_id: str, records: R.RecordsSpec, *, monkeypatch: pytest.MonkeyPatch) -> _Spawns:
    """`lead_author.main --tenant T <run_id>` over a published tenant whose records are `records`, for a run that executed an
    elastic query."""
    from defender.tests.support.tenancy._launch_publish_p4 import directory_for_argv

    spawns = _Spawns()
    monkeypatch.setattr(lead_author_engine, "run_author_stage", spawns.stage)  # lint-monkeypatch: ok — see `_drain`
    with published_tenant(tmp_path / "forge", root=data_root, tenant_id=tenant_id) as t:
        run_dir = curation_run_dir("run-1", tenant_id=t.tenant_id)
        seed_executed_query(run_dir, query_id="elastic.newthing", system="elastic", verb="esql")
        location_path(t.tenant.learning).mkdir(exist_ok=True)
        argv = ["--tenant", t.tenant_id, run_dir.name]
        # by hand there is no batch to commit into: the claim is refused after the spawn this test reads
        with contextlib.suppress(LeadAuthorError):
            lead_author.main(argv, directory=directory_for_argv(argv, records=records))
    return spawns


@pytest.mark.parametrize("entry", ["drain-lead-author", "drain-pitfalls-curator", "by-hand-main"])
def test_1366_r16_every_entry_draws_the_authors_lanes_over_the_tenants_own_records(tmp_path, data_root, monkeypatch, entry):
    """A tenant with a cmdb record and the same tenant without get different spawned scopes through each production entry:
    B's lanes hold cmdb, A's do not, elastic (the control) is in both. (#1366 R16, O1 learning lanes and pitfalls curator)"""
    whole = R.fixture_records()
    assert {OMITTED, "elastic"} <= set(whole.systems), "fixture premise: the records can hold both systems"
    seen: dict[str, tuple[str, ...]] = {}
    for name, records in (("a", R.without(whole, OMITTED)), ("b", whole)):
        where = tmp_path / name
        where.mkdir()
        tenant_id = fixture_uuid(f"tenant:lanes-1366-{name}")
        if entry == "by-hand-main":
            spawns = _by_hand(where, data_root, tenant_id, records, monkeypatch=monkeypatch)
        else:
            spawns = _drain(where, data_root, tenant_id, records, queue="lead" if entry == "drain-lead-author" else "pitfalls", monkeypatch=monkeypatch)
        seen[name] = spawns.scope

    for name in ("a", "b"):
        assert "elastic" in seen[name], seen
        assert PLATFORM_SERVED in seen[name], seen
    assert OMITTED not in seen["a"], f"A has no {OMITTED} record, but its author agent was given the lane: {seen['a']}"
    assert OMITTED in seen["b"], f"B has a {OMITTED} record, but its author agent was not given the lane: {seen['b']}"
