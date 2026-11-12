"""#1366 R16, O1 (learning): a tenant's lanes are drawn over ITS systems through every production entry, never over a roster
the lane made up for itself.

Two tenants, identical but for one record: A's records lack cmdb, B's hold it, and the product checkout carries a cmdb
adapter and an elastic adapter for both. Each entry below is driven from where production starts it (`lead_author_drain`
with its DEFAULT work steps, over the learning store, #1278; the by-hand `lead_author.main` is gone with #1278 A3), with the
tenant's directory handed in the one way an entry takes it, and what is observed is the scope the author agent is SPAWNED
with (`ctx.systems` of the stage, the lanes its write and `rm` shapes are drawn over). A hop that stops handing the tenant's
records down (the tick to its step, the step to the lane module, `run` to its deps, the pitfalls curator to its spawn)
leaves A and B with the same scope and fails one of them; the hops are not named here, so the test holds whichever way R16
passes the tenant's systems down.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from defender.learning.leads import lead_author_engine
from defender.tests.support.learning.core import _state1135 as S
from defender.tests.support.learning.core._store1278 import call, migrated_database, world  # noqa: F401 — fixtures
from defender.tests.support.runtime.engine._declared869 import pitfall_row, seed_executed_query, seed_tree
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.tenancy.tenant_1108_p4._drain_support import BoxSpy, critical_text, drain_paths, lead_author_drain
from defender.tests.tenancy.tenant_1108_p4.conftest import p4_tenant  # noqa: F401 — fixture `world` is built on

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
    def scope(self) -> tuple[str, ...]:
        assert len(self.scopes) == 1, f"expected the author agent spawned once, got {self.scopes}"
        assert self.scopes[0] is not None, "the agent was spawned with no tenant scope at all (the lanes fell back to the checkout)"
        return self.scopes[0]


@pytest.mark.postgres
@pytest.mark.parametrize("entry", ["drain-lead-author", "drain-pitfalls-curator"])
@pytest.mark.parametrize("tenant", ["a", "b"])
def test_1366_r16_every_entry_draws_the_authors_lanes_over_the_tenants_own_records(world, monkeypatch, caplog, entry, tenant):  # noqa: F811 — the imported fixture
    """One real `lead_author_drain` tick with its default work steps, its claim one run that executed an elastic query (the
    lead author) or two elastic pitfalls (the pitfalls curator): B's spawned lanes hold cmdb, A's do not, elastic (the control)
    is in both. (#1366 R16, O1 learning lanes and pitfalls curator)"""
    whole = R.fixture_records()
    assert {OMITTED, "elastic"} <= set(whole.systems), "fixture premise: the records can hold both systems"
    records = R.without(whole, OMITTED) if tenant == "a" else whole
    w = world
    spawns = _Spawns()
    monkeypatch.setattr(lead_author_engine, "run_author_stage", spawns.stage)  # lint-monkeypatch: ok — the spawn reaches the stage through `_spawn_author_agent`, which offers no seam; the recorder stands where a model would be called
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    paths = drain_paths(w.t, _product(w.scratch / "lanes"))
    if entry == "drain-lead-author":
        run_dir = S.curation_run_dir("run-1")
        seed_executed_query(run_dir, query_id="elastic.newthing", system="elastic", verb="esql")
        call(w.dsn, "enqueue_request", w.t.tenant_id, run_dir.name, "case-1", S.curation_row("case-1", run_dir))
    else:
        for i in range(2):
            call(w.dsn, "add_pitfall", w.t.tenant_id, pitfall_row(f"r:l-00{i}:0", "elastic"))

    assert lead_author_drain(w.t, paths, box=BoxSpy(), directory=w.t.directory_with(records=records)) == 0, critical_text(caplog)

    seen = spawns.scope
    assert "elastic" in seen, seen
    assert PLATFORM_SERVED in seen, seen
    if tenant == "a":
        assert OMITTED not in seen, f"A has no {OMITTED} record, but its author agent was given the lane: {seen}"
    else:
        assert OMITTED in seen, f"B has a {OMITTED} record, but its author agent was not given the lane: {seen}"
