"""#1390 A1: the roster's systems include the platform-served registry wherever a system NAME is read, and its adapter files never do."""
from __future__ import annotations

from defender._git import REPO_ROOT
from defender.learning.leads.declared_systems import declared_systems
from defender.systems.verbs import ModuleVerbRegistry, read_roster
from defender.tests.learning.oracle.live_contracts import _spec1224 as S
from defender.tests.support.tenancy import _tenants1106

ADAPTERS = REPO_ROOT / "defender" / "integrations"
SYSTEM = "tacit-knowledge"


def test_1390_name_consumers_see_the_registry_and_file_consumers_do_not():
    """The roster's systems, the registry's `systems()` and the declared systems name `tacit-knowledge`; `adapter_files` does not. A1."""
    roster = read_roster(ADAPTERS)
    registry = ModuleVerbRegistry(roster, _tenants1106.fixture_grants().gather)

    assert "cmdb" in roster.adapter_files and "cmdb" in roster.verbs, "positive control: an adapter"
    assert SYSTEM in roster.verbs
    assert SYSTEM not in roster.adapter_files
    assert not (ADAPTERS / "tacit_knowledge_adapter.py").exists()
    assert "cmdb" in registry.systems() and SYSTEM in registry.systems()
    declared = declared_systems(REPO_ROOT)
    assert "cmdb" in declared and SYSTEM in declared, (
        "the lead-author lane's declared systems leave out the platform-served registry")


def test_1390_the_opening_prompt_lists_the_registry_among_the_systems_and_not_as_down(tmp_path):
    """The run's opening prompt (workspace map included) lists `tacit-knowledge` beside an adapter system, and neither is down. A1, A4."""
    H = S.replay_harness()
    est = S.TacitEstate(tmp_path / "estate")
    run_dir = H.materialize(tmp_path / "run", H.GOLDEN_AB3, run_id=S.RUN_ID)
    main = H.ReplayFn([H.Turn(text="Investigation complete.")])

    H.drive(run_dir, run_id=S.RUN_ID, main=main, verbs=S.plain_registry(est), tenant=est.place())

    opening = main.seen[0]
    for system in ("idp", SYSTEM):
        assert f"- {system}  (a system dispatched via the query tool" in opening, (
            f"the opening prompt's systems list leaves out {system!r}")
    assert "DOWN for this run" not in opening, "a system was reported down at the run's start"
