"""#1390 A1: the roster's systems include the platform-served registry wherever a system NAME is read, and its adapter files never do."""
from __future__ import annotations

import pytest

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


def test_1390_a_case_record_naming_the_registry_is_refused_as_having_no_adapter():
    """A case mapping that names `tacit-knowledge` is refused in `case_system` as a system with no adapter, not as an adapter lacking the comment action. A1."""
    from types import SimpleNamespace

    from defender.systems.case_system import CaseSettingsFault, judge_case_system

    def refusal(system: str) -> str:
        record = SimpleNamespace(case_record=SimpleNamespace(system=system), access={}, systems={})
        with pytest.raises(CaseSettingsFault) as caught:
            judge_case_system(record, defender_dir=REPO_ROOT / "defender")
        return str(caught.value)

    assert "has no adapter" not in refusal("cmdb"), "control: an adapter without the comment action is refused another way"
    said = refusal(SYSTEM)
    assert "has no adapter" in said and SYSTEM in said, f"refused for another reason: {said}"


def test_1390_the_ceiling_gate_knows_the_registry_and_only_its_two_verbs():
    """The report ceiling gate's closed universe holds `tacit-knowledge.lookup` and `.health-check`, and no other verb of it. A1."""
    from defender.skills.invlang.validate import _ceiling

    assert _ceiling._capability_exists("cmdb.health-check"), "control: an adapter's verb is known"
    for known in (SYSTEM, f"{SYSTEM}.lookup", f"{SYSTEM}.health-check"):
        assert _ceiling._capability_exists(known), f"the gate does not know {known!r}"
    assert not _ceiling._capability_exists(f"{SYSTEM}.wipe")


def test_1390_the_workspace_map_command_lists_the_registry(tmp_path, data_root, capsys):
    """`workspace_map.py` over a launched run lists `tacit-knowledge` among the adapters beside an ordinary system. A1."""
    from defender.cli import workspace_map
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    with B.run_tenant(tmp_path, data_root) as t:
        out = B.launch(t, tmp_path, publish=lambda *a, **k: B.fresh(t.commit))
        assert out.rc == 0, out.text()
        capsys.readouterr()
        rc = workspace_map.main(["workspace_map.py", "--tenant", t.tenant_id, out.run_dir.name], directory=t.directory)
        text = capsys.readouterr().out

    assert rc == 0
    listed = [line for line in text.splitlines() if line.startswith("- ") and "dispatched via the query tool" in line]
    assert any(line.startswith("- cmdb ") for line in listed), f"control: an adapter system is listed: {listed}"
    assert any(line.startswith(f"- {SYSTEM} ") for line in listed), f"the map leaves out {SYSTEM}: {listed}"


_ADAPTER = '''\
from defender.kit.verbs import VerbContext


def check_settings(tenant):
    return None


def health_check(ctx: VerbContext) -> dict:
    return {"system": "SYSTEM"}


VERBS = {"health-check": health_check}
'''


def test_1390_connect_check_registry_names_the_reserved_adapter_with_its_reason(tmp_path):
    """The `/connect` scaffold check fails an adapter file named for `tacit-knowledge`, saying the name is reserved and not that it is anomalous; an ordinary adapter passes. A5."""
    from defender.skills.connect import validate_scaffold as scaffold

    def failures(system: str) -> list[str]:
        tree = tmp_path / system
        (tree / "integrations").mkdir(parents=True)
        (tree / "integrations" / f"{system.replace('-', '_')}_adapter.py").write_text(
            _ADAPTER.replace("SYSTEM", system), encoding="utf-8")
        report = scaffold.Report()
        scaffold.check_registry(report, tree, system)
        return [m for status, m in report.rows if status == scaffold.FAIL and "settings check" not in m]

    assert failures("casesys") == [], "positive control: an ordinary adapter passes"
    said = " ".join(failures(SYSTEM))
    assert "reserved" in said and SYSTEM in said, f"the reserved name is not refused with its reason: {said!r}"
    assert "anomalous adapter name" not in said, f"the refusal reads as a malformed name: {said!r}"
