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

    assert "cmdb" in roster.adapter_files, "positive control: an adapter"
    assert "cmdb" in roster.verbs, "positive control: an adapter"
    assert SYSTEM in roster.verbs
    assert SYSTEM not in roster.adapter_files
    assert not (ADAPTERS / "tacit_knowledge_adapter.py").exists()
    assert "cmdb" in registry.systems()
    assert SYSTEM in registry.systems()
    declared = declared_systems(REPO_ROOT)
    assert "cmdb" in declared, "the lead-author lane's declared systems leave out the platform-served registry"
    assert SYSTEM in declared, "the lead-author lane's declared systems leave out the platform-served registry"


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


def test_1390_the_opening_prompt_leaves_out_a_registry_the_tenant_did_not_grant(tmp_path):
    """A tenant whose table grants no verb of the registry is not told about it in the run's opening prompt, while its adapters are listed. A3."""
    H = S.replay_harness()
    est = S.Estate(tmp_path / "estate")
    run_dir = H.materialize(tmp_path / "run", H.GOLDEN_AB3, run_id=S.RUN_ID)
    main = H.ReplayFn([H.Turn(text="Investigation complete.")])

    H.drive(run_dir, run_id=S.RUN_ID, main=main, verbs=S.plain_registry(est), tenant=est.place())

    assert "- idp  (a system dispatched via the query tool" in main.seen[0], "control: an adapter is listed"
    assert f"- {SYSTEM}  (a system dispatched" not in main.seen[0], "the map invites a call that can only be denied"


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
    assert "has no adapter" in said, f"refused for another reason: {said}"
    assert SYSTEM in said, f"refused for another reason: {said}"


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


def test_1390_the_workspace_map_command_lists_the_registry_whatever_today_grants(tmp_path, data_root, capsys):
    """The operator's map of a past run lists the registry with all of it withheld today: no record says what that run was granted, so today's table must not hide it. Amendment 6."""
    from defender import _yaml, tenancy
    from defender.cli import workspace_map
    from defender.systems.run_tenant import host_tenant
    from defender.systems.verb_dispositions import dispositions_path
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    with B.run_tenant(tmp_path, data_root) as t:
        out = B.launch(t, tmp_path, publish=lambda *a, **k: B.fresh(t.commit))
        assert out.rc == 0, out.text()
        with host_tenant(tenancy.resolve_data_root(), t.tenant_id, directory=t.directory) as admitted:
            table = dispositions_path(admitted.tenant.settings)
            doc = _yaml.safe_load(table.read_text(encoding="utf-8"))
            assert doc["dispositions"][SYSTEM]["lookup"]["roles"], "premise: the fixture grants it"
            for verb in doc["dispositions"][SYSTEM]:
                doc["dispositions"][SYSTEM][verb] = {"roles": [], "reason": "withheld today"}
            table.write_text(_yaml.safe_dump(doc), encoding="utf-8")
        capsys.readouterr()
        rc = workspace_map.main(["workspace_map.py", "--tenant", t.tenant_id, out.run_dir.name], directory=t.directory)
        captured = capsys.readouterr()

    assert rc == 0, captured.err
    # The skills section lists the page too: only the adapters section's line counts.
    assert f"- {SYSTEM}  (a system dispatched via the query tool" in captured.out, captured.out


def test_1390_the_map_lists_the_registry_only_for_a_grant_that_holds_it():
    """A role holding any verb of the registry is shown it and a role holding none is not; adapters are listed either way, so an ungranted one still gets its "not granted" answer. A3, O-map."""
    from defender.systems.verb_grant import VerbGrant

    roster = read_roster(ADAPTERS)
    holds = VerbGrant("gather", ((SYSTEM, "lookup", "r"),))
    without = VerbGrant("gather", (("cmdb", "query", "r"),))

    assert SYSTEM in roster.systems_shown_to(holds)
    assert SYSTEM not in roster.systems_shown_to(without)
    assert "cmdb" in roster.systems_shown_to(holds), "an adapter the grant leaves out is still listed"
    assert SYSTEM in roster.systems, "the roster itself still names the registry (A1)"


def test_1390_a_declared_set_of_only_platform_names_declares_nothing():
    """Every lead-author and pitfalls guard refuses a tree with no real system, though the registry's name is in every roster; each still admits the registry's paths once a real one exists. A14."""
    from defender.learning.leads.declared_systems import (
        adapter_systems_under,
        declares_no_system,
        with_platform_systems,
    )

    assert SYSTEM not in adapter_systems_under(ADAPTERS), "the adapter half names a system with no adapter"
    assert "cmdb" in adapter_systems_under(ADAPTERS)
    assert declares_no_system(frozenset({SYSTEM}))
    assert not declares_no_system(frozenset({SYSTEM, "cmdb"}))
    widened = with_platform_systems(frozenset({"cmdb"}))
    assert SYSTEM in widened
    assert isinstance(widened, frozenset), "the widened set can be changed by whoever holds it"


def test_1390_the_pitfalls_and_write_lanes_refuse_an_empty_adapters_tree(tmp_path):
    """With no adapter file, the pitfalls lane and the lead author's write scope refuse instead of running with only the registry's name; with one, both also admit the registry. A14."""
    from defender.learning.leads.declared_systems import ADAPTERS_REL, LeadAuthorError
    from defender.learning.leads.lead_author_engine import _systems_or_raise
    from defender.learning.leads.pitfalls_curator import _require_adapter_declared_systems

    empty = tmp_path / "empty"
    (empty / ADAPTERS_REL).mkdir(parents=True)
    with pytest.raises(LeadAuthorError, match="declares no systems"):
        _require_adapter_declared_systems(empty)
    with pytest.raises(ValueError, match="write scope is empty"):
        _systems_or_raise(empty / "defender")

    assert {"cmdb", SYSTEM} <= _require_adapter_declared_systems(REPO_ROOT)
    assert {"cmdb", SYSTEM} <= set(_systems_or_raise(REPO_ROOT / "defender"))


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
    assert "reserved" in said, f"the reserved name is not refused with its reason: {said!r}"
    assert SYSTEM in said, f"the reserved name is not refused with its reason: {said!r}"
    assert "anomalous adapter name" not in said, f"the refusal reads as a malformed name: {said!r}"


def _tenant_folder(tmp_path, *, granted: bool, registry: str | None):
    """A knowledge folder holding only what the registry-against-grant comparison reads."""
    from defender.systems import tacit_registry

    knowledge = tmp_path / "knowledge"
    table = knowledge / "settings" / "verb-grants.yaml"
    table.parent.mkdir(parents=True)
    roles = "[gather]" if granted else "[]"
    table.write_text(
        "dispositions:\n  tacit-knowledge:\n"
        f"    lookup: {{roles: {roles}, reason: test}}\n", encoding="utf-8")
    if registry is not None:
        path = tacit_registry.registry_path(knowledge / "agent")
        path.parent.mkdir(parents=True)
        path.write_text(registry, encoding="utf-8")
    return knowledge


ONE_ENTRY = """entries:
  - id: tk-1390-note
    pattern: rewrite /etc/ssl/certs/ca-bundle.crt
    actor_scope: uid-0
    host_scope: build-runner-*.prod
    added_by: sre-platform@example.invalid
    added_at: 2026-03-01
    review_by: 2026-08-01
    justification: the image build's own ca-trust step
"""


def test_1390_tenant_check_fails_lookup_granted_with_no_registry(tmp_path):
    """`lookup` granted with no file behind it fails `tenant check`, the one check holding both. Amendment 8."""
    from defender.cli.tenant import _registry_grant_findings

    found = _registry_grant_findings(_tenant_folder(tmp_path, granted=True, registry=None))

    assert len(found) == 1, found
    assert "no registry file" in found[0], found


def test_1390_tenant_check_only_notes_entries_with_no_lookup_grant(tmp_path, capsys):
    """Entries nothing consults earn a note, not a failure: a tenant may write them before granting. Amendment 8."""
    from defender.cli.tenant import _registry_grant_findings

    found = _registry_grant_findings(_tenant_folder(tmp_path, granted=False, registry=ONE_ENTRY))

    assert found == []
    assert "not granted `lookup`" in capsys.readouterr().err


def test_1390_tenant_check_is_quiet_when_grant_and_registry_agree(tmp_path, capsys):
    """Positive controls: a granted registry, and an ungranted tenant with an empty one (the template's state), say nothing."""
    from defender.cli.tenant import _registry_grant_findings

    assert _registry_grant_findings(
        _tenant_folder(tmp_path / "a", granted=True, registry=ONE_ENTRY)) == []
    assert _registry_grant_findings(
        _tenant_folder(tmp_path / "b", granted=False, registry="entries: []\n")) == []
    assert capsys.readouterr().err == ""


def test_1390_a_new_tenant_gets_the_registry_and_its_index_line(tmp_path):
    """The template seeds a clean, empty registry and the page gather's index reads, so granting `lookup` is all a new tenant needs for the system to appear. Amendment 8."""
    from defender.hooks.inject_system_skill_description import descriptor_index
    from defender.systems import tacit_registry
    from defender.systems.verb_grant import VerbGrant
    from defender._paths import adapters_under

    agent = REPO_ROOT / "knowledge" / "tenant-template" / "agent"
    read = tacit_registry.read_registry(tacit_registry.registry_path(agent))
    assert not read.absent, read
    assert not read.problems, read
    assert read.entries == (), read

    roster = read_roster(adapters_under(REPO_ROOT / "defender"))
    grant = VerbGrant("gather", ((SYSTEM, "lookup", "r"),))
    index = descriptor_index(agent / "skills", roster, grant).render()
    assert f"`{SYSTEM}`" in (index or ""), index
