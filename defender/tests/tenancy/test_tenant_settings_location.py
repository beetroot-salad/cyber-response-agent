"""Where tenant settings live: the playground tenant and tenant template resolve through the real resolver, the template grants nothing, and no settings file is readable by the model's read surfaces.

Every host-side settings reader reads the injected tenant's folder, never the checkout's.

Permissions are per run: grants are built from the run's own tenant table, so one process can hold two tenants' grants.
"""
from __future__ import annotations

import shutil
import warnings
from pathlib import Path

import pytest

from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.support.tenancy import _tenants1106 as T
from defender.tests.support.runtime.engine._spec767 import write_report
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S
from defender.tests.support.tenancy._launch_publish_p4 import directory_for_argv
from defender.tests.support.shared._locations_1210 import fixture_data_root


def _committed_tenant_dirs() -> list[Path]:
    """The committed knowledge folders that are a tenant's shape and not the template: the
    frozen test fixture — the one the CI census walks beside the template."""
    return [T.FIXTURE]


def test_the_playground_resolves_through_the_real_resolver():
    td = T.fixture_tenant()
    assert td.id == T.PLAYGROUND_ID
    assert td.settings == location_path(td.data_root) / T.PLAYGROUND_ID / "knowledge" / "settings"
    assert td.agent == location_path(td.data_root) / T.PLAYGROUND_ID / "knowledge" / "agent"
    assert (td.settings / "verb-grants.yaml").read_bytes() == \
        (T.FIXTURE_SETTINGS / "verb-grants.yaml").read_bytes()
    assert td.agent.is_dir()


def test_every_template_row_grants_nobody_and_says_why():
    """Each row is `roles: []` with a reviewable reason: the table is total over the shared
    adapters, so it states a decision about every verb, and the decision is no."""
    vd = T.mod("systems.verb_dispositions")
    with warnings.catch_warnings():
        warnings.simplefilter("error", vd.DispositionWarning)
        rows = vd.load_dispositions(T.TEMPLATE_SETTINGS / "verb-grants.yaml")
    assert rows, "an empty table is refused by the loader, not a grant-nothing table"
    granted = [(r.system, r.verb, sorted(r.roles)) for r in rows if r.roles]
    assert granted == [], granted
    for r in rows:
        reason = (r.reason or "").strip()
        assert len(reason.split()) >= 4, f"{r.system}.{r.verb}: {reason!r}"


def test_the_template_table_is_total_over_the_real_adapters():
    """The template's table is total over the roster's systems: the product's adapters and
    the platform-served ones (adapters stay in the product; system skills are the tenant's,
    and the template's own `agent/` declares none)."""
    from defender._paths import adapters_under
    from defender.systems.verbs import read_roster

    vd = T.mod("systems.verb_dispositions")
    roster = read_roster(adapters_under(T.DEFENDER))
    assert roster.adapter_files, "no adapter read: the census would be vacuous"
    assert set(roster.adapter_files) < set(roster.verbs), "no platform-served system on the roster"
    walked = {s: roster.declared_verbs(s) for s in sorted(roster.verbs)}
    gaps = vd.census_gaps(walked, vd.load_dispositions(T.TEMPLATE_SETTINGS / "verb-grants.yaml"))
    assert not gaps, gaps


def test_the_templates_lead_zero_names_an_established_template_in_the_catalog():
    """The template's `lead-zero.yaml` names a template that exists in its own `agent/`
    catalog (the one a run resolves the id against, never the checkout's), so an operator who
    grants the lead its pair later has nothing else to fix."""
    from defender.knowledge._corpus import is_established, iter_query_templates

    lz = T.mod("systems.lead_zero_config")
    template_id = lz.load_correlation_template(lz.lead_zero_config_path(T.TEMPLATE_SETTINGS))
    catalog = T.TEMPLATE_AGENT / "skills" / "gather" / "queries"
    assert [t.id for t in iter_query_templates(catalog)
            if t.id == template_id and is_established(t)] == [template_id]


def test_a_tenant_copied_from_the_template_resolves_and_grants_gather_nothing(tmp_path):
    root = tmp_path / "tenants"
    shutil.copytree(T.TEMPLATE_DIR, root / fixture_uuid("tenant:newco") / "knowledge")
    (root / fixture_uuid("tenant:newco") / "knowledge" / "agent" / ".tenant-id").write_text(f"{fixture_uuid('tenant:newco')}\n", encoding="utf-8")
    td = T.accept(root, fixture_uuid("tenant:newco"))
    grants = T.run_grants(td.settings)
    assert grants.gather.entries == ()
    assert grants.correlation_system is None


def test_every_committed_tenant_and_the_template_loads_its_table_and_lead_zero():
    vd = T.mod("systems.verb_dispositions")
    lz = T.mod("systems.lead_zero_config")
    folders = [*(d / "settings" for d in _committed_tenant_dirs()), T.TEMPLATE_SETTINGS]
    assert T.FIXTURE_SETTINGS in folders
    for settings in folders:
        with warnings.catch_warnings():
            warnings.simplefilter("error", vd.DispositionWarning)
            assert vd.load_dispositions(vd.dispositions_path(settings)), settings
        assert lz.load_correlation_template(lz.lead_zero_config_path(settings)), settings


def _reader_policies(run_dir: Path):
    from defender.investigation.agent_definition import compile_policy_for

    driver = T.mod("investigation.driver")
    return {
        "main": compile_policy_for(driver.MAIN_DEF, run_dir, defender_dir=T.DEFENDER),
        "gather": compile_policy_for(T.fixture_gather_def(), run_dir, defender_dir=T.DEFENDER),
    }


def _settings_files(leftover_tenant: Path) -> list[Path]:
    """Every settings file the model's read surfaces must not reach: the committed fixture's and the
    template's, plus a tenant repo that still holds the retired `systems/<s>/config.env` /
    `access.yaml` and `case-record.yaml` (#1366 O9 / DC8: `import` and `check` still meet those files
    in a tenant's repo and published export, though nothing reads them afterwards; the committed
    fixture no longer carries them, so a planted tenant stands for them)."""
    files = [p for d in _committed_tenant_dirs() for p in (d / "settings").rglob("*")
             if p.is_file()]
    files += [p for p in T.TEMPLATE_SETTINGS.rglob("*") if p.is_file()]
    files += [p for p in (leftover_tenant / "settings").rglob("*") if p.is_file()]
    return sorted(files)


def test_every_settings_file_is_denied_by_both_read_surfaces_and_a_corpus_file_is_not(tmp_path):
    from defender.investigation import permission
    from defender.investigation.permission.files import read_allowed_path

    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    leftover = S.plant(tmp_path / "leftover-root", T.PLAYGROUND_ID, marker="leftover")
    files = _settings_files(leftover)
    names = {p.name for p in files}
    # The census is non-vacuous: every kind is present to be denied.
    assert {"verb-grants.yaml", "lead-zero.yaml", "case-record.yaml", "config.env", "access.yaml"} <= names, names
    control = T.DEFENDER / "skills" / "gather" / "SKILL.md"
    for role, policy in _reader_policies(run_dir).items():
        allowed = [
            str(f) for f in files
            if permission.decide_read(
                f, run_dir=run_dir, defender_dir=T.DEFENDER, policy=policy).allow
            or read_allowed_path(f, run_dir=run_dir, defender_dir=T.DEFENDER, policy=policy)
        ]
        assert allowed == [], f"{role} may read settings: {allowed}"
        assert permission.decide_read(
            control, run_dir=run_dir, defender_dir=T.DEFENDER, policy=policy).allow, role
        assert read_allowed_path(
            control, run_dir=run_dir, defender_dir=T.DEFENDER, policy=policy), role


MARK = "injected"


#: The injected tenant's comment template; the checkout's fixture carries a different one.
INJECTED_BODY = "injected-tenant-body {disposition}"


@pytest.fixture
def injected(tmp_path) -> Path:
    """The injected tenant's settings folder: `<tmp root>/<T>/knowledge/settings`, every value
    carrying `MARK`, its case-record body distinct from the checkout's."""
    root = tmp_path / "injected-root"
    S.plant(
        root, T.PLAYGROUND_ID, table=T.TABLE_B, marker=MARK,
        lead_zero=T.lead_zero_text("elastic.injected-tenant-template"),
        case_body=INJECTED_BODY,
    )
    td = T.accept(root, T.PLAYGROUND_ID)
    assert not td.settings.is_relative_to(T.REPO_ROOT), "the fixture root must be outside"
    return td.settings


def _record(settings: Path):
    """The run record of the accepted tenant whose `settings/` is `settings`
    (`<root>/<id>/knowledge/settings`), through the real `accept_tenant`."""
    knowledge = settings.parent
    return T.run_tenant(T.accept(knowledge.parent.parent, knowledge.parent.name))


def _ctx(settings: Path, run_dir: Path, env: dict | None = None):
    return T.verb_context(T.DEFENDER, run_dir, env if env is not None else {},
                          settings_dir=settings)


# ---- the adapters' config.env ---------------------------------------------------------------------

def test_the_stub_transport_loads_the_injected_tenants_config(injected, tmp_path):
    transport = T.mod("kit.transport")
    ctx = _ctx(injected, tmp_path)
    transport.load_config(ctx, "cmdb", "CMDB")
    base = transport.record_access(ctx.tenant, "cmdb").base
    assert base == f"http://cmdb-{MARK}:8080"  # the injected tenant's declaration
    checkout = _ctx(T.FIXTURE_SETTINGS, tmp_path)
    transport.load_config(checkout, "cmdb", "CMDB")
    assert transport.record_access(checkout.tenant, "cmdb").base != base, \
        "the fixture no longer discriminates"


def test_a_system_with_no_settings_in_the_injected_tenant_is_a_config_fault_naming_it(tmp_path):
    """A record with no settings is a fault naming the system and its required keys, with no folder path and no
    fallback to the fixture's record (retires the folder-file wording). (#1366 O9, DC6)"""
    faults = T.mod("kit.faults")
    transport = T.mod("kit.transport")
    cmdb = T.mod("integrations.cmdb_adapter")
    root = tmp_path / "injected-root"
    T.place_tenant(root, T.PLAYGROUND_ID, configs={})
    settings = T.accept(root, T.PLAYGROUND_ID).settings
    # cmdb is declared, so its missing settings are the one fault left (the declaration is judged first,
    # #1391 r5 S1): an access file with no config.env plants a recorded cmdb with empty settings.
    (settings / "systems" / "cmdb").mkdir(parents=True, exist_ok=True)
    (settings / "systems" / "cmdb" / "access.yaml").write_text(
        T.access_text("noconf", "cmdb"), encoding="utf-8")
    with pytest.raises(faults.ConfigFault) as caught:
        transport.load_config(_ctx(settings, tmp_path), "cmdb", cmdb.PREFIX)
    text = str(caught.value)
    assert "cmdb" in text, text
    for key in cmdb.REQUIRED_CONFIG_KEYS:
        assert f"{cmdb.PREFIX}_{key}" in text, f"the fault does not name {cmdb.PREFIX}_{key}: {text}"
    for retired in ("config.env", "settings/systems"):
        assert retired not in text, f"a record's fault points at a retired folder file: {text}"
    assert str(settings) not in text
    # Control: the fixture tenant's cmdb record does carry settings, so the refusal above is the absence of
    # a fallback, not the absence of a record anywhere.
    assert R.fixture_records().systems["cmdb"].settings
    assert transport.load_config(_ctx(T.FIXTURE_SETTINGS, tmp_path), "cmdb", cmdb.PREFIX)


# ---- the case-record settings ----------------------------------------------------------------


def test_the_record_leg_comments_to_the_injected_tenants_store_with_its_case_record(
        injected, tmp_path):
    """The `--update-ticket` lane: the real record leg, handed the run's record, addresses the
    injected tenant's case store (`ticket/config.env`) and renders the injected tenant's
    case record body (#1366: seeded from its planted `case-record.yaml`), not the fixture's. Replaces the retired `case-history` mapping
    reader tests (#1359 O2: the open leg and `load_case_mapping` are gone)."""
    from defender.tests.tenancy.case_comment_1359 import _spec1359 as C

    run_dir = tmp_path / fixture_uuid("run-1106")
    run_dir.mkdir()
    C.plant_record(run_dir)
    write_report(run_dir)  # a readable report: the injected body renders over it
    proxy = S.ProxyStandIn(tmp_path / "proxy", S.store_answers_ok())
    S.record_step(run_dir, _record(injected), env={}, proxy_url=proxy.url,
                  request_token="write-token-1106")

    posts = [r for r in proxy.requests() if r["method"] == "POST"]
    assert len(posts) == 1, proxy.requests()
    (post,) = posts
    assert post["url"] == f"http://ticket-{MARK}:8080/tickets/{C.TICKET_KEY}/comments", post
    assert "injected-tenant-body" in post["body"]["body"], "the injected case-record body was not sent"
    assert "injected-tenant-body" not in R.FIXTURE_CASE_BODY, "the fixture no longer discriminates"


# ---- lead-zero ---------------------------------------------------------------------------------

def test_the_lead_zero_config_is_read_from_the_injected_tenant(injected):
    lz = T.mod("systems.lead_zero_config")
    assert lz.load_correlation_template(lz.lead_zero_config_path(injected)) == \
        "elastic.injected-tenant-template"
    assert lz.load_correlation_template(lz.lead_zero_config_path(T.FIXTURE_SETTINGS)) != \
        "elastic.injected-tenant-template"


def _pairs(grant) -> set[tuple[str, str]]:
    return {(s, v) for s, v, _ in grant.entries}


def _registry(grant, **kw):
    from defender._paths import adapters_under
    from defender.systems.verbs import ModuleVerbRegistry, read_roster

    return ModuleVerbRegistry(read_roster(adapters_under(T.DEFENDER)), grant, **kw)


# ---- the value ------------------------------------------------------------------------------

def test_run_grants_projects_the_settings_folders_own_table(tmp_path):
    a = T.place_tenant(tmp_path / "tenants", fixture_uuid("tenant:acme"), table=T.TABLE_A)
    grants = T.run_grants(a / "settings")
    assert Path(grants.path).resolve() == (a / "settings" / "verb-grants.yaml").resolve()
    assert grants.gather.role == "gather"
    assert _pairs(grants.gather) == set(T.GATHER_PAIRS_A)
    assert grants.correlation.role == "lead-zero-correlation"
    assert _pairs(grants.correlation) == set(T.CORRELATION_PAIRS_A)
    assert grants.correlation_system == "elastic"


def test_a_table_that_withholds_the_lead_projects_no_correlation_system(tmp_path):
    b = T.place_tenant(tmp_path / "tenants", fixture_uuid("tenant:bravo"), table=T.TABLE_B)
    grants = T.run_grants(b / "settings")
    assert _pairs(grants.gather) == set(T.GATHER_PAIRS_B)
    assert grants.correlation.entries == ()
    assert grants.correlation_system is None


def test_a_missing_table_refuses_rather_than_projecting_nothing(tmp_path):
    """An absent table is not a deny-all (#995's standing rule) — it raises, naming the file."""
    vd = T.mod("systems.verb_dispositions")
    settings = tmp_path / "empty" / "settings"
    settings.mkdir(parents=True)
    with pytest.raises(vd.DispositionError) as caught:
        T.run_grants(settings)
    assert str(settings / "verb-grants.yaml") in str(caught.value)


# ---- two tenants, one process ------------------------------------------------------------------

def test_one_process_holds_two_tenants_grants_and_each_admits_exactly_its_own_pairs(tmp_path):
    root = tmp_path / "tenants"
    a = T.place_tenant(root, fixture_uuid("tenant:acme"), table=T.TABLE_A)
    b = T.place_tenant(root, fixture_uuid("tenant:bravo"), table=T.TABLE_B)
    grants_a = T.run_grants(a / "settings")
    grants_b = T.run_grants(b / "settings")
    again_a = T.run_grants(a / "settings")

    assert _pairs(grants_a.gather) == set(T.GATHER_PAIRS_A)
    assert _pairs(grants_b.gather) == set(T.GATHER_PAIRS_B)
    assert _pairs(again_a.gather) == set(T.GATHER_PAIRS_A)

    reg_a, reg_b = _registry(grants_a.gather), _registry(grants_b.gather)
    assert reg_a.decide("cmdb", "get-host").outcome == "GRANTED"
    assert reg_b.decide("cmdb", "get-host").outcome != "GRANTED"
    assert reg_b.decide("identity", "get-user").outcome == "GRANTED"
    assert reg_a.decide("identity", "get-user").outcome != "GRANTED"
    # Every pair a table grants is granted by its registry, and none of the other's extras.
    for s, v in T.GATHER_PAIRS_A:
        assert reg_a.decide(s, v).outcome == "GRANTED", (s, v)
    for s, v in T.GATHER_PAIRS_B:
        assert reg_b.decide(s, v).outcome == "GRANTED", (s, v)
    for s, v in T.GATHER_PAIRS_A - T.GATHER_PAIRS_B:
        assert reg_b.decide(s, v).outcome != "GRANTED", (s, v)
    for s, v in T.GATHER_PAIRS_B - T.GATHER_PAIRS_A:
        assert reg_a.decide(s, v).outcome != "GRANTED", (s, v)


def test_a_table_edited_between_two_runs_is_read_again(tmp_path):
    """No per-process cache stands between a run and its tenant's file: the same folder, edited
    between two builds in one process, projects the edit."""
    a = T.place_tenant(tmp_path / "tenants", fixture_uuid("tenant:acme"), table=T.TABLE_A)
    assert ("cmdb", "get-host") in _pairs(T.run_grants(a / "settings").gather)
    (a / "settings" / "verb-grants.yaml").write_text(T.TABLE_B, encoding="utf-8")
    assert _pairs(T.run_grants(a / "settings").gather) == set(T.GATHER_PAIRS_B)


# ---- the operator's audit CLI is an entry point too -------------------------------------------------

@pytest.mark.parametrize("agent", sorted(set(T.mod("cli.policy_cli").AGENT_NAMES) - {"gather"}))
def test_the_policy_cli_shows_every_role_that_names_no_tenant(tmp_path, capsys, agent):
    """Every role but gather is shown with no tenant, over a worktree-shaped tree (the authors bind only such a tree): a
    role whose scope a run hands it (the lead author's systems, #1366 R16) is handed what a caller with no tenant hands,
    never left to fail its own policy's build."""
    from defender.tests.support.runtime.engine._declared869 import seed_tree

    policy_cli = T.mod("cli.policy_cli")
    tree = seed_tree(tmp_path, adapters=("cmdb",)) / "defender"
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    corpus = ["--corpus-name", "lessons"] if agent == "corpus_author" else []  # the role's own per-spawn input
    assert policy_cli.main(["show", agent, "--run-dir", str(run_dir), "--defender-dir", str(tree), *corpus]) == 0
    assert f"agent: {agent}" in capsys.readouterr().out


def test_the_policy_cli_builds_gathers_policy_from_an_injected_root_and_named_tenant(
        tmp_path, capsys, monkeypatch):
    policy_cli = T.mod("cli.policy_cli")
    root = tmp_path / "tenants"
    T.place_tenant(root, fixture_uuid("tenant:acme"))
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    base = ["show", "gather", "--run-dir", str(run_dir)]
    acme = [*base, "--tenant", fixture_uuid("tenant:acme")]
    assert policy_cli.main(acme, directory=directory_for_argv(acme)) == 0
    assert "agent: gather" in capsys.readouterr().out

    text = ""
    ghost = [*base, "--tenant", fixture_uuid("tenant:ghost")]
    try:
        rc = policy_cli.main(ghost, directory=directory_for_argv(ghost))
    except SystemExit as e:
        text = str(e.code)
    except Exception as e:  # noqa: BLE001 — the refusal's text is what is asserted
        text = str(e)
    else:
        assert rc != 0
    text += capsys.readouterr().err
    assert "unrecognized arguments" not in text, text
    assert str(root / fixture_uuid("tenant:ghost")) in text, text


def test_the_policy_cli_refuses_a_tenant_gather_can_query_nothing_under_by_name(
        tmp_path, capsys, monkeypatch):
    import pytest

    policy_cli = T.mod("cli.policy_cli")
    root = tmp_path / "tenants"
    T.place_tenant(root, fixture_uuid("tenant:newco"), table=T.TABLE_BLANK)
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    argv = ["show", "gather", "--run-dir", str(run_dir), "--tenant", fixture_uuid("tenant:newco")]
    with pytest.raises(SystemExit) as caught:
        policy_cli.main(argv, directory=directory_for_argv(argv))
    text = str(caught.value.code)
    assert text.startswith("defender-policy:"), text
    assert "verb-grants.yaml" in text, text
    assert fixture_uuid("tenant:newco") in text, text


def test_1366_p4_the_policy_cli_builds_the_tenant_from_its_records_not_its_folder(tmp_path, capsys, monkeypatch):
    """The policy CLI's tenant comes from the tenant's records (design r7 orchestrator bullets: `policy_cli` passes the
    current records to `run_tenant_for`). The planted folder grants gather cmdb and elastic: with the fixture's records
    `show gather` answers; the SAME folder with a tenant imported with no records (so neither granted system is
    recorded: unrecorded systems are not in the tenant, R12) leaves gather nothing to query and the CLI refuses naming
    both grants, as a run does, not the import (the tenant is imported). A CLI reading the folder would answer in both.
    (#1366 P4, R10, R12)"""
    policy_cli = T.mod("cli.policy_cli")
    root = tmp_path / "tenants"
    T.place_tenant(root, fixture_uuid("tenant:acme"), table=T.TABLE_A)
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    argv = ["show", "gather", "--run-dir", str(run_dir), "--tenant", fixture_uuid("tenant:acme")]

    assert policy_cli.main(argv, directory=directory_for_argv(argv, records=R.fixture_records())) == 0
    assert "agent: gather" in capsys.readouterr().out

    with pytest.raises(SystemExit) as caught:
        policy_cli.main(argv, directory=directory_for_argv(argv, records=R.RecordsSpec()))
    text = str(caught.value.code)
    assert text.startswith("defender-policy:"), text
    assert all(system in text for system in ("cmdb", "elastic")), text
    assert R.AUTHOR[R.IMPORT] not in text, text


@pytest.mark.parametrize("inside", ["code tree", "runs base"])
def test_a_tenant_folder_inside_a_tree_a_box_mounts_is_refused(tmp_path, inside):
    rt = T.mod("systems.run_tenant")
    defender_dir = tmp_path / "repo" / "defender"
    runs_base = tmp_path / "runs"
    defender_dir.mkdir(parents=True)
    runs_base.mkdir()
    outside = tmp_path / "tenants"
    T.place_tenant(outside, fixture_uuid("tenant:acme"))
    assert R.resolve_tenant(fixture_data_root(outside), fixture_uuid("tenant:acme"), defender_dir=defender_dir,
                             dispatches_lead_zero=False, box_mounted=(runs_base,)).tenant_id == fixture_uuid("tenant:acme")
    root = (defender_dir if inside == "code tree" else runs_base) / "tenants"
    T.place_tenant(root, fixture_uuid("tenant:acme"))
    with pytest.raises(rt.TenantRefused, match="which a box mounts"):
        R.resolve_tenant(fixture_data_root(root), fixture_uuid("tenant:acme"), defender_dir=defender_dir, dispatches_lead_zero=False,
                         box_mounted=(runs_base,))
