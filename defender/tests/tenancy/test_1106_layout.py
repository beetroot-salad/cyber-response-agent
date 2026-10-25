"""Where tenant settings live: the playground tenant and tenant template resolve through the real resolver, the template grants nothing, and no settings file is readable by the model's read surfaces."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_data_root, location_path

from defender.tests.support.shared._fixture_uuid import fixture_uuid

import shutil
import warnings
from pathlib import Path

from defender.tests.support.tenancy import _tenants1106 as T


def _committed_tenant_dirs() -> list[Path]:
    """The committed knowledge folders that are a tenant's shape and not the template: the
    frozen test fixture (#1120 H2) — the one the CI census walks beside the template."""
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
    """D1. Each row is `roles: []` with a REVIEWABLE reason — the table is total over the
    shared adapters (O8), so it states a decision about every verb, and the decision is no."""
    vd = T.mod("runtime.verb_dispositions")
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
    """O8 / #1108 P4 (N6: adapters stay in the product; skills and markers are the tenant's):
    the template's table is total over the PRODUCT's adapters. The marker half of
    `declared_systems` was read off the product tree's `defender/skills/<system>/execution.md`
    — lab content P4 removes (O1) — and the template's own `agent/` declares no system, so the
    systems walked are the adapter half alone, read from the checkout's adapters directory."""
    from defender._paths import adapters_under
    from defender.runtime.verbs import read_roster

    vd = T.mod("runtime.verb_dispositions")
    roster = read_roster(adapters_under(T.DEFENDER))
    assert roster.accepted, "no adapter read: the census would be vacuous"
    walked = {s: roster.declared_verbs(s) for s in sorted(roster.accepted)}
    gaps = vd.census_gaps(walked, vd.load_dispositions(T.TEMPLATE_SETTINGS / "verb-grants.yaml"))
    assert not gaps, gaps


def test_the_templates_lead_zero_names_an_established_template_in_the_catalog():
    """M1: the template's `lead-zero.yaml` names a catalog template that EXISTS, so an operator
    who grants the lead its pair later has nothing else to fix.

    #1108 P4 (O1, flow 3 "lead-zero (templates from the copy's catalog)"): the catalog a run
    resolves the id against is the TENANT's `agent/skills/gather/queries/`, never the
    checkout's (which P4 empties), so a tenant made from the template finds the id only in the
    template's own `agent/` catalog."""
    from defender.knowledge._corpus import is_established, iter_query_templates

    lz = T.mod("runtime.lead_zero_config")
    template_id = lz.load_correlation_template(lz.lead_zero_config_path(T.TEMPLATE_SETTINGS))
    catalog = T.TEMPLATE_AGENT / "skills" / "gather" / "queries"
    assert [t.id for t in iter_query_templates(catalog)
            if t.id == template_id and is_established(t)] == [template_id]


def test_a_tenant_copied_from_the_template_resolves_and_grants_gather_nothing(tmp_path):
    root = tmp_path / "tenants"
    shutil.copytree(T.TEMPLATE_DIR, root / fixture_uuid("tenant:newco") / "knowledge")
    (root / fixture_uuid("tenant:newco") / "knowledge" / "agent" / ".tenant-id").write_text(f"{fixture_uuid('tenant:newco')}\n", encoding="utf-8")
    T.mod("tenancy._tenant").create_tenant(fixture_data_root(root), fixture_uuid("tenant:newco"))
    td = T.accept(root, fixture_uuid("tenant:newco"))
    grants = T.run_grants(td.settings)
    assert grants.gather.entries == ()
    assert grants.correlation_system is None


def test_every_committed_tenant_and_the_template_loads_its_table_and_lead_zero():
    vd = T.mod("runtime.verb_dispositions")
    lz = T.mod("runtime.lead_zero_config")
    folders = [*(d / "settings" for d in _committed_tenant_dirs()), T.TEMPLATE_SETTINGS]
    assert T.FIXTURE_SETTINGS in folders
    for settings in folders:
        with warnings.catch_warnings():
            warnings.simplefilter("error", vd.DispositionWarning)
            assert vd.load_dispositions(vd.dispositions_path(settings)), settings
        assert lz.load_correlation_template(lz.lead_zero_config_path(settings)), settings


def test_every_committed_tenant_passes_the_resolver(tmp_path):
    """Each committed knowledge folder, placed under a data root as an operator places one, is
    accepted by the real `accept_tenant`, and its settings half is the placed copy."""
    root = tmp_path / "data"
    folders = _committed_tenant_dirs()
    assert folders, "no committed knowledge folder to check"
    for n, folder in enumerate(folders):
        tenant_id = fixture_uuid(f"tenant:committed-{n}")
        shutil.copytree(folder, root / tenant_id / "knowledge")
        (root / tenant_id / "knowledge" / "agent" / ".tenant-id").write_text(
            f"{tenant_id}\n", encoding="utf-8")
        (root / tenant_id / "tenant.json").write_text(
            f'{{"tenant_id": "{tenant_id}", "created_at": "2026-09-28T00:00:00+00:00"}}\n',
            encoding="utf-8")
        td = T.accept(root, tenant_id)
        assert td.settings == root / tenant_id / "knowledge" / "settings"
        assert (td.settings / "verb-grants.yaml").read_bytes() == \
            (folder / "settings" / "verb-grants.yaml").read_bytes()


def _reader_policies(run_dir: Path):
    from defender.runtime.agent_definition import compile_policy_for

    driver = T.mod("runtime.driver")
    return {
        "main": compile_policy_for(driver.MAIN_DEF, run_dir, defender_dir=T.DEFENDER),
        "gather": compile_policy_for(T.fixture_gather_def(), run_dir, defender_dir=T.DEFENDER),
    }


def _settings_files() -> list[Path]:
    files = [p for d in _committed_tenant_dirs() for p in (d / "settings").rglob("*")
             if p.is_file()]
    files += [p for p in T.TEMPLATE_SETTINGS.rglob("*") if p.is_file()]
    return sorted(files)


def test_every_settings_file_is_denied_by_both_read_surfaces_and_a_corpus_file_is_not(tmp_path):
    from defender.runtime import permission
    from defender.runtime.permission.files import read_allowed_path

    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    files = _settings_files()
    names = {p.name for p in files}
    # The census is non-vacuous: every kind is present to be denied.
    assert {"verb-grants.yaml", "lead-zero.yaml", "mapping.yaml", "config.env"} <= names, names
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
