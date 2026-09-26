"""#1106 — where the settings live now: the committed layout, the template, the read gate and
the bridge (O9, M1, D1, C9, O7, D4).

M1 moves the four settings kinds — each system's `config.env`, `verb-grants.yaml`,
`lead-zero.yaml`, `systems/case-history/mapping.yaml` — out of `defender/knowledge/environment/`
to `knowledge/tenants/playground/settings/` at the REPO ROOT, creates an empty `agent/` half
beside it, and adds `knowledge/tenant-template/` whose table grants NOTHING (D1). Nothing under
`defender/` holds a settings kind afterwards, and `defender/knowledge/` is gone (O9).

That location is also the whole of O7's discharge: the model's read roots are the run dir and
`defender_dir`, and `settings/` now sits under neither — so the gate denies every settings file
by construction rather than by the `.env` substring filter that happened to catch `config.env`
alone (K9). Pinned through the real gate, `decide_read` and the bash lane's
`read_allowed_path`, with a corpus file as the positive control.

D4's bridge: the tenant record a fresh runs base mints says `playground`, not `default`, and an
existing record is read back as written — never remapped.
"""
from __future__ import annotations

import os
import shutil
import warnings
from pathlib import Path

from defender import _git
from defender.tests import _tenants1106 as T
from defender.tests._dispositions995 import (
    CORRELATION_CENSUS,
    GATHER_CENSUS,
    WITHHELD_CENSUS,
)

#: The four settings kinds, by what a census can see: a file's name (and, for the mapping, the
#: folder it sits in).
_SETTINGS_NAMES = ("config.env", "verb-grants.yaml", "lead-zero.yaml")

#: The seven systems that carried a `config.env` before the move — conservation, not a rule:
#: host-state and tacit-knowledge need none, which is why D3 does not require one at start.
_CONFIGURED_SYSTEMS = frozenset({
    "case-history", "change-mgmt", "cmdb", "elastic", "identity", "threat-intel", "ticket",
})


def _is_settings_kind(rel: Path) -> bool:
    return rel.name in _SETTINGS_NAMES or (
        rel.name == "mapping.yaml" and rel.parent.name == "case-history"
    )


def _committed_tenant_dirs() -> list[Path]:
    return sorted(p for p in T.TENANTS_ROOT.iterdir() if p.is_dir())


# =============================================================================================
# O9 — nothing under defender/ holds a settings kind, and defender/knowledge/ is gone.
# =============================================================================================

def test_defender_knowledge_no_longer_exists():
    assert not T.RETIRED_KNOWLEDGE.exists(), (
        f"{T.RETIRED_KNOWLEDGE} still exists — M1 moves `environment/` out and deletes the "
        "whole directory (it held nothing else)"
    )


def test_no_settings_kind_is_tracked_or_on_disk_under_defender():
    """O9's census, over BOTH the index and the working tree: a copy left on disk is as much a
    copy in the box's read-only mount as a tracked one."""
    tracked = [
        Path(p) for p in _git.git(["ls-files", "defender"], cwd=T.REPO_ROOT).splitlines() if p
    ]
    tracked_hits = sorted(str(p) for p in tracked if _is_settings_kind(p))
    on_disk: list[str] = []
    for dirpath, dirnames, filenames in os.walk(T.DEFENDER):
        dirnames[:] = [d for d in dirnames if d not in {".venv", "__pycache__", "node_modules"}]
        for name in filenames:
            rel = (Path(dirpath) / name).relative_to(T.REPO_ROOT)
            if _is_settings_kind(rel):
                on_disk.append(str(rel))
    assert tracked_hits == [], tracked_hits
    assert on_disk == [], on_disk


# =============================================================================================
# M1 — the playground tenant holds the four kinds, moved rather than rewritten.
# =============================================================================================

def test_the_playground_settings_half_holds_the_four_kinds():
    assert (T.PLAYGROUND_SETTINGS / "verb-grants.yaml").is_file()
    assert (T.PLAYGROUND_SETTINGS / "lead-zero.yaml").is_file()
    assert (T.PLAYGROUND_SETTINGS / "systems" / "case-history" / "mapping.yaml").is_file()
    configured = {
        p.parent.name for p in (T.PLAYGROUND_SETTINGS / "systems").glob("*/config.env")
    }
    assert configured == _CONFIGURED_SYSTEMS, configured


def test_the_playground_resolves_through_the_real_resolver():
    td = T.playground_tenant()
    assert td.tenant_id == T.PLAYGROUND_ID
    assert td.settings == T.PLAYGROUND_SETTINGS.resolve()
    assert td.agent == T.PLAYGROUND_AGENT.resolve()


def test_the_moved_table_grants_exactly_what_the_retired_one_did():
    """Conservation across the move: the playground's projection is the census transcribed in
    `_dispositions995.py` before #995 — a move that edited a row would change who may call
    what, silently, under a "rename" commit."""
    grants = T.playground_grants()
    assert {(s, v) for s, v, _ in grants.gather.entries} == set(GATHER_CENSUS)
    assert {(s, v) for s, v, _ in grants.correlation.entries} == set(CORRELATION_CENSUS)
    assert grants.correlation_system == "elastic"
    rows = T.mod("runtime.verb_dispositions").load_dispositions(
        T.PLAYGROUND_SETTINGS / "verb-grants.yaml")
    assert {(r.system, r.verb) for r in rows if not r.roles} == set(WITHHELD_CENSUS)


def test_the_moved_lead_zero_and_mapping_carry_the_retired_values():
    lz = T.mod("runtime.lead_zero_config")
    assert lz.load_correlation_template(lz.lead_zero_config_path(T.PLAYGROUND_SETTINGS)) == \
        T.SHIPPED_CORRELATION_TEMPLATE
    predicate = T.mod("scripts.case_history.case_ticket").release_predicate(T.PLAYGROUND_SETTINGS)
    assert predicate.released_status == "closed"


def test_the_playground_agent_half_exists_and_holds_no_settings_kind():
    """Created empty but for a placeholder (so git keeps it), and it is what the box mounts —
    so a settings file here would be a settings file in every playground run's box (O1)."""
    assert T.PLAYGROUND_AGENT.is_dir()
    hits = [p for p in T.PLAYGROUND_AGENT.rglob("*")
            if p.is_file() and _is_settings_kind(p.relative_to(T.PLAYGROUND_AGENT))]
    assert hits == [], hits


# =============================================================================================
# D1 / C9 — the template grants nothing, loads clean, and a tenant copied from it cannot run.
# =============================================================================================

def test_the_template_has_both_halves_and_the_required_files():
    assert T.TEMPLATE_AGENT.is_dir()
    for rel in T.REQUIRED_FILES:
        assert (T.TEMPLATE_SETTINGS / rel).is_file(), rel


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
    """O8 for the template: its table decides every (system, verb) the real tree declares —
    grants describe SHARED code, so a template missing a row is a template whose copies are
    missing it too."""
    from defender._paths import adapters_under
    from defender.learning.leads.declared_systems import declared_systems
    from defender.runtime.verbs import read_roster

    vd = T.mod("runtime.verb_dispositions")
    roster = read_roster(adapters_under(T.DEFENDER))
    walked = {s: roster.declared_verbs(s) for s in sorted(declared_systems(T.REPO_ROOT))}
    gaps = vd.census_gaps(walked, vd.load_dispositions(T.TEMPLATE_SETTINGS / "verb-grants.yaml"))
    assert not gaps, gaps


def test_the_templates_lead_zero_names_an_established_template_in_the_catalog():
    """M1: the template's `lead-zero.yaml` names a catalog template that EXISTS, so an operator
    who grants the lead its pair later has nothing else to fix."""
    from defender._corpus import is_established, iter_query_templates

    lz = T.mod("runtime.lead_zero_config")
    template_id = lz.load_correlation_template(lz.lead_zero_config_path(T.TEMPLATE_SETTINGS))
    catalog = T.DEFENDER / "skills" / "gather" / "queries"
    assert [t.id for t in iter_query_templates(catalog)
            if t.id == template_id and is_established(t)] == [template_id]


def test_a_tenant_copied_from_the_template_resolves_and_grants_gather_nothing(tmp_path):
    """C9's premise: a copy of the template is a COMPLETE tenant (the resolver takes it) whose
    gather grant is empty — which the run then refuses at start (see
    `e2e/test_1106_run_start.py`). The correlation lead is withheld, which is legal alone."""
    root = tmp_path / "tenants"
    shutil.copytree(T.TEMPLATE_DIR, root / "newco")
    td = T.tenants().tenant_dir(root, "newco")
    grants = T.run_grants(td.settings)
    assert grants.gather.entries == ()
    assert grants.correlation_system is None


# =============================================================================================
# O8 (the committed half) — every committed tenant and the template load.
# =============================================================================================

def test_every_committed_tenant_and_the_template_loads_its_table_and_lead_zero():
    vd = T.mod("runtime.verb_dispositions")
    lz = T.mod("runtime.lead_zero_config")
    folders = [*(d / "settings" for d in _committed_tenant_dirs()), T.TEMPLATE_SETTINGS]
    assert T.PLAYGROUND_SETTINGS in folders
    for settings in folders:
        with warnings.catch_warnings():
            warnings.simplefilter("error", vd.DispositionWarning)
            assert vd.load_dispositions(vd.dispositions_path(settings)), settings
        assert lz.load_correlation_template(lz.lead_zero_config_path(settings)), settings


def test_every_committed_tenant_passes_the_resolver():
    for tenant in _committed_tenant_dirs():
        td = T.tenants().tenant_dir(T.TENANTS_ROOT, tenant.name)
        assert td.settings == (tenant / "settings").resolve()


def test_the_settings_path_helpers_take_the_settings_folder(tmp_path):
    """The two fixed-path constants (`DISPOSITIONS_REL`, `LEAD_ZERO_CONFIG_REL`) gave way to
    helpers over the folder a run resolved — the one place each filename is spelled."""
    vd = T.mod("runtime.verb_dispositions")
    lz = T.mod("runtime.lead_zero_config")
    assert vd.dispositions_path(tmp_path) == tmp_path / "verb-grants.yaml"
    assert lz.lead_zero_config_path(tmp_path) == tmp_path / "lead-zero.yaml"


# =============================================================================================
# O7 — the model cannot read any settings/ file through the host read gate.
# =============================================================================================

def _reader_policies(run_dir: Path):
    from defender.runtime.agent_definition import compile_policy_for

    driver = T.mod("runtime.driver")
    return {
        "main": compile_policy_for(driver.MAIN_DEF, run_dir, defender_dir=T.DEFENDER),
        "gather": compile_policy_for(T.playground_gather_def(), run_dir, defender_dir=T.DEFENDER),
    }


def _settings_files() -> list[Path]:
    files = [p for d in _committed_tenant_dirs() for p in (d / "settings").rglob("*")
             if p.is_file()]
    files += [p for p in T.TEMPLATE_SETTINGS.rglob("*") if p.is_file()]
    return sorted(files)


def test_every_settings_file_is_denied_by_both_read_surfaces_and_a_corpus_file_is_not(tmp_path):
    """Each settings file of every committed tenant and of the template, through the read tool
    (`decide_read`) and the bash operand lane (`read_allowed_path`), for both reader roles — and
    the positive control, a corpus file under `defender/`, through the same gate calls."""
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


# =============================================================================================
# D4 — the bridge: the record mints `playground`, and an existing record is never remapped.
# =============================================================================================

def test_the_default_tenant_id_is_playground():
    assert T.mod("_tenant").DEFAULT_TENANT_ID == "playground"


def test_a_fresh_runs_base_mints_the_playground_tenant(tmp_path):
    tenant = T.mod("_tenant")
    record = tenant.ensure_tenant(tmp_path / "runs")
    assert record.tenant_id == "playground"
    assert tenant.read_tenant(tmp_path / "runs").tenant_id == "playground"


def test_an_existing_default_record_is_read_back_as_written_not_remapped(tmp_path):
    """D4: `default` is not quietly turned into `playground` — it hits D3 at run start, where
    the refusal names the record file (`e2e/test_1106_run_start.py`). The control: a
    `playground` record reads back as `playground`."""
    tenant = T.mod("_tenant")
    T.plant_tenant_record(tmp_path / "legacy", "default")
    assert tenant.ensure_tenant(tmp_path / "legacy").tenant_id == "default"
    T.plant_tenant_record(tmp_path / "current", "playground")
    assert tenant.ensure_tenant(tmp_path / "current").tenant_id == "playground"


def test_no_live_markdown_still_points_at_the_retired_environment_path():
    """The pointers follow the move (K1's markdown census). Several are FUNCTIONAL, not prose:
    `/connect` tells its agent where to write a new system's `config.env` and table rows, and
    each system's `execution.md` tells the model where its config lives — pointing either at a
    folder that no longer exists recreates the settings under `defender/` (O9). `docs/archive`
    is history and stays untouched."""
    hits: list[str] = []
    candidates = [*T.DEFENDER.rglob("*.md"),
                  T.REPO_ROOT / ".claude" / "skills" / "prompt-hygiene" / "SKILL.md"]
    for path in candidates:
        rel = path.relative_to(T.REPO_ROOT)
        if {".venv", "node_modules"} & set(rel.parts) or rel.parts[:3] == ("defender", "docs", "archive"):
            continue
        if path.is_file() and "knowledge/environment" in path.read_text(encoding="utf-8"):
            hits.append(str(rel))
    assert hits == [], hits
