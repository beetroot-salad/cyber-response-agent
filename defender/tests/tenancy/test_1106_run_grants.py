"""Permissions are per run: grants are built from the run's own tenant table, so one process can hold two tenants' grants."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests.support.tenancy import _tenants1106 as T


def _pairs(grant) -> set[tuple[str, str]]:
    return {(s, v) for s, v, _ in grant.entries}


def _registry(grant, **kw):
    from defender._paths import adapters_under
    from defender.runtime.verbs import ModuleVerbRegistry, read_roster

    return ModuleVerbRegistry(read_roster(adapters_under(T.DEFENDER)), grant, **kw)


# ---- the value ------------------------------------------------------------------------------

def test_run_grants_projects_the_settings_folders_own_table(tmp_path):
    a = T.place_tenant(tmp_path / "tenants", "acme", table=T.TABLE_A)
    grants = T.run_grants(a / "settings")
    assert Path(grants.path).resolve() == (a / "settings" / "verb-grants.yaml").resolve()
    assert grants.gather.role == "gather"
    assert _pairs(grants.gather) == set(T.GATHER_PAIRS_A)
    assert grants.correlation.role == "lead-zero-correlation"
    assert _pairs(grants.correlation) == set(T.CORRELATION_PAIRS_A)
    assert grants.correlation_system == "elastic"


def test_a_table_that_withholds_the_lead_projects_no_correlation_system(tmp_path):
    b = T.place_tenant(tmp_path / "tenants", "bravo", table=T.TABLE_B)
    grants = T.run_grants(b / "settings")
    assert _pairs(grants.gather) == set(T.GATHER_PAIRS_B)
    assert grants.correlation.entries == ()
    assert grants.correlation_system is None


def test_a_missing_table_refuses_rather_than_projecting_nothing(tmp_path):
    """An absent table is not a deny-all (#995's standing rule) — it raises, naming the file."""
    vd = T.mod("runtime.verb_dispositions")
    settings = tmp_path / "empty" / "settings"
    settings.mkdir(parents=True)
    with pytest.raises(vd.DispositionError) as caught:
        T.run_grants(settings)
    assert str(settings / "verb-grants.yaml") in str(caught.value)


# ---- O3: two tenants, one process ---------------------------------------------------------------

def test_one_process_holds_two_tenants_grants_and_each_admits_exactly_its_own_pairs(tmp_path):
    root = tmp_path / "tenants"
    a = T.place_tenant(root, "acme", table=T.TABLE_A)
    b = T.place_tenant(root, "bravo", table=T.TABLE_B)
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
    a = T.place_tenant(tmp_path / "tenants", "acme", table=T.TABLE_A)
    assert ("cmdb", "get-host") in _pairs(T.run_grants(a / "settings").gather)
    (a / "settings" / "verb-grants.yaml").write_text(T.TABLE_B, encoding="utf-8")
    assert _pairs(T.run_grants(a / "settings").gather) == set(T.GATHER_PAIRS_B)


# ---- M4: no table is read at import ----------------------------------------------------------------


# ---- the refusal names the run's own table ----------------------------------------------------


# ---- the verb context carries the run's tenant record -------------------------------------------


# ---- the operator's audit CLI is an entry point too -------------------------------------------------

def test_the_policy_cli_builds_gathers_policy_from_an_injected_root_and_named_tenant(
        tmp_path, capsys, monkeypatch):
    policy_cli = T.mod("scripts.policy_cli")
    root = tmp_path / "tenants"
    T.place_tenant(root, "acme")
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    base = ["show", "gather", "--run-dir", str(run_dir)]
    assert policy_cli.main([*base, "--tenant", "acme"]) == 0
    assert "agent: gather" in capsys.readouterr().out

    text = ""
    try:
        rc = policy_cli.main([*base, "--tenant", "ghost"])
    except SystemExit as e:
        text = str(e.code)
    except Exception as e:  # noqa: BLE001 — the refusal's text is what is asserted
        text = str(e)
    else:
        assert rc != 0
    text += capsys.readouterr().err
    assert "unrecognized arguments" not in text, text
    assert str(root / "ghost") in text, text


def test_the_policy_cli_refuses_a_tenant_gather_can_query_nothing_under_by_name(
        tmp_path, capsys, monkeypatch):
    import pytest

    policy_cli = T.mod("scripts.policy_cli")
    root = tmp_path / "tenants"
    T.place_tenant(root, "newco", table=T.TABLE_BLANK)
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    with pytest.raises(SystemExit) as caught:
        policy_cli.main(["show", "gather", "--run-dir", str(run_dir), "--tenant", "newco"])
    text = str(caught.value.code)
    assert text.startswith("defender-policy:"), text
    assert "verb-grants.yaml" in text, text
    assert "newco" in text, text


@pytest.mark.parametrize("inside", ["code tree", "runs base"])
def test_a_tenant_folder_inside_a_tree_a_box_mounts_is_refused(tmp_path, inside):
    rt = T.mod("runtime.run_tenant")
    defender_dir = tmp_path / "repo" / "defender"
    runs_base = tmp_path / "runs"
    defender_dir.mkdir(parents=True)
    runs_base.mkdir()
    outside = tmp_path / "tenants"
    T.place_tenant(outside, "acme")
    assert rt.resolve_tenant(outside, "acme", defender_dir=defender_dir,
                             dispatches_lead_zero=False, box_mounted=(runs_base,)).tenant_id == "acme"
    root = (defender_dir if inside == "code tree" else runs_base) / "tenants"
    T.place_tenant(root, "acme")
    with pytest.raises(rt.TenantRefused, match="which a box mounts"):
        rt.resolve_tenant(root, "acme", defender_dir=defender_dir, dispatches_lead_zero=False,
                          box_mounted=(runs_base,))
