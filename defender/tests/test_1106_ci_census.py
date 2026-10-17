"""The verb-disposition census gate checks every committed knowledge folder, red on one missing row."""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from defender.tests import _tenants1106 as T
from defender.tests._dispositions995 import planted_tree
from defender.tests._repo import seed_repo

GATE = T.REPO_ROOT / "scripts" / "lint" / "lint_verb_disposition_census.py"

_LEAD = "lead-zero-correlation"
_WHY = "the template grants nothing until an operator decides"

#: The fixture's table: total over the planted census, and grants the correlation lead
#: alpha.lookup.
ROWS_ONE: dict[tuple[str, str], dict] = {
    ("alpha", "health-check"): {"roles": ["gather", _LEAD]},
    ("alpha", "lookup"): {"roles": ["gather", _LEAD]},
    ("beta", "health-check"): {"roles": ["gather"]},
    ("beta", "lookup"): {"roles": ["gather"]},
}

#: A table that is total and withholds the lead (legal: the lead is skipped, not the run).
ROWS_TWO: dict[tuple[str, str], dict] = {
    pair: {"roles": ["gather"]} for pair in ROWS_ONE
}

#: The template: total, and grants nothing (D1).
ROWS_TEMPLATE: dict[tuple[str, str], dict] = {
    pair: {"roles": [], "reason": _WHY} for pair in ROWS_ONE
}


def _without(rows: dict[tuple[str, str], dict], pair: tuple[str, str]) -> dict:
    assert pair in rows
    return {k: v for k, v in rows.items() if k != pair}


def _repo(tmp_path: Path, *, fixture: dict = ROWS_ONE, template: dict = ROWS_TEMPLATE,
          fixture_lead_zero: str = T.CENSUS_LEAD_ZERO_ID,
          template_lead_zero: str = T.CENSUS_LEAD_ZERO_ID) -> Path:
    """A committed repo declaring alpha and beta, whose two walked knowledge folders
    (`knowledge/tenant-fixture/`, `knowledge/tenant-template/`, #1120 C26) hold `fixture` and
    `template`, each with a `lead-zero.yaml` naming the given id."""
    repo = planted_tree(tmp_path, {"alpha": "lookup", "beta": "lookup"})
    T.plant_census_settings(repo, fixture, template_rows=template)
    for name, lead_zero in (("tenant-fixture", fixture_lead_zero),
                            ("tenant-template", template_lead_zero)):
        (repo / "knowledge" / name / "settings" / "lead-zero.yaml").write_text(
            T.lead_zero_text(lead_zero), encoding="utf-8")
    seed_repo(repo, add="-A", message="knowledge folders")
    return repo


def _gate(repo: Path) -> tuple[int, str]:
    proc = subprocess.run([sys.executable, str(GATE), "--root", str(repo)],
                          capture_output=True, text=True, cwd=T.REPO_ROOT)
    return proc.returncode, proc.stdout + proc.stderr


def test_the_gate_is_green_over_every_tenant_and_the_template_and_says_it_looked(tmp_path):
    rc, out = _gate(_repo(tmp_path))
    assert rc == 0, out
    for folder in ("tenant-fixture", "tenant-template"):
        assert folder in out, f"the gate did not say it checked {folder}:\n{out}"


def test_a_row_missing_from_one_tenant_turns_the_gate_red_naming_that_tenant(tmp_path):
    """The fixture is walked AFTER the template, so a gate that checked only the first folder
    stays green here."""
    rc, out = _gate(_repo(tmp_path, fixture=_without(ROWS_ONE, ("beta", "lookup"))))
    assert rc != 0, out
    assert "tenant-fixture" in out, out
    assert "beta.lookup" in out, out


@pytest.mark.parametrize("fault", ["no agent half", "no mapping", "linked settings half"])
def test_a_tenant_the_run_would_refuse_at_start_turns_the_gate_red(tmp_path, fault):
    """CI checks a folder through the run's own folder rules (`check_knowledge_folder`): a
    folder whose table loads and whose census is total, but which `run.py` refuses at start,
    is not clean. The control is the green test above — the same repo without the fault."""
    repo = _repo(tmp_path)
    one = repo / "knowledge" / "tenant-fixture"
    if fault == "no agent half":
        shutil.rmtree(one / "agent")
    elif fault == "no mapping":
        (one / "settings" / "systems" / "case-history" / "mapping.yaml").unlink()
    else:
        shutil.rmtree(one / "settings")
        (one / "settings").symlink_to(repo / "knowledge" / "tenant-template" / "settings")
    rc, out = _gate(repo)
    assert rc != 0, out
    assert "tenant-fixture" in out, out
    assert "a run would refuse this folder" in out, out


def test_a_row_missing_from_the_template_turns_the_gate_red_naming_the_template(tmp_path):
    rc, out = _gate(_repo(tmp_path, template=_without(ROWS_TEMPLATE, ("alpha", "health-check"))))
    assert rc != 0, out
    assert "tenant-template" in out, out
    assert "alpha.health-check" in out, out


def test_a_withheld_leads_config_naming_no_catalog_template_still_turns_the_gate_red(tmp_path):
    """O8 says each folder's lead-zero names a template the catalog HOLDS — not only when the
    table grants the lead. Here the fixture withholds the lead (the run skips it, so the
    run-start check never consults the id), and its config names a template that does not
    exist: CI is the only place that catches it before an operator grants the lead. Control:
    the default repo, where every folder names the real template, is green (the test above)."""
    rc, out = _gate(_repo(tmp_path, fixture=ROWS_TWO, fixture_lead_zero="alpha.no-such-template"))
    assert rc != 0, out
    assert "tenant-fixture" in out, out
    assert "alpha.no-such-template" in out, out


def test_a_lead_zero_naming_no_catalog_template_turns_the_gate_red_naming_the_tenant(tmp_path):
    """M7: the run-start agreement check, run in CI per folder. The fixture grants the lead
    alpha.lookup and names a template the catalog does not hold."""
    rc, out = _gate(_repo(tmp_path, fixture_lead_zero="alpha.no-such-template"))
    assert rc != 0, out
    assert "tenant-fixture" in out, out
    assert "alpha.no-such-template" in out, out


#: A second established catalog template, binding `beta.lookup` — a template that EXISTS but
#: is filed on another pair than the one the fixture grants its lead (`alpha.lookup`).
_BETA_TEMPLATE = T.CENSUS_QUERY_TEMPLATE.replace("alpha.by-entity", "beta.by-entity").replace(
    "Everything alpha knows", "Everything beta knows")


def test_a_lead_zero_naming_an_existing_template_on_another_pair_turns_the_gate_red(tmp_path):
    """M7 runs the AGREEMENT check, not only existence: the fixture's lead-zero names
    `beta.by-entity`, which the catalog holds and which binds `beta.lookup`, while its table
    grants the lead `alpha.lookup`. The control is the green repo, whose lead-zero names the
    template on the granted pair."""
    repo = _repo(tmp_path, fixture_lead_zero="beta.by-entity")
    beta = repo / "defender" / "skills" / "gather" / "queries" / "beta" / "by-entity.md"
    beta.parent.mkdir(parents=True, exist_ok=True)
    beta.write_text(_BETA_TEMPLATE, encoding="utf-8")
    seed_repo(repo, add="-A", message="beta template")
    rc, out = _gate(repo)
    assert rc != 0, out
    assert "tenant-fixture" in out, out
    assert "beta.by-entity" in out, out
    assert "alpha.lookup" in out, out


