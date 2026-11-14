"""The verb-disposition census gate checks every committed knowledge folder, red on one missing row."""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from defender.tests.support.tenancy import _tenants1106 as T
from defender.tests.support.invlang.validation._dispositions995 import planted_tree
from defender.tests.support.shared.contracts._repo import seed_repo
from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H1120

GATE = T.REPO_ROOT / "tooling" / "lint" / "lint_verb_disposition_census.py"

#: The fixture's table: total over the planted census, and grants the correlation lead
#: alpha.lookup.
ROWS_ONE = H1120.CENSUS_ROWS

#: A table that is total and withholds the lead (legal: the lead is skipped, not the run).
ROWS_TWO: dict[tuple[str, str], dict] = {
    pair: {"roles": ["gather"]} for pair in ROWS_ONE
}

#: The template: total, and grants nothing.
ROWS_TEMPLATE = H1120.CENSUS_TEMPLATE_ROWS


def _without(rows: dict[tuple[str, str], dict], pair: tuple[str, str]) -> dict:
    assert pair in rows
    return {k: v for k, v in rows.items() if k != pair}


def _repo(tmp_path: Path, *, fixture: dict = ROWS_ONE, template: dict = ROWS_TEMPLATE) -> Path:
    """A committed repo declaring alpha and beta, whose two walked knowledge folders
    (`defender/tests/fixtures/tenant-fixture/`, `knowledge/tenant-template/`) hold `fixture` and
    `template`."""
    repo = planted_tree(tmp_path, {"alpha": "lookup", "beta": "lookup"})
    T.plant_census_settings(repo, fixture, template_rows=template)
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


@pytest.mark.parametrize("fault", ["no agent half", "linked settings half"])
def test_a_tenant_the_run_would_refuse_at_start_turns_the_gate_red(tmp_path, fault):
    repo = _repo(tmp_path)
    one = T.committed_folder(repo, "tenant-fixture")
    if fault == "no agent half":
        shutil.rmtree(one / "agent")
    else:
        shutil.rmtree(one / "settings")
        (one / "settings").symlink_to(T.committed_folder(repo, "tenant-template") / "settings")
    rc, out = _gate(repo)
    assert rc != 0, out
    assert "tenant-fixture" in out, out
    assert "a run would refuse this folder" in out, out


def test_a_fixture_with_no_case_file_keeps_the_gate_green(tmp_path):
    """#1359 O2: neither a case-record file nor a case-history folder is required of a tenant."""
    repo = _repo(tmp_path)
    one = T.committed_folder(repo, "tenant-fixture") / "settings"
    shutil.rmtree(one / "systems" / "case-history", ignore_errors=True)
    (one / "case-record.yaml").unlink(missing_ok=True)
    rc, out = _gate(repo)
    assert rc == 0, out


@pytest.mark.parametrize("folder", ["tenant-fixture", "tenant-template"])
def test_1345_a_leftover_malformed_alert_mapping_file_keeps_the_gate_green(tmp_path, folder):
    """The folders hold no `settings/alert-mapping.yaml` and the gate is green; a malformed one left in either is not
    read, so it stays green. (#1345 O5; the template used to be refused without it)"""
    repo = _repo(tmp_path)
    leftover = T.committed_folder(repo, folder) / "settings" / "alert-mapping.yaml"
    assert not leftover.exists()  # premise: the planted folders carry none
    rc, out = _gate(repo)
    assert rc == 0, out
    leftover.write_text("summary: [unclosed\nsignature: {\n", encoding="utf-8")
    seed_repo(repo, add="-A", message="a leftover file")

    rc, out = _gate(repo)

    assert rc == 0, out
    assert "alert-mapping" not in out, out


def test_a_row_missing_from_the_template_turns_the_gate_red_naming_the_template(tmp_path):
    rc, out = _gate(_repo(tmp_path, template=_without(ROWS_TEMPLATE, ("alpha", "health-check"))))
    assert rc != 0, out
    assert "tenant-template" in out, out
    assert "alpha.health-check" in out, out
