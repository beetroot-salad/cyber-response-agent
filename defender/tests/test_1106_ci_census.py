"""#1106 O8 / M7 — CI checks every committed tenant and the template, not one table.

Before #1106 the census gate (`scripts/lint/lint_verb_disposition_census.py`, run by CI with no
arguments) loaded ONE table — `defender/knowledge/environment/verb-grants.yaml` — and compared
it with the walked adapter census. After it there is a table per tenant folder, and M7 makes the
gate iterate every `knowledge/tenants/*/settings` plus `knowledge/tenant-template/settings`:
each must be total over the SHARED adapters (grants describe shared code), each must load, and
each folder's `lead-zero.yaml` must name a template the catalog holds and agree with its table
— a check that today only the run-start path makes (`driver/__init__.py`).

Driven as CI drives it — the real gate script as a subprocess, `--root` a planted, committed
repo — and every red is paired with the green repo it differs from by one row (or one id):
a gate that went red on everything, or checked only the first folder, fails one side.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from defender.tests import _tenants1106 as T
from defender.tests._dispositions995 import planted_tree
from defender.tests._repo import seed_repo

GATE = T.REPO_ROOT / "scripts" / "lint" / "lint_verb_disposition_census.py"

_LEAD = "lead-zero-correlation"
_WHY = "the template grants nothing until an operator decides"

#: Tenant one: total over the planted census, and grants the correlation lead alpha.lookup.
ROWS_ONE: dict[tuple[str, str], dict] = {
    ("alpha", "health-check"): {"roles": ["gather", _LEAD]},
    ("alpha", "lookup"): {"roles": ["gather", _LEAD]},
    ("beta", "health-check"): {"roles": ["gather"]},
    ("beta", "lookup"): {"roles": ["gather"]},
}

#: Tenant two: total, lead withheld (legal: the lead is skipped, not the run).
ROWS_TWO: dict[tuple[str, str], dict] = {
    pair: {"roles": ["gather"]} for pair in ROWS_ONE
}

#: The template: total, and grants nothing (D1).
ROWS_TEMPLATE: dict[tuple[str, str], dict] = {
    pair: {"roles": [], "reason": _WHY} for pair in ROWS_ONE
}


def _table(rows: dict[tuple[str, str], dict]) -> str:
    """A table holding exactly `rows` (a JSON object is a valid YAML flow mapping)."""
    lines = ["dispositions:"]
    for system in sorted({s for s, _ in rows}):
        lines.append(f"  {system}:")
        for (s, verb), body in sorted(rows.items()):
            if s == system:
                lines.append(f"    {verb}: {json.dumps(body)}")
    return "\n".join(lines) + "\n"


def _without(rows: dict[tuple[str, str], dict], pair: tuple[str, str]) -> dict:
    assert pair in rows
    return {k: v for k, v in rows.items() if k != pair}


def _repo(tmp_path: Path, *, one: dict = ROWS_ONE, two: dict = ROWS_TWO,
          template: dict = ROWS_TEMPLATE, one_lead_zero: str = T.CENSUS_LEAD_ZERO_ID,
          extra: tuple[str, ...] = ()) -> Path:
    repo = planted_tree(tmp_path, {"alpha": "lookup", "beta": "lookup"})
    T.plant_census_catalog(repo)
    tenants = repo / "knowledge" / "tenants"
    T.plant_tenant(tenants, "tenant-one", table=_table(one), configs={},
                   lead_zero=T.lead_zero_text(one_lead_zero))
    T.plant_tenant(tenants, "tenant-two", table=_table(two), configs={},
                   lead_zero=T.lead_zero_text(T.CENSUS_LEAD_ZERO_ID))
    T.plant_tenant(repo / "knowledge", "tenant-template", table=_table(template), configs={},
                   lead_zero=T.lead_zero_text(T.CENSUS_LEAD_ZERO_ID))
    for name in extra:
        shutil.copytree(repo / "knowledge" / "tenant-template", tenants / name)
    seed_repo(repo, add="-A", message="tenants")
    return repo


def _gate(repo: Path) -> tuple[int, str]:
    proc = subprocess.run([sys.executable, str(GATE), "--root", str(repo)],
                          capture_output=True, text=True, cwd=T.REPO_ROOT)
    return proc.returncode, proc.stdout + proc.stderr


def test_the_fixture_tables_load_and_the_template_grants_nothing(tmp_path):
    """Guard on the fixtures themselves, through the real loader."""
    vd = T.mod("runtime.verb_dispositions")
    for name, rows in (("one", ROWS_ONE), ("two", ROWS_TWO), ("template", ROWS_TEMPLATE)):
        path = tmp_path / name / "verb-grants.yaml"
        path.parent.mkdir()
        path.write_text(_table(rows), encoding="utf-8")
        assert {(r.system, r.verb) for r in vd.load_dispositions(path)} == set(ROWS_ONE)
    assert not any(r.roles for r in vd.load_dispositions(tmp_path / "template" / "verb-grants.yaml"))


def test_the_gate_is_green_over_every_tenant_and_the_template_and_says_it_looked(tmp_path):
    rc, out = _gate(_repo(tmp_path))
    assert rc == 0, out
    for folder in ("tenant-one", "tenant-two", "tenant-template"):
        assert folder in out, f"the gate did not say it checked {folder}:\n{out}"


def test_a_row_missing_from_one_tenant_turns_the_gate_red_naming_that_tenant(tmp_path):
    rc, out = _gate(_repo(tmp_path, two=_without(ROWS_TWO, ("beta", "lookup"))))
    assert rc != 0, out
    assert "tenant-two" in out, out
    assert "beta.lookup" in out, out


def test_a_row_missing_from_the_template_turns_the_gate_red_naming_the_template(tmp_path):
    rc, out = _gate(_repo(tmp_path, template=_without(ROWS_TEMPLATE, ("alpha", "health-check"))))
    assert rc != 0, out
    assert "tenant-template" in out, out
    assert "alpha.health-check" in out, out


def test_a_lead_zero_naming_no_catalog_template_turns_the_gate_red_naming_the_tenant(tmp_path):
    """M7: the run-start agreement check, run in CI per folder. Tenant one grants the lead
    alpha.lookup and names a template the catalog does not hold."""
    rc, out = _gate(_repo(tmp_path, one_lead_zero="alpha.no-such-template"))
    assert rc != 0, out
    assert "tenant-one" in out, out
    assert "alpha.no-such-template" in out, out


#: A second established catalog template, binding `beta.lookup` — a template that EXISTS but
#: is filed on another pair than the one tenant one grants its lead (`alpha.lookup`).
_BETA_TEMPLATE = T.CENSUS_QUERY_TEMPLATE.replace("alpha.by-entity", "beta.by-entity").replace(
    "Everything alpha knows", "Everything beta knows")


def test_a_lead_zero_naming_an_existing_template_on_another_pair_turns_the_gate_red(tmp_path):
    """M7 runs the AGREEMENT check, not only existence: tenant one's lead-zero names
    `beta.by-entity`, which the catalog holds and which binds `beta.lookup`, while its table
    grants the lead `alpha.lookup`. The control is the green repo, whose lead-zero names the
    template on the granted pair."""
    repo = _repo(tmp_path, one_lead_zero="beta.by-entity")
    beta = repo / "defender" / "skills" / "gather" / "queries" / "beta" / "by-entity.md"
    beta.parent.mkdir(parents=True, exist_ok=True)
    beta.write_text(_BETA_TEMPLATE, encoding="utf-8")
    seed_repo(repo, add="-A", message="beta template")
    rc, out = _gate(repo)
    assert rc != 0, out
    assert "tenant-one" in out, out
    assert "beta.by-entity" in out, out
    assert "alpha.lookup" in out, out


def test_a_new_tenant_copied_from_the_template_keeps_the_gate_green(tmp_path):
    """O8's second half: a freshly copied tenant is CI-clean (it grants nothing, which the run
    refuses at start — C9 — and CI does not)."""
    rc, out = _gate(_repo(tmp_path, extra=("newco",)))
    assert rc == 0, out
    assert "newco" in out, out


def test_the_gate_checks_the_real_repos_tenants_and_template():
    """The no-argument path CI runs: green over the committed tree, and it names the playground
    tenant and the template it covered."""
    proc = subprocess.run([sys.executable, str(GATE)], capture_output=True, text=True,
                          cwd=T.REPO_ROOT)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert T.PLAYGROUND_ID in out, out
    assert "tenant-template" in out, out
