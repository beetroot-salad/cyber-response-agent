"""D1's owner lint, D9's fixture and census lint, O10, M10's docs, N11's build context."""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import textwrap
import uuid
from pathlib import Path

import pytest

from defender.cli import tenant as tenant_py
from defender.tests.support.invlang.validation import _dispositions995 as D995
from defender.tests.support.shared.contracts import _spec1077 as S
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender.tests.support.shared.contracts._by_path import LINT_DIR, load_lint_gate
from defender.tests.support.shared.contracts._repo import seed_repo
from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H

REPO = H.REPO_ROOT
DEFENDER = H.DEFENDER

#: `tooling/lint/lint_verb_disposition_census.py`, run as CI runs it (a process).
lint_verb_disposition_census = LINT_DIR / "lint_verb_disposition_census.py"

JOIN_FINDING = "literal-free join onto an owner-derived value"


def _lint_run_records():
    """`tooling/lint/lint_run_records.py`, a fresh copy, reached the way CI reaches it."""
    lint_run_records = load_lint_gate("lint_run_records",
                                      name=f"lint_run_records_1120_{uuid.uuid4().hex}")
    return lint_run_records


def _scan_planted(tmp_path: Path, rel: str, source: str) -> list[str]:
    """`lint_run_records.scan` over a tmp tree holding exactly one planted module — the
    findings' display lines."""
    lint_run_records = _lint_run_records()
    S.plant(tmp_path, rel, source)
    return [f.display for f in lint_run_records.scan(tmp_path)]


def _in(displays: list[str], fn: str) -> list[str]:
    return [d for d in displays if f" {fn}(): " in d]


def _census(root: Path) -> tuple[int, str]:
    """`lint_verb_disposition_census.py --root <root>`: exit status and output."""
    proc = subprocess.run(  # noqa: S603 — fixed argv, the test's own interpreter
        [sys.executable, str(lint_verb_disposition_census), "--root", str(root)],
        capture_output=True, text=True, cwd=str(REPO), timeout=300, check=False)
    return proc.returncode, proc.stdout + proc.stderr


#: Tenant's data-root record locations (D1's lint sentence), each joined literal-free.
RECORD_LOCATIONS = ("tenant_root", H.ROW_PATH_PROPERTY, "runs", "sessions", "episodes", "learning",
                    "worktrees")

#: The knowledge-half attributes whose owning loaders must stay lint-clean, joined in exactly
KNOWLEDGE_JOINS = ("settings", "knowledge", "agent")

#: The settings-half loaders that survive piece 1 unchanged (profile resource
SETTINGS_LOADER_MODULES = (
    "runtime/verb_dispositions.py", "runtime/lead_zero_config.py", "runtime/run_tenant.py",
    "runtime/case_ticket.py", "integrations/elastic_adapter.py",
    "integrations/_stub_transport.py", "learning/branch/estate/stagers/elastic.py",
    "learning/branch/staging.py", "skills/connect/validate_scaffold.py",
)


@pytest.mark.gate
def test_1120_run_records_lint_owns_tenant_record_locations_but_not_knowledge_settings_or_agent(
        tmp_path: Path) -> None:
    joins = "".join(
        f"def join_{prop}(tenant: Tenant, name: str) -> Path:\n"
        f"    return tenant.{prop} / name\n\n" for prop in RECORD_LOCATIONS)
    clean = "".join(
        f"def join_{prop}(tenant: Tenant, name: str) -> Path:\n"
        f"    return tenant.{prop} / name\n\n" for prop in KNOWLEDGE_JOINS)
    source = (
        "from pathlib import Path\n\n"
        "from defender.episodes._episode_paths import EpisodePaths\n"
        "from defender.tenancy._tenant import Tenant\n\n\n"
        f"{joins}{clean}"
        f"def row_only(tenant: Tenant) -> Path:\n    return tenant.{H.ROW_PATH_PROPERTY}\n\n"
        "def control(ep: Path, run_id: str) -> Path:\n"
        "    return EpisodePaths(ep).runs / run_id\n")
    displays = _scan_planted(tmp_path, "runtime/tenant_joins.py", source)
    assert _in(displays, "control"), f"the join arm is not live:\n{displays}"
    unflagged = [p for p in RECORD_LOCATIONS
                 if not any("owner-only record location" in d for d in _in(displays, f"join_{p}"))]
    assert unflagged == [], (
        f"a literal-free join onto Tenant.{unflagged} is not owner-derived to the lint:\n"
        + "\n".join(displays))
    flagged_clean = {fn: _in(displays, fn)
                     for fn in (f"join_{p}" for p in KNOWLEDGE_JOINS)
                     if _in(displays, fn)}
    assert flagged_clean == {}, (
        f"joins onto settings/knowledge/agent (or a bare row read) are reported: {flagged_clean}")

    assert any("owner-only record location" in d for d in _in(displays, "row_only"))

    real = [f.display for f in _lint_run_records().scan(DEFENDER)]
    in_loaders = [d for d in real if d.split(":", 1)[0] in SETTINGS_LOADER_MODULES]
    assert in_loaders == [], f"the settings loaders gained run-records findings: {in_loaders}"


def test_1120_run_records_lint_tags_accept_tenant_locals_and_run_tenant_chains(
        tmp_path: Path) -> None:
    call = 'accept_tenant(root, "acme", defender_dir=root, box_mounted=())'
    source = textwrap.dedent(f"""\
        from pathlib import Path

        from defender.episodes._episode_paths import EpisodePaths
        from defender.tenancy._tenant import accept_tenant
        from defender.runtime.run_tenant import RunTenant


        def local_runs(root: Path, run_id: str) -> Path:
            t = {call}
            return t.runs / run_id


        def call_runs(root: Path, run_id: str) -> Path:
            return {call}.runs / run_id


        def chain_learning(run_tenant: RunTenant, name: str) -> Path:
            return run_tenant.tenant.learning / name


        def local_settings(root: Path, name: str) -> Path:
            t = {call}
            return t.settings / name


        def local_knowledge(root: Path, name: str) -> Path:
            t = {call}
            return t.knowledge / name


        def local_agent(root: Path, name: str) -> Path:
            t = {call}
            return t.agent / name


        def call_settings(root: Path, name: str) -> Path:
            return {call}.settings / name


        def chain_settings(run_tenant: RunTenant, name: str) -> Path:
            return run_tenant.tenant.settings / name


        def chain_agent(run_tenant: RunTenant, name: str) -> Path:
            return run_tenant.tenant.agent / name


        def run_tenant_settings(run_tenant: RunTenant, name: str) -> Path:
            return run_tenant.settings / name


        def control(ep: Path, run_id: str) -> Path:
            return EpisodePaths(ep).runs / run_id
        """)
    displays = _scan_planted(tmp_path, "runtime/factory_joins.py", source)
    assert _in(displays, "control"), f"the join arm is not live:\n{displays}"
    untagged = [fn for fn in ("local_runs", "call_runs", "chain_learning")
                if not any("owner-only record location" in d for d in _in(displays, fn))]
    assert untagged == [], (
        f"these record-location joins escape the lint (M5 tagging): {untagged}\n"
        + "\n".join(displays))
    clean = ("local_settings", "local_knowledge", "local_agent", "call_settings",
             "chain_settings", "chain_agent", "run_tenant_settings")
    flagged = {fn: _in(displays, fn) for fn in clean if _in(displays, fn)}
    assert flagged == {}, f"knowledge-half joins are reported: {flagged}"


_LEAD = "lead-zero-correlation"
_WHY = "the template grants nothing until an operator decides"

#: A total table over the planted census (alpha.lookup, beta.lookup and their health-checks),
GRANTED_ROWS: dict[tuple[str, str], dict] = {
    ("alpha", "health-check"): {"roles": ["gather", _LEAD]},
    ("alpha", "lookup"): {"roles": ["gather", _LEAD]},
    ("beta", "health-check"): {"roles": ["gather"]},
    ("beta", "lookup"): {"roles": ["gather"]},
}
TEMPLATE_ROWS = {pair: {"roles": [], "reason": _WHY} for pair in GRANTED_ROWS}


def _table(rows: dict[tuple[str, str], dict]) -> str:
    import json
    lines = ["dispositions:"]
    for system in sorted({s for s, _ in rows}):
        lines.append(f"  {system}:")
        lines.extend(f"    {verb}: {json.dumps(body)}"
                     for (s, verb), body in sorted(rows.items()) if s == system)
    return "\n".join(lines) + "\n"


def _planted_repo(tmp_path: Path, *, fixture_rows: dict = GRANTED_ROWS,
                  template_rows: dict = TEMPLATE_ROWS,
                  lab_rows: dict | None = None, broken_lab: bool = False,
                  systems: dict[str, str] | None = None) -> Path:
    """A committed synthetic repo (`_dispositions995.planted_tree`) declaring `systems`, with the lead-
    zero catalog template, a template folder and a fixture folder — plus, on request, a lab under
    knowledge/tenants/ (`lab_rows`) or a broken one (`broken_lab`)."""
    repo = D995.planted_tree(tmp_path, systems or {"alpha": "lookup", "beta": "lookup"})
    T1106.plant_census_catalog(repo)
    lead_zero = T1106.lead_zero_text(T1106.CENSUS_LEAD_ZERO_ID)
    T1106.plant_tenant(repo / "knowledge", "tenant-template", table=_table(template_rows),
                       configs={}, lead_zero=lead_zero)
    T1106.plant_tenant(repo / "knowledge", "tenant-fixture", table=_table(fixture_rows),
                       configs={}, lead_zero=lead_zero)
    if lab_rows is not None:
        T1106.plant_tenant(repo / "knowledge" / "tenants", "playground", table=_table(lab_rows),
                           configs={}, lead_zero=lead_zero)
    if broken_lab:
        T1106.plant_tenant(repo / "knowledge" / "tenants", "x", configs={},
                           lead_zero=lead_zero, omit=("verb-grants.yaml",))
    seed_repo(repo, add="-A", message="tenants")
    return repo


def _clean_names(out: str) -> set[str]:
    return set(re.findall(r"lint_verb_disposition_census: (\S+): clean", out))


def test_1120_the_census_lint_walks_the_template_and_the_fixture_and_no_tenants_root(
        tmp_path: Path) -> None:
    rc, out = _census(_planted_repo(tmp_path / "clean", broken_lab=True))
    assert rc == 0, f"the census lint refused a repo whose template and fixture are clean:\n{out}"
    assert _clean_names(out) == {"tenant-template", "tenant-fixture"}, out

    gapped = {k: v for k, v in GRANTED_ROWS.items() if k != ("beta", "lookup")}
    rc, out = _census(_planted_repo(tmp_path / "gapped", fixture_rows=gapped))
    assert rc == 1, f"a fixture table omitting beta.lookup is not a finding (rc {rc}):\n{out}"
    assert "tenant-fixture: beta.lookup" in out, out


#: The four violating folders d9_lint_and_check_share_one_rule drives through both surfaces,
def _no_settings(folder: Path) -> str:
    shutil.rmtree(folder / "settings")
    return "/settings"


def _symlink_in_agent(folder: Path) -> str:
    outside = folder.parent / "outside.txt"
    outside.write_text("not the tenant's\n", encoding="utf-8")
    (folder / "agent" / "planted-link").symlink_to(outside)
    return "/agent/planted-link"


def _undecided_verb(folder: Path) -> str:
    H.edit_table(folder / "settings", drop=("    get-change:",))
    return "change-mgmt.get-change"


def _phantom_verb(folder: Path) -> str:
    table = folder / "settings" / "verb-grants.yaml"
    text = table.read_text(encoding="utf-8")
    table.write_text(text.replace("  cmdb:\n", "  cmdb:\n    no-such-verb: {roles: [gather]}\n",
                                  1), encoding="utf-8")
    return "cmdb.no-such-verb"


#: A lead-zero template the running catalog lacks: the census lint's own `_lead_zero_fault`
ABSENT_TEMPLATE = "elastic.no-such-template"


def _lead_zero_disagreement(folder: Path) -> str:
    (folder / "settings" / "lead-zero.yaml").write_text(
        f"correlation_template: {ABSENT_TEMPLATE}\n", encoding="utf-8")
    return ABSENT_TEMPLATE


def _extra_top_level_entry(folder: Path) -> str:
    """V3/V12: an operator's .env at the tenant repo's top level — outside the allow-list."""
    (folder / ".env").write_text("API_TOKEN=an-operator-secret\n", encoding="utf-8")
    return "/.env"


VIOLATIONS = [
    pytest.param(_no_settings, id="missing-settings"),
    pytest.param(_symlink_in_agent, id="symlink-in-agent"),
    pytest.param(_undecided_verb, id="undecided"),
    pytest.param(_phantom_verb, id="phantom-verb"),
    pytest.param(_lead_zero_disagreement, id="lead-zero-disagreement"),
    pytest.param(_extra_top_level_entry, id="extra-top-level-entry"),
]


@pytest.mark.gate
def test_1120_the_census_lint_and_check_folder_agree_on_a_violating_folder(
        tmp_path: Path) -> None:
    checkout = H.tmp_checkout(tmp_path / "co")
    fixture_slot = checkout / "knowledge" / "tenant-fixture"
    rc, out = _census(checkout)
    assert rc == 0, f"the census lint refused a checkout whose template and fixture are clean:\n{out}"
    assert "tenant-fixture" in _clean_names(out), f"the lint did not walk the fixture:\n{out}"
    H.assert_clean(H.check(tenant_py, None, "--folder", str(H.FIXTURE)))

    problems = []
    for param in VIOLATIONS:
        plant = param.values[0]
        case = tmp_path / "cases" / param.id
        shutil.copytree(H.FIXTURE, case, symlinks=True)
        token = plant(case)
        shutil.rmtree(fixture_slot)
        shutil.copytree(case, fixture_slot, symlinks=True)
        lint_rc, lint_out = _census(checkout)
        want_lint = f"{fixture_slot.name}{token}" if token.startswith("/") else token
        if lint_rc == 0 or want_lint not in lint_out:
            problems.append(f"{param.id}: the census lint (rc {lint_rc}) did not name "
                            f"{want_lint!r}:\n{lint_out[-1500:]}")
        proc = H.check(tenant_py, None, "--folder", str(case))
        want_check = f"{case.name}{token}" if token.startswith("/") else token
        check_out = H.output(proc)
        if proc.returncode != 1 or want_check not in check_out:
            problems.append(f"{param.id}: check --folder (rc {proc.returncode}) did not name "
                            f"{want_check!r}:\n{check_out[-1500:]}")
    assert problems == [], "\n\n".join(problems)


def test_1159_the_census_lint_keeps_exit_2_and_its_own_framing_when_the_census_is_blind(
        tmp_path: Path) -> None:
    """#1159 non-obligation: the lint's exit scheme is unchanged."""
    checkout = H.tmp_checkout(tmp_path / "checkout")
    rc, out = _census(checkout)
    assert rc == 0, f"the control checkout is not clean:\n{out}"
    H.add_adapter(checkout, H.BROKEN_SYSTEM, H.BROKEN_ADAPTER)
    rc, out = _census(checkout)
    assert rc == 2, f"the census-blind lint exited {rc}, not 2:\n{out}"
    assert H.BROKEN_SYSTEM in out, f"the lint does not name the broken adapter:\n{out}"
    assert "was not checked" not in out, (
        f"the lint's output carries the check command's unchecked-table framing:\n{out}")
