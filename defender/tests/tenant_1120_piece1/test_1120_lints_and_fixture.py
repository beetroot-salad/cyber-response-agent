"""#1120 piece 1 — D1's owner lint, D9's fixture and census lint, O10, M10's docs, N11's build context.

* `lint_run_records` moves its owner introspection from the public `TenantPaths` to `Tenant`,
  PER ATTRIBUTE (M5, human): joins onto the data-root record locations (`dir`, the row file's
  path, `runs`, `sessions`, `episodes`, `learning`, `worktrees`) are owner-derived and flagged
  when literal-free; joins onto `settings`, `knowledge` and `agent` stay clean in every shape,
  including an unannotated `accept_tenant(...)` local and a `RunTenant.tenant` chain. The #1077
  rename proof keeps holding with `Tenant` reading the row through the owner.
* `knowledge/tenant-fixture/` (A4) is the product repo's frozen copy of the lab's settings;
  `lint_verb_disposition_census` walks the template and the fixture and never
  `knowledge/tenants/` again, through the same folder rule `tenant.py check --folder` applies.
* O10 as narrowed by H2: no test, lint or CI file reaches the lab through a removed symbol,
  flag or retired resolver helper; the path-only readers keep finding the lab by path until
  D9 step 7.
* M10: the docs and skills piece 1's removals falsify document clone-then-setup; N11: the
  devcontainer's data root never enters a docker build context.

The lints are DRIVEN the way CI drives them — `lint_run_records.scan` over a planted tree
(`_spec1077.gate_findings`'s idiom) and `lint_verb_disposition_census.py --root <tmp repo>` as a
process — over trees built in the test. Nothing is written into the checkout. See
`_spec1120.py` for the coined names (`Tenant.row_path` is one).
"""
from __future__ import annotations

import ast
import os
import re
import shutil
import subprocess
import sys
import textwrap
import uuid
from pathlib import Path

import pytest

from defender import _tenant
from defender.runtime import verb_dispositions
from defender.scripts import tenant as tenant_py
from defender.tests import _dispositions995 as D995
from defender.tests import _spec1077 as S
from defender.tests import _tenants1106 as T1106
from defender.tests._by_path import LINT_DIR, import_lint_lib, load_lint_gate, load_module
from defender.tests._repo import seed_repo
from defender.tests.tenant_1120_piece1 import _spec1120 as H

REPO = H.REPO_ROOT
DEFENDER = H.DEFENDER

#: `scripts/lint/lint_verb_disposition_census.py`, run as CI runs it (a process).
lint_verb_disposition_census = LINT_DIR / "lint_verb_disposition_census.py"

JOIN_FINDING = "literal-free join onto an owner-derived value"


def _lint_run_records():
    """`scripts/lint/lint_run_records.py`, a fresh copy, reached the way CI reaches it."""
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


# ======================================================================================
# D1 / M5 — lint_run_records owns Tenant's record locations, per attribute.
# ======================================================================================

#: Tenant's data-root record locations (D1's lint sentence), each joined literal-free.
RECORD_LOCATIONS = ("dir", H.ROW_PATH_PROPERTY, "runs", "sessions", "episodes", "learning",
                    "worktrees")

#: The knowledge-half attributes whose owning loaders must stay lint-clean, joined in exactly
#: the shape the record locations are.
KNOWLEDGE_JOINS = ("settings", "knowledge", "agent")

#: The settings-half loaders that survive piece 1 unchanged (profile resource
#: `tenant_knowledge`): the real sweep must report nothing in them.
SETTINGS_LOADER_MODULES = (
    "runtime/verb_dispositions.py", "runtime/lead_zero_config.py", "runtime/run_tenant.py",
    "scripts/case_history/case_ticket.py", "scripts/adapters/elastic_adapter.py",
    "scripts/adapters/_stub_transport.py", "learning/branch/estate/stagers/elastic.py",
    "learning/branch/staging.py", "skills/connect/validate_scaffold.py",
)


def test_1120_run_records_lint_owns_tenant_record_locations_but_not_knowledge_settings_or_agent(
        tmp_path: Path) -> None:
    """Run over a swept module whose functions take a parameter annotated as Tenant,
    lint_run_records reports a literal-free join onto the tenant's dir, onto the row file's
    path property, and onto runs, sessions, episodes, learning and worktrees — the data-root
    record locations Tenant owns. It reports nothing for the same literal-free join onto
    tenant.settings, tenant.knowledge or tenant.agent: knowledge, settings and agent are not
    run-record owners, so the loaders that join onto them stay lint-clean (M5's per-attribute
    owner table). A swept module reaching the row only through the Tenant property is not
    reported (supersedes pass-A's TenantPaths row check). The real sweep of the checkout reports nothing in any settings
    loader. The positive control: a join onto EpisodePaths(ep).runs is reported by the same
    scan, so the join arm is live."""
    joins = "".join(
        f"def join_{prop}(tenant: Tenant, name: str) -> Path:\n"
        f"    return tenant.{prop} / name\n\n" for prop in RECORD_LOCATIONS)
    clean = "".join(
        f"def join_{prop}(tenant: Tenant, name: str) -> Path:\n"
        f"    return tenant.{prop} / name\n\n" for prop in KNOWLEDGE_JOINS)
    source = (
        "from pathlib import Path\n\n"
        "from defender._episode_paths import EpisodePaths\n"
        "from defender._tenant import Tenant\n\n\n"
        f"{joins}{clean}"
        f"def row_only(tenant: Tenant) -> Path:\n    return tenant.{H.ROW_PATH_PROPERTY}\n\n"
        "def control(ep: Path, run_id: str) -> Path:\n"
        "    return EpisodePaths(ep).runs / run_id\n")
    displays = _scan_planted(tmp_path, "runtime/tenant_joins.py", source)
    assert _in(displays, "control"), f"the join arm is not live:\n{displays}"
    unflagged = [p for p in RECORD_LOCATIONS
                 if not any(JOIN_FINDING in d for d in _in(displays, f"join_{p}"))]
    assert unflagged == [], (
        f"a literal-free join onto Tenant.{unflagged} is not owner-derived to the lint:\n"
        + "\n".join(displays))
    flagged_clean = {fn: _in(displays, fn)
                     for fn in (*(f"join_{p}" for p in KNOWLEDGE_JOINS), "row_only")
                     if _in(displays, fn)}
    assert flagged_clean == {}, (
        f"joins onto settings/knowledge/agent (or a bare row read) are reported: {flagged_clean}")

    real = [f.display for f in _lint_run_records().scan(DEFENDER)]
    in_loaders = [d for d in real if d.split(":", 1)[0] in SETTINGS_LOADER_MODULES]
    assert in_loaders == [], f"the settings loaders gained run-records findings: {in_loaders}"


def test_1120_run_records_lint_tags_accept_tenant_locals_and_run_tenant_chains(
        tmp_path: Path) -> None:
    """M5 (human, reading (a) plus tagging): a literal-free join onto tenant.runs from an
    UNANNOTATED local bound to an accept_tenant(...) call is reported, as is one straight off
    the call; a join onto run_tenant.tenant.learning for a parameter annotated RunTenant is
    reported. The same literal-free joins onto settings, knowledge and agent stay clean in
    every one of those shapes, and onto RunTenant's own settings. The positive control: the EpisodePaths join is
    reported by the same scan."""
    call = 'accept_tenant(root, "acme", defender_dir=root, box_mounted=())'
    source = textwrap.dedent(f"""\
        from pathlib import Path

        from defender._episode_paths import EpisodePaths
        from defender._tenant import accept_tenant
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
                if not any(JOIN_FINDING in d for d in _in(displays, fn))]
    assert untagged == [], (
        f"these record-location joins escape the lint (M5 tagging): {untagged}\n"
        + "\n".join(displays))
    clean = ("local_settings", "local_knowledge", "local_agent", "call_settings",
             "chain_settings", "chain_agent", "run_tenant_settings")
    flagged = {fn: _in(displays, fn) for fn in clean if _in(displays, fn)}
    assert flagged == {}, f"knowledge-half joins are reported: {flagged}"


def _upper_str_constants(source: str) -> dict[str, str]:
    out = {}
    for node in ast.parse(source).body:
        if (isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id.isupper() and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            out[node.targets[0].id] = node.value.value
    return out


#: Run inside the RENAMED tree: create the row through the owner, place a knowledge folder,
#: and accept the tenant — `Tenant` must find the row at its renamed name.
_TENANT_ROUND_TRIP = """\
import shutil, sys
from pathlib import Path
from defender import _tenant
work, fixture, renamed_row = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
root = work / "data"
root.mkdir(parents=True)
_tenant.create_tenant(root, _tenant.TenantId("acme"))
assert (root / "acme" / renamed_row).is_file(), sorted(p.name for p in (root / "acme").iterdir())
assert not (root / "acme" / "tenant.json").exists(), "the row kept its old name"
knowledge = root / "acme" / "knowledge"
shutil.copytree(fixture, knowledge)
(knowledge / "agent" / ".tenant-id").write_text("acme\\n", encoding="utf-8")
tenant = _tenant.accept_tenant(root, "acme", defender_dir=Path(_tenant.__file__).parent,
                               box_mounted=())
assert tenant.row.tenant_id == "acme", tenant.row
assert getattr(tenant, sys.argv[4]) == root / "acme" / renamed_row, getattr(tenant, sys.argv[4])
print("TENANT ROUNDTRIP OK")
"""


def test_1120_the_1077_rename_proof_holds_with_tenant_in_the_renamed_set(
        tmp_path: Path) -> None:
    """R0 (x1078_s108): the #1077 rename proof keeps holding over Tenant. Every upper-case
    string constant _tenant.py binds (outside the proof's own skip lists) is renamed by the
    proof's rewrite, the row's name among them; and in the renamed tree a real round trip —
    create_tenant writes the row, the operator places a knowledge folder, accept_tenant
    accepts the tenant — finds the row at its RENAMED name through Tenant's row and its row
    file's path property, while no file keeps the old name. A Tenant that hand-composed
    tenant.json instead of asking its owner would fail the round trip."""
    proof = load_module(DEFENDER / "tests" / "test_1077_rename_proof.py",
                        name=f"rename_proof_1120_{uuid.uuid4().hex}")
    source = Path(_tenant.__file__).read_text(encoding="utf-8")
    rewritten, _count = proof._rewrite_owner(source)
    before = _upper_str_constants(source)
    after = _upper_str_constants(rewritten)
    unrenamed = sorted(n for n, v in before.items()
                       if n not in proof._SKIP_NAMES and v not in proof._SKIP_VALUES
                       and after.get(n) == v)
    assert unrenamed == [], f"the rewrite leaves _tenant.py's {unrenamed} unrenamed"
    assert H.ROW_NAME in before.values(), "_tenant.py no longer spells the row's name"

    tree = proof._renamed_tree(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    proc = subprocess.run(  # noqa: S603 — fixed argv, the test's own interpreter
        [sys.executable, "-c", _TENANT_ROUND_TRIP, str(work), str(H.FIXTURE),
         proof._renamed(H.ROW_NAME), H.ROW_PATH_PROPERTY],
        capture_output=True, text=True, timeout=300, cwd=str(tree),
        env={**{k: v for k, v in os.environ.items()
                if k not in (H.DATA_ROOT_ENV, H.LEARNING_STATE_ENV)},
             "PYTHONPATH": str(tree), "PYTHONDONTWRITEBYTECODE": "1"},
        check=False)
    broke = ("the Tenant round trip broke when _tenant.py's records were renamed through their "
             f"owner:\n{proc.stdout[-2000:]}\n{proc.stderr[-3000:]}")
    assert proc.returncode == 0, broke
    assert "TENANT ROUNDTRIP OK" in proc.stdout, broke


# ======================================================================================
# D9 — the fixture tenant (A4).
# ======================================================================================

#: The systems the lab configures, and so the fixture (test_1106_layout's literal).
CONFIGURED_SYSTEMS = frozenset({
    "case-history", "change-mgmt", "cmdb", "elastic", "identity", "threat-intel", "ticket",
})


def test_1120_the_fixture_tenant_carries_the_labs_grants_and_lead_zero_outside_defender(
        ) -> None:
    """knowledge/tenant-fixture/ exists with settings/ and agent/ halves and does not lie
    under defender/ (A4: outside the box-mounted tree). It is the lab frozen, and the
    reference (N14): its table's gather grant is exactly GATHER_CENSUS, its correlation grant
    CORRELATION_CENSUS on elastic, its withheld rows WITHHELD_CENSUS, every one with a reason;
    its lead-zero.yaml names elastic.correlate-alerts-by-entity, which the running checkout's
    catalog resolves and agrees with; its case-history mapping equals the template's and
    releases on closed; it configures the lab's seven systems; its agent half holds no
    settings kind; and it commits no agent/.tenant-id (M8). The table is total over the
    running checkout's census. The lab-content assertions of C26 hold over the fixture."""
    fixture, settings, agent = H.FIXTURE, H.FIXTURE / "settings", H.FIXTURE / "agent"
    assert settings.is_dir(), f"{fixture} lacks its settings half"
    assert agent.is_dir(), f"{fixture} lacks its agent half"
    assert not fixture.resolve().is_relative_to(DEFENDER.resolve()), "the fixture is box-mounted"
    for rel in H.REQUIRED_SETTINGS:
        assert (settings / rel).is_file(), f"the fixture lacks {rel}"
    assert not (fixture / H.TENANT_ID_FILE).exists(), "the fixture commits a .tenant-id (M8)"

    grants = verb_dispositions.run_grants(settings)
    assert {(s, v) for s, v, *_ in grants.gather.entries} == set(D995.GATHER_CENSUS)
    assert {(s, v) for s, v, *_ in grants.correlation.entries} == set(D995.CORRELATION_CENSUS)
    assert grants.correlation_system == "elastic"
    rows = verb_dispositions.load_dispositions(settings / "verb-grants.yaml")
    assert {(r.system, r.verb) for r in rows if not r.roles} == set(D995.WITHHELD_CENSUS)

    lz = H.mod("runtime.lead_zero_config")
    template = lz.load_correlation_template(lz.lead_zero_config_path(settings))
    assert template == H.FIXTURE_CORRELATION_TEMPLATE
    rt = H.mod("runtime.run_tenant")
    dispatch = rt.correlation_dispatch(settings, rt.catalog_templates(DEFENDER),
                                       grants.correlation)
    assert dispatch.template_id == H.FIXTURE_CORRELATION_TEMPLATE

    mapping = settings / "systems" / "case-history" / "mapping.yaml"
    assert mapping.read_bytes() == (
        H.TEMPLATE / "settings" / "systems" / "case-history" / "mapping.yaml").read_bytes()
    predicate = H.mod("scripts.case_history.case_ticket").release_predicate(settings)
    assert predicate.released_status == "closed"
    configured = {p.parent.name for p in (settings / "systems").glob("*/config.env")}
    assert configured == CONFIGURED_SYSTEMS, configured
    settings_kinds = [p for p in agent.rglob("*")
                      if p.name in ("verb-grants.yaml", "lead-zero.yaml", "mapping.yaml",
                                    "config.env")]
    assert settings_kinds == [], f"the agent half holds settings: {settings_kinds}"

    ds = H.mod("learning.leads.declared_systems")
    roster = ds.read_adapters(H.mod("_paths").adapters_under(DEFENDER))
    walked = {s: roster.declared_verbs(s) for s in ds.declared_systems_over(roster, REPO)}
    gaps = verb_dispositions.census_gaps(walked, rows)
    assert not gaps, gaps


def _spells_the_fixture(path: Path) -> bool:
    text = path.read_text(encoding="utf-8", errors="replace")
    return "tenant-fixture" in text or re.search(
        r"""["']tenant["']\s*\+\s*["']-fixture["']""", text) is not None


def test_1120_no_production_module_names_the_fixture_tenant() -> None:
    """No module under defender/ outside tests/ spells tenant-fixture or builds a path to it,
    so the fixture is never a run's tenant outside tests (A4). The positive control: the same
    scan over scripts/lint/lint_verb_disposition_census.py finds it — the census lint is the
    fixture's one non-test reader (D9)."""
    offenders = sorted(
        str(p.relative_to(REPO)) for p in DEFENDER.rglob("*.py")
        if "tests" not in p.relative_to(DEFENDER).parts and ".venv" not in p.parts
        and _spells_the_fixture(p))
    assert offenders == [], f"production modules name the fixture tenant: {offenders}"
    assert _spells_the_fixture(lint_verb_disposition_census), (
        "the census lint does not name knowledge/tenant-fixture, so the scan above cannot see "
        "the reference it exists to forbid elsewhere")


# ======================================================================================
# D9 — the census lint walks the template and the fixture, and no tenants root.
# ======================================================================================

_LEAD = "lead-zero-correlation"
_WHY = "the template grants nothing until an operator decides"

#: A total table over the planted census (alpha.lookup, beta.lookup and their health-checks),
#: granting the correlation lead alpha's pair.
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
    """A committed synthetic repo (`_dispositions995.planted_tree`) declaring `systems`, with
    the lead-zero catalog template, a template folder and a fixture folder — plus, on request,
    a lab under knowledge/tenants/ (`lab_rows`) or a broken one (`broken_lab`)."""
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
    """Run with its root at a tmp repo holding a valid template, a valid fixture and a broken
    knowledge/tenants/x/ (no verb-grants.yaml), lint_verb_disposition_census exits 0 and its
    clean lines name exactly tenant-template and tenant-fixture: the tenants root is walked by
    no gate (D9). It exits 1, naming tenant-fixture and the pair, when the fixture's table
    omits a declared verb — the fixture is walked, not merely named."""
    rc, out = _census(_planted_repo(tmp_path / "clean", broken_lab=True))
    assert rc == 0, f"the census lint refused a repo whose template and fixture are clean:\n{out}"
    assert _clean_names(out) == {"tenant-template", "tenant-fixture"}, out

    gapped = {k: v for k, v in GRANTED_ROWS.items() if k != ("beta", "lookup")}
    rc, out = _census(_planted_repo(tmp_path / "gapped", fixture_rows=gapped))
    assert rc == 1, f"a fixture table omitting beta.lookup is not a finding (rc {rc}):\n{out}"
    assert "tenant-fixture: beta.lookup" in out, out


#: The four violating folders d9_lint_and_check_share_one_rule drives through both surfaces,
#: each built from the real fixture, with the token both surfaces must name. A path token
#: ("/settings") is matched after the folder's own name, so an absolute and a repo-relative
#: spelling of the path both satisfy it.
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
#: is the run-start agreement check (92 #2), so M6 (b) makes it a rule both surfaces apply.
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


def test_1120_the_census_lint_and_check_folder_agree_on_a_violating_folder(
        tmp_path: Path) -> None:
    """For each of a folder missing settings/, one with a symlink in agent/ reaching outside
    it (U4), one whose table leaves a declared verb undecided, one with a phantom verb, one
    whose lead-zero.yaml names a template the running catalog lacks (M6 (b): the lead-zero
    agreement is shared too, V4), and one with a .env at its top level (V12's allow-list),
    lint_verb_disposition_census (over a tmp copy of this checkout whose fixture is that
    folder) and `tenant.py check --folder <folder>` both refuse and name the same finding —
    the folder rules both apply, judged against the same running census and catalog. Both
    accept the clean fixture: the lint exits 0 over the copy, and check --folder exits 0 over
    the fixture."""
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


# ======================================================================================
# O10 as narrowed by H2 — no test, lint or CI file reaches the lab through a removed surface.
# ======================================================================================

#: The repo's scope-aware name resolver: the census asks it what a receiver is bound to.
_AST = import_lint_lib("_astlib")

#: Names D1 removes from `defender._tenants` (and the refusal class the catchers stop
#: naming, M7). Distinctive enough to flag as any attribute or import.
REMOVED_NAMES = frozenset({
    "default_tenants_root", "entry_tenant", "entry_tenant_args", "TenantDir", "TenantDirError",
})
#: `tenant_dir` is also a common local helper name (pass-A's `_spec1078.tenant_dir`), so it is
#: flagged only when read off the `_tenants` module.
REMOVED_MODULE_ATTRS = frozenset({"tenant_dir"})
#: `_tenants1106`'s helpers that resolve the lab through the removed resolver (H2: no
#: test-only survival of it), and — the lab now retired (human, PR #1157: #1158 folded in) —
#: its path constants, which the path-only readers used until then.
RETIRED_HELPERS = frozenset({"playground_tenant", "playground_run_tenant"})
RETIRED_LAB_CONSTANTS = frozenset({"PLAYGROUND", "PLAYGROUND_SETTINGS", "PLAYGROUND_AGENT",
                                   "TENANTS_ROOT"})
REMOVED_FLAG = "--tenants-root"
#: The retired lab's tree, as a path string spells it.
LAB_TREE = "knowledge/tenants"


def _bare_strings(tree: ast.AST) -> set[int]:
    """The ids of every bare-string statement's constant (docstrings): prose reaches no path
    and passes no flag, as `lint_run_records` treats it."""
    return {id(n.value) for n in ast.walk(tree)
            if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)}


def _is_tenants_module(node: ast.expr, env) -> bool:
    """`node` is the `defender._tenants` module: RESOLVED through its import however it is
    spelled (`from defender import _tenants as t`, `import defender._tenants as t`,
    `defender._tenants`), or a duck-typed module handle the resolver cannot see — a
    `*._tenants` attribute, or a test helper that returns the module (`tenants()`,
    `mod("_tenants")`), matched by name because no import binds it."""
    if _AST.origin(node, env) == "defender._tenants":
        return True
    if isinstance(node, ast.Attribute):
        return node.attr == "_tenants"
    if isinstance(node, ast.Call):  # `tenants()` / `mod("_tenants")`
        fn = node.func
        name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")
        literal = [a.value for a in node.args if isinstance(a, ast.Constant)]
        return name == "tenants" or (name == "mod" and literal == ["_tenants"])
    return False


def _removed_imports(node: ast.ImportFrom) -> list[list[str]]:
    """The removed members an import statement names. The statement's spelling IS the
    finding: once D1 removes the member, the import fails whatever name it would bind."""
    names = {a.name for a in node.names}
    removed = names & (REMOVED_NAMES | REMOVED_MODULE_ATTRS)
    retired = names & (RETIRED_HELPERS | RETIRED_LAB_CONSTANTS)
    module = str(node.module)
    return [sorted(hit) for hit, owner in (
                (removed, module == "defender._tenants"),  # lint-ast-resolve: ok — reports an import statement naming a removed member; it fails at import whatever it binds
                (retired, module.endswith("_tenants1106")))  # lint-ast-resolve: ok — same: the import statement is the reach being reported
            if hit and owner]


def _py_findings(path: Path, rel: str) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
    env = _AST.module_env(tree)
    prose = _bare_strings(tree)
    out = []
    for node in ast.walk(tree):
        line = getattr(node, "lineno", 0)
        if isinstance(node, ast.ImportFrom) and node.module:
            out += [f"{rel}:{line}: imports {hit}" for hit in _removed_imports(node)]
        elif isinstance(node, ast.Attribute):
            if node.attr in REMOVED_NAMES:
                out.append(f"{rel}:{line}: .{node.attr}")
            elif node.attr in REMOVED_MODULE_ATTRS and _is_tenants_module(node.value, env):
                out.append(f"{rel}:{line}: _tenants.{node.attr}")
            elif node.attr in RETIRED_HELPERS:
                out.append(f"{rel}:{line}: .{node.attr} (resolves the lab via the removed resolver)")
            elif node.attr in RETIRED_LAB_CONSTANTS:
                out.append(f"{rel}:{line}: .{node.attr} (the retired lab's path)")
        elif (isinstance(node, ast.Constant) and isinstance(node.value, str)
              and id(node) not in prose):
            out += [f"{rel}:{line}: {hit}" for hit in _spelled(node.value)]
    return out


def _spelled(text: str) -> list[str]:
    """What a non-prose string spells of the removed surface: the flag, or the lab's path."""
    if REMOVED_FLAG in text:
        return [f"spells {REMOVED_FLAG}"]
    if LAB_TREE in text:
        return [f"spells the retired lab's path {LAB_TREE}"]
    return []


def lab_reach_census(root: Path, *, exclude: tuple[Path, ...] = ()) -> list[str]:
    """Every place under `root`'s defender/tests, scripts/lint and .github/workflows that
    reaches the lab through a removed symbol, flag, retired resolver helper or path constant,
    or spells its path. `exclude` names directories or files skipped whole (the spec suite,
    which names the removed surface on purpose to pin its removal; migrate's test, which
    builds a lab into a tmp checkout's history)."""
    root = Path(root)
    # The lint dir is the census lint's own home: the one lint piece 1 moves off the lab.
    lint_dir = root / lint_verb_disposition_census.parent.relative_to(REPO)
    found: list[str] = []
    for base in (root / "defender" / "tests", lint_dir):
        for path in sorted(base.rglob("*.py")) if base.is_dir() else []:
            if any(path.is_relative_to(x) for x in exclude) or "__pycache__" in path.parts:
                continue
            found += _py_findings(path, path.relative_to(root).as_posix())
    workflows = root / ".github" / "workflows"
    for path in sorted(workflows.glob("*.y*ml")) if workflows.is_dir() else []:
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if REMOVED_FLAG in line or "knowledge/tenants" in line:
                found.append(f"{path.relative_to(root).as_posix()}:{n}: {line.strip()[:80]}")
    return found


def test_1120_no_test_lint_or_ci_file_reads_knowledge_tenants(tmp_path: Path) -> None:
    """Narrowed per H2 (human), then widened when the lab was retired (human, PR #1157: #1158
    folded in): no file under defender/tests/, scripts/lint/ or .github/workflows/ reaches the
    checkout's lab through a removed symbol or flag — default_tenants_root, entry_tenant,
    entry_tenant_args, TenantDir, TenantDirError, the _tenants module's tenant_dir,
    --tenants-root — through the retired _tenants1106 resolver helpers (playground_tenant,
    playground_run_tenant) or path constants (PLAYGROUND, PLAYGROUND_SETTINGS,
    PLAYGROUND_AGENT, TENANTS_ROOT), or by spelling knowledge/tenants in a non-prose string;
    no workflow names the tenants root. The path-only readers' H2 exemption ends with the lab.
    The failure lists every offending site. The positive control: the same census over a tmp
    tree holding one planted reference of each shape reports each, the path-only read
    included; it runs first, so it is live at base."""
    planted = tmp_path / "planted"
    S.plant(planted, "defender/tests/test_planted.py",
            "from defender._tenants import default_tenants_root\n"
            "from defender import _tenants\n"
            "from defender.tests._tenants1106 import playground_tenant\n"
            "from defender.tests import _tenants1106 as T\n"
            "SETTINGS = T.PLAYGROUND_SETTINGS\n"
            "ARGV = ['--tenants-root', 'x']\n"
            "LAB = 'knowledge/tenants/playground/settings'\n"
            "def f(root):\n    return _tenants.tenant_dir(root, 'playground')\n")
    S.plant(planted, ".github/workflows/ci.yml", "run: lint --tenants-root knowledge/tenants\n")
    control = "\n".join(lab_reach_census(planted))
    for needle in ("default_tenants_root", "playground_tenant", "spells --tenants-root",
                   "_tenants.tenant_dir", ".github/workflows/ci.yml",
                   ".PLAYGROUND_SETTINGS (the retired lab's path)",
                   "test_planted.py:7: spells the retired lab's path"):
        assert needle in control, f"the census misses a planted {needle!r}:\n{control}"

    spec_suite = Path(__file__).resolve().parent
    migrate_test = DEFENDER / "tests" / "test_1120_migrate.py"
    found = lab_reach_census(REPO, exclude=(spec_suite, migrate_test))
    files = sorted({f.split(":", 1)[0] for f in found})
    assert found == [], (
        f"{len(found)} site(s) in {len(files)} file(s) still reach the lab through the removed "
        "surface (H2's re-home census):\n  " + "\n  ".join(files) + "\n\nsites:\n  "
        + "\n  ".join(found[:200]))


# ======================================================================================
# s084 — an adapter gains a verb while the lab is walked by no gate.
# ======================================================================================

#: The C26 test modules whose lab-content assertions move to the fixture in piece 1.
C26_MODULES = ("test_1106_layout.py", "test_verb_dispositions_995.py",
               "test_correlation_template_1003.py", "test_verb_roster_632.py",
               "test_gather_template_discovery.py", "test_1106_ci_census.py",
               "test_case_ticket.py")
#: How a test module takes the lab as its subject (C26's sites): the lab's settings and agent
#: halves and the helpers that load or resolve them. `PLAYGROUND_ID` and `TENANTS_ROOT` are
#: left out — a tenant id or a planted tree's layout is not the lab's content.
LAB_SUBJECT_NAMES = frozenset({
    "PLAYGROUND", "PLAYGROUND_SETTINGS", "PLAYGROUND_AGENT", "playground_grants",
    "playground_tenant", "playground_gather_def", "playground_run_tenant",
})
LAB_PATH = "knowledge/tenants/playground"


def _lab_subjects(path: Path) -> list[str]:
    """Where `path` reads the lab: a `LAB_SUBJECT_NAMES` reference, or a string that is not a
    docstring or other bare-string statement and spells the lab's path."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    prose = _bare_strings(tree)
    hits = set()
    for n in ast.walk(tree):
        name = n.attr if isinstance(n, ast.Attribute) else getattr(n, "id", None)
        if name in LAB_SUBJECT_NAMES:
            hits.add(name)
        elif (isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in prose
              and LAB_PATH in n.value):
            hits.add(repr(LAB_PATH))
    return sorted(hits)


def test_1120_s9_adapter_gains_a_verb_while_lab_is_walked_by_no_gate(tmp_path: Path) -> None:
    """After piece 1 and before D9 step 7, a PR adds a verb to an adapter and edits only the
    template's and the fixture's tables, as the census lint demands. CI stays green: the
    census lint, run over a repo whose lab table lacks the new verb while the template and
    the fixture decide it, exits 0 — the lab goes stale, unwalked (H2). And it stays green in
    the tests too, because piece 1 moved every C26 lab-content assertion to the fixture: none
    of the C26 test modules takes the lab as its subject any more — its settings or agent
    half, the helpers that load or resolve it, or a string spelling its path."""
    systems = {"alpha": "lookup", "beta": "lookup", "gamma": "fresh-verb"}
    added = {("gamma", "fresh-verb"): {"roles": ["gather"]},
             ("gamma", "health-check"): {"roles": ["gather"]}}
    repo = _planted_repo(tmp_path, systems=systems, fixture_rows={**GRANTED_ROWS, **added},
                         template_rows={**TEMPLATE_ROWS,
                                        **{p: {"roles": [], "reason": _WHY} for p in added}},
                         lab_rows=GRANTED_ROWS)
    rc, out = _census(repo)
    assert rc == 0, (
        f"the census lint still walks the lab: a stale lab table fails CI (rc {rc}):\n{out}")
    assert "playground" not in out, f"the census lint still names the lab:\n{out}"

    lab_subjects = [f"{name}: {hits}" for name in C26_MODULES
                    if (hits := _lab_subjects(DEFENDER / "tests" / name))]
    assert lab_subjects == [], (
        "C26 modules still assert lab content (move them to the fixture):\n  "
        + "\n  ".join(lab_subjects))


# ======================================================================================
# R5 — the path-only readers survive piece 1 (H2).
# ======================================================================================

def test_1120_the_lab_is_retired_from_the_checkout() -> None:
    """R5 superseded (human, PR #1157: "Fold" — #1158 folded into piece 1, D9 step 7 reached
    early): the lab is no longer committed — the checkout's git tracks nothing under
    knowledge/tenants/ — and the template and the fixture, the two committed tenants, are.
    That no test reads the lab by path or symbol is o10_tests_need_no_tenant_repo's census."""
    tracked = subprocess.run(
        ["git", "-C", str(REPO), "ls-files", "--cached", "--", LAB_TREE,
         "knowledge/tenant-template", "knowledge/tenant-fixture"],
        capture_output=True, text=True, check=True, timeout=60).stdout.splitlines()
    lab = [t for t in tracked if t.startswith(LAB_TREE + "/")]
    assert lab == [], f"the checkout still commits the retired lab: {lab[:5]}"
    for kept in ("knowledge/tenant-template/", "knowledge/tenant-fixture/"):
        assert any(t.startswith(kept) for t in tracked), f"the checkout no longer commits {kept}"


# ======================================================================================
# M10 — the docs and skills piece 1's removals falsify.
# ======================================================================================

#: M10's slice (human, (a) with DC2's text), resolved at a1c65801.
M10_DOCS = (
    DEFENDER / "skills" / "connect" / "SKILL.md",
    DEFENDER / "skills" / "handbook" / "content" / "knowledge-and-skills.md",
    REPO / ".devcontainer" / "README.runtime.md",
    REPO / ".devcontainer" / "Dockerfile.runtime",
    DEFENDER / "evals" / "held_out.py",
    DEFENDER / "evals" / "oracle_golden" / "generate_case.py",
    DEFENDER / "docs" / "case-history-write-path.md",
    DEFENDER / "docs" / "state-surface-adapters.md",
    DEFENDER / "scripts" / "adapters" / "README.md",
    REPO / ".claude" / "skills" / "prompt-hygiene" / "SKILL.md",
)
#: The fresh-run docs `test_1078_docs` pins the setup step in (pass-A D8, C58): wherever the
#: setup step is documented, it is documented as clone-then-setup (M10 with DC2).
SETUP_STEP_DOCS = (
    REPO / "README.md", DEFENDER / "CLAUDE.md", REPO / ".devcontainer" / "README.runtime.md",
    DEFENDER / "run.py", DEFENDER / "evals" / "held_out.py", DEFENDER / "evals" / "README.md",
    DEFENDER / "evals" / "oracle_golden" / "README.md",
    DEFENDER / "evals" / "oracle_golden" / "generate_case.py",
    DEFENDER / "docs" / "oracle-calibration.md", DEFENDER / "skills" / "handbook" / "SKILL.md",
    DEFENDER / "skills" / "handbook" / "content" / "runtime-loop.md",
)

_SETUP_FROM = re.compile(r"setup\s+\S+\s+--from\b")
_CLONE_INTO_KNOWLEDGE = re.compile(r"\bclone\b[^\n]{0,160}knowledge")
_AFTER_CLONE = re.compile(
    r"(after|once|when)\b[^.\n]{0,60}\bclone\b[^.\n]{0,60}\b(exit|complete|finish|succeed)",
    re.IGNORECASE)
_CREDENTIALS = re.compile(r"credential helper|ssh[- ]agent", re.IGNORECASE)


def test_1120_docs_and_skills_name_clone_then_setup_and_no_tenants_root() -> None:
    """The docs and skills piece 1's removals falsify — connect SKILL.md, the handbook's
    knowledge-and-skills.md, README.runtime.md and Dockerfile.runtime's comments, held_out's
    and generate_case's docstrings, case-history-write-path.md, state-surface-adapters.md,
    the adapters README and the prompt-hygiene skill — name no --tenants-root, no setup with a
    --from source, and no knowledge/tenants as a settings location. Every doc that documents
    the tenant.py setup step (these and the fresh-run docs pass-A pins it in) documents it as
    DC2 has it: clone the tenant repo into <root>/<id>/knowledge on the host, then run
    tenant.py setup <id>. Together they tell the operator to run setup after the clone exits
    0 (NF3) and to clone with a credential helper or an ssh agent, never a credential in the
    URL (NF5)."""
    setup_step = f"{H.script_of(tenant_py).name} setup"
    problems = []
    slice_text = ""
    for doc in dict.fromkeys((*M10_DOCS, *SETUP_STEP_DOCS)):
        assert doc.is_file(), f"M10's doc {doc} moved"
        text = doc.read_text(encoding="utf-8")
        slice_text += text + "\n"
        rel = doc.relative_to(REPO)
        if doc in M10_DOCS:
            for bad, found in ((REMOVED_FLAG, REMOVED_FLAG in text),
                               ("setup … --from", _SETUP_FROM.search(text) is not None),
                               ("knowledge/tenants", "knowledge/tenants" in text)):
                if found:
                    problems.append(f"{rel}: still names {bad}")
        if setup_step in text and not _CLONE_INTO_KNOWLEDGE.search(text):
            problems.append(f"{rel}: documents `{setup_step}` without the clone into "
                            "<root>/<id>/knowledge before it")
    if not _AFTER_CLONE.search(slice_text):
        problems.append("no doc says to run setup after the clone exits 0 (NF3)")
    if not _CREDENTIALS.search(slice_text):
        problems.append("no doc says to clone with a credential helper or an ssh agent (NF5)")
    assert problems == [], "M10's docs still describe the removed surface:\n  " + "\n  ".join(
        problems)


# ======================================================================================
# N11 — the devcontainer's data root never enters a build context.
# ======================================================================================

def _dockerignore_excludes(rules: list[str], rel: str) -> bool:
    """Docker's `.dockerignore` semantics, enough for this file: each rule is a
    `filepath.Match` glob (`**` any depth) matched against the path and each of its parent
    directories; a `!` rule re-includes; the LAST matching rule wins."""
    parts = rel.split("/")
    candidates = ["/".join(parts[:i]) for i in range(1, len(parts) + 1)]
    excluded = False
    for raw in rules:
        negate = raw.startswith("!")
        pattern = raw[1:] if negate else raw
        pattern = pattern.strip("/")
        regex = re.escape(pattern).replace(r"\*\*/", "(?:.*/)?").replace(r"\*\*", ".*")
        regex = regex.replace(r"\*", "[^/]*").replace(r"\?", "[^/]")
        if any(re.fullmatch(regex, c) for c in candidates):
            excluded = not negate
    return excluded


def test_1120_dockerignore_keeps_the_devcontainer_data_root_out_of_the_build_context() -> None:
    """Piece 1 puts every tenant's settings under the devcontainer's data root,
    /workspace/.defender-data, which is the repo root's .defender-data — inside the context
    (../, the repo root) the dev and runtime images build with. The repo root's .dockerignore
    excludes it, so a tenant's settings and knowledge never enter a build context (N11,
    promoted s11). The positive control: the same reading of the file excludes the committed
    knowledge/ folder it already lists and keeps defender/run.py in the context."""
    compose = (REPO / ".devcontainer" / "docker-compose.yml").read_text(encoding="utf-8")
    for premise in ("context: ../", "/workspace/.defender-data"):
        assert premise in compose, (
            f"docker-compose.yml no longer spells {premise!r} — the devcontainer no longer builds "
            "from the repo root or keeps its data root there; re-derive which .dockerignore "
            "applies")
    rules = [ln.strip() for ln in (REPO / ".dockerignore").read_text(encoding="utf-8").splitlines()
             if ln.strip() and not ln.strip().startswith("#")]
    assert _dockerignore_excludes(rules, "knowledge/tenants/playground/settings/verb-grants.yaml")
    assert not _dockerignore_excludes(rules, "defender/run.py")
    assert _dockerignore_excludes(rules, ".defender-data/acme/knowledge/settings/verb-grants.yaml"), (
        ".dockerignore does not exclude .defender-data: the devcontainer's tenant settings and "
        "knowledge enter the dev and runtime images' build context")
