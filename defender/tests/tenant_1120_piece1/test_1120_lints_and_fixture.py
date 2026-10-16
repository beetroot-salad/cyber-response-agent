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
import functools
import os
import re
import shutil
import subprocess
import sys
import textwrap
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender import _tenant
from defender.runtime import verb_dispositions
from defender.scripts import tenant as tenant_py
from defender.tests import _dispositions995 as D995
from defender.tests import _spec1077 as S
from defender.tests import _tenants1106 as T1106
from defender.tests._by_path import LINT_DIR, cached_source, import_lint_lib, load_lint_gate, load_module
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
    "runtime/case_ticket.py", "scripts/adapters/elastic_adapter.py",
    "scripts/adapters/_stub_transport.py", "learning/branch/estate/stagers/elastic.py",
    "learning/branch/staging.py", "skills/connect/validate_scaffold.py",
)


@pytest.mark.gate
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


# ======================================================================================
# D9 — the fixture tenant (A4).
# ======================================================================================

#: The systems the lab configures, and so the fixture (test_1106_layout's literal).
CONFIGURED_SYSTEMS = frozenset({
    "case-history", "change-mgmt", "cmdb", "elastic", "host-state", "identity", "threat-intel",
    "ticket",
})


def _spells_the_fixture(path: Path) -> bool:
    text = cached_source(path)
    return "tenant-fixture" in text or re.search(
        r"""["']tenant["']\s*\+\s*["']-fixture["']""", text) is not None


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


@pytest.mark.gate
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


def _node_findings(node: ast.AST, rel: str, env: Callable[[], Any],
                   prose: Callable[[], set[int]]) -> list[str]:
    """What one syntax node spells of the removed surface (`env`/`prose` are built on demand)."""
    line = getattr(node, "lineno", 0)
    if isinstance(node, ast.ImportFrom) and node.module:
        return [f"{rel}:{line}: imports {hit}" for hit in _removed_imports(node)]
    if isinstance(node, ast.Attribute):
        if node.attr in REMOVED_NAMES:
            return [f"{rel}:{line}: .{node.attr}"]
        if node.attr in REMOVED_MODULE_ATTRS and _is_tenants_module(node.value, env()):
            return [f"{rel}:{line}: _tenants.{node.attr}"]
        if node.attr in RETIRED_HELPERS:
            return [f"{rel}:{line}: .{node.attr} (resolves the lab via the removed resolver)"]
        if node.attr in RETIRED_LAB_CONSTANTS:
            return [f"{rel}:{line}: .{node.attr} (the retired lab's path)"]
    elif isinstance(node, ast.Constant) and isinstance(node.value, str):
        hits = _spelled(node.value)
        if hits and id(node) not in prose():
            return [f"{rel}:{line}: {hit}" for hit in hits]
    return []


def _py_findings(path: Path, rel: str) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
    # The import env and the prose set each cost a whole-tree walk; build them only when a
    # node that needs one turns up (almost no file has such a node).
    env = functools.cache(lambda: _AST.module_env(tree))
    prose = functools.cache(lambda: _bare_strings(tree))
    return [f for node in ast.walk(tree) for f in _node_findings(node, rel, env, prose)]


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


# ======================================================================================
# s084 — an adapter gains a verb while the lab is walked by no gate.
# ======================================================================================

#: The C26 test modules whose lab-content assertions move to the fixture in piece 1.
C26_MODULES = ("test_1106_layout.py", "test_verb_dispositions_995.py",
               "test_correlation_template_1003.py",
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


# ======================================================================================
# R5 — the path-only readers survive piece 1 (H2).
# ======================================================================================



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
    DEFENDER / "docs" / "oracle-calibration.md", DEFENDER / "skills" / "handbook" / "SKILL.md",
    DEFENDER / "skills" / "handbook" / "content" / "runtime-loop.md",
)

_SETUP_FROM = re.compile(r"setup\s+\S+\s+--from\b")
_CLONE_INTO_KNOWLEDGE = re.compile(r"\bclone\b[^\n]{0,160}knowledge")
_AFTER_CLONE = re.compile(
    r"(after|once|when)\b[^.\n]{0,60}\bclone\b[^.\n]{0,60}\b(exit|complete|finish|succeed)",
    re.IGNORECASE)
_CREDENTIALS = re.compile(r"credential helper|ssh[- ]agent", re.IGNORECASE)


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


def test_1159_the_census_lint_keeps_exit_2_and_its_own_framing_when_the_census_is_blind(
        tmp_path: Path) -> None:
    """#1159 non-obligation: the lint's exit scheme is unchanged. Over a tmp checkout whose
    adapter does not parse (the census was never taken) it exits EXACTLY 2 — "the gate could
    not run" — naming the broken system, and never `tenant.py check`'s framing that a table
    went unchecked (that line is built only in tenant.py; the lint checks no table at all
    then). The positive control: the same checkout before the broken adapter exits 0."""
    checkout = H.tmp_checkout(tmp_path / "checkout")
    rc, out = _census(checkout)
    assert rc == 0, f"the control checkout is not clean:\n{out}"
    H.add_adapter(checkout, H.BROKEN_SYSTEM, H.BROKEN_ADAPTER)
    rc, out = _census(checkout)
    assert rc == 2, f"the census-blind lint exited {rc}, not 2:\n{out}"
    assert H.BROKEN_SYSTEM in out, f"the lint does not name the broken adapter:\n{out}"
    assert "was not checked" not in out, (
        f"the lint's output carries the check command's unchecked-table framing:\n{out}")
